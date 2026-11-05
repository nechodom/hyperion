//! What a registry holds under a tag: the digest of an image reference.
//!
//! Two ways, chosen by what the registry is, because Docker Hub rate-limits
//! anonymous pulls per IP address and a node's own `docker pull` must not pay
//! for this check:
//!
//! * Docker Hub: an anonymous token, then a `HEAD` on the manifest. A `HEAD`
//!   is not a pull to Hub, so the budget stays where it was (measured on a
//!   node: `docker buildx imagetools inspect` costs a pull per run, three
//!   `HEAD`s cost none). The token request and the `HEAD` go through
//!   `/usr/bin/curl`, with the options on stdin and bounded in time.
//! * Anything else, and a Hub repository that wants a login: `docker buildx
//!   imagetools inspect`, which signs in with Docker's own credential store.
//!   Hyperion never reads `~/.docker/config.json`, never asks for a password
//!   and never puts one on a command line. A registry whose credentials the
//!   agent's Docker cannot reach answers `Unauthorized`.
//!
//! The reference is parsed and validated first and then built into a URL;
//! it is never part of a shell string.

use crate::cmd::{curl_config_quote, curl_with_config_capture};
use crate::docker::{self, DockerCmd, DockerError, ImageRef};

/// Why a registry could not say what is under a tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteDigestError {
    /// HTTP 429. Asking again soon makes it worse.
    RateLimited,
    /// The registry wants credentials Hyperion's Docker does not have.
    Unauthorized,
    /// Unreachable, an odd answer, or the tag is not there. The text is one
    /// short line for the operator.
    Unavailable(String),
    /// This node cannot ask: `docker buildx` is missing.
    Unsupported,
}

impl std::fmt::Display for RemoteDigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited => f.write_str("the registry's rate limit was reached"),
            Self::Unauthorized => f.write_str("the registry refused access (unauthorized)"),
            Self::Unavailable(t) => write!(f, "the registry could not be asked: {t}"),
            Self::Unsupported => f.write_str("docker buildx is missing"),
        }
    }
}

const HUB_REGISTRY: &str = "registry-1.docker.io";
const HUB_AUTH: &str = "auth.docker.io";
/// Media types a manifest `HEAD` must ask for, the index types first: the
/// digest a local `RepoDigests` entry holds is the index digest of a
/// multi-arch image, and a registry answers with the digest of whichever
/// type the request prefers.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";
/// One curl run, token or `HEAD`.
const CURL_MAX_TIME_SECS: u32 = 20;
const CURL_CONNECT_SECS: u32 = 8;
const IMAGETOOLS_MAX_BYTES: usize = 256 * 1024;
const REASON_MAX_CHARS: usize = 160;

/// A parsed image reference. The pieces are validated; none can carry a
/// quote, space or control character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// `docker.io` for every spelling of Docker Hub.
    pub registry: String,
    /// `library/nginx`, `user/app`, `o/app`.
    pub repo: String,
    /// `latest` when the reference names none.
    pub tag: String,
    /// `sha256:...` when the reference pins one.
    pub digest: Option<String>,
}

impl Reference {
    pub fn is_hub(&self) -> bool {
        self.registry == "docker.io"
    }

    /// The repository as a local `RepoDigests` entry spells it: Hub drops
    /// `docker.io/` and the `library/` of official images, every other
    /// registry keeps its host.
    pub fn repo_name(&self) -> String {
        if self.is_hub() {
            self.repo
                .strip_prefix("library/")
                .unwrap_or(&self.repo)
                .to_string()
        } else {
            format!("{}/{}", self.registry, self.repo)
        }
    }
}

fn is_hub_host(h: &str) -> bool {
    matches!(h, "docker.io" | "index.docker.io" | "registry-1.docker.io")
}

fn valid_registry(h: &str) -> bool {
    let (host, port) = match h.rsplit_once(':') {
        Some((a, p)) => (a, Some(p)),
        None => (h, None),
    };
    !host.is_empty()
        && host.len() <= 253
        && host
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        && port.map_or(true, |p| {
            !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit())
        })
}

/// One path component of a repository: lowercase alphanumerics joined by
/// single `.`, `_`, `__` or runs of `-`.
fn valid_component(c: &str) -> bool {
    let b = c.as_bytes();
    let alnum = |x: u8| x.is_ascii_lowercase() || x.is_ascii_digit();
    if b.is_empty() || !alnum(b[0]) || !alnum(b[b.len() - 1]) {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if alnum(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && !alnum(b[i]) {
            i += 1;
        }
        let sep = &b[start..i];
        let ok = sep == b"." || sep == b"_" || sep == b"__" || sep.iter().all(|x| *x == b'-');
        if !ok {
            return false;
        }
    }
    true
}

fn valid_tag(t: &str) -> bool {
    let b = t.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b.iter()
            .all(|x| x.is_ascii_alphanumeric() || matches!(x, b'_' | b'.' | b'-'))
}

fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Split a reference the way Docker does: a first component with a `.` or a
/// `:` (or `localhost`) is a registry host, otherwise the name is on Docker
/// Hub, where a name without a `/` lives under `library/`.
pub fn parse_reference(s: &str) -> Result<Reference, String> {
    let bad = || format!("not an image reference: {s:?}");
    if s.is_empty() || s.len() > 512 {
        return Err(bad());
    }
    let (name_tag, digest) = match s.split_once('@') {
        Some((a, d)) => (a, Some(d)),
        None => (s, None),
    };
    if let Some(d) = digest {
        if !valid_digest(d) {
            return Err(bad());
        }
    }
    let tail_at = name_tag.rfind('/').map_or(0, |i| i + 1);
    let (name, tag) = match name_tag[tail_at..].find(':') {
        Some(i) => (&name_tag[..tail_at + i], Some(&name_tag[tail_at + i + 1..])),
        None => (name_tag, None),
    };
    if let Some(t) = tag {
        if !valid_tag(t) {
            return Err(bad());
        }
    }
    let first = name.split('/').next().unwrap_or("");
    let has_host =
        name.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    let (registry, repo) = if has_host {
        (first, &name[first.len() + 1..])
    } else {
        ("docker.io", name)
    };
    if !valid_registry(registry) || repo.is_empty() {
        return Err(bad());
    }
    let hub = is_hub_host(registry);
    let registry = if hub { "docker.io" } else { registry };
    if !repo.split('/').all(valid_component) {
        return Err(bad());
    }
    let repo = if hub && !repo.contains('/') {
        format!("library/{repo}")
    } else {
        repo.to_string()
    };
    Ok(Reference {
        registry: registry.to_string(),
        repo,
        tag: tag.unwrap_or("latest").to_string(),
        digest: digest.map(str::to_string),
    })
}

/// The repository part of a reference or of a `RepoDigests` entry
/// (`nginx@sha256:...`), spelled the one way [`Reference::repo_name`] uses.
/// `None` for anything that is not a name.
pub fn repo_name_of(s: &str) -> Option<String> {
    parse_reference(s).ok().map(|r| r.repo_name())
}

// ---------------------------------------------------------------------------
// Docker Hub: anonymous token + HEAD
// ---------------------------------------------------------------------------

/// The options for one curl run, on stdin. Bounded in time and size, https
/// only, no redirects followed. `write-out` appends the HTTP status after the
/// output, on a line of its own.
fn curl_base(url: &str, head: bool) -> String {
    let mut c = String::new();
    c.push_str("silent\n");
    if head {
        c.push_str("head\n");
    }
    c.push_str(&format!("connect-timeout = {CURL_CONNECT_SECS}\n"));
    c.push_str(&format!("max-time = {CURL_MAX_TIME_SECS}\n"));
    c.push_str("max-filesize = 262144\n");
    c.push_str("proto = \"=https\"\n");
    c.push_str("write-out = \"\\n%{http_code}\"\n");
    c.push_str(&format!("url = \"{}\"\n", curl_config_quote(url)));
    c
}

fn token_config(repo: &str) -> String {
    curl_base(
        &format!(
            "https://{HUB_AUTH}/token?service=registry.docker.io&scope=repository:{repo}:pull"
        ),
        false,
    )
}

fn head_config(repo: &str, tag: &str, token: &str) -> String {
    let mut c = curl_base(
        &format!("https://{HUB_REGISTRY}/v2/{repo}/manifests/{tag}"),
        true,
    );
    c.push_str(&format!(
        "header = \"Authorization: Bearer {}\"\n",
        curl_config_quote(token)
    ));
    c.push_str(&format!(
        "header = \"Accept: {}\"\n",
        curl_config_quote(MANIFEST_ACCEPT)
    ));
    c
}

/// Split curl's output into the body (or headers) and the status that
/// `write-out` put on the last line. `None` when there is no status.
fn split_status(out: &str) -> Option<(&str, u16)> {
    let (body, code) = out.trim_end().rsplit_once('\n')?;
    Some((body, code.trim().parse().ok()?))
}

/// An anonymous token from the Hub auth service. Only a token that is plain
/// header text is accepted.
fn parse_token_answer(out: &str) -> Result<String, RemoteDigestError> {
    let Some((body, code)) = split_status(out) else {
        return Err(RemoteDigestError::Unavailable(
            "the token service gave no answer".into(),
        ));
    };
    match code {
        200 => {}
        429 => return Err(RemoteDigestError::RateLimited),
        c => {
            return Err(RemoteDigestError::Unavailable(format!(
                "the token service answered {c}"
            )))
        }
    }
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| RemoteDigestError::Unavailable("the token service answered oddly".into()))?;
    let token = v
        .get("token")
        .or_else(|| v.get("access_token"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    let plain = !token.is_empty()
        && token.len() <= 8192
        && token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~' | b'+' | b'/' | b'=')
        });
    if plain {
        Ok(token.to_string())
    } else {
        Err(RemoteDigestError::Unavailable(
            "the token service answered oddly".into(),
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HeadAnswer {
    Digest(String),
    /// 401 or 403: the repository is not public.
    NeedsLogin,
}

fn parse_head_answer(out: &str) -> Result<HeadAnswer, RemoteDigestError> {
    let Some((headers, code)) = split_status(out) else {
        return Err(RemoteDigestError::Unavailable(
            "the registry gave no answer".into(),
        ));
    };
    match code {
        200 => {}
        401 | 403 => return Ok(HeadAnswer::NeedsLogin),
        404 => {
            return Err(RemoteDigestError::Unavailable(
                "the registry has no such tag".into(),
            ))
        }
        429 => return Err(RemoteDigestError::RateLimited),
        c => {
            return Err(RemoteDigestError::Unavailable(format!(
                "the registry answered {c}"
            )))
        }
    }
    let digest = headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("docker-content-digest")
            .then(|| v.trim().to_string())
    });
    match digest {
        Some(d) if valid_digest(&d) => Ok(HeadAnswer::Digest(d)),
        _ => Err(RemoteDigestError::Unavailable(
            "the registry sent no digest".into(),
        )),
    }
}

async fn curl(config: &str) -> Result<String, RemoteDigestError> {
    match curl_with_config_capture(config).await {
        // Exit codes other than 0 are the transport's: resolve, connect,
        // TLS, timeout. The status comes from `write-out` otherwise.
        Ok((out, _, 0)) => Ok(out),
        Ok((_, _, _)) => Err(RemoteDigestError::Unavailable(
            "the registry could not be reached".into(),
        )),
        Err(_) => Err(RemoteDigestError::Unavailable(
            "curl could not be run".into(),
        )),
    }
}

async fn hub_head(r: &Reference) -> Result<HeadAnswer, RemoteDigestError> {
    let token = parse_token_answer(&curl(&token_config(&r.repo)).await?)?;
    parse_head_answer(&curl(&head_config(&r.repo, &r.tag, &token)).await?)
}

// ---------------------------------------------------------------------------
// docker buildx imagetools inspect
// ---------------------------------------------------------------------------

/// The manifest digest from `imagetools inspect`: the first `Digest:` line
/// that starts in column 0. Per-platform `Digest:` lines are indented.
fn parse_imagetools_digest(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.strip_prefix("Digest:"))
        .map(|d| d.trim().to_string())
        .filter(|d| valid_digest(d))
}

/// What a failed `imagetools inspect` was about, from docker's own stderr.
fn classify_imagetools_failure(stderr: &str) -> RemoteDigestError {
    let t = stderr.to_ascii_lowercase();
    if t.contains("not a docker command") || (t.contains("unknown command") && t.contains("buildx"))
    {
        return RemoteDigestError::Unsupported;
    }
    if t.contains("toomanyrequests") || t.contains("429") || t.contains("rate limit") {
        return RemoteDigestError::RateLimited;
    }
    if t.contains("unauthorized")
        || t.contains("401")
        || t.contains("403")
        || t.contains("denied")
        || t.contains("failed to authorize")
        || t.contains("authentication required")
    {
        return RemoteDigestError::Unauthorized;
    }
    let line = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let line: String = line
        .chars()
        .filter(|c| !c.is_control())
        .take(REASON_MAX_CHARS)
        .collect();
    if t.contains("not found") || t.contains("manifest unknown") {
        return RemoteDigestError::Unavailable("the registry has no such tag".into());
    }
    RemoteDigestError::Unavailable(if line.is_empty() {
        "docker could not read the registry".into()
    } else {
        line
    })
}

async fn imagetools(image: &ImageRef) -> Result<String, RemoteDigestError> {
    match docker::run(
        &DockerCmd::ImagetoolsInspect(image.clone()),
        IMAGETOOLS_MAX_BYTES,
    )
    .await
    {
        Ok(out) => parse_imagetools_digest(&String::from_utf8_lossy(&out))
            .ok_or_else(|| RemoteDigestError::Unavailable("the registry sent no digest".into())),
        Err(DockerError::Failed(t)) => Err(classify_imagetools_failure(&t)),
        Err(DockerError::NotInstalled) => Err(RemoteDigestError::Unavailable(
            "docker is not installed on this node".into(),
        )),
        Err(DockerError::NotResponding) => Err(RemoteDigestError::Unavailable(
            "docker did not answer".into(),
        )),
        Err(DockerError::Parse(_)) => Err(RemoteDigestError::Unavailable(
            "docker's answer could not be read".into(),
        )),
    }
}

/// The digest the registry holds under `image`'s tag.
///
/// Docker Hub is asked with a `HEAD` and an anonymous token so the check
/// never spends the node's pull budget. A Hub repository that wants a login,
/// and every other registry, is asked through `docker buildx imagetools`,
/// which uses Docker's own credential store.
pub async fn remote_digest(image: &ImageRef) -> Result<String, RemoteDigestError> {
    let r = parse_reference(image.as_str()).map_err(RemoteDigestError::Unavailable)?;
    if r.digest.is_some() {
        return Err(RemoteDigestError::Unavailable(
            "the reference is pinned to a digest".into(),
        ));
    }
    if r.is_hub() {
        match hub_head(&r).await? {
            HeadAnswer::Digest(d) => return Ok(d),
            HeadAnswer::NeedsLogin => {}
        }
    }
    imagetools(image).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Reference {
        parse_reference(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn docker_hub_short_names() {
        for (input, repo, tag) in [
            ("nginx", "library/nginx", "latest"),
            ("nginx:alpine", "library/nginx", "alpine"),
            ("user/app:1", "user/app", "1"),
            ("user/app", "user/app", "latest"),
            ("docker.io/library/nginx:1.27", "library/nginx", "1.27"),
            ("docker.io/nginx", "library/nginx", "latest"),
            ("index.docker.io/user/app:2", "user/app", "2"),
            ("registry-1.docker.io/user/app", "user/app", "latest"),
        ] {
            let p = r(input);
            assert!(p.is_hub(), "{input}");
            assert_eq!((p.repo.as_str(), p.tag.as_str()), (repo, tag), "{input}");
            assert_eq!(p.digest, None);
        }
    }

    #[test]
    fn other_registries_keep_their_host() {
        let p = r("ghcr.io/o/app:1.2");
        assert!(!p.is_hub());
        assert_eq!(
            (p.registry.as_str(), p.repo.as_str(), p.tag.as_str()),
            ("ghcr.io", "o/app", "1.2")
        );
        let p = r("registry.example.cz:5000/team/app");
        assert_eq!(
            (p.registry.as_str(), p.repo.as_str(), p.tag.as_str()),
            ("registry.example.cz:5000", "team/app", "latest")
        );
        let p = r("localhost:5000/app:dev");
        assert_eq!(p.registry, "localhost:5000");
        assert_eq!(r("localhost/app").registry, "localhost");
        // A host with a port, not a tag: the first component decides.
        assert!(!r("myhost:5000/x").is_hub());
    }

    #[test]
    fn a_digest_pins_the_reference() {
        let d = "sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606";
        let p = r(&format!("nginx@{d}"));
        assert_eq!(p.digest.as_deref(), Some(d));
        let p = r(&format!("ghcr.io/o/app:1.2@{d}"));
        assert_eq!((p.tag.as_str(), p.digest.as_deref()), ("1.2", Some(d)));
    }

    #[test]
    fn repo_names_compare_across_spellings() {
        assert_eq!(repo_name_of("nginx:alpine").as_deref(), Some("nginx"));
        assert_eq!(
            repo_name_of("nginx@sha256:aa"),
            None,
            "a short digest is no digest"
        );
        assert_eq!(
            repo_name_of("docker.io/library/nginx:1").as_deref(),
            Some("nginx")
        );
        assert_eq!(repo_name_of("user/app:2").as_deref(), Some("user/app"));
        assert_eq!(
            repo_name_of("ghcr.io/o/app:1").as_deref(),
            Some("ghcr.io/o/app")
        );
        let d = "sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606";
        assert_eq!(
            repo_name_of(&format!("nginx@{d}")).as_deref(),
            Some("nginx")
        );
        assert_eq!(
            repo_name_of(&format!("ghcr.io/o/app@{d}")).as_deref(),
            Some("ghcr.io/o/app")
        );
    }

    #[test]
    fn nonsense_is_refused() {
        for bad in [
            "",
            "Nginx",
            "a b",
            "x;rm -rf /",
            "-x",
            "nginx:",
            "nginx:bad tag",
            "ghcr.io/",
            "user//app",
            "user/app@sha256:xyz",
            "user/app:\"x",
            "UPPER/case",
            "a/-b",
            "a/b-",
            "a/b..c",
            "host:99999999/x",
            "host:/x",
        ] {
            assert!(parse_reference(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_head_asks_for_the_index_types_first() {
        let cfg = head_config("library/nginx", "alpine", "tok.en-1");
        let accept = cfg
            .lines()
            .find(|l| l.starts_with("header = \"Accept:"))
            .expect("accept header");
        let oci_index = accept
            .find("application/vnd.oci.image.index.v1+json")
            .expect("oci index");
        let list = accept
            .find("application/vnd.docker.distribution.manifest.list.v2+json")
            .expect("manifest list");
        let oci_manifest = accept
            .find("application/vnd.oci.image.manifest.v1+json")
            .expect("oci");
        let v2 = accept
            .find("application/vnd.docker.distribution.manifest.v2+json")
            .expect("v2");
        assert!(oci_index < list && list < oci_manifest && oci_manifest < v2);
        assert!(cfg
            .contains("url = \"https://registry-1.docker.io/v2/library/nginx/manifests/alpine\""));
        assert!(cfg.contains("\nhead\n"));
        assert!(cfg.contains("Authorization: Bearer tok.en-1"));
    }

    #[test]
    fn every_curl_is_bounded_and_https_only() {
        for cfg in [
            token_config("library/nginx"),
            head_config("library/nginx", "alpine", "t"),
        ] {
            assert!(cfg.contains("max-time = "), "{cfg}");
            assert!(cfg.contains("connect-timeout = "), "{cfg}");
            assert!(cfg.contains("max-filesize = "), "{cfg}");
            assert!(cfg.contains("proto = \"=https\""), "{cfg}");
            assert!(!cfg.contains("location"), "no redirects");
        }
        assert!(token_config("library/nginx").contains("scope=repository:library/nginx:pull"));
    }

    #[test]
    fn a_hub_token_answer() {
        assert_eq!(
            parse_token_answer("{\"token\":\"abc.DEF-1_2\",\"expires_in\":300}\n200").unwrap(),
            "abc.DEF-1_2"
        );
        assert_eq!(
            parse_token_answer("{\"access_token\":\"zzz\"}\n200").unwrap(),
            "zzz"
        );
        assert_eq!(
            parse_token_answer("{\"errors\":[]}\n429"),
            Err(RemoteDigestError::RateLimited)
        );
        for bad in [
            "{\"token\":\"a b\"}\n200",
            "{\"token\":\"a\\\"b\"}\n200",
            "{\"token\":\"a\\nb\"}\n200",
            "{\"token\":\"\"}\n200",
            "not json\n200",
            "{\"token\":\"x\"}\n500",
            "",
        ] {
            assert!(
                matches!(
                    parse_token_answer(bad),
                    Err(RemoteDigestError::Unavailable(_))
                ),
                "{bad:?}"
            );
        }
    }

    const D: &str = "sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606";

    #[test]
    fn a_head_answer_carries_the_digest() {
        let out = format!(
            "HTTP/2 200 \r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n\
             Docker-Content-Digest: {D}\r\nratelimit-remaining: 98;w=3600\r\n\r\n\n200"
        );
        assert_eq!(
            parse_head_answer(&out).unwrap(),
            HeadAnswer::Digest(D.into())
        );
    }

    #[test]
    fn a_head_answer_that_is_not_a_digest_is_not_one() {
        for out in [
            "HTTP/2 200 \r\ncontent-type: x\r\n\r\n\n200".to_string(),
            "HTTP/2 200 \r\ndocker-content-digest: sha256:short\r\n\r\n\n200".to_string(),
            "HTTP/2 200 \r\ndocker-content-digest: md5:abc\r\n\r\n\n200".to_string(),
            "".to_string(),
        ] {
            assert!(
                matches!(
                    parse_head_answer(&out),
                    Err(RemoteDigestError::Unavailable(_))
                ),
                "{out:?}"
            );
        }
    }

    #[test]
    fn head_statuses() {
        assert_eq!(
            parse_head_answer("HTTP/2 401 \r\n\r\n\n401").unwrap(),
            HeadAnswer::NeedsLogin
        );
        assert_eq!(
            parse_head_answer("HTTP/2 403 \r\n\r\n\n403").unwrap(),
            HeadAnswer::NeedsLogin
        );
        assert_eq!(
            parse_head_answer("HTTP/2 429 \r\n\r\n\n429"),
            Err(RemoteDigestError::RateLimited)
        );
        assert!(matches!(
            parse_head_answer("HTTP/2 404 \r\n\r\n\n404"),
            Err(RemoteDigestError::Unavailable(t)) if t.contains("no such tag")
        ));
        assert!(matches!(
            parse_head_answer("HTTP/2 503 \r\n\r\n\n503"),
            Err(RemoteDigestError::Unavailable(t)) if t.contains("503")
        ));
    }

    #[test]
    fn imagetools_output_gives_the_manifest_digest() {
        let out = format!(
            "Name:      docker.io/library/nginx:alpine\n\
             MediaType: application/vnd.oci.image.index.v1+json\n\
             Digest:    {D}\n\n\
             Manifests:\n  Name:        docker.io/library/nginx:alpine@sha256:aa\n  \
             MediaType:   application/vnd.oci.image.manifest.v1+json\n  \
             Platform:    linux/amd64\n  Digest:    sha256:{}\n",
            "b".repeat(64)
        );
        assert_eq!(parse_imagetools_digest(&out).as_deref(), Some(D));
        assert_eq!(parse_imagetools_digest("Name: x\n"), None);
        assert_eq!(parse_imagetools_digest("Digest: nope\n"), None);
    }

    #[test]
    fn imagetools_failures_are_told_apart() {
        for (text, want) in [
            (
                "ERROR: failed to authorize: failed to fetch anonymous token: 401 Unauthorized",
                RemoteDigestError::Unauthorized,
            ),
            (
                "ERROR: pull access denied, repository does not exist or may require authorization",
                RemoteDigestError::Unauthorized,
            ),
            (
                "ERROR: toomanyrequests: You have reached your pull rate limit",
                RemoteDigestError::RateLimited,
            ),
            (
                "docker: 'buildx' is not a docker command.",
                RemoteDigestError::Unsupported,
            ),
            (
                "unknown command: docker buildx",
                RemoteDigestError::Unsupported,
            ),
        ] {
            assert_eq!(classify_imagetools_failure(text), want, "{text}");
        }
        assert!(matches!(
            classify_imagetools_failure("ERROR: dial tcp: lookup r.example: no such host"),
            RemoteDigestError::Unavailable(t) if t.contains("no such host")
        ));
        let long = format!("ERROR: {}", "x".repeat(5000));
        assert!(matches!(
            classify_imagetools_failure(&long),
            RemoteDigestError::Unavailable(t) if t.chars().count() <= REASON_MAX_CHARS
        ));
    }

    /// Needs the network: the real Hub, anonymously, as the node does it.
    /// `cargo test -p hyperion-adapters live_hub -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn live_hub_head_of_nginx_alpine() {
        let d = remote_digest(&ImageRef::parse("nginx:alpine").unwrap())
            .await
            .unwrap();
        assert!(valid_digest(&d), "{d}");
    }
}
