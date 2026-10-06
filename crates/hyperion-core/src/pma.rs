//! Node side of the phpMyAdmin pass-through: one browser request in, one
//! phpMyAdmin response out, over nginx's root-only unix socket.
//!
//! See `hyperion_types::pma` for the security model. What lives here is the
//! part only the owning node can do: attach the hosting's database
//! credentials (read from this node's secrets store) and talk to nginx.
//!
//! The HTTP is deliberately HTTP/1.0 with no keep-alive: nginx then answers
//! with a plain body terminated by connection close — no chunked encoding to
//! decode — which keeps the parser small enough to test exhaustively.

use base64::Engine as _;
use hyperion_types::pma::{
    filter_cookie_header, filter_response_headers, header_value_ok, PmaHttpRequest,
    PmaHttpResponse, FORWARDED_REQUEST_HEADERS, MAX_RESPONSE_BODY,
};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// nginx's phpMyAdmin server listens here. The directory is 0700 root, so
/// only root (this agent) can connect — written by `packaging/install/
/// phpmyadmin.sh`.
pub const NGINX_SOCKET: &str = "/run/hyperion-pma/nginx.sock";

/// How long one phpMyAdmin request may take end to end. A heavy query or an
/// export can run a while; the master's RPC timeout for this request kind is
/// set just above it.
pub const REQUEST_TIMEOUT_SECS: u64 = 300;

/// The credentials attached to every request. They travel to nginx (and on
/// to PHP as `HTTP_X_HYPERION_PMA_*`) base64-encoded, so a password with any
/// byte in it still makes a valid header.
pub struct PmaCreds<'a> {
    pub db_user: &'a str,
    pub db_password: &'a str,
    pub db_name: &'a str,
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// Serialise the request nginx receives. `hosting_id` and `req` must already
/// have passed the `hyperion_types::pma` checks; header values are filtered
/// once more here, because this is the last point before bytes hit a socket.
pub fn build_request(
    hosting_id: &str,
    req: &PmaHttpRequest,
    body: &[u8],
    creds: &PmaCreds<'_>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1024 + body.len());
    out.extend_from_slice(
        format!(
            "{} /pma/{}{} HTTP/1.0\r\n",
            req.method, hosting_id, req.path
        )
        .as_bytes(),
    );
    // Host = the browser's authority, so anything phpMyAdmin derives from
    // HTTP_HOST matches what the browser sees. base_url_ok() vetted it.
    let host = req
        .base_url
        .strip_prefix("https://")
        .and_then(|r| r.split('/').next())
        .unwrap_or("localhost");
    let mut line = |k: &str, v: &str| {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    };
    line("Host", host);
    line("Connection", "close");
    for (k, v) in &req.headers {
        let lk = k.to_ascii_lowercase();
        if lk == "cookie" {
            if let Some(c) = filter_cookie_header([v.as_str()]) {
                line("cookie", &c);
            }
        } else if FORWARDED_REQUEST_HEADERS.contains(&lk.as_str()) && header_value_ok(v) {
            line(&lk, v);
        }
    }
    line("X-Hyperion-Pma-User", &b64(creds.db_user));
    line("X-Hyperion-Pma-Password", &b64(creds.db_password));
    line("X-Hyperion-Pma-Db", &b64(creds.db_name));
    line("X-Hyperion-Pma-Base", &b64(&req.base_url));
    if req.method == "POST" || !body.is_empty() {
        line("Content-Length", &body.len().to_string());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Parse nginx's raw answer into a filtered response.
pub fn parse_response(raw: &[u8]) -> Result<PmaHttpResponse, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("phpMyAdmin answered without a complete header block")?;
    let head =
        std::str::from_utf8(&raw[..split]).map_err(|_| "phpMyAdmin sent non-UTF-8 headers")?;
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| format!("bad status line from phpMyAdmin: {status_line:.80}"))?;
    let pairs: Vec<(&str, &str)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    Ok(PmaHttpResponse {
        status,
        headers: filter_response_headers(pairs),
        body_b64: base64::engine::general_purpose::STANDARD.encode(body),
    })
}

/// One round trip to nginx over `socket`.
pub async fn round_trip(
    socket: &Path,
    hosting_id: &str,
    req: &PmaHttpRequest,
    body: &[u8],
    creds: &PmaCreds<'_>,
) -> Result<PmaHttpResponse, String> {
    let wire = build_request(hosting_id, req, body, creds);
    let fut = async {
        let mut stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|e| format!("connect {}: {e}", socket.display()))?;
        stream
            .write_all(&wire)
            .await
            .map_err(|e| format!("send to phpMyAdmin: {e}"))?;
        // Do NOT shut down the write half here. nginx reads a half-closed
        // connection as the client going away and aborts the FastCGI request
        // (a 499 with an empty answer) — seen while testing this against a
        // real nginx. HTTP/1.0 + `Connection: close` already ends the
        // exchange: nginx closes after the response.
        //
        // Read to EOF with a ceiling: header block + MAX_RESPONSE_BODY.
        let cap = MAX_RESPONSE_BODY + 64 * 1024;
        let mut raw = Vec::new();
        let mut limited = (&mut stream).take(cap as u64 + 1);
        limited
            .read_to_end(&mut raw)
            .await
            .map_err(|e| format!("read from phpMyAdmin: {e}"))?;
        if raw.len() > cap {
            return Err(format!(
                "phpMyAdmin's answer is larger than {} MiB — export big tables from a backup instead",
                MAX_RESPONSE_BODY / (1024 * 1024)
            ));
        }
        parse_response(&raw)
    };
    tokio::time::timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS), fut)
        .await
        .map_err(|_| format!("phpMyAdmin did not answer within {REQUEST_TIMEOUT_SECS}s"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "01920a3b-7c4d-7e8f-9a0b-1c2d3e4f5a6b";

    fn req(method: &str, path: &str, headers: Vec<(&str, &str)>) -> PmaHttpRequest {
        PmaHttpRequest {
            method: method.into(),
            path: path.into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body_b64: String::new(),
            base_url: format!("https://panel.example.com:8447/pma/{ID}/"),
        }
    }

    const CREDS: PmaCreds<'static> = PmaCreds {
        db_user: "lm_abc123_u",
        db_password: "p@ss\nword:with\"odd bytes",
        db_name: "lm_abc123_shop",
    };

    #[test]
    fn request_carries_creds_encoded_and_drops_smuggled_headers() {
        let r = req(
            "POST",
            "/index.php?route=/sql",
            vec![
                ("content-type", "application/x-www-form-urlencoded"),
                // A forged credential header must not reach nginx even if a
                // compromised master put it on the wire.
                ("x-hyperion-pma-user", "cm9vdA=="),
                ("authorization", "Basic x"),
                ("cookie", "hyperion_session=SECRET; phpMyAdmin_https=abc"),
            ],
        );
        let wire = build_request(ID, &r, b"a=1", &CREDS);
        let s = String::from_utf8(wire).unwrap();
        assert!(s.starts_with(&format!("POST /pma/{ID}/index.php?route=/sql HTTP/1.0\r\n")));
        assert!(s.contains("Host: panel.example.com:8447\r\n"));
        assert!(s.contains("content-type: application/x-www-form-urlencoded\r\n"));
        assert!(s.contains("cookie: phpMyAdmin_https=abc\r\n"));
        assert!(!s.contains("cm9vdA=="));
        assert!(!s.contains("SECRET"));
        assert!(!s.to_ascii_lowercase().contains("authorization"));
        assert!(s.contains(&format!(
            "X-Hyperion-Pma-Password: {}\r\n",
            b64(CREDS.db_password)
        )));
        assert!(!s.contains("p@ss"));
        assert!(s.contains("Content-Length: 3\r\n"));
        assert!(s.ends_with("\r\n\r\na=1"));
        // Exactly one header block: the password's newline did not split it.
        assert_eq!(s.matches("\r\n\r\n").count(), 1);
    }

    #[test]
    fn get_has_no_content_length() {
        let wire = build_request(ID, &req("GET", "/", vec![]), b"", &CREDS);
        let s = String::from_utf8(wire).unwrap();
        assert!(s.starts_with(&format!("GET /pma/{ID}/ HTTP/1.0\r\n")));
        assert!(!s.contains("Content-Length"));
    }

    #[test]
    fn parses_and_filters_response() {
        let raw = b"HTTP/1.1 302 Found\r\nServer: nginx\r\nX-Powered-By: PHP/8.3\r\n\
Set-Cookie: phpMyAdmin_https=x; path=/pma/a/\r\nSet-Cookie: pma_lang=cs\r\n\
Location: https://h:8447/pma/a/index.php\r\nContent-Type: text/html\r\n\r\n<b>\r\n\r\nbody</b>";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 302);
        let names: Vec<&str> = r.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            ["set-cookie", "set-cookie", "location", "content-type"]
        );
        let body = base64::engine::general_purpose::STANDARD
            .decode(&r.body_b64)
            .unwrap();
        assert_eq!(body, b"<b>\r\n\r\nbody</b>");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_response(b"").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nno end").is_err());
        assert!(parse_response(b"HTTP/1.1 abc OK\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 999 Nope\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn round_trip_over_a_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("nginx.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let got = String::from_utf8_lossy(&buf[..n]).to_string();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
                .await
                .unwrap();
            got
        });
        let r = round_trip(&sock, ID, &req("GET", "/", vec![]), b"", &CREDS)
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body_b64, b64("hello"));
        let seen = server.await.unwrap();
        assert!(seen.contains("X-Hyperion-Pma-Db: "));
    }
}
