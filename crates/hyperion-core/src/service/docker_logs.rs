//! Reading container and stack logs.
//!
//! The container is looked up in the node's own inspect result and docker is
//! handed the id found there, never anything that came from a form. Output is
//! bounded at every step (bytes read, lines kept, the filter, the response),
//! decoded lossily, stripped of escape sequences and never written to a log,
//! an audit entry or a notification.
//!
//! Following is polling: the caller hands back the `cursor` it got. A cursor
//! is the last timestamp seen plus a fingerprint of every line seen at exactly
//! that timestamp, so two lines that share a timestamp are neither shown twice
//! nor lost when the second one turns up in a later poll.

use super::docker::daemon_silent;
use super::*;
use hyperion_adapters::docker::{ContainerId, DockerCmd, DockerError};
use hyperion_types::docker::{
    DockerContainer, DockerLogChunk, DockerLogLine, DockerLogRequest, DEFAULT_LOG_LINES,
    MAX_LOG_BYTES, MAX_LOG_LINES,
};
use std::sync::Arc;

/// `docker logs` processes running at once for a whole-stack read.
const MAX_CONCURRENT_READS: usize = 8;
/// Containers read for one stack. More than this is a stack nobody reads
/// through a web page; the rest is reported as left out.
const MAX_STACK_CONTAINERS: usize = 32;
/// Room kept below [`MAX_LOG_BYTES`] for the envelope and the per-line
/// bookkeeping.
const BYTE_HEADROOM: usize = 1024;
/// Counted against the byte budget for each line on top of its strings.
const LINE_OVERHEAD: usize = 16;
/// Longest filter accepted, in characters.
const FILTER_MAX_CHARS: usize = 200;
/// Longest cursor accepted.
const CURSOR_MAX_BYTES: usize = 2048;
/// Fingerprints kept for lines that share the newest timestamp. Beyond this a
/// line may be shown twice; none is ever lost.
const CURSOR_MAX_SEEN: usize = 64;
/// Longest name taken from a request.
const NAME_MAX_CHARS: usize = 128;
/// Longest actor name written to the audit entry.
const ACTOR_MAX_CHARS: usize = 64;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Remove ANSI escape sequences (colours, cursor movement, window titles).
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\u{1b}' => match it.peek().copied() {
                Some('[') => {
                    it.next();
                    skip_csi(&mut it);
                }
                // Operating system command, device control and the like: a
                // string that ends at BEL or at ESC \.
                Some(']' | 'P' | '^' | '_' | 'X') => {
                    it.next();
                    while let Some(n) = it.next() {
                        if n == '\u{7}' {
                            break;
                        }
                        if n == '\u{1b}' {
                            if it.peek() == Some(&'\\') {
                                it.next();
                            }
                            break;
                        }
                    }
                }
                // ESC, some intermediates, one final character.
                Some(n) if ('\u{20}'..='\u{2f}').contains(&n) => {
                    while it.peek().is_some_and(|n| ('\u{20}'..='\u{2f}').contains(n)) {
                        it.next();
                    }
                    it.next();
                }
                Some(_) => {
                    it.next();
                }
                None => {}
            },
            '\u{9b}' => skip_csi(&mut it),
            c => out.push(c),
        }
    }
    out
}

/// Past the parameters of a control sequence and its final character. A
/// character that cannot belong to one ends it unconsumed.
fn skip_csi(it: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&n) = it.peek() {
        match n {
            '\u{40}'..='\u{7e}' => {
                it.next();
                return;
            }
            '\u{20}'..='\u{3f}' => {
                it.next();
            }
            _ => return,
        }
    }
}

/// What is shown for one line of a log: no escape sequences, no control
/// characters (a tab stays) and none of the characters that reorder text.
fn clean_text(s: &str) -> String {
    strip_ansi(s)
        .chars()
        .filter(|&c| {
            (c == '\t' || !c.is_control())
                && !matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

/// `s` cut to at most `max` bytes, on a character boundary.
fn cut_at_char(s: &str, max: usize) -> &str {
    let mut i = max.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

/// Nanoseconds since the epoch for one of docker's timestamps.
fn ts_nanos(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()?
        .timestamp_nanos_opt()
}

/// Sort key of a line; lines without a usable timestamp sort first.
fn key_of(l: &DockerLogLine) -> i64 {
    ts_nanos(&l.ts).unwrap_or(i64::MIN)
}

/// FNV-1a, because a cursor outlives the process that made it and
/// `DefaultHasher` promises nothing across releases.
pub(crate) fn fingerprint(l: &DockerLogLine) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in l
        .service
        .bytes()
        .chain(std::iter::once(0))
        .chain(l.text.bytes())
    {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Where a reader stopped: the newest timestamp it has, and the lines it has
/// at exactly that timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogCursor {
    nanos: i64,
    seen: Vec<u64>,
}

impl LogCursor {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        if s.len() > CURSOR_MAX_BYTES {
            return None;
        }
        let (n, rest) = s.split_once(':').unwrap_or((s, ""));
        let nanos: i64 = n.parse().ok().filter(|n| *n >= 0)?;
        let mut seen = Vec::new();
        if !rest.is_empty() {
            for h in rest.split('.') {
                if h.is_empty() || h.len() > 16 {
                    return None;
                }
                seen.push(u64::from_str_radix(h, 16).ok()?);
                if seen.len() > CURSOR_MAX_SEEN {
                    return None;
                }
            }
        }
        Some(Self { nanos, seen })
    }

    pub(crate) fn render(&self) -> String {
        if self.seen.is_empty() {
            return self.nanos.to_string();
        }
        let seen: Vec<String> = self.seen.iter().map(|h| format!("{h:x}")).collect();
        format!("{}:{}", self.nanos, seen.join("."))
    }

    /// Whole seconds to give `docker logs --since`, rounded down so the line
    /// at the cursor is read again and recognised rather than missed.
    fn since_secs(&self) -> i64 {
        self.nanos.div_euclid(1_000_000_000)
    }
}

/// Lines not yet seen by a reader at `cursor`. Without one, all of them.
pub(crate) fn lines_after(
    lines: Vec<DockerLogLine>,
    cursor: Option<&LogCursor>,
) -> Vec<DockerLogLine> {
    let Some(c) = cursor else { return lines };
    let mut seen = c.seen.clone();
    lines
        .into_iter()
        .filter(|l| {
            let k = key_of(l);
            if k < c.nanos {
                return false;
            }
            if k > c.nanos {
                return true;
            }
            // One fingerprint covers one line: two identical lines at the
            // same instant are two lines.
            let f = fingerprint(l);
            match seen.iter().position(|s| *s == f) {
                Some(i) => {
                    seen.swap_remove(i);
                    false
                }
                None => true,
            }
        })
        .collect()
}

/// The cursor for a reader who has now seen `fresh` (what [`lines_after`]
/// returned) on top of what `old` covered.
fn advance(old: Option<&LogCursor>, fresh: &[DockerLogLine]) -> Option<LogCursor> {
    let newest = fresh.iter().map(key_of).filter(|k| *k != i64::MIN).max();
    let Some(newest) = newest else {
        return old.cloned();
    };
    let mut seen: Vec<u64> = match old {
        Some(o) if o.nanos == newest => o.seen.clone(),
        _ => Vec::new(),
    };
    for l in fresh.iter().filter(|l| key_of(l) == newest) {
        if seen.len() < CURSOR_MAX_SEEN {
            seen.push(fingerprint(l));
        }
    }
    Some(LogCursor {
        nanos: newest,
        seen,
    })
}

/// Several containers' lines as one log: oldest first, equal timestamps in
/// the order the containers were given, and only the newest `limit` kept.
pub(crate) fn merge_by_ts(parts: Vec<Vec<DockerLogLine>>, limit: usize) -> Vec<DockerLogLine> {
    let mut keyed: Vec<(i64, DockerLogLine)> = parts
        .into_iter()
        .flatten()
        .map(|l| (key_of(&l), l))
        .collect();
    keyed.sort_by_key(|(k, _)| *k);
    let skip = keyed.len().saturating_sub(limit);
    keyed.into_iter().skip(skip).map(|(_, l)| l).collect()
}

/// Turn what `docker logs --timestamps` printed into lines. Never fails: bytes
/// that are not UTF-8 are replaced, a line without a timestamp takes the one
/// before it, and a run that was cut short loses its last, partial line.
pub(crate) fn parse_log_bytes(bytes: &[u8], service: &str, cut_short: bool) -> Vec<DockerLogLine> {
    let mut pieces: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    // The text after the last newline is nothing when the output ended with
    // one. Otherwise it is a last line docker printed without a newline (kept),
    // or, when the run was cut short, a line cut in the middle (dropped,
    // unless it is the only thing there is to show).
    if pieces.last().is_some_and(|p| p.is_empty()) || (cut_short && pieces.len() > 1) {
        pieces.pop();
    }
    let mut out: Vec<DockerLogLine> = Vec::with_capacity(pieces.len());
    let mut last_ts = String::new();
    for raw in pieces {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let line = String::from_utf8_lossy(raw);
        let (ts, rest) = match line.split_once(' ') {
            Some((t, r)) if ts_nanos(t).is_some() => (t, r),
            None if ts_nanos(&line).is_some() => (&*line, ""),
            _ => ("", &*line),
        };
        if !ts.is_empty() {
            last_ts = ts.to_string();
        }
        let text = clean_text(rest);
        if ts.is_empty() && text.is_empty() {
            continue;
        }
        out.push(DockerLogLine {
            ts: last_ts.clone(),
            service: service.to_string(),
            text,
        });
    }
    out.sort_by_key(key_of);
    out
}

/// The newest lines that fit in `budget` bytes, oldest first, and whether
/// anything was left out. A single line larger than the budget is cut.
pub(crate) fn fit_bytes(lines: Vec<DockerLogLine>, budget: usize) -> (Vec<DockerLogLine>, bool) {
    let mut kept: Vec<DockerLogLine> = Vec::new();
    let mut used = 0usize;
    let mut cut = false;
    let total = lines.len();
    for mut l in lines.into_iter().rev() {
        let fixed = l.ts.len() + l.service.len() + LINE_OVERHEAD;
        let cost = fixed + l.text.len();
        if used + cost <= budget {
            used += cost;
            kept.push(l);
            continue;
        }
        cut = true;
        if kept.is_empty() {
            let room = budget.saturating_sub(fixed);
            let keep = cut_at_char(&l.text, room).len();
            l.text.truncate(keep);
            kept.push(l);
        }
        break;
    }
    cut |= kept.len() < total;
    kept.reverse();
    (kept, cut)
}

/// Lines whose text contains `needle`, which is already lower case.
fn apply_filter(lines: Vec<DockerLogLine>, needle: &str) -> Vec<DockerLogLine> {
    lines
        .into_iter()
        .filter(|l| l.text.to_lowercase().contains(needle))
        .collect()
}

fn clean_actor(s: &str) -> String {
    let t: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(ACTOR_MAX_CHARS)
        .collect();
    let t = t.trim();
    if t.is_empty() {
        "web".to_string()
    } else {
        t.to_string()
    }
}

fn name_ok(s: &str) -> bool {
    s.chars().count() <= NAME_MAX_CHARS && !s.chars().any(|c| c.is_control())
}

fn bad(message: &str) -> RpcError {
    RpcError::Validation {
        message: message.into(),
    }
}

/// A docker failure as the person at the log page should read it. Docker's
/// own words are not passed on: with stdout and stderr merged they can be
/// log text.
fn log_error(e: &DockerError) -> RpcError {
    match e {
        DockerError::NotInstalled => bad("Docker is not installed on this node."),
        DockerError::NotResponding => daemon_silent(),
        DockerError::Failed(_) => bad(
            "Docker could not read that log. The container may have been removed a moment \
             ago; reload the page.",
        ),
        DockerError::Parse(_) => bad("Docker's output could not be read."),
    }
}

/// `f` over every item, at most `limit` at a time, results in the order of
/// the items. A task that panics yields `None` and spares the others.
pub(crate) async fn bounded_map<T, R, F, Fut>(items: Vec<T>, limit: usize, f: F) -> Vec<Option<R>>
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> Fut,
    Fut: std::future::Future<Output = R> + Send + 'static,
{
    let gate = Arc::new(tokio::sync::Semaphore::new(limit.max(1)));
    let mut set = tokio::task::JoinSet::new();
    let n = items.len();
    for (i, item) in items.into_iter().enumerate() {
        let (gate, work) = (gate.clone(), f(item));
        set.spawn(async move {
            let _permit = gate.acquire_owned().await;
            (i, work.await)
        });
    }
    let mut out: Vec<Option<R>> = (0..n).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, r)) = joined {
            out[i] = Some(r);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The call
// ---------------------------------------------------------------------------

struct Target {
    id: ContainerId,
    service: String,
}

fn target_of(c: &DockerContainer) -> Option<Target> {
    Some(Target {
        id: ContainerId::parse(&c.id).ok()?,
        service: if c.service.is_empty() {
            c.name.clone()
        } else {
            c.service.clone()
        },
    })
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Read a container's or a stack's log. Nothing from the request reaches
    /// docker: the container is found in the node's own inspect result. At
    /// most [`MAX_CONCURRENT_READS`] `docker logs` run at once and the answer
    /// never holds more than [`MAX_LOG_BYTES`].
    pub async fn docker_logs(&self, req: DockerLogRequest) -> Result<DockerLogChunk, RpcError> {
        if !name_ok(&req.project) || req.project.starts_with('(') {
            return Err(bad("not a stack name"));
        }
        if let Some(c) = &req.container {
            if c.is_empty() || !name_ok(c) {
                return Err(bad("not a container name"));
            }
        }
        let needle = match req.filter.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(f) if f.chars().count() > FILTER_MAX_CHARS => {
                return Err(bad("The filter is too long."))
            }
            Some(f) if f.chars().any(|c| c.is_control()) => {
                return Err(bad("The filter has control characters."))
            }
            Some(f) => Some(f.to_lowercase()),
        };
        let cursor = match req.since_cursor.as_deref() {
            None | Some("") => None,
            Some(c) => Some(LogCursor::parse(c).ok_or_else(|| bad("not a log cursor"))?),
        };
        let wanted = match req.lines {
            0 => DEFAULT_LOG_LINES,
            n => n.min(MAX_LOG_LINES),
        };

        // Which containers: only ever ones the node itself reported.
        let status = self.docker_overview().await?;
        let project = status
            .projects
            .iter()
            .find(|p| p.name == req.project)
            .ok_or_else(|| bad("No such stack on this node."))?;
        let mut left_out = false;
        let targets: Vec<Target> = match &req.container {
            Some(name) => {
                let c = project
                    .containers
                    .iter()
                    .find(|c| &c.name == name)
                    .ok_or_else(|| bad("No such container in this stack."))?;
                vec![target_of(c).ok_or_else(|| bad("That container has no readable id."))?]
            }
            None => {
                let all: Vec<Target> = project.containers.iter().filter_map(target_of).collect();
                if all.len() > MAX_STACK_CONTAINERS {
                    left_out = true;
                }
                all.into_iter().take(MAX_STACK_CONTAINERS).collect()
            }
        };
        if targets.is_empty() {
            return Err(bad("This stack has no containers to read."));
        }

        // A poll must not lose lines between two beats, and a filter needs
        // something to look through; a plain first read wants what was asked.
        let tail = if cursor.is_some() || needle.is_some() {
            MAX_LOG_LINES
        } else {
            wanted
        };
        let limit = (if cursor.is_some() {
            MAX_LOG_LINES
        } else {
            wanted
        }) as usize;
        let since = cursor.as_ref().map(LogCursor::since_secs);
        let share = MAX_LOG_BYTES / targets.len();

        let reads = self.docker_read_logs(targets, tail, since, share).await;

        let mut parts: Vec<Vec<DockerLogLine>> = Vec::new();
        let mut unreadable = 0u32;
        let mut cut_short = left_out;
        let mut first_error: Option<DockerError> = None;
        for r in reads {
            match r {
                Ok((lines, cut)) => {
                    cut_short |= cut;
                    parts.push(lines);
                }
                Err(e) => {
                    unreadable += 1;
                    first_error.get_or_insert(e);
                }
            }
        }
        let outcome = |ok: bool| if ok { "ok" } else { "failed" };
        if parts.is_empty() {
            self.docker_logs_audit(&req, wanted, outcome(false)).await;
            return Err(log_error(
                &first_error.unwrap_or(DockerError::NotResponding),
            ));
        }
        self.docker_logs_audit(&req, wanted, outcome(true)).await;

        let merged = merge_by_ts(parts, usize::MAX);
        let fresh = lines_after(merged, cursor.as_ref());
        // The cursor covers everything read, so lines a filter hides are not
        // asked for again.
        let next = advance(cursor.as_ref(), &fresh);
        let shown = match &needle {
            Some(n) => apply_filter(fresh, n),
            None => fresh,
        };
        let skip = shown.len().saturating_sub(limit);
        let shown: Vec<DockerLogLine> = shown.into_iter().skip(skip).collect();
        let (lines, over) = fit_bytes(shown, MAX_LOG_BYTES - BYTE_HEADROOM);
        Ok(DockerLogChunk {
            lines,
            cursor: next.map(|c| c.render()),
            // Dropping old lines to honour the line count is not a loss the
            // reader has to be told about; running out of bytes is.
            truncated: cut_short || over,
            unreadable,
        })
    }

    /// One `docker logs` per target, eight at a time, in the order given.
    async fn docker_read_logs(
        &self,
        targets: Vec<Target>,
        tail: u32,
        since: Option<i64>,
        share: usize,
    ) -> Vec<Result<(Vec<DockerLogLine>, bool), DockerError>> {
        let adapters = self.adapters.clone();
        bounded_map(targets, MAX_CONCURRENT_READS, move |t: Target| {
            let adapters = adapters.clone();
            async move {
                adapters
                    .docker_read(
                        DockerCmd::Logs {
                            id: t.id,
                            tail,
                            since,
                        },
                        share,
                    )
                    .await
                    .map(|bytes| {
                        let cut_short = bytes.len() >= share;
                        let bytes = &bytes[..bytes.len().min(share)];
                        (parse_log_bytes(bytes, &t.service, cut_short), cut_short)
                    })
            }
        })
        .await
        .into_iter()
        .map(|r| r.unwrap_or(Err(DockerError::NotResponding)))
        .collect()
    }

    /// The audit entry for opening a log: who, which stack and container. No
    /// filter and no text.
    async fn docker_logs_audit(&self, req: &DockerLogRequest, lines: u32, result: &str) {
        let Some(actor) = req.audit_actor.as_deref() else {
            return;
        };
        let shown = if req.project.is_empty() {
            "(other)"
        } else {
            req.project.as_str()
        };
        let target = match &req.container {
            Some(c) => format!("{shown}/{c}"),
            None => shown.to_string(),
        };
        self.append_audit_as(
            0,
            &clean_actor(actor),
            "docker.logs.read",
            Some(&target),
            &serde_json::json!({
                "project": req.project,
                "container": req.container,
                "lines": lines,
            })
            .to_string(),
            result,
        )
        .await;
    }
}
