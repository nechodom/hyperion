//! The run journal: how a detached export says where it is.
//!
//! A backgrounded export has nobody watching its stderr, so "where is it" has to
//! be answerable from disk, minutes or hours later, from a fresh shell. That is
//! what this module is: an append-only NDJSON file both writers share, plus the
//! renderers that turn it into a status line.
//!
//! Two processes append to it — the Rust packer (one event per site) and the
//! bash upload loop (one event per chunk) — so the format is chosen for exactly
//! that: one `writeln!` to an `O_APPEND` handle, never a read-modify-write.
//! Appends under `PIPE_BUF` are atomic on Linux, and every line here is far
//! under it, so the two writers cannot interleave a partial record. Bash can
//! emit its lines with a bare `printf`, which is why the shell side needs no
//! JSON tooling.
//!
//! **Nothing computes a rate at write time.** Samples are recorded with their
//! timestamps and every derived figure — percentage, bytes/second, ETA — is
//! computed in [`measured_rate`] when the status is rendered. That keeps the one
//! piece of arithmetic that could lie in a single tested function instead of
//! spread across shell and Rust.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A rate is reported only across a window at least this wide. Two chunks that
/// landed 300 ms apart say nothing about the next hour.
pub const RATE_MIN_WINDOW_SECS: i64 = 20;

/// ...and only once this many bytes moved inside it.
pub const RATE_MIN_BYTES: u64 = 32 * 1024 * 1024;

/// How far back to look for the older sample of the pair.
pub const RATE_LOOKBACK_SECS: i64 = 120;

/// Below this, the operator watches a progress bar; at or above it the run is
/// detached and they check on it with the status command. The threshold is the
/// operator's, and it decides only what is DISPLAYED — the run is detached
/// either way, so an SSH drop can never cancel an export.
pub const FOREGROUND_MAX_BYTES: u64 = 3 * 1024 * 1024 * 1024;

/// One line of the journal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "k")]
pub enum Event {
    /// Written once, first, by the runner: what this run is and what it expects.
    #[serde(rename = "start")]
    Start {
        t: i64,
        /// First 8 hex of the token's sha256 — enough to prove a journal belongs
        /// to the token being resumed, useless as a credential. The token itself
        /// is never written here; this file outlives the transfer.
        token_fp: String,
        pid: u32,
        sites_total: u64,
        /// Σ `du -sb` of the selected docroots. `None` when any docroot could not
        /// be measured, in which case no percentage is ever shown for packing.
        input_total: Option<u64>,
    },
    /// One site finished packing.
    #[serde(rename = "site")]
    Site {
        t: i64,
        done: u64,
        name: String,
        /// Bytes of source material packed so far, against `input_total`.
        input_done: u64,
    },
    /// A site or database could not be packed and was skipped. Recorded rather
    /// than only printed, because the panel has to be able to tell "the exporter
    /// deliberately left this out" apart from "the bundle was truncated".
    #[serde(rename = "skip")]
    Skip { t: i64, what: String, why: String },
    /// The bundle is sealed: this is its exact size and digest.
    #[serde(rename = "bundle")]
    Bundle { t: i64, bytes: u64, sha256: String },
    /// An upload sample — the server acknowledged bytes up to `off`.
    #[serde(rename = "upload")]
    Upload { t: i64, off: u64 },
    /// A transient failure the runner is retrying.
    #[serde(rename = "retry")]
    Retry { t: i64, why: String, wait: i64 },
    /// Terminal success.
    #[serde(rename = "done")]
    Done { t: i64, job: String },
    /// Terminal failure.
    #[serde(rename = "fail")]
    Fail { t: i64, why: String },
}

impl Event {
    pub fn at(&self) -> i64 {
        match self {
            Event::Start { t, .. }
            | Event::Site { t, .. }
            | Event::Skip { t, .. }
            | Event::Bundle { t, .. }
            | Event::Upload { t, .. }
            | Event::Retry { t, .. }
            | Event::Done { t, .. }
            | Event::Fail { t, .. } => *t,
        }
    }
}

/// Append one event. Creates the file 0600 if absent.
///
/// `O_APPEND` plus a single short `write` is what makes this safe to call from
/// the packer while the shell is appending its own lines: the kernel serialises
/// each append, so records never interleave.
pub fn append(path: &Path, ev: &Event) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut line = serde_json::to_string(ev).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(line.as_bytes())
}

/// Everything the journal says, reduced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunState {
    pub token_fp: String,
    pub pid: Option<u32>,
    pub sites_total: u64,
    pub sites_done: u64,
    pub last_site: String,
    pub input_total: Option<u64>,
    pub input_done: u64,
    pub bundle_bytes: Option<u64>,
    pub bundle_sha256: String,
    pub uploaded: u64,
    pub samples: Vec<(i64, u64)>,
    pub skipped: Vec<String>,
    pub retries: Vec<String>,
    pub started_at: i64,
    pub last_at: i64,
    /// `Some(Ok(job_id))` / `Some(Err(reason))` once the run reached a terminal
    /// event. `None` while it is still in flight — or while it is dead without
    /// having said so, which is why the caller must also check the pid.
    pub outcome: Option<Result<String, String>>,
}

impl RunState {
    pub fn phase(&self) -> &'static str {
        match (&self.outcome, self.bundle_bytes) {
            (Some(Ok(_)), _) => "done",
            (Some(Err(_)), _) => "failed",
            (None, Some(_)) => "uploading",
            (None, None) => "packing",
        }
    }
}

/// Fold a journal file into a [`RunState`]. Unparseable lines are skipped rather
/// than fatal: a torn last line (the process was killed mid-write) must not make
/// the whole status unreadable, which is exactly when it is most needed.
pub fn read(path: &Path) -> std::io::Result<RunState> {
    let text = std::fs::read_to_string(path)?;
    let mut st = RunState::default();
    for line in text.lines() {
        let Ok(ev) = serde_json::from_str::<Event>(line) else {
            continue;
        };
        st.last_at = st.last_at.max(ev.at());
        match ev {
            Event::Start {
                t,
                token_fp,
                pid,
                sites_total,
                input_total,
            } => {
                // A `start` means a NEW attempt began, so everything terminal
                // before it is history. Without this reset a resumed run reads
                // its predecessor's `fail` line and `--status` reports "Export
                // FAILED" while the retry is working — and the old upload
                // samples would drag the measured rate with them.
                st = RunState {
                    started_at: t,
                    token_fp,
                    pid: Some(pid),
                    sites_total,
                    input_total,
                    last_at: t,
                    // The sealed bundle survives a resume on purpose (the
                    // packing is not repeated), so its size and digest are
                    // re-read from the journal's later `bundle` line rather
                    // than carried across — a resume that RE-packs must not
                    // inherit the previous bundle's identity.
                    ..Default::default()
                };
            }
            Event::Site {
                done,
                name,
                input_done,
                ..
            } => {
                st.sites_done = done;
                st.last_site = name;
                st.input_done = input_done;
            }
            Event::Skip { what, why, .. } => st.skipped.push(format!("{what} — {why}")),
            Event::Bundle { bytes, sha256, .. } => {
                st.bundle_bytes = Some(bytes);
                st.bundle_sha256 = sha256;
            }
            Event::Upload { t, off } => {
                st.uploaded = off;
                st.samples.push((t, off));
            }
            Event::Retry { why, wait, .. } => st.retries.push(format!("{why} (waited {wait}s)")),
            Event::Done { job, .. } => st.outcome = Some(Ok(job)),
            Event::Fail { why, .. } => st.outcome = Some(Err(why)),
        }
    }
    Ok(st)
}

/// Bytes per second, or `None` when no honest figure can be produced.
///
/// The rule, in one place: take the newest sample and the oldest one still
/// inside [`RATE_LOOKBACK_SECS`]; require the window to be at least
/// [`RATE_MIN_WINDOW_SECS`] wide and to contain at least [`RATE_MIN_BYTES`].
/// A non-positive time delta (the clock stepped back under ntp) yields `None`
/// rather than a wild number.
pub fn measured_rate(samples: &[(i64, u64)], now: i64) -> Option<f64> {
    let (newest_t, newest_b) = *samples.last()?;
    let floor = now.min(newest_t) - RATE_LOOKBACK_SECS;
    let (oldest_t, oldest_b) = *samples.iter().find(|(t, _)| *t >= floor)?;
    let dt = newest_t - oldest_t;
    if dt < RATE_MIN_WINDOW_SECS {
        return None;
    }
    let db = newest_b.checked_sub(oldest_b)?;
    if db < RATE_MIN_BYTES {
        return None;
    }
    Some(db as f64 / dt as f64)
}

/// `1.4 GB`, in the same shape the panel uses.
pub fn human_bytes(b: u64) -> String {
    const U: [(&str, f64); 5] = [
        ("TB", 1e12),
        ("GB", 1e9),
        ("MB", 1e6),
        ("kB", 1e3),
        ("B", 1.0),
    ];
    for (name, div) in U {
        if b as f64 >= div {
            let v = b as f64 / div;
            return if v >= 100.0 || div == 1.0 {
                format!("{v:.0} {name}")
            } else {
                format!("{v:.1} {name}")
            };
        }
    }
    "0 B".into()
}

/// `2h 14m`, `4m 38s`, `12s`.
pub fn human_secs(s: i64) -> String {
    if s < 60 {
        return format!("{s}s");
    }
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m {sec}s")
    }
}

/// Whether the process that wrote this journal is still alive.
///
/// Without this a status read after a reboot renders a live-looking `uploading`
/// phase for a run that no longer exists — the journal's last line is the same
/// either way. Signal 0 does no work; it only asks whether the pid is there.
pub fn pid_alive(pid: u32) -> bool {
    // SAFETY-FREE: no unsafe in this crate. `kill -0` via /proc is enough on
    // Linux and this only ever runs on the source box.
    Path::new(&format!("/proc/{pid}")).exists()
}

/// The multi-line status an operator reads.
///
/// `alive` is passed in rather than probed here so the renderer stays a pure
/// function of its inputs and can be unit-tested without a live process.
pub fn render_status(st: &RunState, now: i64, alive: bool) -> String {
    let mut out = String::new();
    match &st.outcome {
        Some(Ok(job)) => {
            out.push_str("Export finished — the bundle is on the Hyperion box.\n");
            out.push_str(&format!("  import job: {job}\n"));
            out.push_str("  Watch it finish in Hyperion under Import.\n");
        }
        Some(Err(why)) => {
            out.push_str("Export FAILED.\n");
            out.push_str(&format!("  {why}\n"));
            out.push_str("  Re-run the same one-liner — packing is not repeated and\n");
            out.push_str("  the upload continues from where it stopped.\n");
        }
        // No `start` recorded yet. The runner detaches the worker and attaches
        // the viewer within a few shell builtins, so the first read routinely
        // lands before the worker has written its first line — and "no pid" is
        // not "the pid is gone".
        // Nothing has been recorded at all. The runner detaches the worker and
        // attaches the viewer within a few shell builtins, so the first read
        // routinely lands before the worker has written its first line — and
        // "nothing yet" is not "the pid is gone". Narrow on purpose: any
        // recorded progress means the run is past this state, whatever the
        // journal says about a pid.
        None if st.pid.is_none()
            && st.samples.is_empty()
            && st.sites_done == 0
            && st.bundle_bytes.is_none() =>
        {
            out.push_str("Starting the export…\n");
            out.push_str("  The worker has not reported yet. If this does not change\n");
            out.push_str("  within a minute, check the log beside the journal.\n");
        }
        None if !alive => {
            // The one case a naive reader gets wrong: the last line looks like
            // progress, but nothing is running.
            let pid = st.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
            out.push_str("The export process is NOT running.\n");
            out.push_str(&format!(
                "  pid {pid} is gone and it never recorded an outcome — the box may\n\
                 \x20 have rebooted, or the kernel killed it.\n"
            ));
            out.push_str("  Re-run the same one-liner to continue where it stopped.\n");
        }
        None if st.bundle_bytes.is_none() => {
            out.push_str(&format!(
                "Packing {}/{} sites{}\n",
                st.sites_done,
                st.sites_total,
                if st.last_site.is_empty() {
                    String::new()
                } else {
                    format!(" — last: {}", st.last_site)
                }
            ));
            match st.input_total {
                Some(total) if total > 0 => {
                    let pct = (st.input_done.min(total) * 100) / total;
                    out.push_str(&format!(
                        "  {} of {} ({pct}%)\n",
                        human_bytes(st.input_done),
                        human_bytes(total)
                    ));
                }
                _ => {
                    out.push_str(&format!(
                        "  {} packed so far (total unknown — no percentage)\n",
                        human_bytes(st.input_done)
                    ));
                }
            }
            let idle = now - st.last_at;
            if idle > 300 {
                out.push_str(&format!(
                    "  nothing new for {} — a very large site or a stuck database dump\n",
                    human_secs(idle)
                ));
            }
        }
        None => {
            let total = st.bundle_bytes.unwrap_or(0);
            let pct = (st.uploaded.min(total) * 100)
                .checked_div(total)
                .unwrap_or(0);
            out.push_str(&format!(
                "Uploading {} of {} ({pct}%)\n",
                human_bytes(st.uploaded),
                human_bytes(total)
            ));
            match measured_rate(&st.samples, now) {
                Some(rate) if rate > 0.0 => {
                    let left = total.saturating_sub(st.uploaded);
                    let eta = (left as f64 / rate) as i64;
                    let window = st.samples.last().map(|(t, _)| now.min(*t)).unwrap_or(now)
                        - st.samples
                            .iter()
                            .find(|(t, _)| *t >= now - RATE_LOOKBACK_SECS)
                            .map(|(t, _)| *t)
                            .unwrap_or(now);
                    out.push_str(&format!(
                        "  {}/s — about {} left (measured over the last {})\n",
                        human_bytes(rate as u64),
                        human_secs(eta),
                        human_secs(window.max(1))
                    ));
                }
                _ => {
                    out.push_str("  —/s, no estimate yet (measuring)\n");
                }
            }
            let idle = now - st.last_at;
            if idle > 120 {
                out.push_str(&format!("  no new bytes for {}\n", human_secs(idle)));
            }
        }
    }
    if !st.skipped.is_empty() {
        out.push_str(&format!(
            "\n{} item(s) could NOT be exported and were skipped:\n",
            st.skipped.len()
        ));
        for s in &st.skipped {
            out.push_str(&format!("  - {s}\n"));
        }
        out.push_str("These sites will arrive incomplete. Fix them and re-run if that matters.\n");
    }
    if !st.retries.is_empty() {
        out.push_str(&format!("\n{} retry/retries so far.\n", st.retries.len()));
    }
    out
}

/// One line, for the live bar in the operator's terminal.
pub fn render_bar_line(st: &RunState, now: i64, cols: usize) -> String {
    let (label, done, total) = match st.bundle_bytes {
        None => ("packing ", st.input_done, st.input_total.unwrap_or(0)),
        Some(b) => ("uploading", st.uploaded, b),
    };
    if total == 0 {
        return format!("{label} {} (total unknown)", human_bytes(done));
    }
    let pct = (done.min(total) * 100) / total;
    let eta = match measured_rate(&st.samples, now) {
        Some(r) if r > 0.0 && st.bundle_bytes.is_some() => {
            format!(
                " ~{} left",
                human_secs((total.saturating_sub(done) as f64 / r) as i64)
            )
        }
        _ => String::new(),
    };
    let tail = format!(
        " {pct:>3}% {}/{}{eta}",
        human_bytes(done),
        human_bytes(total)
    );
    let width = cols
        .saturating_sub(label.len() + tail.len() + 3)
        .clamp(8, 40);
    let filled = (width * pct as usize) / 100;
    format!(
        "{label} [{}{}]{tail}",
        "#".repeat(filled),
        "·".repeat(width - filled)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(pairs: &[(i64, u64)]) -> Vec<(i64, u64)> {
        pairs.to_vec()
    }

    #[test]
    fn no_rate_from_a_single_sample() {
        assert_eq!(measured_rate(&s(&[(100, 1_000_000_000)]), 100), None);
    }

    #[test]
    fn no_rate_from_too_narrow_a_window() {
        // 5 seconds apart, plenty of bytes — still not a window worth
        // extrapolating an hour from.
        let samples = s(&[(100, 0), (105, RATE_MIN_BYTES * 10)]);
        assert_eq!(measured_rate(&samples, 105), None);
    }

    #[test]
    fn no_rate_from_too_few_bytes() {
        // A wide window, but almost nothing moved in it.
        let samples = s(&[(100, 0), (200, RATE_MIN_BYTES - 1)]);
        assert_eq!(measured_rate(&samples, 200), None);
    }

    #[test]
    fn no_rate_when_the_clock_steps_backwards() {
        // ntp corrected mid-transfer: the newest sample is older than the one
        // before it. A naive divide would print a negative or enormous rate.
        let samples = s(&[(500, 0), (400, RATE_MIN_BYTES * 4)]);
        assert_eq!(measured_rate(&samples, 500), None);
    }

    #[test]
    fn a_wide_enough_window_measures() {
        let samples = s(&[(100, 0), (160, RATE_MIN_BYTES * 6)]);
        let r = measured_rate(&samples, 160).expect("60s / 192 MiB is measurable");
        assert!((r - (RATE_MIN_BYTES * 6) as f64 / 60.0).abs() < 1.0);
    }

    #[test]
    fn the_window_only_looks_back_two_minutes() {
        // An ancient first sample must not be used as the reference — otherwise
        // a transfer that stalled for an hour and resumed would report the
        // average across the stall rather than the rate right now.
        let samples = s(&[(0, 0), (1000, RATE_MIN_BYTES), (1060, RATE_MIN_BYTES * 9)]);
        let r = measured_rate(&samples, 1060).expect("recent pair is measurable");
        let expected = (RATE_MIN_BYTES * 8) as f64 / 60.0;
        assert!((r - expected).abs() < 1.0, "got {r}, expected {expected}");
    }

    #[test]
    fn status_says_measuring_rather_than_inventing_an_eta() {
        let st = RunState {
            bundle_bytes: Some(10_000_000_000),
            uploaded: 1_000_000,
            samples: s(&[(100, 1_000_000)]),
            last_at: 100,
            ..Default::default()
        };
        let out = render_status(&st, 100, true);
        assert!(out.contains("(measuring)"), "{out}");
        assert!(!out.contains("left"), "no ETA may be printed yet:\n{out}");
    }

    #[test]
    fn packing_without_a_denominator_prints_no_percentage() {
        let st = RunState {
            sites_total: 7,
            sites_done: 3,
            last_site: "example.cz".into(),
            input_total: None,
            input_done: 1_400_000_000,
            last_at: 500,
            ..Default::default()
        };
        let out = render_status(&st, 500, true);
        assert!(out.contains("total unknown"), "{out}");
        assert!(
            !out.contains('%'),
            "a percentage needs a denominator:\n{out}"
        );
    }

    /// The first read of a just-created journal must not read as a death.
    #[test]
    fn a_run_that_has_not_reported_yet_is_not_called_dead() {
        let st = RunState::default();
        let out = render_status(&st, 0, false);
        assert!(out.contains("Starting"), "{out}");
        assert!(
            !out.contains("NOT running"),
            "no pid recorded is not the same as a pid that is gone:\n{out}"
        );
    }

    #[test]
    fn a_dead_process_is_not_rendered_as_progress() {
        let st = RunState {
            pid: Some(24817),
            bundle_bytes: Some(1_000_000_000),
            uploaded: 400_000_000,
            samples: s(&[(100, 400_000_000)]),
            last_at: 100,
            ..Default::default()
        };
        let out = render_status(&st, 100, false);
        assert!(out.contains("NOT running"), "{out}");
        assert!(
            out.contains("24817"),
            "name the pid so it can be checked:\n{out}"
        );
        assert!(!out.contains("Uploading"), "{out}");
    }

    #[test]
    fn skipped_items_are_surfaced_not_buried() {
        let st = RunState {
            outcome: Some(Ok("job-9".into())),
            skipped: vec!["a.cz (docroot) — permission denied".into()],
            ..Default::default()
        };
        let out = render_status(&st, 0, false);
        assert!(out.contains("could NOT be exported"), "{out}");
        assert!(out.contains("a.cz (docroot)"), "{out}");
    }

    /// A resumed run must not report its predecessor's failure.
    #[test]
    fn a_new_start_clears_the_previous_attempts_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.ndjson");
        let start = |pid: u32| Event::Start {
            t: 1,
            token_fp: "abc".into(),
            pid,
            sites_total: 3,
            input_total: Some(1000),
        };
        append(&p, &start(1)).unwrap();
        append(&p, &Event::Upload { t: 2, off: 500 }).unwrap();
        append(
            &p,
            &Event::Fail {
                t: 3,
                why: "network died".into(),
            },
        )
        .unwrap();
        // The operator re-runs the one-liner.
        append(&p, &start(2)).unwrap();
        append(&p, &Event::Upload { t: 5, off: 600 }).unwrap();

        let st = read(&p).unwrap();
        assert_eq!(st.outcome, None, "the old failure must not resurface");
        assert_eq!(st.pid, Some(2), "the live pid is the new one");
        assert_eq!(
            st.samples.len(),
            1,
            "samples from the dead attempt would distort the measured rate"
        );
        let out = render_status(&st, 5, true);
        assert!(!out.contains("FAILED"), "{out}");
    }

    #[test]
    fn a_torn_last_line_does_not_break_the_read() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.ndjson");
        append(
            &p,
            &Event::Start {
                t: 1,
                token_fp: "deadbeef".into(),
                pid: 42,
                sites_total: 2,
                input_total: Some(100),
            },
        )
        .unwrap();
        append(&p, &Event::Upload { t: 2, off: 50 }).unwrap();
        // The process was killed mid-write.
        std::fs::write(
            &p,
            format!("{}{{\"k\":\"upl", std::fs::read_to_string(&p).unwrap()),
        )
        .unwrap();
        let st = read(&p).unwrap();
        assert_eq!(st.uploaded, 50);
        assert_eq!(st.pid, Some(42));
    }

    #[test]
    fn the_journal_never_contains_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.ndjson");
        append(
            &p,
            &Event::Start {
                t: 1,
                token_fp: "0123abcd".into(),
                pid: 1,
                sites_total: 1,
                input_total: None,
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("token_fp"));
        // Only the fingerprint, and it is short enough to be useless as a
        // credential even if the file leaks.
        assert_eq!(
            text.matches("0123abcd").count(),
            1,
            "the fingerprint is the ONLY token-derived value in the journal"
        );
    }

    #[test]
    fn the_journal_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.ndjson");
        append(&p, &Event::Upload { t: 1, off: 1 }).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the journal sits beside plaintext DB dumps");
    }

    #[test]
    fn human_bytes_reads_like_a_size() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1_400_000_000), "1.4 GB");
        assert_eq!(human_bytes(340_000_000_000), "340 TB".replace("TB", "GB"));
    }

    #[test]
    fn human_secs_reads_like_a_duration() {
        assert_eq!(human_secs(12), "12s");
        assert_eq!(human_secs(278), "4m 38s");
        assert_eq!(human_secs(8040), "2h 14m");
    }
}
