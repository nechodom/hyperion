//! Automatic PHP `memory_limit` — raise it when a site runs out, lower it
//! again once the site has been quiet for a while.
//!
//! The pool sets `memory_limit` as `php_admin_value`, so nothing inside the
//! site (`WP_MEMORY_LIMIT`, `ini_set`) can raise it; a site that genuinely
//! needs more — an Elementor editor, a WooCommerce import — just dies with
//! `Allowed memory size of … bytes exhausted` until someone edits the limits
//! card. PHP writes that fatal to FastCGI stderr, which nginx appends to the
//! site's own `logs/error.log`, so the owning node can see it without the
//! site's help and act on it.
//!
//! Everything here is pure: the decision, the log-line parser and the stored
//! state. The node does the I/O. All of it lives in the OWNING node's
//! `hosting_kv`, because the pool it rewrites is there.
//!
//! Bounds, because "dynamic" must never mean "unbounded":
//! * never above the operator's ceiling for the site (`KV_MAX_MB`);
//! * never above what the node can hold — `limit × max_children` stays under
//!   three quarters of the node's RAM;
//! * never below the operator's own value (`State::base_mb`) when lowering.

use serde::{Deserialize, Serialize};

/// `"on"` turns the automation on for a hosting. Anything else is off.
pub const KV_ENABLED: &str = "php.mem_auto";
/// The highest `memory_limit` (MiB) the automation may set for a hosting.
pub const KV_MAX_MB: &str = "php.mem_auto_max_mb";
/// JSON-encoded [`State`].
pub const KV_STATE: &str = "php.mem_auto_state";

/// Ceiling when the operator has not set one. Covers Elementor and
/// WooCommerce; a site that needs more than this almost always has a plugin
/// leaking, and raising further would only hide it.
pub const DEFAULT_MAX_MB: i64 = 512;
/// How much one raise or one lowering moves the limit.
pub const STEP_MB: i64 = 128;
/// Minimum gap between two changes, so one burst of fatals is answered with
/// one step and the next step is decided on what the NEW limit does.
pub const COOLDOWN_SECS: i64 = 10 * 60;
/// Quiet period (no out-of-memory, no change) before one step back down.
pub const LOWER_AFTER_SECS: i64 = 14 * 86_400;
/// How often a site stuck at its ceiling is reported again.
pub const CAPPED_ALERT_EVERY_SECS: i64 = 86_400;
/// Most of `error.log` read per tick. A site logging more than this between
/// two ticks is read from the newest part only.
pub const MAX_SCAN_BYTES: u64 = 8 * 1024 * 1024;

/// What the node remembers per hosting between ticks.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// The operator's own `memory_limit` — the floor a lowering returns to.
    /// Reset whenever someone sets the limit by hand.
    pub base_mb: i64,
    /// Last out-of-memory fatal seen AT OR ABOVE the limit in force.
    #[serde(default)]
    pub last_oom_at: i64,
    /// Last time the limit changed (by this automation or by hand).
    #[serde(default)]
    pub last_change_at: i64,
    /// Last "stuck at the ceiling" alert.
    #[serde(default)]
    pub capped_alert_at: i64,
    /// Inode of `error.log` when last read, to notice rotation.
    #[serde(default)]
    pub log_ino: u64,
    /// Byte offset read up to.
    #[serde(default)]
    pub log_offset: u64,
}

impl State {
    pub fn parse(s: &str) -> Option<State> {
        serde_json::from_str(s).ok()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// An out-of-memory seen since the last change and not yet answered.
    ///
    /// Remembered rather than taken from this tick's lines alone: fatals that
    /// land during the cooldown are read (the offset moves past them) and
    /// would otherwise be forgotten by the time the cooldown ends.
    pub fn oom_pending(&self) -> bool {
        self.last_oom_at > self.last_change_at
    }
}

/// What the tick should do for one hosting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Nothing,
    /// Rewrite the pool with this `memory_limit` (MiB).
    Raise {
        to: i64,
    },
    Lower {
        to: i64,
    },
    /// Still running out, but already at the most it may get. `by_ram` when
    /// the node's memory, not the operator's ceiling, is what stops it.
    Capped {
        at: i64,
        by_ram: bool,
    },
}

/// The `N` in `Allowed memory size of N bytes exhausted`, from one log line.
pub fn parse_oom_limit_bytes(line: &str) -> Option<u64> {
    const NEEDLE: &str = "Allowed memory size of ";
    let rest = &line[line.find(NEEDLE)? + NEEDLE.len()..];
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if digits_end == 0 || !rest[digits_end..].starts_with(" bytes exhausted") {
        return None;
    }
    rest[..digits_end].parse().ok()
}

/// Out-of-memory fatals in `text` that hit a limit of at least
/// `current_mb`.
///
/// A fatal at a LOWER limit is from before the last raise — a line nginx
/// wrote after the tick read past the change, or an old log — and must not
/// push the limit up again.
pub fn count_ooms(text: &str, current_mb: i64) -> usize {
    let floor = (current_mb.max(0) as u64) * 1024 * 1024;
    text.lines()
        .filter_map(parse_oom_limit_bytes)
        .filter(|&n| n >= floor)
        .count()
}

/// Decide one hosting's step. `st.last_oom_at` must already include this
/// tick's fatals. `ram_cap_mb` is the most the node can afford per worker
/// (`None` when the node's memory could not be read).
pub fn decide(
    now: i64,
    current_mb: i64,
    ceiling_mb: i64,
    ram_cap_mb: Option<i64>,
    st: &State,
) -> Step {
    let base = st.base_mb;
    // The operator lowered the ceiling under a value this automation set.
    // Never below their own base: that one is theirs, not ours.
    let lower_bound = ceiling_mb.max(base);
    if current_mb > lower_bound {
        return Step::Lower { to: lower_bound };
    }

    if st.oom_pending() {
        let ram = ram_cap_mb.unwrap_or(i64::MAX);
        let cap = ceiling_mb.min(ram);
        if current_mb >= cap {
            if st.capped_alert_at > 0 && now - st.capped_alert_at < CAPPED_ALERT_EVERY_SECS {
                return Step::Nothing;
            }
            return Step::Capped {
                at: current_mb,
                by_ram: ram < ceiling_mb,
            };
        }
        if now - st.last_change_at < COOLDOWN_SECS {
            return Step::Nothing;
        }
        return Step::Raise {
            to: (current_mb + STEP_MB).min(cap),
        };
    }

    let quiet_since = st.last_oom_at.max(st.last_change_at);
    if current_mb > base && now - quiet_since >= LOWER_AFTER_SECS {
        return Step::Lower {
            to: (current_mb - STEP_MB).max(base),
        };
    }
    Step::Nothing
}

/// The operator's own `memory_limit` once a limits-card save lands — the
/// value the automation steps back down to, so the one its ceiling must be
/// above. Mirrors `set_limits`: a value different from the stored one becomes
/// the new floor; resubmitting the stored (possibly raised) value keeps the
/// floor already in `st`.
pub fn floor_after_save(typed_mb: i64, stored_mb: Option<i64>, st: Option<&State>) -> i64 {
    match (stored_mb, st) {
        (Some(stored), Some(s)) if typed_mb == stored && s.base_mb > 0 => s.base_mb,
        _ => typed_mb,
    }
}

/// A ceiling at or under the floor leaves the automation nothing to raise
/// to: every out-of-memory ends as a "stuck at the ceiling" alert.
pub fn ceiling_leaves_no_room(ceiling_mb: i64, floor_mb: i64) -> bool {
    ceiling_mb <= floor_mb
}

/// Per-worker memory the node can afford: three quarters of its RAM shared
/// by every worker the pool may run at once.
pub fn ram_cap_mb(mem_total_mb: i64, max_children: i64) -> Option<i64> {
    if mem_total_mb <= 0 {
        return None;
    }
    Some(mem_total_mb * 3 / 4 / max_children.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn st(base: i64) -> State {
        State {
            base_mb: base,
            ..State::default()
        }
    }

    #[test]
    fn parses_the_nginx_fastcgi_line() {
        let l = r#"2026/10/05 12:00:01 [error] 123#123: *45 FastCGI sent in stderr: "PHP message: PHP Fatal error:  Allowed memory size of 268435456 bytes exhausted (tried to allocate 20480 bytes) in /home/x/x.cz/htdocs/wp-content/plugins/elementor/includes/controls/base-multiple.php on line 59" while reading response header"#;
        assert_eq!(parse_oom_limit_bytes(l), Some(256 * MIB));
    }

    #[test]
    fn ignores_lines_that_only_look_similar() {
        assert_eq!(parse_oom_limit_bytes("PHP Warning: something"), None);
        assert_eq!(
            parse_oom_limit_bytes("Allowed memory size of  bytes exhausted"),
            None
        );
        assert_eq!(parse_oom_limit_bytes("Allowed memory size of 12abc"), None);
    }

    #[test]
    fn counts_only_fatals_at_the_current_limit_or_above() {
        let text = "Allowed memory size of 268435456 bytes exhausted\n\
                    Allowed memory size of 402653184 bytes exhausted\n\
                    unrelated\n";
        assert_eq!(count_ooms(text, 256), 2);
        // After a raise to 384, the 256 line is history.
        assert_eq!(count_ooms(text, 384), 1);
        assert_eq!(count_ooms(text, 512), 0);
    }

    #[test]
    fn raises_one_step_on_a_fresh_oom() {
        let mut s = st(256);
        s.last_oom_at = 1_000_000;
        assert_eq!(
            decide(1_000_000, 256, 512, None, &s),
            Step::Raise { to: 384 }
        );
    }

    #[test]
    fn waits_out_the_cooldown_but_remembers_the_oom() {
        let mut s = st(256);
        s.last_change_at = 1_000_000;
        s.last_oom_at = 1_000_100;
        assert_eq!(decide(1_000_100, 384, 512, None, &s), Step::Nothing);
        assert_eq!(
            decide(1_000_000 + COOLDOWN_SECS, 384, 512, None, &s),
            Step::Raise { to: 512 }
        );
    }

    #[test]
    fn never_raises_past_the_ceiling() {
        let mut s = st(256);
        s.last_oom_at = 10;
        assert_eq!(
            decide(COOLDOWN_SECS * 2, 448, 512, None, &s),
            Step::Raise { to: 512 }
        );
        assert_eq!(
            decide(COOLDOWN_SECS * 2, 512, 512, None, &s),
            Step::Capped {
                at: 512,
                by_ram: false
            }
        );
    }

    #[test]
    fn node_ram_caps_below_the_ceiling() {
        let mut s = st(256);
        s.last_oom_at = 10;
        // 2 GiB node, 5 workers ⇒ 307 MiB each.
        let ram = ram_cap_mb(2048, 5);
        assert_eq!(ram, Some(307));
        assert_eq!(
            decide(COOLDOWN_SECS * 2, 256, 512, ram, &s),
            Step::Raise { to: 307 }
        );
        assert_eq!(
            decide(COOLDOWN_SECS * 2, 307, 512, ram, &s),
            Step::Capped {
                at: 307,
                by_ram: true
            }
        );
    }

    #[test]
    fn capped_alert_is_throttled() {
        let mut s = st(256);
        s.last_oom_at = 100;
        s.capped_alert_at = 50;
        assert_eq!(decide(60, 512, 512, None, &s), Step::Nothing);
        assert!(matches!(
            decide(50 + CAPPED_ALERT_EVERY_SECS, 512, 512, None, &s),
            Step::Capped { .. }
        ));
    }

    #[test]
    fn lowers_one_step_after_a_quiet_fortnight_never_below_base() {
        let mut s = st(256);
        s.last_oom_at = 0;
        s.last_change_at = 100;
        assert_eq!(
            decide(100 + LOWER_AFTER_SECS - 1, 512, 512, None, &s),
            Step::Nothing
        );
        assert_eq!(
            decide(100 + LOWER_AFTER_SECS, 512, 512, None, &s),
            Step::Lower { to: 384 }
        );
        assert_eq!(
            decide(100 + LOWER_AFTER_SECS, 300, 512, None, &s),
            Step::Lower { to: 256 }
        );
        assert_eq!(
            decide(100 + LOWER_AFTER_SECS, 256, 512, None, &s),
            Step::Nothing
        );
    }

    #[test]
    fn a_recent_oom_postpones_the_lowering() {
        let mut s = st(256);
        s.last_change_at = 100;
        s.last_oom_at = 50; // answered (before the change)
        assert!(!s.oom_pending());
        assert!(matches!(
            decide(100 + LOWER_AFTER_SECS, 384, 512, None, &s),
            Step::Lower { .. }
        ));
    }

    #[test]
    fn a_lowered_ceiling_pulls_the_limit_down_but_not_under_base() {
        let s = st(256);
        assert_eq!(decide(0, 768, 512, None, &s), Step::Lower { to: 512 });
        // Ceiling under the operator's own value: their value wins.
        let s = st(384);
        assert_eq!(decide(0, 512, 256, None, &s), Step::Lower { to: 384 });
        assert_eq!(decide(0, 384, 256, None, &s), Step::Nothing);
    }

    #[test]
    fn state_round_trips_and_tolerates_missing_fields() {
        let s = State {
            base_mb: 256,
            last_oom_at: 1,
            last_change_at: 2,
            capped_alert_at: 3,
            log_ino: 4,
            log_offset: 5,
        };
        assert_eq!(State::parse(&s.to_json()), Some(s));
        assert_eq!(State::parse(r#"{"base_mb":128}"#), Some(st(128)));
        assert_eq!(State::parse("garbage"), None);
    }

    #[test]
    fn floor_after_save_follows_set_limits() {
        // Raised 512 → 640; the card resubmits 640 unchanged: floor stays 512.
        assert_eq!(floor_after_save(640, Some(640), Some(&st(512))), 512);
        // A new value typed by hand is the new floor.
        assert_eq!(floor_after_save(1024, Some(640), Some(&st(512))), 1024);
        // No state yet (never on) or no stored row: the typed value.
        assert_eq!(floor_after_save(1024, Some(1024), None), 1024);
        assert_eq!(floor_after_save(256, None, Some(&st(512))), 256);
        assert_eq!(floor_after_save(256, Some(256), Some(&st(0))), 256);
    }

    #[test]
    fn a_ceiling_at_or_under_the_floor_leaves_no_room() {
        // The reported case: 1024 MB of its own, ceiling 512.
        assert!(ceiling_leaves_no_room(512, 1024));
        assert!(ceiling_leaves_no_room(1024, 1024));
        assert!(!ceiling_leaves_no_room(1152, 1024));
        // And decide() agrees: an OOM there only ever reports Capped.
        let mut s = st(1024);
        s.last_oom_at = 1_000_000;
        assert!(matches!(
            decide(1_000_000, 1024, 512, None, &s),
            Step::Capped { .. }
        ));
    }
}
