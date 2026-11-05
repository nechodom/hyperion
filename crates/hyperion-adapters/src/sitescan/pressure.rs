//! When the box is busy, the scan waits. The worker is already capped, but a
//! node that is swapping or queueing is better left alone than made slower.

use std::cell::Cell;
use std::time::Duration;

/// Memory PSI `some avg10` above this many percent is pressure.
const PSI_PRESSURE_PERCENT: f64 = 20.0;
/// Sleep this long between looks while waiting.
pub const PAUSE_STEP: Duration = Duration::from_secs(30);
/// Waited in total for one run; after this the run returns what it has and the
/// next one resumes.
pub const PAUSE_MAX: Duration = Duration::from_secs(30 * 60);

/// Load above one runnable task per core, or memory stalls, mean the box is busy.
/// `None` for PSI (kernel without it, or not Linux) leaves load to decide.
pub fn is_under_pressure(load1: f64, cores: usize, psi_some_avg10: Option<f64>) -> bool {
    load1 > cores as f64 || psi_some_avg10.is_some_and(|p| p > PSI_PRESSURE_PERCENT)
}

/// The 1-minute figure from `/proc/loadavg`.
pub fn parse_loadavg(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// `some avg10=` from `/proc/pressure/memory`.
pub fn parse_psi_some_avg10(text: &str) -> Option<f64> {
    let line = text.lines().find(|l| l.starts_with("some "))?;
    line.split_whitespace()
        .find_map(|f| f.strip_prefix("avg10="))?
        .parse()
        .ok()
}

/// CPUs of the host. Not `available_parallelism`: that follows the cgroup's
/// CPU quota, and the worker's own quota is a fraction of a core while the load
/// average it is compared with counts the whole host.
pub fn host_cores() -> usize {
    #[cfg(target_os = "linux")]
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        let n = info.lines().filter(|l| l.starts_with("processor")).count();
        if n > 0 {
            return n;
        }
    }
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// Is the box busy now? Unreadable figures never count as pressure, so a
/// system without `/proc` (macOS) is never held up.
#[cfg(target_os = "linux")]
pub fn sample_pressure(cores: usize) -> bool {
    let Some(load1) = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|t| parse_loadavg(&t))
    else {
        return false;
    };
    let psi = std::fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|t| parse_psi_some_avg10(&t));
    is_under_pressure(load1, cores, psi)
}

#[cfg(not(target_os = "linux"))]
pub fn sample_pressure(_cores: usize) -> bool {
    false
}

/// The `pause` closure `scan_site` takes: false at once when the box is quiet;
/// otherwise sleeps `step` at a time until it is, and true (stop, resume
/// later) once `max` has been waited in total over the life of the gate.
pub fn gate<'a>(
    busy: impl Fn() -> bool + 'a,
    sleep: impl Fn(Duration) + 'a,
    step: Duration,
    max: Duration,
) -> impl Fn() -> bool + 'a {
    let waited = Cell::new(Duration::ZERO);
    move || {
        while busy() {
            if waited.get() >= max {
                return true;
            }
            sleep(step);
            waited.set(waited.get() + step);
        }
        false
    }
}

/// The gate the worker uses: real load and PSI, real sleeping.
pub fn system_gate() -> impl Fn() -> bool {
    let cores = host_cores();
    gate(
        move || sample_pressure(cores),
        std::thread::sleep,
        PAUSE_STEP,
        PAUSE_MAX,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pressure_true_when_load_exceeds_cores() {
        assert!(is_under_pressure(2.5, 2, None));
        assert!(!is_under_pressure(2.0, 2, None));
        assert!(!is_under_pressure(0.3, 8, Some(1.0)));
        // Memory stalls count on an idle CPU.
        assert!(is_under_pressure(0.1, 8, Some(20.5)));
        assert!(!is_under_pressure(0.1, 8, Some(20.0)));
    }

    #[test]
    fn pressure_none_psi_uses_load_only() {
        assert!(!is_under_pressure(0.1, 4, None));
        assert!(is_under_pressure(4.1, 4, None));
    }

    #[test]
    fn proc_text_is_parsed() {
        assert_eq!(parse_loadavg("0.52 0.40 0.31 1/312 9981\n"), Some(0.52));
        assert_eq!(parse_loadavg(""), None);
        assert_eq!(parse_loadavg("garbage"), None);
        let psi = "some avg10=12.50 avg60=3.00 avg300=1.00 total=123\nfull avg10=9.00 avg60=0.00 avg300=0.00 total=5\n";
        assert_eq!(parse_psi_some_avg10(psi), Some(12.5));
        assert_eq!(parse_psi_some_avg10("full avg10=9.00\n"), None);
        assert_eq!(parse_psi_some_avg10("some avg60=1.00\n"), None);
    }

    #[test]
    fn a_quiet_box_is_never_waited_for() {
        let slept = Cell::new(0u32);
        let g = gate(
            || false,
            |_| slept.set(slept.get() + 1),
            PAUSE_STEP,
            PAUSE_MAX,
        );
        assert!(!g());
        assert!(!g());
        assert_eq!(slept.get(), 0);
    }

    #[test]
    fn a_busy_box_is_waited_for_in_steps_until_it_calms() {
        let looks = Cell::new(0u32);
        let slept = Cell::new(Duration::ZERO);
        let g = gate(
            || {
                looks.set(looks.get() + 1);
                looks.get() <= 3
            },
            |d| slept.set(slept.get() + d),
            PAUSE_STEP,
            PAUSE_MAX,
        );
        assert!(!g());
        assert_eq!(slept.get(), 3 * PAUSE_STEP);
    }

    #[test]
    fn waiting_stops_after_thirty_minutes_in_total() {
        let slept = Cell::new(Duration::ZERO);
        let g = gate(
            || true,
            |d| slept.set(slept.get() + d),
            PAUSE_STEP,
            PAUSE_MAX,
        );
        assert!(g());
        assert_eq!(slept.get(), PAUSE_MAX);
        // The budget is for the run: a later ask gives up without sleeping.
        assert!(g());
        assert_eq!(slept.get(), PAUSE_MAX);
    }

    #[test]
    fn this_machine_can_be_sampled() {
        assert!(host_cores() >= 1);
        // Must not panic, whatever /proc holds; macOS is never pressured.
        let _ = sample_pressure(host_cores());
        #[cfg(target_os = "macos")]
        assert!(!sample_pressure(1));
    }
}
