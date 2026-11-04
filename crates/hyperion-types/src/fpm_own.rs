//! Per-user PHP-FPM masters: unit names and the node preflight verdict.
//!
//! A site user that runs its own master gets a templated systemd unit
//! (`hyperion-fpm8.3@<user>.service`) inside its own slice, so the kernel
//! enforces the user's CPU and memory shares. Pure: the agent gathers
//! [`PreflightFacts`], this module only names things and judges.

use serde::{Deserialize, Serialize};

use crate::php::PhpVersion;
use crate::phpworkers::NODE_FREE_RAM_DIVISOR;

/// RAM one more master costs a node, measured as the resident size of an idle
/// master plus its slice bookkeeping. The estimate the preflight multiplies by
/// the users still to convert.
pub const MB_PER_USER: i64 = 11;

/// The cgroup v2 controllers a user's slice needs to get a CPU and memory cap.
const REQUIRED_CONTROLLERS: [&str; 2] = ["cpu", "memory"];
/// First systemd with the cgroup v2 behaviour the slices rely on.
const MIN_SYSTEMD: u32 = 252;

/// The user as a systemd unit instance name, like `systemd-escape`: ASCII
/// alphanumerics, `:`, `_` and `.` stay (a leading `.` does not), `/` becomes
/// `-`, every other byte becomes `\xHH`.
pub fn instance_name(user: &str) -> String {
    let mut out = String::with_capacity(user.len());
    for (i, b) in user.bytes().enumerate() {
        match b {
            b'/' => out.push('-'),
            b'.' if i == 0 => out.push_str(r"\x2e"),
            b if b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.') => {
                out.push(b as char)
            }
            b => out.push_str(&format!(r"\x{b:02x}")),
        }
    }
    out
}

/// `hyperion-fpm8.4@<escaped user>.service`.
pub fn unit_name(ver: PhpVersion, user: &str) -> String {
    format!(
        "hyperion-fpm{}@{}.service",
        ver.as_str(),
        instance_name(user)
    )
}

/// The template the instances come from: `hyperion-fpm8.4@.service`.
pub fn template_name(ver: PhpVersion) -> String {
    format!("hyperion-fpm{}@.service", ver.as_str())
}

/// The user's slice, shared by every PHP version of that user.
pub fn slice_name(user: &str) -> String {
    format!("hyperion-sites-{}.slice", instance_name(user))
}

/// What the node reports; every field is a plain reading, the verdict is
/// [`judge`]'s.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PreflightFacts {
    /// Contents of `/sys/fs/cgroup/cgroup.controllers`; `None` when the file
    /// is missing (no cgroup v2).
    pub cgroup_controllers: Option<String>,
    /// Major version of the running systemd; `None` when it could not be read.
    pub systemd_version: Option<u32>,
    /// `SwapTotal` from `/proc/meminfo`.
    pub swap_total_kib: i64,
    pub mem_total_mb: Option<i64>,
    pub mem_available_mb: Option<i64>,
    /// System users with a PHP pool.
    pub php_users: i64,
    /// Of those, the ones that already run their own master.
    pub own_users: i64,
}

/// Why a node cannot run own masters.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum PreflightBlock {
    NoCgroup2,
    MissingController(String),
    OldSystemd(u32),
    UnknownSystemd,
    LowRam {
        need_mb: i64,
        free_after_mb: i64,
        floor_mb: i64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    pub blocks: Vec<PreflightBlock>,
    /// Swap is worth a line in the report, never a reason to refuse.
    pub has_swap: bool,
    /// What converting the remaining users adds to the node's RAM use.
    pub extra_mb: i64,
    pub php_users: i64,
    pub own_users: i64,
}

impl Preflight {
    pub fn ok(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// The verdict on a node. Only users still on the shared master cost RAM; RAM
/// that could not be read is not a block, as in the worker raise.
pub fn judge(facts: &PreflightFacts) -> Preflight {
    let mut blocks = Vec::new();
    match &facts.cgroup_controllers {
        None => blocks.push(PreflightBlock::NoCgroup2),
        Some(list) => {
            for need in REQUIRED_CONTROLLERS {
                if !list.split_whitespace().any(|c| c == need) {
                    blocks.push(PreflightBlock::MissingController(need.to_string()));
                }
            }
        }
    }
    match facts.systemd_version {
        None => blocks.push(PreflightBlock::UnknownSystemd),
        Some(v) if v < MIN_SYSTEMD => blocks.push(PreflightBlock::OldSystemd(v)),
        Some(_) => {}
    }
    let extra_mb = (facts.php_users - facts.own_users).max(0) * MB_PER_USER;
    if let (Some(total), Some(avail)) = (facts.mem_total_mb, facts.mem_available_mb) {
        let floor_mb = total / NODE_FREE_RAM_DIVISOR;
        let free_after_mb = avail - extra_mb;
        if free_after_mb < floor_mb {
            blocks.push(PreflightBlock::LowRam {
                need_mb: extra_mb,
                free_after_mb,
                floor_mb,
            });
        }
    }
    Preflight {
        blocks,
        has_swap: facts.swap_total_kib > 0,
        extra_mb,
        php_users: facts.php_users,
        own_users: facts.own_users,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node that passes everything; each test spoils one thing.
    fn good() -> PreflightFacts {
        PreflightFacts {
            cgroup_controllers: Some("cpuset cpu io memory pids".into()),
            systemd_version: Some(252),
            swap_total_kib: 0,
            mem_total_mb: Some(4096),
            mem_available_mb: Some(3000),
            php_users: 10,
            own_users: 0,
        }
    }

    #[test]
    fn escapes_like_systemd_escape() {
        assert_eq!(instance_name("alice_cz"), "alice_cz");
        assert_eq!(instance_name("im-port.ed"), r"im\x2dport.ed");
        assert_eq!(instance_name(".hidden"), r"\x2ehidden");
        assert_eq!(instance_name("a b"), r"a\x20b");
        assert_eq!(
            unit_name(PhpVersion::V8_4, "im-port.ed"),
            r"hyperion-fpm8.4@im\x2dport.ed.service"
        );
        assert_eq!(
            slice_name("im-port.ed"),
            r"hyperion-sites-im\x2dport.ed.slice"
        );
        assert_eq!(template_name(PhpVersion::V8_3), "hyperion-fpm8.3@.service");
    }

    #[test]
    fn own_paths() {
        assert_eq!(
            PhpVersion::V8_3.own_socket_path("a"),
            "/run/php/8.3/site/a.sock"
        );
        assert_eq!(
            PhpVersion::V8_3.own_config_path("a"),
            "/etc/hyperion/fpm/8.3/a.conf"
        );
        assert_eq!(PhpVersion::V8_3.own_config_dir(), "/etc/hyperion/fpm/8.3");
    }

    #[test]
    fn judge_passes_a_good_node() {
        let p = judge(&good());
        assert!(p.ok(), "{:?}", p.blocks);
        assert!(!p.has_swap);
    }

    #[test]
    fn judge_blocks_what_cannot_work() {
        let p = judge(&PreflightFacts {
            cgroup_controllers: None,
            ..good()
        });
        assert_eq!(p.blocks, vec![PreflightBlock::NoCgroup2]);
        assert!(!p.ok());

        let p = judge(&PreflightFacts {
            cgroup_controllers: Some("memory pids".into()),
            ..good()
        });
        assert_eq!(
            p.blocks,
            vec![PreflightBlock::MissingController("cpu".into())]
        );

        let p = judge(&PreflightFacts {
            cgroup_controllers: Some("pids".into()),
            ..good()
        });
        assert_eq!(
            p.blocks,
            vec![
                PreflightBlock::MissingController("cpu".into()),
                PreflightBlock::MissingController("memory".into()),
            ]
        );

        let p = judge(&PreflightFacts {
            systemd_version: Some(251),
            ..good()
        });
        assert_eq!(p.blocks, vec![PreflightBlock::OldSystemd(251)]);

        let p = judge(&PreflightFacts {
            systemd_version: None,
            ..good()
        });
        assert_eq!(p.blocks, vec![PreflightBlock::UnknownSystemd]);
    }

    #[test]
    fn judge_counts_only_unconverted_users_against_ram() {
        // Floor is 4096 / 5 = 819. 30 users, 10 already own: 20 more cost 220.
        let facts = PreflightFacts {
            mem_available_mb: Some(1000),
            php_users: 30,
            own_users: 10,
            ..good()
        };
        let p = judge(&facts);
        assert_eq!(
            p.blocks,
            vec![PreflightBlock::LowRam {
                need_mb: 220,
                free_after_mb: 780,
                floor_mb: 819,
            }]
        );

        let p = judge(&PreflightFacts {
            mem_available_mb: Some(1100),
            ..facts
        });
        assert!(p.ok(), "{:?}", p.blocks);
        assert_eq!(p.extra_mb, 220);
        assert_eq!((p.php_users, p.own_users), (30, 10));
    }

    #[test]
    fn unknown_ram_is_not_a_block() {
        let p = judge(&PreflightFacts {
            mem_total_mb: None,
            mem_available_mb: None,
            ..good()
        });
        assert!(p.ok());
        let p = judge(&PreflightFacts {
            mem_available_mb: None,
            ..good()
        });
        assert!(p.ok());
    }

    #[test]
    fn swap_is_reported_but_never_a_block() {
        let p = judge(&PreflightFacts {
            swap_total_kib: 1024,
            ..good()
        });
        assert!(p.has_swap);
        assert!(p.ok());
        assert!(!judge(&good()).has_swap);
    }
}
