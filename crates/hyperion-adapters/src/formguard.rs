//! Contact form guard — a module of the Hyperion must-use plugin that refuses
//! contact-form submissions nobody can act on: no message, the same message
//! sent again a moment later, too many from one sender in an hour, a link in
//! the name field.
//!
//! It is NOT a bot filter. The incident it was written for had a honeypot and
//! reCAPTCHA v3 on every form and they held: the junk came from real people on
//! phones, sent to the contact page by an ad, who submitted the form empty and
//! then tapped the button again. A hidden field or a score cannot tell those
//! from a customer; what they typed can.
//!
//! Elementor Pro forms only, for now — it validates on the server and gives a
//! hook that can refuse with a message next to a field. A refusal is written
//! to `logs/hyperion-formguard.log` beside the docroot so the panel can show
//! what was turned away: a guard that silently eats a real enquiry is worse
//! than the junk.
//!
//! Same security model as [`crate::regguard`] for the plugin file. The log is
//! written by the tenant's PHP and read here as ROOT, so it is reached through
//! [`crate::files::resolve_inside_jail`], read from the tail only, and every
//! field is treated as text somebody else chose.

use std::path::{Path, PathBuf};

use hyperion_types::formguard::FormGuardHit;

use crate::wpplugin::Module;
use crate::AdapterError;

/// Bumped whenever [`FORMGUARD_TEMPLATE`] changes in a way that matters.
pub const FORMGUARD_VERSION: u32 = 1;

/// `<site dir>/logs/<this>`. The module derives the same path from
/// `WP_CONTENT_DIR`; the two must agree.
pub const LOG_FILE: &str = "hyperion-formguard.log";

/// Never read more than this from the end of the log. The module caps the file
/// at a quarter of it, but the file is the tenant's to write.
const LOG_TAIL_BYTES: u64 = 512 * 1024;

/// Longest any one field of a log line is passed on.
const FIELD_MAX_CHARS: usize = 120;

/// The module. Static except for `{{VERSION}}`.
const FORMGUARD_TEMPLATE: &str = r#"<?php
/**
 * Hyperion contact form guard — loaded by mu-plugins/hyperion.php.
 *
 * Refuses Elementor Pro form submissions that carry no message, repeat one
 * just sent, come too often from one sender, or have a link in the name
 * field. Managed by Hyperion — edits are overwritten.
 * Version: {{VERSION}}
 */
if (!defined('ABSPATH')) { exit; }
if (defined('HYPERION_FORMGUARD_VERSION') || class_exists('Hyperion_Form_Guard', false)) { return; }

define('HYPERION_FORMGUARD_VERSION', {{VERSION}});

// Inside a condition for the same reason as the sign-up guard: a top-level
// class is bound when the file is compiled, before the check above runs.
if (!class_exists('Hyperion_Form_Guard', false)) {
    class Hyperion_Form_Guard {
        const MIN_MESSAGE    = 10;   // characters; below this a message says nothing
        const DUP_WINDOW     = 600;  // seconds an identical submission is refused for
        const PER_HOUR_IP    = 5;    // accepted submissions per address per hour
        const PER_HOUR_EMAIL = 3;    // accepted submissions per e-mail per hour

        public static function boot() {
            // After Elementor's own validators (required fields, reCAPTCHA):
            // what they refuse is theirs to report.
            add_action('elementor_pro/forms/validation', array(__CLASS__, 'validate'), 20, 2);
            // Fires only for a submission that went through, which is the
            // only kind that may count against the next one.
            add_action('elementor_pro/forms/new_record', array(__CLASS__, 'accepted'), 10, 2);
        }

        /** Field types that carry nothing the visitor wrote. */
        protected static function is_plumbing($type) {
            return in_array($type, array('honeypot', 'recaptcha', 'recaptcha_v3', 'hidden',
                                         'html', 'step', 'acceptance', 'password'), true);
        }

        /** Elementor's field list as plain id/type/title/value rows. */
        protected static function rows($record) {
            $out = array();
            if (!is_object($record) || !method_exists($record, 'get')) { return $out; }
            $fields = $record->get('fields');
            if (!is_array($fields)) { return $out; }
            foreach ($fields as $id => $f) {
                if (!is_array($f)) { continue; }
                $type = isset($f['type']) ? (string) $f['type'] : 'text';
                if (self::is_plumbing($type)) { continue; }
                $v = isset($f['value']) ? $f['value'] : '';
                if (is_array($v)) { $v = implode(', ', array_map('strval', $v)); }
                $out[] = array(
                    'id'    => isset($f['id']) ? (string) $f['id'] : (string) $id,
                    'type'  => $type,
                    'title' => isset($f['title']) ? (string) $f['title'] : '',
                    'value' => trim((string) $v),
                );
            }
            return $out;
        }

        protected static function form_key($record) {
            $id = '';
            if (is_object($record) && method_exists($record, 'get_form_settings')) {
                $id = (string) $record->get_form_settings('id');
            }
            return $id;
        }

        protected static function form_name($record) {
            $n = '';
            if (is_object($record) && method_exists($record, 'get_form_settings')) {
                $n = (string) $record->get_form_settings('form_name');
            }
            return $n;
        }

        protected static function len($s) {
            return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : strlen($s);
        }

        protected static function has_link($s) {
            return (bool) preg_match('~(https?://|www\.[a-z0-9-]|[a-z0-9-]{2,}\.[a-z]{2,}/)~i', $s);
        }

        protected static function email_of($rows) {
            foreach ($rows as $r) {
                if ($r['type'] === 'email' && $r['value'] !== '') { return strtolower($r['value']); }
            }
            return '';
        }

        /** The same submission, whatever the capitals and spacing. */
        protected static function fingerprint($form, $rows) {
            $parts = array($form);
            foreach ($rows as $r) {
                $parts[] = $r['id'] . '=' . strtolower(preg_replace('~\s+~u', ' ', $r['value']));
            }
            return md5(implode("\x1f", $parts));
        }

        /**
         * What is wrong with what the visitor wrote, or '' when nothing is.
         * Looks only at the submission itself — no stored state.
         */
        public static function judge_content($rows) {
            foreach ($rows as $r) {
                if ($r['type'] === 'text'
                    && preg_match('~name|nombre|nom\b|jm[eé]no~iu', $r['id'] . ' ' . $r['title'])
                    && self::has_link($r['value'])) {
                    return 'link_in_name';
                }
            }
            // "Says nothing" needs a message field to be empty AND nothing
            // else chosen: a booking form with a date and a party size is a
            // complete request with no message at all.
            $has_message = false; $longest = 0; $other = false;
            foreach ($rows as $r) {
                if ($r['type'] === 'textarea') {
                    $has_message = true;
                    $longest = max($longest, self::len($r['value']));
                } elseif (in_array($r['type'], array('select', 'radio', 'checkbox', 'date',
                                                     'time', 'number', 'upload'), true)
                          && $r['value'] !== '') {
                    $other = true;
                }
            }
            if ($has_message && !$other && $longest < self::MIN_MESSAGE) {
                return $longest === 0 ? 'empty' : 'short';
            }
            return '';
        }

        protected static function count_in_hour($key) {
            $c = get_transient($key);
            if (!is_array($c) || !isset($c['n'], $c['since']) || time() - (int) $c['since'] >= 3600) {
                return array('n' => 0, 'since' => time());
            }
            return array('n' => (int) $c['n'], 'since' => (int) $c['since']);
        }

        protected static function bump($key) {
            $c = self::count_in_hour($key);
            $c['n']++;
            set_transient($key, $c, max(1, 3600 - (time() - $c['since'])));
        }

        protected static function ip() {
            return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        }

        /** Content first, then what this sender already sent. */
        public static function judge($form, $rows, $ip) {
            $rule = self::judge_content($rows);
            if ($rule !== '') { return $rule; }
            if (get_transient('hyp_fg_d_' . self::fingerprint($form, $rows)) !== false) {
                return 'duplicate';
            }
            if ($ip !== '') {
                $c = self::count_in_hour('hyp_fg_i_' . md5($ip));
                if ($c['n'] >= self::PER_HOUR_IP) { return 'rate'; }
            }
            $email = self::email_of($rows);
            if ($email !== '') {
                $c = self::count_in_hour('hyp_fg_e_' . md5($email));
                if ($c['n'] >= self::PER_HOUR_EMAIL) { return 'rate'; }
            }
            return '';
        }

        /** What the visitor is told, in the site's language where we have it. */
        public static function message($rule) {
            $lang = strtolower(substr((string) (function_exists('get_locale') ? get_locale() : 'en'), 0, 2));
            $t = array(
                'empty' => array(
                    'en' => 'Please write a few words about what you need.',
                    'es' => 'Por favor, escriba unas palabras sobre lo que necesita.',
                    'cs' => 'Napište prosím pár slov o tom, co potřebujete.',
                ),
                'duplicate' => array(
                    'en' => 'We already have this message. There is no need to send it again.',
                    'es' => 'Ya hemos recibido este mensaje. No hace falta enviarlo de nuevo.',
                    'cs' => 'Tuto zprávu už máme. Není potřeba ji posílat znovu.',
                ),
                'rate' => array(
                    'en' => 'Too many messages in a short time. Please try again later.',
                    'es' => 'Demasiados mensajes en poco tiempo. Inténtelo de nuevo más tarde.',
                    'cs' => 'Příliš mnoho zpráv za krátkou dobu. Zkuste to prosím později.',
                ),
                'link_in_name' => array(
                    'en' => 'Please enter your name without a web address.',
                    'es' => 'Escriba su nombre sin una dirección web.',
                    'cs' => 'Zadejte prosím jméno bez webové adresy.',
                ),
            );
            $k = $rule === 'short' ? 'empty' : $rule;
            if (!isset($t[$k])) { return ''; }
            return isset($t[$k][$lang]) ? $t[$k][$lang] : $t[$k]['en'];
        }

        /** The field the message is shown under. */
        protected static function target_field($rule, $rows) {
            $want = $rule === 'link_in_name' ? 'text' : 'textarea';
            foreach ($rows as $r) { if ($r['type'] === $want) { return $r['id']; } }
            return isset($rows[0]) ? $rows[0]['id'] : '';
        }

        public static function validate($record, $ajax) {
            if (!is_object($ajax) || !method_exists($ajax, 'add_error')) { return; }
            // Already refused by Elementor: its message stands, and it is not ours to count.
            if (!empty($ajax->errors)) { return; }
            // Someone building or testing the form.
            if (function_exists('current_user_can') && current_user_can('edit_posts')) { return; }
            $rows = self::rows($record);
            if (!$rows) { return; }
            $rule = self::judge(self::form_key($record), $rows, self::ip());
            if ($rule === '') { return; }
            $field = self::target_field($rule, $rows);
            if ($field === '') { return; }
            $ajax->add_error($field, self::message($rule));
            self::log($rule, self::form_name($record), self::email_of($rows), self::ip());
        }

        public static function accepted($record, $ajax = null) {
            $rows = self::rows($record);
            if (!$rows) { return; }
            set_transient('hyp_fg_d_' . self::fingerprint(self::form_key($record), $rows), 1, self::DUP_WINDOW);
            $ip = self::ip();
            if ($ip !== '') { self::bump('hyp_fg_i_' . md5($ip)); }
            $email = self::email_of($rows);
            if ($email !== '') { self::bump('hyp_fg_e_' . md5($email)); }
        }

        /** Beside the docroot, so it is not downloadable: it names senders. */
        public static function log_path() {
            if (!defined('WP_CONTENT_DIR')) { return ''; }
            return dirname(dirname(WP_CONTENT_DIR)) . '/logs/hyperion-formguard.log';
        }

        /** One line per refusal, capped, never throws. */
        protected static function log($rule, $form, $email, $ip) {
            $path = self::log_path();
            if ($path === '' || !is_dir(dirname($path))) { return; }
            $flat = function ($s) { return substr(str_replace(array("\n", "\r", "\t"), ' ', (string) $s), 0, 200); };
            $line = gmdate('Y-m-d\TH:i:s') . "\t" . $flat($rule) . "\t" . $flat($form) . "\t"
                  . $flat($email) . "\t" . $flat($ip) . "\n";
            // Keep the newest half, as the mail log does.
            $size = @filesize($path);
            if ($size !== false && $size > 131072) {
                $tail = @file_get_contents($path, false, null, $size - 65536);
                if (is_string($tail)) {
                    $nl = strpos($tail, "\n");
                    @file_put_contents($path, $nl === false ? '' : substr($tail, $nl + 1), LOCK_EX);
                }
            }
            @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
        }
    }
    Hyperion_Form_Guard::boot();
}
"#;

/// The module body with the version marker filled in.
pub fn render_module() -> String {
    FORMGUARD_TEMPLATE.replace("{{VERSION}}", &FORMGUARD_VERSION.to_string())
}

/// `<root_dir>/wp-content/mu-plugins/hyperion/formguard.php` — the logical
/// path, for tests.
pub fn module_path(root_dir: &str) -> PathBuf {
    crate::wpplugin::module_path(root_dir, Module::FormGuard)
}

/// Is the guard installed and current?
pub async fn is_installed(root_dir: &str) -> bool {
    crate::wpplugin::module_state(root_dir, Module::FormGuard, &render_module()).await
        == crate::wpplugin::FileState::Current
}

/// Write (or rewrite) the module, owned by the site user. `Ok(false)` when the
/// site is not WordPress.
pub async fn install(root_dir: &str, system_user: &str) -> Result<bool, AdapterError> {
    crate::wpplugin::install_module(root_dir, system_user, Module::FormGuard, &render_module())
        .await
}

/// Remove it — best-effort, used when the operator turns the guard off.
pub async fn remove(root_dir: &str) {
    crate::wpplugin::remove_module(root_dir, Module::FormGuard).await
}

/// Does the site carry Elementor Pro? Without it the module loads and does
/// nothing, and the card should say so rather than show a green dot.
pub async fn has_elementor_pro(root_dir: &str) -> bool {
    tokio::fs::try_exists(Path::new(root_dir).join("wp-content/plugins/elementor-pro"))
        .await
        .unwrap_or(false)
}

/// What reading the refusal log told us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalLog {
    /// Newest last.
    Read(Vec<FormGuardHit>),
    /// No file: nothing has been refused yet.
    Absent,
    /// There is something at that path we will not or cannot read. Not
    /// evidence that nothing was refused.
    Unreadable,
}

fn clip(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(FIELD_MAX_CHARS)
        .collect()
}

/// One log line, or `None` for anything that is not ours: the file is written
/// by the site's PHP, so a line is whatever the tenant made it.
fn parse_line(line: &str) -> Option<FormGuardHit> {
    let mut f = line.split('\t');
    let at = f.next()?;
    let rule = f.next()?;
    // `YYYY-MM-DDTHH:MM:SS`, ASCII only — it is compared as a string later.
    let b = at.as_bytes();
    if b.len() != 19
        || !b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        })
    {
        return None;
    }
    if !matches!(
        rule,
        "empty" | "short" | "duplicate" | "rate" | "link_in_name"
    ) {
        return None;
    }
    Some(FormGuardHit {
        at: at.to_string(),
        rule: rule.to_string(),
        form: clip(f.next().unwrap_or("")),
        email: clip(f.next().unwrap_or("")),
        ip: clip(f.next().unwrap_or("")),
    })
}

/// The refusals recorded for a site, newest last, from the tail of the log.
pub async fn read_refusals(root_dir: &str) -> RefusalLog {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    // The log lives beside the docroot, so the jail is the SITE directory.
    let Some(site_dir) = Path::new(root_dir).parent() else {
        return RefusalLog::Unreadable;
    };
    let rel = format!("logs/{LOG_FILE}");
    let Ok(path) = crate::files::resolve_inside_jail(site_dir, &rel).await else {
        return RefusalLog::Unreadable;
    };
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RefusalLog::Absent,
        Err(_) => return RefusalLog::Unreadable,
    };
    let Ok(meta) = file.metadata().await else {
        return RefusalLog::Unreadable;
    };
    if !meta.is_file() {
        return RefusalLog::Unreadable;
    }
    let skipped = meta.len() > LOG_TAIL_BYTES;
    if skipped
        && file
            .seek(std::io::SeekFrom::Start(meta.len() - LOG_TAIL_BYTES))
            .await
            .is_err()
    {
        return RefusalLog::Unreadable;
    }
    let mut raw = Vec::new();
    if file
        .take(LOG_TAIL_BYTES)
        .read_to_end(&mut raw)
        .await
        .is_err()
    {
        return RefusalLog::Unreadable;
    }
    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.lines();
    if skipped {
        // The cut landed mid-line.
        lines.next();
    }
    RefusalLog::Read(lines.filter_map(parse_line).collect())
}

/// How many of `hits` are at or after `since` (unix seconds).
pub fn refused_since(hits: &[FormGuardHit], since: i64) -> u32 {
    let cutoff = crate::wpmail::iso_utc(since);
    hits.iter()
        .filter(|h| h.at.as_str() >= cutoff.as_str())
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_fills_the_version_marker() {
        let php = render_module();
        assert!(!php.contains("{{VERSION}}"), "template token left unfilled");
        assert!(php.contains("class Hyperion_Form_Guard"));
        assert!(php.contains(&format!("HYPERION_FORMGUARD_VERSION', {FORMGUARD_VERSION}")));
        // The module and the reader must agree on where the log is.
        assert!(php.contains(&format!("/logs/{LOG_FILE}")));
    }

    #[tokio::test]
    async fn install_detect_remove_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_str().unwrap();

        assert!(!install(root, "nobody").await.unwrap());
        assert!(!is_installed(root).await);

        tokio::fs::create_dir_all(dir.path().join("wp-content"))
            .await
            .unwrap();
        assert!(install(root, "nobody").await.unwrap());
        assert!(is_installed(root).await);
        assert!(!has_elementor_pro(root).await);

        tokio::fs::create_dir_all(dir.path().join("wp-content/plugins/elementor-pro"))
            .await
            .unwrap();
        assert!(has_elementor_pro(root).await);

        remove(root).await;
        assert!(!is_installed(root).await);
    }

    #[test]
    fn a_line_that_is_not_ours_is_not_a_refusal() {
        let ok =
            parse_line("2026-11-12T02:21:39\tempty\tNew Form EN\ta@b.cz\t203.0.113.7").unwrap();
        assert_eq!(ok.rule, "empty");
        assert_eq!(ok.form, "New Form EN");
        assert_eq!(ok.email, "a@b.cz");
        assert_eq!(ok.ip, "203.0.113.7");
        // Missing trailing fields are empty, not a reason to drop the line.
        assert!(parse_line("2026-11-12T02:21:39\trate").is_some());

        for bad in [
            "",
            "garbage",
            "2026-11-12 02:21:39\tempty\tf\te\ti",
            "2026-11-12T02:21:3é\tempty\tf\te\ti",
            "9999-99-99T99:99:99x\tempty",
            "2026-11-12T02:21:39\t<script>\tf\te\ti",
        ] {
            assert!(parse_line(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn fields_are_clipped_and_stripped_of_control_characters() {
        let long = "x".repeat(500);
        let hit = parse_line(&format!("2026-11-12T02:21:39\tshort\t{long}\ta\u{7}b\t1")).unwrap();
        assert_eq!(hit.form.chars().count(), FIELD_MAX_CHARS);
        assert_eq!(hit.email, "ab");
    }

    #[test]
    fn counts_only_refusals_inside_the_window() {
        let hit = |at: &str| FormGuardHit {
            at: at.into(),
            rule: "empty".into(),
            ..Default::default()
        };
        // 2026-11-12T00:00:00Z
        let since = 1_794_441_600;
        assert_eq!(crate::wpmail::iso_utc(since), "2026-11-12T00:00:00");
        let hits = [
            hit("2026-11-11T23:59:59"),
            hit("2026-11-12T00:00:00"),
            hit("2026-11-12T08:00:00"),
        ];
        assert_eq!(refused_since(&hits, since), 2);
    }

    #[tokio::test]
    async fn reads_the_log_beside_the_docroot_and_refuses_a_symlink() {
        let site = tempfile::TempDir::new().unwrap();
        let root = site.path().join("htdocs");
        let logs = site.path().join("logs");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&logs).unwrap();
        let root = root.to_str().unwrap();

        assert_eq!(read_refusals(root).await, RefusalLog::Absent);

        std::fs::write(
            logs.join(LOG_FILE),
            "2026-11-12T02:21:39\tempty\tContact\ta@b.cz\t203.0.113.7\nnot a line\n\
             2026-11-12T02:21:49\tduplicate\tContact\ta@b.cz\t203.0.113.7\n",
        )
        .unwrap();
        let RefusalLog::Read(hits) = read_refusals(root).await else {
            panic!("log not read");
        };
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[1].rule, "duplicate");

        // Read as root and shown in the panel: a link here would be an
        // arbitrary file read.
        let secret = site.path().join("secret");
        std::fs::write(&secret, "2026-11-12T02:21:39\tempty\tleak\tx\ty\n").unwrap();
        std::fs::remove_file(logs.join(LOG_FILE)).unwrap();
        std::os::unix::fs::symlink(&secret, logs.join(LOG_FILE)).unwrap();
        assert_eq!(read_refusals(root).await, RefusalLog::Unreadable);
    }

    #[tokio::test]
    async fn a_huge_log_is_read_from_the_tail_only() {
        let site = tempfile::TempDir::new().unwrap();
        let root = site.path().join("htdocs");
        let logs = site.path().join("logs");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&logs).unwrap();
        let line = "2026-11-12T02:21:39\tempty\tContact\ta@b.cz\t203.0.113.7\n";
        let n = (LOG_TAIL_BYTES as usize / line.len()) * 3;
        let mut body = line.repeat(n);
        body.push_str("2026-11-12T09:00:00\trate\tLast\t\t\n");
        std::fs::write(logs.join(LOG_FILE), body).unwrap();
        let RefusalLog::Read(hits) = read_refusals(root.to_str().unwrap()).await else {
            panic!("log not read");
        };
        assert!(hits.len() < n / 2, "read {} of {n} lines", hits.len());
        assert_eq!(hits.last().unwrap().form, "Last");
    }
}
