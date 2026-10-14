//! Registration spam guard — a must-use plugin that blocks automated sign-ups
//! (a link in a name field, or a filled honeypot) across native WordPress,
//! WooCommerce and Paid Member Subscriptions, and deletes a spam account that
//! still slips through right after it is created.
//!
//! Same security model as [`crate::wpmail`]: the plugin lives in a tree the
//! tenant can write, everything below runs as ROOT, so every path is resolved
//! through [`crate::files::resolve_inside_jail`], which refuses a symlink at
//! any segment, and the final `chown` uses `-h` so it can never follow a link
//! planted in the race window.

use std::path::PathBuf;

use crate::wpplugin::Module;
use crate::AdapterError;

/// Bumped whenever [`REGGUARD_TEMPLATE`] changes in a way that matters — the
/// on-disk marker is compared against it so an agent update relands a corrected
/// plugin on the next tick instead of leaving the old one.
pub const REGGUARD_VERSION: u32 = 2;

/// The plugin. Static except for `{{VERSION}}`. Written to do nothing in the
/// common case — a few registration hooks, no I/O unless a sign-up is actually
/// submitted.
const REGGUARD_TEMPLATE: &str = r#"<?php
/**
 * Hyperion registration spam guard — loaded by mu-plugins/hyperion.php.
 *
 * Blocks automated spam sign-ups — a link in a name field, or a filled
 * honeypot — across native WordPress, WooCommerce and Paid Member
 * Subscriptions. Managed by Hyperion — edits are overwritten.
 * Version: {{VERSION}}
 */
if (!defined('ABSPATH')) { exit; }
if (defined('HYPERION_REGGUARD_VERSION') || class_exists('Hyperion_Reg_Guard', false)) { return; }

define('HYPERION_REGGUARD_VERSION', {{VERSION}});

// Declared inside a condition on purpose: PHP binds a plain top-level class
// when the file is COMPILED, before the check above runs — so the check
// would always see the class and return before boot(), and a second copy of
// the file would be a fatal "cannot declare class" instead of a no-op.
if (!class_exists('Hyperion_Reg_Guard', false)) {
    class Hyperion_Reg_Guard {
        const HP = 'hyp_url_confirm'; // honeypot field — a bot fills it, a human never sees it

        public static function boot() {
            add_action('register_form',             array(__CLASS__, 'honeypot'));
            add_action('woocommerce_register_form', array(__CLASS__, 'honeypot'));
            // PMS has no `pms_register_form` action; this is the one its
            // register form template fires inside the <form>.
            add_action('pms_register_form_after_fields', array(__CLASS__, 'honeypot'));

            add_filter('registration_errors',             array(__CLASS__, 'block'), 9, 1);
            add_filter('woocommerce_registration_errors', array(__CLASS__, 'block'), 9, 1);
            add_action('pms_register_form_validation',    array(__CLASS__, 'block_pms'), 9);

            // Universal backstop: delete a spammy account right after ANY path
            // creates it — covers plugin flows whose validation hook we don't know.
            // Priority 1 so it runs before the welcome mail goes out: that mail,
            // with the link in the "name", is what the spammer is after.
            add_action('user_register', array(__CLASS__, 'sweep'), 1);
        }

        public static function honeypot() {
            echo '<div style="position:absolute!important;left:-9999px!important;top:-9999px" aria-hidden="true">'
                . '<label>Leave this field empty</label>'
                . '<input type="text" name="' . self::HP . '" tabindex="-1" autocomplete="off" value=""></div>';
        }

        protected static function is_spam_submission() {
            if (!empty($_POST[self::HP])) { return true; }
            $fields = array('user_login', 'username', 'first_name', 'last_name', 'nickname',
                            'display_name', 'billing_first_name', 'billing_last_name');
            foreach ($fields as $f) {
                if (isset($_POST[$f]) && is_string($_POST[$f]) && self::has_link((string) wp_unslash($_POST[$f]))) {
                    return true;
                }
            }
            return false;
        }

        // A link (or a domain-with-path) inside a NAME field is the signature — a
        // real person's name never carries one. The trailing slash requirement
        // keeps a legitimate "J.Co" style name from being caught.
        protected static function has_link($s) {
            return (bool) preg_match('~(https?://|www\.[a-z0-9-]|[a-z0-9-]{2,}\.[a-z]{2,}/)~i', $s);
        }

        public static function block($errors) {
            if (is_wp_error($errors) && self::is_spam_submission()) {
                $errors->add('hyperion_spam', 'Registration blocked.');
            }
            return $errors;
        }

        public static function block_pms() {
            if (self::is_spam_submission() && function_exists('pms_errors')) {
                pms_errors()->add('hyperion_spam', 'Registration blocked.');
            }
        }

        public static function sweep($user_id) {
            // An administrator adding an account by hand, or an operator
            // importing users over WP-CLI, means it — the sweep is for anonymous
            // sign-ups only. Before this an admin who created "www.firma.cz" as
            // a login watched it vanish without a word.
            if ((defined('WP_CLI') && WP_CLI) || current_user_can('create_users')) { return; }
            $u = get_userdata($user_id);
            if (!$u) { return; }
            $blob = $u->user_login . ' ' . $u->display_name . ' '
                  . get_user_meta($user_id, 'first_name', true) . ' '
                  . get_user_meta($user_id, 'last_name', true) . ' '
                  . get_user_meta($user_id, 'nickname', true);
            // Only a fresh, content-less subscriber-tier account carrying the
            // signature — never someone who has posted or holds a real role.
            if (self::has_link($blob)
                && in_array('subscriber', (array) $u->roles, true)
                && count_user_posts($user_id) == 0) {
                require_once ABSPATH . 'wp-admin/includes/user.php';
                wp_delete_user($user_id);
            }
        }
    }
    Hyperion_Reg_Guard::boot();
}
"#;

/// The plugin body with the version marker filled in.
pub fn render_mu_plugin() -> String {
    REGGUARD_TEMPLATE.replace("{{VERSION}}", &REGGUARD_VERSION.to_string())
}

/// `<root_dir>/wp-content/mu-plugins/hyperion/regguard.php` — the logical
/// path, for tests.
pub fn mu_plugin_path(root_dir: &str) -> PathBuf {
    crate::wpplugin::module_path(root_dir, Module::RegGuard)
}

/// Is the guard installed and current? `false` for a non-WordPress site, a
/// missing file, a stale version, or a symlink we refuse to read through.
pub async fn is_installed(root_dir: &str) -> bool {
    crate::wpplugin::module_state(root_dir, Module::RegGuard, &render_mu_plugin()).await
        == crate::wpplugin::FileState::Current
}

/// Write (or rewrite) the plugin, owned by the site user. `Ok(false)` when the
/// site is not WordPress — nothing to do, not an error.
pub async fn install(root_dir: &str, system_user: &str) -> Result<bool, AdapterError> {
    crate::wpplugin::install_module(root_dir, system_user, Module::RegGuard, &render_mu_plugin())
        .await
}

/// Remove it — best-effort, used when the operator turns the guard off.
pub async fn remove(root_dir: &str) {
    crate::wpplugin::remove_module(root_dir, Module::RegGuard).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_fills_the_version_marker() {
        let php = render_mu_plugin();
        assert!(!php.contains("{{VERSION}}"), "template token left unfilled");
        assert!(php.contains("class Hyperion_Reg_Guard"));
        assert!(php.contains(&format!("HYPERION_REGGUARD_VERSION', {REGGUARD_VERSION}")));
    }

    #[tokio::test]
    async fn install_detect_remove_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_str().unwrap();

        // Not WordPress yet → install is a no-op and nothing is detected.
        assert!(!install(root, "nobody").await.unwrap());
        assert!(!is_installed(root).await);

        // Make it WordPress, then install.
        tokio::fs::create_dir_all(dir.path().join("wp-content"))
            .await
            .unwrap();
        assert!(install(root, "nobody").await.unwrap());
        assert!(is_installed(root).await);

        // The file carries the version marker + the guard class.
        let php = tokio::fs::read_to_string(mu_plugin_path(root))
            .await
            .unwrap();
        assert!(php.contains("Hyperion_Reg_Guard"));
        assert!(php.contains(&format!("HYPERION_REGGUARD_VERSION', {REGGUARD_VERSION}")));

        remove(root).await;
        assert!(!is_installed(root).await);
    }
}
