//! The one Hyperion must-use plugin every WordPress site carries.
//!
//! # Layout
//!
//! ```text
//! wp-content/mu-plugins/hyperion.php          loader + Tools → Hyperion page
//! wp-content/mu-plugins/hyperion/mail.php     sender pin + failed-send log
//! wp-content/mu-plugins/hyperion/regguard.php registration spam guard
//! wp-content/mu-plugins/hyperion/preview.php  preview-host support
//! wp-content/mu-plugins/hyperion/status.php   what the agent last saw
//! ```
//!
//! WordPress loads only the top-level files of `mu-plugins/`, so the loader
//! includes the modules. Each module keeps its own lifecycle — the mail tick,
//! the spam-guard toggle and the vhost writer still decide on their own
//! whether their file exists — which is why this is one plugin with several
//! files rather than one rendered file: a single file would have to be
//! re-rendered from every feature's state by whichever writer touched it
//! last, and the three writers live in different layers.
//!
//! Before this, each feature was its own top-level file
//! (`hyperion-mail.php`, …). [`adopt_legacy`] moves those into the module
//! directory, and the loader skips a module while its old copy still sits
//! next to it — loading both would register every hook twice and redeclare
//! the spam guard's class, which is fatal. That also makes an agent rollback
//! safe: the older agent rewrites its top-level file, and the loader steps
//! aside for it.
//!
//! # The status page
//!
//! Read-only on purpose. The agent writes `status.php` (when it last looked,
//! what it found); the page renders it, and an old timestamp is how the page
//! knows Hyperion has stopped looking after the site. Nothing in WordPress
//! talks back to Hyperion: every byte of PHP here runs as the tenant, so a
//! credential for calling the panel would belong to every plugin on the
//! site, and settings written from wp-admin would be tenant input read by a
//! root process. Configuration stays in the panel.
//!
//! # Security
//!
//! Same model as before the merge: the tree is tenant-writable and all of
//! this runs as ROOT. Every path goes through
//! [`crate::files::resolve_inside_jail`] (refuses a symlink at any segment),
//! files are written to a fresh `O_EXCL` temp name and renamed into place (a
//! planted link or hard link on the final name is replaced, never written
//! through — and PHP never includes a half-written file), and `chown -h`
//! never follows a link.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::AdapterError;

/// Bumped whenever [`LOADER_TEMPLATE`] changes; the file is compared byte for
/// byte, so any change relands on the next tick anyway — the number is for a
/// person reading the plugin list.
pub const LOADER_VERSION: u32 = 1;

/// `wp-content/mu-plugins/<this>`.
pub const LOADER_FILE: &str = "hyperion.php";

/// `wp-content/mu-plugins/<this>/`.
pub const MODULE_DIR: &str = "hyperion";

/// `wp-content/mu-plugins/hyperion/<this>`.
pub const STATUS_FILE: &str = "status.php";

/// One feature of the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Module {
    Mail,
    RegGuard,
    Preview,
}

impl Module {
    pub const ALL: [Module; 3] = [Module::Mail, Module::RegGuard, Module::Preview];

    /// File name inside [`MODULE_DIR`]. The loader's list must match.
    pub fn file(self) -> &'static str {
        match self {
            Module::Mail => "mail.php",
            Module::RegGuard => "regguard.php",
            Module::Preview => "preview.php",
        }
    }

    /// The top-level file this feature used to be, before the merge.
    pub fn legacy_file(self) -> &'static str {
        match self {
            Module::Mail => "hyperion-mail.php",
            Module::RegGuard => "hyperion-regguard.php",
            Module::Preview => "hyperion-preview.php",
        }
    }
}

/// State of one managed file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// Not a WordPress site at all — nothing to install, and saying
    /// "missing" would be a finding about a site that has no WordPress.
    NotWordPress,
    Missing,
    /// Present, but not what we would write now. Rewriting is the fix and it
    /// is safe to do unattended.
    Stale,
    Current,
}

/// The loader. Static except for `{{VERSION}}`.
///
/// Runs on every request of every site: a handful of `is_file` stats (the
/// stat cache absorbs them) and nothing else outside wp-admin.
const LOADER_TEMPLATE: &str = r#"<?php
/**
 * Plugin Name: Hyperion
 * Description: Hosting integration managed by Hyperion — keeps outgoing mail on this site's domain, blocks spam sign-ups, supports preview addresses, and shows what the server last checked under Tools → Hyperion. Managed by Hyperion — edits are overwritten.
 * Version: {{VERSION}}
 * Author: Hyperion
 */
if (!defined('ABSPATH')) { exit; }
if (defined('HYPERION_LOADER_VERSION')) { return; }
define('HYPERION_LOADER_VERSION', {{VERSION}});
define('HYPERION_DIR', __DIR__ . '/hyperion');

/*
 * Feature modules. Hyperion decides which exist; the loader only includes
 * them. A module whose old single-file copy (hyperion-<name>.php next to this
 * file) is still present is skipped: WordPress already loads that copy, and
 * loading both would register every hook twice.
 */
$GLOBALS['hyperion_modules'] = array();
foreach (array(
    'mail'     => 'hyperion-mail.php',
    'regguard' => 'hyperion-regguard.php',
    'preview'  => 'hyperion-preview.php',
) as $hyperion_mod => $hyperion_legacy) {
    if (is_file(__DIR__ . '/' . $hyperion_legacy)) {
        $GLOBALS['hyperion_modules'][$hyperion_mod] = 'legacy';
    } elseif (is_file(HYPERION_DIR . '/' . $hyperion_mod . '.php')) {
        include_once HYPERION_DIR . '/' . $hyperion_mod . '.php';
        $GLOBALS['hyperion_modules'][$hyperion_mod] = 'on';
    }
}
unset($hyperion_mod, $hyperion_legacy);

/** What the server agent last wrote about this site, or an empty array. */
function hyperion_status() {
    static $status = null;
    if ($status === null) {
        $file = HYPERION_DIR . '/status.php';
        $status = is_file($file) ? include $file : array();
        if (!is_array($status)) { $status = array(); }
    }
    return $status;
}

/** English or Czech, by the viewing user's locale. */
function hyperion_t($en, $cs) {
    $locale = function_exists('get_user_locale') ? get_user_locale() : get_locale();
    return strpos((string) $locale, 'cs') === 0 ? $cs : $en;
}

/**
 * Seconds since the agent last looked, or null when it never has.
 *
 * The agent rewrites the status at least hourly, so three hours without one
 * means it has stopped: the agent is down, or the site was moved off the
 * server it is on.
 */
function hyperion_status_age() {
    $s = hyperion_status();
    if (empty($s['checked_at'])) { return null; }
    return max(0, time() - (int) $s['checked_at']);
}
define('HYPERION_STALE_AFTER', 3 * HOUR_IN_SECONDS);

function hyperion_when($ts) {
    $ts = (int) $ts;
    if ($ts <= 0) { return '—'; }
    $fmt = get_option('date_format') . ' ' . get_option('time_format');
    $abs = function_exists('wp_date') ? wp_date($fmt, $ts) : date_i18n($fmt, $ts);
    return sprintf(hyperion_t('%1$s (%2$s ago)', '%1$s (před %2$s)'), $abs, human_time_diff($ts, time()));
}

if (is_admin()) {
    add_action('admin_menu', function () {
        add_management_page('Hyperion', 'Hyperion', 'manage_options', 'hyperion', 'hyperion_render_page');
    });

    // Site Health is where WordPress already sends people to ask "is my
    // site OK?", so the same answer goes there.
    add_filter('site_status_tests', function ($tests) {
        $tests['direct']['hyperion'] = array(
            'label' => 'Hyperion',
            'test'  => 'hyperion_site_health',
        );
        return $tests;
    });
}

function hyperion_site_health() {
    $age = hyperion_status_age();
    $ok = $age !== null && $age <= HYPERION_STALE_AFTER;
    return array(
        'label'       => $ok
            ? hyperion_t('Hyperion is looking after this site', 'Hyperion spravuje tento web')
            : hyperion_t('Hyperion has not checked this site recently', 'Hyperion tento web nedávno nekontroloval'),
        'status'      => $ok ? 'good' : 'recommended',
        'badge'       => array('label' => 'Hyperion', 'color' => $ok ? 'blue' : 'orange'),
        'description' => '<p>' . esc_html(hyperion_verdict_text($age)) . '</p>',
        'actions'     => '<p><a href="' . esc_url(admin_url('tools.php?page=hyperion')) . '">'
            . esc_html(hyperion_t('Details', 'Podrobnosti')) . '</a></p>',
        'test'        => 'hyperion',
    );
}

function hyperion_verdict_text($age) {
    $s = hyperion_status();
    if ($age === null) {
        return hyperion_t(
            'The server has not reported on this site yet. The first check normally arrives within a few minutes of the plugin being installed.',
            'Server o tomto webu zatím nic nehlásil. První kontrola obvykle dorazí do několika minut od instalace pluginu.'
        );
    }
    if ($age > HYPERION_STALE_AFTER) {
        return sprintf(hyperion_t(
            'The last check was %s. The server normally checks every hour, so its agent may be stopped or the site may have been moved. If this lasts, contact your hosting provider.',
            'Poslední kontrola proběhla %s. Server běžně kontroluje každou hodinu, takže jeho agent možná neběží nebo byl web přesunut. Pokud to přetrvává, kontaktujte svého poskytovatele hostingu.'
        ), hyperion_when($s['checked_at']));
    }
    return sprintf(hyperion_t(
        'Connected. Last check %s.',
        'Spojení je v pořádku. Poslední kontrola %s.'
    ), hyperion_when($s['checked_at']));
}

function hyperion_render_page() {
    if (!current_user_can('manage_options')) { return; }
    $s = hyperion_status();
    $age = hyperion_status_age();
    $ok = $age !== null && $age <= HYPERION_STALE_AFTER;
    $mods = $GLOBALS['hyperion_modules'];
    $on = hyperion_t('On', 'Zapnuto');
    $off = hyperion_t('Off', 'Vypnuto');
    $rows = array();

    $mail = isset($s['mail']) && is_array($s['mail']) ? $s['mail'] : array();
    if (!empty($mods['mail'])) {
        $from = isset($mail['from']) ? $mail['from'] : '—';
        // Older status files have no pin_from; the rewrite was always on then.
        $pin = !array_key_exists('pin_from', $mail) || !empty($mail['pin_from']);
        $txt = $pin
            ? sprintf(hyperion_t(
                'Hyperion rewrites a From address on another domain to %s, so mail passes SPF. A site that sends through its own SMTP server can have the rewrite switched off in the Hyperion panel.',
                'Hyperion přepisuje adresu odesílatele z jiné domény na %s, aby e-maily prošly kontrolou SPF. Pokud web odesílá přes vlastní SMTP server, lze přepisování vypnout v panelu Hyperion.'
            ), $from)
            : hyperion_t(
                'Hyperion does not change this site\'s mail: the From address and SMTP settings are the site\'s own. Failed sends are still recorded.',
                'Hyperion e-maily tohoto webu nemění: adresa odesílatele i nastavení SMTP jsou vlastní nastavení webu. Neodeslané e-maily se dál zaznamenávají.'
            );
        if (isset($mail['failures_7d'])) {
            $n = (int) $mail['failures_7d'];
            $txt .= ' ' . ($n === 0
                ? hyperion_t('No failed sends in the last 7 days.', 'Za posledních 7 dní žádné neodeslané e-maily.')
                : sprintf(hyperion_t('%d failed send(s) in the last 7 days.', 'Neodeslané e-maily za posledních 7 dní: %d.'), $n));
        }
        if (!empty($mail['forced_local'])) {
            $txt .= ' ' . hyperion_t(
                'Mail is sent through the server instead of the SMTP plugin, because the plugin was failing; settings saved in that plugin have no effect until sending is handed back in the Hyperion panel.',
                'E-maily odcházejí přes server místo SMTP pluginu, protože plugin selhával; nastavení uložené v pluginu se neprojeví, dokud se odesílání v panelu Hyperion nevrátí pluginu.'
            );
        }
        $rows[] = array(
            hyperion_t('Outgoing mail', 'Odchozí e-maily'),
            !empty($mail['forced_local'])
                ? hyperion_t('Sent by Hyperion', 'Odesílá Hyperion')
                : ($pin ? hyperion_t('Rewrites sender', 'Přepisuje odesílatele') : hyperion_t('Unchanged', 'Nepřepisuje')),
            $txt,
        );
    } else {
        $rows[] = array(hyperion_t('Outgoing mail', 'Odchozí e-maily'), $off, '');
    }

    $rows[] = array(
        hyperion_t('Sign-up spam guard', 'Ochrana registrací proti spamu'),
        !empty($mods['regguard']) ? $on : $off,
        !empty($mods['regguard'])
            ? hyperion_t('Sign-ups with a link in a name field, or a filled hidden field, are refused.', 'Registrace s odkazem v poli jména nebo s vyplněným skrytým polem se odmítají.')
            : '',
    );

    if (!empty($mods['preview'])) {
        $rows[] = array(
            hyperion_t('Preview address', 'Náhledová adresa'),
            $on,
            hyperion_t('The site can be viewed on its preview address before DNS points here.', 'Web lze zobrazit na náhledové adrese ještě před přesměrováním DNS.'),
        );
    }

    $b = isset($s['backup']) && is_array($s['backup']) ? $s['backup'] : array();
    if (!empty($b['last_ok_at'])) {
        $txt = sprintf(hyperion_t('Last successful backup %s.', 'Poslední úspěšná záloha %s.'), hyperion_when($b['last_ok_at']));
        if (!empty($b['last_failed_at']) && (int) $b['last_failed_at'] > (int) $b['last_ok_at']) {
            $txt .= ' ' . sprintf(hyperion_t('A later backup failed %s.', 'Pozdější záloha selhala %s.'), hyperion_when($b['last_failed_at']));
        }
        $rows[] = array(hyperion_t('Backups', 'Zálohy'), $on, $txt);
    } elseif (!empty($s)) {
        $rows[] = array(hyperion_t('Backups', 'Zálohy'), '—', hyperion_t('No successful backup on record.', 'Žádná úspěšná záloha v záznamech.'));
    }
    ?>
    <div class="wrap">
        <h1>Hyperion</h1>
        <div class="notice <?php echo $ok ? 'notice-success' : 'notice-warning'; ?> inline">
            <p><strong><?php echo esc_html($ok
                ? hyperion_t('Hyperion is looking after this site.', 'Hyperion spravuje tento web.')
                : hyperion_t('Hyperion has not checked this site recently.', 'Hyperion tento web nedávno nekontroloval.')); ?></strong>
            <?php echo esc_html(hyperion_verdict_text($age)); ?></p>
        </div>
        <table class="widefat striped" style="max-width:60em;margin-top:1em">
            <tbody>
            <?php foreach ($rows as $r) : ?>
                <tr>
                    <th scope="row" style="width:14em"><?php echo esc_html($r[0]); ?></th>
                    <td style="width:10em"><?php echo esc_html($r[1]); ?></td>
                    <td><?php echo esc_html($r[2]); ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <p class="description" style="margin-top:1em">
            <?php echo esc_html(hyperion_t(
                'These features are managed from the Hyperion panel; this page only shows their state.',
                'Tyto funkce se spravují v panelu Hyperion; tato stránka jen ukazuje jejich stav.'
            )); ?>
            <?php if (!empty($s['domain'])) : ?>
                <br><?php echo esc_html(sprintf('%s · %s · %s %s',
                    $s['domain'],
                    isset($s['node']) ? $s['node'] : '—',
                    hyperion_t('plugin', 'plugin'),
                    HYPERION_LOADER_VERSION . (empty($s['agent']) ? '' : ' / ' . $s['agent']))); ?>
            <?php endif; ?>
        </p>
    </div>
    <?php
}
"#;

/// The loader with its version filled in.
pub fn render_loader() -> String {
    LOADER_TEMPLATE.replace("{{VERSION}}", &LOADER_VERSION.to_string())
}

/// What the agent tells the status page. Every field is optional on the PHP
/// side, so adding one here never breaks a page reading an older file.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SiteStatus {
    /// Unix seconds. The page's "is Hyperion still looking?" is this.
    pub checked_at: i64,
    pub agent: String,
    pub node: String,
    pub domain: String,
    pub mail: Option<MailStatus>,
    pub backup: BackupStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct MailStatus {
    pub from: String,
    /// `None` when the failure log could not be read — the page then says
    /// nothing about failures rather than "none".
    pub failures_7d: Option<usize>,
    pub forced_local: bool,
    /// Does Hyperion rewrite a From address on another domain? Off when the
    /// operator left the site's own SMTP setup alone.
    pub pin_from: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BackupStatus {
    pub last_ok_at: Option<i64>,
    pub last_failed_at: Option<i64>,
}

/// `status.php` for `status`.
///
/// The data travels as JSON inside a PHP single-quoted string, never as PHP
/// literals: only `\` and `'` are special in that string, so escaping those
/// two is the whole of the escaping, and nothing a domain or an error message
/// contains can become code. The `ABSPATH` guard stops the file answering a
/// direct HTTP request — it names the site's sender and node.
pub fn render_status(status: &SiteStatus) -> String {
    let json = serde_json::to_string(status).unwrap_or_else(|_| "{}".into());
    format!(
        "<?php\n// Written by Hyperion — what the server last checked. Edits are overwritten.\n\
         if (!defined('ABSPATH')) {{ exit; }}\nreturn json_decode('{}', true);\n",
        php_single_quoted(&json)
    )
}

/// Escape for a PHP single-quoted string: only `\` and `'` are special there.
pub fn php_single_quoted(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\'', "\\'")
}

fn is_wordpress(root_dir: &str) -> bool {
    Path::new(root_dir).join("wp-content").is_dir()
}

/// `<root>/wp-content/mu-plugins/hyperion/<module>` — the LOGICAL path, for
/// tests and messages. Never open this as root; resolve it.
pub fn module_path(root_dir: &str, module: Module) -> PathBuf {
    Path::new(root_dir)
        .join("wp-content/mu-plugins")
        .join(MODULE_DIR)
        .join(module.file())
}

/// `<root>/wp-content/mu-plugins/hyperion.php` — logical, as above.
pub fn loader_path(root_dir: &str) -> PathBuf {
    Path::new(root_dir)
        .join("wp-content/mu-plugins")
        .join(LOADER_FILE)
}

async fn resolve(root_dir: &str, rel: &str) -> Result<PathBuf, AdapterError> {
    crate::files::resolve_inside_jail(Path::new(root_dir), rel).await
}

fn mu_rel() -> &'static str {
    "wp-content/mu-plugins"
}

fn module_dir_rel() -> String {
    format!("wp-content/mu-plugins/{MODULE_DIR}")
}

/// Contents of a managed file, read without following a link anywhere on
/// the way. `Ok(None)` = not there.
async fn read_managed(root_dir: &str, rel: &str) -> Result<Option<String>, AdapterError> {
    let path = resolve(root_dir, rel).await?;
    match tokio::fs::read_to_string(&path).await {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AdapterError::Other(format!("read {}: {e}", path.display()))),
    }
}

async fn state_of(root_dir: &str, rel: &str, expected: &str) -> FileState {
    if !is_wordpress(root_dir) {
        return FileState::NotWordPress;
    }
    // A symlink anywhere reads as `Stale`, which sends the caller to the
    // install — where the link on our own name is replaced by a real file.
    // Reading THROUGH it would compare an unrelated file to our template.
    match read_managed(root_dir, rel).await {
        Ok(Some(found)) if found == expected => FileState::Current,
        Ok(Some(_)) | Err(_) => FileState::Stale,
        Ok(None) => FileState::Missing,
    }
}

/// What is on disk for `module`, compared with `expected`.
pub async fn module_state(root_dir: &str, module: Module, expected: &str) -> FileState {
    state_of(
        root_dir,
        &format!("{}/{}", module_dir_rel(), module.file()),
        expected,
    )
    .await
}

/// The module file's contents, if it is there and readable without
/// following a link.
pub async fn module_contents(root_dir: &str, module: Module) -> Option<String> {
    read_managed(root_dir, &format!("{}/{}", module_dir_rel(), module.file()))
        .await
        .ok()
        .flatten()
}

/// Write `contents` to `<dir>/<name>`, where `dir` is an already-resolved,
/// real directory inside the site.
///
/// Through a temp name and a rename, for two reasons. A request that
/// includes the file mid-write would parse half a plugin and take the site
/// down with a fatal error. And a link the tenant planted on the final name —
/// a symlink, or a hard link to a root-owned file — is REPLACED by the rename
/// instead of written through. The temp name is cleared first and then opened
/// `O_EXCL`, which refuses a link planted there too.
async fn write_atomic(dir: &Path, name: &str, contents: &str) -> Result<PathBuf, AdapterError> {
    // Unique per write, so the tick and an operator's toggle writing the
    // same module at once cannot remove each other's temp file.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.hyperion-tmp-{}-{seq}", std::process::id()));
    let dest = dir.join(name);
    let _ = tokio::fs::remove_file(&tmp).await;
    let body = contents.as_bytes().to_vec();
    let tmp_w = tmp.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp_w)?;
        f.write_all(&body)?;
        f.sync_all()
    })
    .await
    .map_err(|e| AdapterError::Other(format!("write {}: {e}", tmp.display())))?
    .map_err(|e| AdapterError::Other(format!("write {}: {e}", tmp.display())))?;
    if let Err(e) = tokio::fs::rename(&tmp, &dest).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(AdapterError::Other(format!(
            "rename {}: {e}",
            dest.display()
        )));
    }
    Ok(dest)
}

/// Resolve `rel` as a directory inside the site and create it if missing.
/// Refuses a symlink at any segment.
async fn ensure_dir(root_dir: &str, rel: &str) -> Result<PathBuf, AdapterError> {
    let dir = resolve(root_dir, rel).await?;
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| AdapterError::Other(format!("create {}: {e}", dir.display())))?;
    // `create_dir_all` dereferences; re-resolve so a link swapped in while it
    // ran is refused rather than used.
    resolve(root_dir, rel).await
}

/// Hand `paths` to the site user. `-h` because chown follows a symlink by
/// default: a link planted between the resolve and this call would otherwise
/// hand the tenant its target.
async fn chown_to_site(system_user: &str, paths: &[&Path]) {
    if system_user.trim().is_empty() || paths.is_empty() {
        return;
    }
    let mut cmd = tokio::process::Command::new("/usr/bin/chown");
    cmd.arg("-h").arg(format!("{system_user}:{system_user}"));
    for p in paths {
        cmd.arg(p);
    }
    let _ = cmd.output().await;
}

/// Write the loader if it is not already exactly [`render_loader`].
/// `Ok(false)` = nothing written (current, or not WordPress).
pub async fn ensure_loader(root_dir: &str, system_user: &str) -> Result<bool, AdapterError> {
    if !is_wordpress(root_dir) {
        return Ok(false);
    }
    let want = render_loader();
    if state_of(root_dir, &format!("{}/{LOADER_FILE}", mu_rel()), &want).await == FileState::Current
    {
        return Ok(false);
    }
    let mu = ensure_dir(root_dir, mu_rel()).await?;
    let path = write_atomic(&mu, LOADER_FILE, &want).await?;
    chown_to_site(system_user, &[&mu, &path]).await;
    Ok(true)
}

/// Write (or rewrite) one module, and the loader that includes it.
///
/// `Ok(false)` when the site is not WordPress — nothing to do, not an error.
/// Removes the module's old top-level copy: the loader skips a module while
/// that copy exists, so leaving it would keep the stale one running.
pub async fn install_module(
    root_dir: &str,
    system_user: &str,
    module: Module,
    contents: &str,
) -> Result<bool, AdapterError> {
    if !is_wordpress(root_dir) {
        return Ok(false);
    }
    let mu = ensure_dir(root_dir, mu_rel()).await?;
    let dir = ensure_dir(root_dir, &module_dir_rel()).await?;
    let path = write_atomic(&dir, module.file(), contents).await?;
    // After the new file is in place, so there is never a moment with
    // neither. `remove_file` unlinks a link rather than its target, and `mu`
    // is a resolved real directory, so this cannot reach outside the site.
    let _ = tokio::fs::remove_file(mu.join(module.legacy_file())).await;
    chown_to_site(system_user, &[&mu, &dir, &path]).await;
    ensure_loader(root_dir, system_user).await?;
    Ok(true)
}

/// Remove one module (and its old top-level copy). Best-effort.
///
/// The directories are resolved first: removing by the logical path would
/// let a tenant who swapped `mu-plugins/hyperion` for a link to `/etc` have
/// root delete `/etc/mail.php` for them.
pub async fn remove_module(root_dir: &str, module: Module) {
    if let Ok(mu) = resolve(root_dir, mu_rel()).await {
        let _ = tokio::fs::remove_file(mu.join(module.legacy_file())).await;
    }
    if let Ok(dir) = resolve(root_dir, &module_dir_rel()).await {
        let _ = tokio::fs::remove_file(dir.join(module.file())).await;
    }
}

/// Write `status.php`. `Ok(false)` when the site is not WordPress.
pub async fn write_status(
    root_dir: &str,
    system_user: &str,
    status: &SiteStatus,
) -> Result<bool, AdapterError> {
    if !is_wordpress(root_dir) {
        return Ok(false);
    }
    let dir = ensure_dir(root_dir, &module_dir_rel()).await?;
    let path = write_atomic(&dir, STATUS_FILE, &render_status(status)).await?;
    chown_to_site(system_user, &[&dir, &path]).await;
    Ok(true)
}

/// Move pre-merge top-level files into the module directory.
///
/// A legacy file with no module beside it is carried over as it is, so a
/// feature whose own writer is switched off for this site (mail with the
/// self-repair off, say) keeps working, just from its new place. When both
/// exist the module wins — the legacy copy is what an older agent left
/// behind — and the legacy copy is removed. A symlink on a legacy name is
/// removed, never read. Returns how many files were moved or removed.
pub async fn adopt_legacy(root_dir: &str, system_user: &str) -> Result<usize, AdapterError> {
    if !is_wordpress(root_dir) {
        return Ok(0);
    }
    let Ok(mu) = resolve(root_dir, mu_rel()).await else {
        return Ok(0);
    };
    let mut n = 0;
    for m in Module::ALL {
        let legacy = mu.join(m.legacy_file());
        let Ok(md) = tokio::fs::symlink_metadata(&legacy).await else {
            continue;
        };
        if md.file_type().is_file() && module_contents(root_dir, m).await.is_none() {
            let body = read_managed(root_dir, &format!("{}/{}", mu_rel(), m.legacy_file()))
                .await?
                .unwrap_or_default();
            install_module(root_dir, system_user, m, &body).await?;
        } else {
            let _ = tokio::fs::remove_file(&legacy).await;
        }
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn wp_site() -> (tempfile::TempDir, String) {
        let site = tempfile::tempdir().expect("tmp");
        let root = site.path().join("htdocs");
        std::fs::create_dir_all(root.join("wp-content")).expect("wp-content");
        let r = root.to_string_lossy().to_string();
        (site, r)
    }

    #[test]
    fn the_loader_lists_every_module_by_its_file_names() {
        let php = render_loader();
        assert!(!php.contains("{{"), "unfilled token");
        for m in Module::ALL {
            let name = m.file().trim_end_matches(".php");
            assert!(
                php.contains(&format!("'{name}' ")) && php.contains(m.legacy_file()),
                "loader does not know module {m:?}"
            );
        }
    }

    #[test]
    fn status_cannot_break_out_of_its_php_string() {
        let s = SiteStatus {
            domain: "ev'il\\.cz');system('id".into(),
            ..Default::default()
        };
        let php = render_status(&s);
        // Lex the string the way PHP does: `\` escapes the next character,
        // the first bare `'` ends it. What follows must be the call's own
        // tail — anything else is code the value smuggled in.
        let body = php.split("json_decode('").nth(1).expect("call");
        let mut chars = body.char_indices();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '\'' => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let end = end.expect("string is closed");
        assert_eq!(&body[end..], "', true);\n", "{php}");
        assert!(php.contains("if (!defined('ABSPATH')) { exit; }"));
    }

    #[tokio::test]
    async fn install_writes_module_and_loader_and_clears_the_legacy_copy() {
        let (_site, root) = wp_site();
        let mu = Path::new(&root).join("wp-content/mu-plugins");
        std::fs::create_dir_all(&mu).expect("mu");
        std::fs::write(mu.join("hyperion-mail.php"), "<?php // old").expect("legacy");

        assert!(install_module(&root, "", Module::Mail, "<?php // new")
            .await
            .expect("install"));
        assert_eq!(
            std::fs::read_to_string(module_path(&root, Module::Mail)).expect("module"),
            "<?php // new"
        );
        assert_eq!(
            std::fs::read_to_string(loader_path(&root)).expect("loader"),
            render_loader()
        );
        assert!(!mu.join("hyperion-mail.php").exists(), "legacy copy left");
        assert_eq!(
            module_state(&root, Module::Mail, "<?php // new").await,
            FileState::Current
        );
        assert_eq!(
            module_state(&root, Module::Mail, "<?php // other").await,
            FileState::Stale
        );

        remove_module(&root, Module::Mail).await;
        assert_eq!(
            module_state(&root, Module::Mail, "<?php // new").await,
            FileState::Missing
        );
    }

    #[tokio::test]
    async fn a_non_wordpress_site_is_left_alone() {
        let site = tempfile::tempdir().expect("tmp");
        let root = site.path().to_string_lossy().to_string();
        assert!(!install_module(&root, "", Module::Mail, "x")
            .await
            .expect("ok"));
        assert!(!ensure_loader(&root, "").await.expect("ok"));
        assert_eq!(
            module_state(&root, Module::Mail, "x").await,
            FileState::NotWordPress
        );
        assert!(!site.path().join("wp-content").exists());
    }

    #[tokio::test]
    async fn legacy_files_are_adopted_or_dropped() {
        let (_site, root) = wp_site();
        let mu = Path::new(&root).join("wp-content/mu-plugins");
        std::fs::create_dir_all(&mu).expect("mu");
        // Only a legacy copy: carried over unchanged.
        std::fs::write(mu.join("hyperion-regguard.php"), "<?php // guard").expect("w");
        // Both: the module wins.
        install_module(&root, "", Module::Mail, "<?php // module")
            .await
            .expect("install");
        std::fs::write(mu.join("hyperion-mail.php"), "<?php // older agent").expect("w");

        assert_eq!(adopt_legacy(&root, "").await.expect("adopt"), 2);
        assert_eq!(
            module_contents(&root, Module::RegGuard).await.as_deref(),
            Some("<?php // guard")
        );
        assert_eq!(
            module_contents(&root, Module::Mail).await.as_deref(),
            Some("<?php // module")
        );
        assert!(!mu.join("hyperion-regguard.php").exists());
        assert!(!mu.join("hyperion-mail.php").exists());
        // Nothing left to do the second time.
        assert_eq!(adopt_legacy(&root, "").await.expect("adopt"), 0);
    }

    /// Root following a tenant's link out of the site is the escape this
    /// module's path handling exists to stop — for the directory, which is
    /// refused, and for the file name, which is replaced.
    #[tokio::test]
    async fn a_symlinked_module_directory_is_refused() {
        let (_site, root) = wp_site();
        let outside = tempfile::tempdir().expect("tmp2");
        let mu = Path::new(&root).join("wp-content/mu-plugins");
        std::fs::create_dir_all(&mu).expect("mu");
        symlink(outside.path(), mu.join(MODULE_DIR)).expect("symlink");

        let err = install_module(&root, "victim", Module::Mail, "<?php // x")
            .await
            .expect_err("must refuse a symlinked module dir");
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(!outside.path().join("mail.php").exists());

        // Remove must not reach through it either.
        std::fs::write(outside.path().join("mail.php"), "keep").expect("w");
        remove_module(&root, Module::Mail).await;
        assert!(
            outside.path().join("mail.php").exists(),
            "root deleted outside the site"
        );
    }

    #[tokio::test]
    async fn links_on_our_file_names_are_replaced_not_written_through() {
        let (_site, root) = wp_site();
        let outside = tempfile::tempdir().expect("tmp2");
        let victim = outside.path().join("victim.conf");
        std::fs::write(&victim, "original").expect("victim");
        let dir = Path::new(&root)
            .join("wp-content/mu-plugins")
            .join(MODULE_DIR);
        std::fs::create_dir_all(&dir).expect("dir");
        symlink(&victim, dir.join("mail.php")).expect("symlink");
        std::fs::hard_link(&victim, dir.join(STATUS_FILE)).expect("hardlink");

        install_module(&root, "", Module::Mail, "<?php // ours")
            .await
            .expect("install");
        write_status(&root, "", &SiteStatus::default())
            .await
            .expect("status");

        assert_eq!(std::fs::read_to_string(&victim).expect("v"), "original");
        assert_eq!(
            module_contents(&root, Module::Mail).await.as_deref(),
            Some("<?php // ours")
        );
        assert!(std::fs::read_to_string(dir.join(STATUS_FILE))
            .expect("status")
            .contains("json_decode"));
    }
}
