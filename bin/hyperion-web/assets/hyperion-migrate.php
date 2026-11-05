<?php
/**
 * Plugin Name: Hyperion Migration
 * Description: Moves this WordPress site to a Hyperion panel. Generate a code in Hyperion (Import → WordPress plugin) and paste it under Tools → Hyperion Migration.
 * Version: 1.0.0
 * Requires at least: 4.7
 * Requires PHP: 5.6
 * Author: Hyperion
 * License: MIT
 *
 * The source of a migration is a host we know nothing about, so this assumes the
 * least it can: no shell, a short execution limit, little memory, little spare
 * disk. The work runs in slices, one per AJAX request from the admin's browser
 * tab, and every slice is sent to Hyperion straight away, so nothing the size of
 * the site is ever stored here. State lives in a small work directory, which is
 * what makes a closed tab or a killed request resumable.
 *
 * Kept to PHP 5.6 syntax on purpose: sites being moved off old hosting are exactly
 * the ones still running old PHP.
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Hyperion_Migrate
{
    const OPTION = 'hyperion_migrate_run';
    const NONCE = 'hyperion_migrate';
    const CODE_PREFIX = 'HYP1.';
    const DUMP_END = '-- hyperion-migrate: dump complete';
    const MAX_WARNINGS = 40;
    const MIN_RAW = 262144;
    const MAX_RAW = 8388608;

    public static function boot()
    {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        foreach (array('check', 'start', 'step', 'cancel') as $action) {
            add_action('wp_ajax_hyperion_migrate_' . $action, array(__CLASS__, 'ajax_' . $action));
        }
        register_deactivation_hook(__FILE__, array(__CLASS__, 'discard_run'));
    }

    public static function menu()
    {
        add_management_page('Hyperion Migration', 'Hyperion Migration', 'manage_options', 'hyperion-migrate', array(__CLASS__, 'page'));
    }

    /** The export reads the whole database, so on a network only a super admin may run it. */
    private static function allowed()
    {
        return is_multisite() ? is_super_admin() : current_user_can('manage_options');
    }

    private static function insecure_allowed()
    {
        return defined('HYPERION_MIGRATE_ALLOW_INSECURE') && HYPERION_MIGRATE_ALLOW_INSECURE;
    }

    // ---- AJAX ---------------------------------------------------------------

    private static function ajax_guard()
    {
        if (!self::allowed() || !check_ajax_referer(self::NONCE, 'nonce', false)) {
            self::reply(array('fatal' => 'Your WordPress session has expired. Reload this page and log in again; the transfer will continue.'), 403);
        }
        // Another plugin's stray output must not corrupt the JSON reply.
        @ini_set('display_errors', '0');
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
    }

    private static function reply($data, $code = 200)
    {
        $data['nonce'] = wp_create_nonce(self::NONCE);
        wp_send_json($data, $code);
    }

    /** Decode a pasted code. Returns array(url, token), or a string saying what is wrong. */
    private static function parse_code($code)
    {
        $code = preg_replace('/\s+/', '', (string) $code);
        if (strpos($code, self::CODE_PREFIX) !== 0) {
            return 'That is not a Hyperion code. It starts with ' . self::CODE_PREFIX;
        }
        $raw = base64_decode(strtr(substr($code, strlen(self::CODE_PREFIX)), '-_', '+/'), true);
        $data = $raw === false ? null : json_decode($raw, true);
        if (!is_array($data) || empty($data['u']) || empty($data['t'])) {
            return 'That code is incomplete. Copy it again from Hyperion.';
        }
        $url = untrailingslashit((string) $data['u']);
        $token = (string) $data['t'];
        if (!preg_match('/^[A-Za-z0-9]{16,128}$/', $token) || !preg_match('#^https?://[A-Za-z0-9.\-:\[\]]+$#', $url)) {
            return 'That code is damaged. Copy it again from Hyperion.';
        }
        // The token and then the site's database and wp-config go to this address.
        if (strpos($url, 'https://') !== 0 && !self::insecure_allowed()) {
            return 'This panel is not on HTTPS, and sending a site\'s database over plain HTTP would expose it. Put the panel on HTTPS and generate a new code.';
        }
        return array($url, $token);
    }

    public static function ajax_check()
    {
        self::ajax_guard();
        $parsed = self::parse_code(isset($_POST['code']) ? wp_unslash($_POST['code']) : '');
        if (is_string($parsed)) {
            self::reply(array('fatal' => $parsed));
        }
        list($url, $token) = $parsed;
        $r = self::panel_request($url, $token, 'GET', '/import/upload/status');
        if ($r['net'] !== '') {
            self::reply(array('fatal' => 'This server cannot reach ' . $url . ': ' . $r['net']));
        }
        $f = self::kv($r['body']);
        if ($r['code'] !== 200 || !isset($f['state']) || $f['state'] === 'cancelled') {
            self::reply(array('fatal' => 'Hyperion does not accept this code. It has expired or was cancelled, so generate a new one.'));
        }
        self::reply(array('panel' => (string) wp_parse_url($url, PHP_URL_HOST), 'site' => (string) get_option('home')));
    }

    public static function ajax_start()
    {
        self::ajax_guard();
        $parsed = self::parse_code(isset($_POST['code']) ? wp_unslash($_POST['code']) : '');
        if (is_string($parsed)) {
            self::reply(array('fatal' => $parsed));
        }
        self::discard_run();
        $dir = self::make_work_dir();
        if ($dir === '') {
            self::reply(array('fatal' => 'Could not create a small work folder in wp-content/uploads or the system temp folder. Make one of them writable and try again.'));
        }
        // Not autoloaded: holds a credential, and has no business in every request.
        add_option(self::OPTION, array('dir' => $dir, 'url' => $parsed[0], 'token' => $parsed[1]), '', 'no');
        self::save_state($dir, self::initial_state());
        self::reply(self::progress(self::load_state($dir)));
    }

    public static function ajax_cancel()
    {
        self::ajax_guard();
        self::discard_run();
        self::reply(array('cancelled' => true));
    }

    public static function ajax_step()
    {
        self::ajax_guard();
        $run = get_option(self::OPTION);
        if (!is_array($run) || empty($run['dir'])) {
            self::reply(array('idle' => true));
        }
        $dir = $run['dir'];
        if (!empty($run['finished'])) {
            self::reply(array('phase' => 'done', 'percent' => 100, 'job_url' => $run['job_url'], 'warnings' => $run['warnings']));
        }
        // A retry can arrive while the request it gave up on is still running, and
        // two of those appending to one stream would corrupt it.
        $lock = @fopen($dir . '/lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            self::reply(array('busy' => true));
        }
        ignore_user_abort(true);
        @set_time_limit(180);
        if (function_exists('wp_raise_memory_limit')) {
            wp_raise_memory_limit('admin');
        }
        $state = self::load_state($dir);
        if (!is_array($state)) {
            self::discard_run();
            self::reply(array('fatal' => 'The transfer\'s work folder is gone. Generate a new code in Hyperion and start again.'));
        }
        if (!empty($_POST['shrink'])) {
            $state['budget'] = max(2, (int) ($state['budget'] / 2));
            $state['raw'] = max(self::MIN_RAW, (int) ($state['raw'] / 2));
        }
        $worker = new self($run, $state);
        $reply = $worker->advance();
        flock($lock, LOCK_UN);
        fclose($lock);
        self::reply($reply);
    }

    // ---- run state ----------------------------------------------------------

    private static function make_work_dir()
    {
        $name = 'hyperion-migrate-' . wp_generate_password(32, false, false);
        $uploads = wp_upload_dir(null, false);
        $parents = array();
        if (empty($uploads['error']) && !empty($uploads['basedir'])) {
            $parents[] = $uploads['basedir'];
        }
        $parents[] = untrailingslashit(get_temp_dir());
        foreach ($parents as $parent) {
            $dir = $parent . '/' . $name;
            if (wp_mkdir_p($dir) && is_writable($dir)) {
                // nginx ignores .htaccess. The unguessable name is the real protection.
                @file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
                @file_put_contents($dir . '/index.html', '');
                return $dir;
            }
        }
        return '';
    }

    public static function discard_run()
    {
        $run = get_option(self::OPTION);
        if (is_array($run) && !empty($run['dir'])) {
            self::remove_dir($run['dir']);
        }
        delete_option(self::OPTION);
    }

    private static function remove_dir($dir)
    {
        // Only ever a directory this plugin named.
        if (strpos(basename($dir), 'hyperion-migrate-') !== 0 || !is_dir($dir)) {
            return;
        }
        foreach ((array) @scandir($dir) as $f) {
            if ($f !== '.' && $f !== '..') {
                @unlink($dir . '/' . $f);
            }
        }
        @rmdir($dir);
    }

    private static function initial_state()
    {
        $max = (int) ini_get('max_execution_time');
        $budget = $max > 0 ? max(2, min(10, (int) ($max / 3))) : 10;
        return array(
            'phase' => 'scan',
            'run' => wp_generate_password(32, false, false),
            'budget' => $budget,
            'raw' => 1048576,
            'warnings' => array(),
            'stack' => array(''),
            'visited' => array(),
            'config_done' => false,
            'scan_files' => 0,
            'scan_bytes' => 0,
            'pending' => null,
            'sent' => array('db' => 0, 'files' => 0),
            'db' => null,
            'list_pos' => 0,
            'cur' => null,
            'members' => 0,
            'read_bytes' => 0,
            'dump_bytes' => 0,
        );
    }

    private static function load_state($dir)
    {
        $raw = @file_get_contents($dir . '/state.json');
        return $raw === false ? null : json_decode($raw, true);
    }

    private static function save_state($dir, $state)
    {
        // Rename so a request killed mid-write cannot leave half a state behind.
        $tmp = $dir . '/state.tmp';
        if (@file_put_contents($tmp, wp_json_encode($state)) === false || !@rename($tmp, $dir . '/state.json')) {
            return false;
        }
        return true;
    }

    private static function progress($state)
    {
        $total = max(1, $state['scan_bytes'] + (is_array($state['db']) ? $state['db']['estimate'] : 0));
        $done = $state['read_bytes'] + $state['dump_bytes'];
        $labels = array(
            'scan' => 'Listing the site\'s files',
            'begin' => 'Contacting Hyperion',
            'db' => 'Sending the database',
            'files' => 'Sending the files',
            'commit' => 'Handing over to Hyperion',
        );
        $percent = $state['phase'] === 'scan' ? 1 : (int) min(99, 2 + 97 * $done / $total);
        return array(
            'phase' => $state['phase'],
            'label' => isset($labels[$state['phase']]) ? $labels[$state['phase']] : '',
            'percent' => $percent,
            'done_bytes' => $done,
            'total_bytes' => $total,
        );
    }

    // ---- one slice ----------------------------------------------------------

    private $run;
    private $state;
    private $dir;
    private $deadline;
    private $root;

    private function __construct($run, $state)
    {
        $this->run = $run;
        $this->state = $state;
        $this->dir = $run['dir'];
        $this->deadline = microtime(true) + $state['budget'];
        $this->root = self::site_root();
    }

    private static function site_root()
    {
        if (!function_exists('get_home_path')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $root = trailingslashit(get_home_path());
        // get_home_path() infers this from the request's script path. Trust it only
        // if it really is ABSPATH or a parent of it.
        if (!is_dir($root) || strpos(ABSPATH, $root) !== 0) {
            $root = ABSPATH;
        }
        return $root;
    }

    private function warn($message)
    {
        if (count($this->state['warnings']) < self::MAX_WARNINGS) {
            $this->state['warnings'][] = $message;
        }
    }

    private function time_left()
    {
        return microtime(true) < $this->deadline;
    }

    /** Run one slice and say how it went. */
    private function advance()
    {
        $started = microtime(true);
        $phase = $this->state['phase'];
        if ($this->state['pending'] !== null) {
            $outcome = $this->send_pending();
        } elseif ($phase === 'scan') {
            $outcome = $this->step_scan();
        } elseif ($phase === 'begin') {
            $outcome = $this->step_begin();
        } elseif ($phase === 'db') {
            $outcome = $this->step_db();
        } elseif ($phase === 'files') {
            $outcome = $this->step_files();
        } else {
            $outcome = $this->step_commit();
        }
        if ($outcome === null && $this->state['pending'] !== null) {
            $outcome = $this->send_pending();
        }
        // Size the next slice by how this one went, so a slow host is not walked
        // into its execution limit and a fast one is not held back.
        $took = microtime(true) - $started;
        if ($took > $this->state['budget'] * 2) {
            $this->state['raw'] = max(self::MIN_RAW, (int) ($this->state['raw'] / 2));
        } elseif ($took < $this->state['budget'] / 2) {
            $this->state['raw'] = min(self::MAX_RAW, $this->state['raw'] * 2);
        }

        // Before any save: a finished run has no work folder left to save into.
        if (is_array($outcome) && isset($outcome['finished'])) {
            return $outcome;
        }
        if (is_array($outcome) && isset($outcome['fatal'])) {
            $outcome['warnings'] = $this->state['warnings'];
            self::save_state($this->dir, $this->state);
            return $outcome;
        }
        if (!self::save_state($this->dir, $this->state)) {
            return array('fatal' => 'Could not write to the work folder. Is the disk full?');
        }
        if (is_array($outcome) && isset($outcome['retry'])) {
            return $outcome + self::progress($this->state);
        }
        return self::progress($this->state);
    }

    // ---- scan ---------------------------------------------------------------

    /** Paths left out, relative to the site root, with why. Prefix match on whole segments. */
    private function excluded_dirs()
    {
        $content = $this->content_rel();
        if ($content === null) {
            return array();
        }
        $dirs = array(
            'cache' => 'page cache',
            'ai1wm-backups' => 'old backups',
            'updraft' => 'old backups',
            'backups-dup-lite' => 'old backups',
            'backups-dup-pro' => 'old backups',
            'backup-db' => 'old backups',
            'backupwordpress' => 'old backups',
            'backups' => 'old backups',
            'wflogs' => 'Wordfence logs',
            'upgrade' => 'WordPress temp files',
            'upgrade-temp-backup' => 'WordPress temp files',
        );
        $out = array();
        foreach ($dirs as $d => $why) {
            $out[($content === '' ? '' : $content . '/') . $d] = $why;
        }
        return $out;
    }

    /** wp-content's path under the root, or null if it lives outside the root. */
    private function content_rel()
    {
        $content = trailingslashit(wp_normalize_path(WP_CONTENT_DIR));
        $root = wp_normalize_path($this->root);
        if (strpos($content, $root) !== 0) {
            return null;
        }
        return untrailingslashit(substr($content, strlen($root)));
    }

    /**
     * Files that would break the site on the new server.
     *   object-cache.php, advanced-cache.php, db.php: drop-ins that outlive their
     *     plugin and carry the old server's paths and cache sockets.
     *   .user.ini, php.ini: usually an auto_prepend_file with an absolute path
     *     (Wordfence), which is a fatal error on every request once that path is gone.
     */
    private function excluded_file($rel)
    {
        $content = $this->content_rel();
        if ($content !== null) {
            $prefix = $content === '' ? '' : $content . '/';
            if (in_array($rel, array($prefix . 'object-cache.php', $prefix . 'advanced-cache.php', $prefix . 'db.php', $prefix . 'debug.log'), true)) {
                return true;
            }
        }
        if ($rel === '.user.ini' || $rel === 'php.ini') {
            return true;
        }
        return basename($rel) === 'error_log';
    }

    private function step_scan()
    {
        $list = @fopen($this->dir . '/list.txt', 'a');
        if (!$list) {
            return array('fatal' => 'Could not write to the work folder. Is the disk full?');
        }
        if (empty($this->state['config_done'])) {
            $this->state['config_done'] = true;
            if ($this->config_path() !== '') {
                fwrite($list, 'c' . base64_encode('wp-config.php') . "\n");
                $this->state['scan_files']++;
            } else {
                $this->warn('wp-config.php was not found, so the imported site will need one written by hand.');
            }
            if ($this->content_rel() === null) {
                $this->warn('wp-content is outside the site\'s folder (' . WP_CONTENT_DIR . ') and was not transferred. Copy it by hand.');
            }
            if (is_multisite()) {
                $this->warn('This is a multisite network. Its database and files were transferred, but its extra domains and nginx rules need setting up by hand.');
            }
        }
        $excluded = $this->excluded_dirs();
        $own = wp_normalize_path(dirname(__FILE__));
        $work = wp_normalize_path($this->dir);
        $config_real = $this->config_path() === '' ? '' : realpath($this->config_path());

        while (!empty($this->state['stack']) && $this->time_left()) {
            $rel_dir = array_pop($this->state['stack']);
            $abs_dir = $this->root . $rel_dir;
            $handle = @opendir($abs_dir);
            if (!$handle) {
                $this->warn('Could not read the folder ' . ($rel_dir === '' ? '/' : $rel_dir) . ', so it was not transferred.');
                continue;
            }
            while (($name = readdir($handle)) !== false) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $rel = $rel_dir === '' ? $name : $rel_dir . '/' . $name;
                $abs = $this->root . $rel;
                $norm = wp_normalize_path($abs);
                if ($norm === $own || $norm === $work || $name === '.git' || $name === '.svn') {
                    continue;
                }
                if (isset($excluded[$rel])) {
                    $this->warn('Left out ' . $rel . ' (' . $excluded[$rel] . ').');
                    continue;
                }
                if (is_link($abs)) {
                    $this->scan_link($list, $rel, $abs);
                } elseif (is_dir($abs)) {
                    fwrite($list, 'd' . base64_encode($rel) . "\n");
                    $this->state['scan_files']++;
                    $this->state['stack'][] = $rel;
                } elseif (is_file($abs)) {
                    if ($this->excluded_file($rel) || ($config_real !== '' && realpath($abs) === $config_real)) {
                        continue;
                    }
                    $this->add_file($list, $rel, $abs);
                }
            }
            closedir($handle);
        }
        fclose($list);
        if (empty($this->state['stack'])) {
            $this->state['phase'] = 'begin';
        }
        return null;
    }

    private function add_file($list, $rel, $abs)
    {
        if (!is_readable($abs)) {
            $this->warn('Could not read ' . $rel . ', so it was not transferred.');
            return;
        }
        fwrite($list, 'f' . base64_encode($rel) . "\n");
        $this->state['scan_files']++;
        $this->state['scan_bytes'] += (int) @filesize($abs);
    }

    /**
     * A symlink survives only if it stays inside the site by a plain relative path;
     * the importer refuses anything else, and would be right to. One that leads out
     * of the site (shared uploads on a deploy layout, say) is copied as real files,
     * since dropping it would silently lose the content.
     */
    private function scan_link($list, $rel, $abs)
    {
        $target = @readlink($abs);
        $real = realpath($abs);
        if ($target === false || $real === false) {
            $this->warn('Left out the broken link ' . $rel . '.');
            return;
        }
        if ($target[0] !== '/' && !preg_match('#(^|/)\.\.(/|$)#', $target)) {
            fwrite($list, 'l' . base64_encode($rel) . "\n");
            $this->state['scan_files']++;
            return;
        }
        if (is_file($real)) {
            $this->add_file($list, $rel, $abs);
            return;
        }
        if (!is_dir($real)) {
            return;
        }
        // A link can point back up its own tree. Follow each real folder once.
        if (isset($this->state['visited'][$real]) || strpos(trailingslashit($abs), trailingslashit($real)) === 0) {
            $this->warn('Left out the link ' . $rel . ', which points back into a folder already being copied.');
            return;
        }
        $this->state['visited'][$real] = 1;
        fwrite($list, 'd' . base64_encode($rel) . "\n");
        $this->state['scan_files']++;
        $this->state['stack'][] = $rel;
    }

    private function config_path()
    {
        foreach (array(ABSPATH . 'wp-config.php', dirname(ABSPATH) . '/wp-config.php') as $p) {
            if (@is_file($p)) {
                return $p;
            }
        }
        return '';
    }

    /**
     * wp-config.php as it should land. Always at the top of the site, where the
     * importer looks and WordPress finds it even when core is in a subfolder.
     * Hyperion rewrites its DB_* lines. Lines naming this server's paths are
     * disabled here, because only this side knows what those paths are.
     */
    private function config_for_transfer()
    {
        $raw = @file_get_contents($this->config_path());
        if ($raw === false) {
            return null;
        }
        $roots = array_unique(array(untrailingslashit($this->root), untrailingslashit(ABSPATH), dirname(ABSPATH)));
        $out = array();
        foreach (explode("\n", $raw) as $line) {
            $is_define = preg_match('/^\s*define\s*\(\s*[\'"]([A-Z0-9_]+)[\'"]/i', $line, $m);
            $names_path = false;
            foreach ($roots as $r) {
                if ($r !== '' && strpos($line, $r) !== false) {
                    $names_path = true;
                }
            }
            if ($is_define && $names_path) {
                $this->warn('wp-config.php: disabled ' . $m[1] . ', which named a path on the old server.');
                $line = '// Disabled by the Hyperion migration (a path on the old server): ' . $line;
            } elseif (preg_match('/^\s*(require|include)(_once)?[\s(]*[\'"]\//', $line)) {
                $this->warn('wp-config.php loads a file by absolute path. It will not exist on the new server: ' . trim(substr($line, 0, 120)));
            }
            $out[] = $line;
        }
        return implode("\n", $out);
    }

    // ---- begin --------------------------------------------------------------

    private function step_begin()
    {
        if (!is_array($this->state['db'])) {
            $this->state['db'] = $this->plan_db();
        }
        $body = wp_json_encode(array(
            'run' => $this->state['run'],
            'home_url' => (string) get_option('home'),
            'wp_version' => (string) get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'files_bytes' => $this->state['scan_bytes'],
            'db_estimate' => $this->state['db']['estimate'],
            'warnings' => $this->state['warnings'],
        ));
        $r = $this->panel('POST', '/import/upload/wp/begin', $body, array('Content-Type' => 'application/json'));
        if ($r['net'] !== '' || $r['code'] >= 500 && $r['code'] !== 507) {
            return array('retry' => 'Waiting for Hyperion: ' . ($r['net'] !== '' ? $r['net'] : 'HTTP ' . $r['code']));
        }
        if ($r['code'] !== 200) {
            return array('fatal' => trim($r['body']));
        }
        $f = self::kv($r['body']);
        if (isset($f['state']) && $f['state'] === 'importing') {
            return $this->finish(isset($f['job']) ? $f['job'] : '-');
        }
        // A fresh run on an empty server. Anything else would mean a stream that
        // belongs to another run, and those must not be spliced together.
        if (!empty($f['offset_db']) || !empty($f['offset_files'])) {
            return array('fatal' => 'Hyperion already holds part of this transfer from an earlier attempt that this site no longer remembers. Generate a new code and start again.');
        }
        $this->state['phase'] = 'db';
        return null;
    }

    // ---- database -----------------------------------------------------------

    /** Which tables to send. Only this site's: a shared database can hold other sites. */
    private function plan_db()
    {
        global $wpdb;
        $wpdb->suppress_errors(true);
        $prefix = $wpdb->base_prefix;
        $tables = array();
        $views = array();
        $others = array();
        foreach ((array) $wpdb->get_results('SHOW FULL TABLES', ARRAY_N) as $row) {
            if ($prefix !== '' && strpos($row[0], $prefix) !== 0) {
                $others[] = $row[0];
            } elseif (strtoupper($row[1]) === 'VIEW') {
                $views[] = $row[0];
            } else {
                $tables[] = $row[0];
            }
        }
        if ($others) {
            $this->warn(count($others) . ' table(s) in this database do not start with "' . $prefix . '" and were left out as not belonging to this site: ' . implode(', ', array_slice($others, 0, 8)) . (count($others) > 8 ? ', …' : '') . '.');
        }
        $estimate = 0;
        foreach ((array) $wpdb->get_results('SHOW TABLE STATUS', ARRAY_A) as $row) {
            if (in_array($row['Name'], $tables, true)) {
                $estimate += (int) $row['Data_length'];
            }
        }
        $charset = $wpdb->query('SET NAMES utf8mb4') === false ? 'utf8' : 'utf8mb4';
        return array(
            'tables' => $tables,
            'views' => $views,
            'charset' => $charset,
            'estimate' => $estimate,
            'index' => 0,
            'table_started' => false,
            'last_key' => null,
            'offset' => 0,
            'header_done' => false,
            'views_done' => false,
        );
    }

    private function step_db()
    {
        global $wpdb;
        $wpdb->suppress_errors(true);
        $db = &$this->state['db'];
        // Read in one known state on every request. UTC, so a TIMESTAMP means the
        // same instant on the far side whatever this server's timezone is. No
        // sql_mode, so NO_BACKSLASH_ESCAPES cannot change what escaping produces.
        $wpdb->query('SET NAMES ' . $db['charset']);
        $wpdb->query("SET SESSION time_zone = '+00:00'");
        $wpdb->query("SET SESSION sql_mode = ''");

        $buf = '';
        if (!$db['header_done']) {
            $db['header_done'] = true;
            $buf .= "-- Hyperion migration dump\nSET NAMES {$db['charset']};\nSET time_zone = '+00:00';\n"
                . "SET FOREIGN_KEY_CHECKS = 0;\nSET UNIQUE_CHECKS = 0;\nSET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';\n";
        }
        $limit = $this->state['raw'];
        while (strlen($buf) < $limit && $this->time_left() && $db['index'] < count($db['tables'])) {
            $table = $db['tables'][$db['index']];
            if (!$db['table_started']) {
                $create = $this->create_table_sql($table);
                if ($create === null) {
                    return array('fatal' => 'Could not read the structure of table ' . $table . ': ' . $wpdb->last_error);
                }
                $buf .= "\nDROP TABLE IF EXISTS `" . self::ident($table) . "`;\n" . $create . ";\n";
                $db['table_started'] = true;
                $db['last_key'] = null;
                $db['offset'] = 0;
            }
            $batch = $this->dump_rows($table, $limit - strlen($buf));
            if (is_array($batch)) {
                return $batch;
            }
            $buf .= $batch;
            if (!$db['table_started']) {
                $db['index']++;
            }
        }
        if ($db['index'] >= count($db['tables']) && strlen($buf) < $limit && $this->time_left()) {
            if (!$db['views_done']) {
                $db['views_done'] = true;
                $buf .= $this->views_sql();
            }
            $buf .= "\nSET FOREIGN_KEY_CHECKS = 1;\nSET UNIQUE_CHECKS = 1;\n" . self::DUMP_END . ' tables=' . count($db['tables']) . "\n";
            $this->state['phase'] = 'files';
        }
        $this->state['dump_bytes'] += strlen($buf);
        unset($db);
        return $this->queue($buf, 'db');
    }

    private static function ident($name)
    {
        return str_replace('`', '``', $name);
    }

    private function create_table_sql($table)
    {
        global $wpdb;
        $row = $wpdb->get_row('SHOW CREATE TABLE `' . self::ident($table) . '`', ARRAY_N);
        if (empty($row[1])) {
            return null;
        }
        return self::portable_sql($row[1]);
    }

    /** MySQL 8 syntax a MariaDB target refuses. */
    private static function portable_sql($sql)
    {
        $sql = preg_replace('/utf8mb4_0900_[a-z_]+/', 'utf8mb4_unicode_520_ci', $sql);
        return preg_replace("/\s*\/\*!80016 DEFAULT ENCRYPTION='[NY]' \*\/|\s*DEFAULT ENCRYPTION='[NY]'/", '', $sql);
    }

    /** Views go in without their DEFINER, an account that does not exist on the target. */
    private function views_sql()
    {
        global $wpdb;
        $out = '';
        foreach ($this->state['db']['views'] as $view) {
            $row = $wpdb->get_row('SHOW CREATE VIEW `' . self::ident($view) . '`', ARRAY_N);
            if (empty($row[1])) {
                $this->warn('Could not read view ' . $view . ', so it was not transferred.');
                continue;
            }
            $create = preg_replace('/\sDEFINER=\S+/', '', $row[1]);
            $out .= "\nDROP VIEW IF EXISTS `" . self::ident($view) . "`;\n" . self::portable_sql($create) . ";\n";
        }
        return $out;
    }

    /**
     * One batch of INSERTs from the current table, or array('fatal' => …). Clears
     * table_started when the table is finished. Pages by primary key, because
     * OFFSET re-reads every earlier row and crawls on a large table.
     */
    private function dump_rows($table, $room)
    {
        global $wpdb;
        $db = &$this->state['db'];
        $quoted = '`' . self::ident($table) . '`';
        $columns = $wpdb->get_results('SHOW FULL COLUMNS FROM ' . $quoted, ARRAY_A);
        if (empty($columns)) {
            return array('fatal' => 'Could not read the columns of table ' . $table . ': ' . $wpdb->last_error);
        }
        $names = array();
        $binary = array();
        $positions = array();
        foreach ($columns as $c) {
            // A generated column refuses an explicit value on INSERT.
            if (preg_match('/GENERATED|VIRTUAL|STORED/i', (string) $c['Extra'])) {
                continue;
            }
            $positions[$c['Field']] = count($names);
            $binary[] = (bool) preg_match('/blob|binary|bit\(|geometry|point|linestring|polygon/i', (string) $c['Type']);
            $names[] = '`' . self::ident($c['Field']) . '`';
        }
        if (!$names) {
            $db['table_started'] = false;
            return '';
        }
        $key_columns = array();
        foreach ((array) $wpdb->get_results('SHOW KEYS FROM ' . $quoted . " WHERE Key_name = 'PRIMARY'", ARRAY_A) as $k) {
            $key_columns[(int) $k['Seq_in_index']] = $k['Column_name'];
        }
        ksort($key_columns);
        foreach ($key_columns as $k) {
            if (!isset($positions[$k])) {
                $key_columns = array();
                break;
            }
        }

        $sql = 'SELECT ' . implode(', ', $names) . ' FROM ' . $quoted;
        if ($key_columns) {
            $key_sql = array();
            foreach ($key_columns as $k) {
                $key_sql[] = '`' . self::ident($k) . '`';
            }
            if ($db['last_key'] !== null) {
                $sql .= ' WHERE (' . implode(', ', $key_sql) . ') > (' . implode(', ', $db['last_key']) . ')';
            }
            $sql .= ' ORDER BY ' . implode(', ', $key_sql);
        }
        $rows_wanted = $this->batch_rows($table, $room);
        $sql .= ' LIMIT ' . ($key_columns ? '' : (int) $db['offset'] . ', ') . $rows_wanted;
        $rows = $wpdb->get_results($sql, ARRAY_N);
        if ($rows === null || $wpdb->last_error !== '') {
            return array('fatal' => 'Could not read table ' . $table . ': ' . $wpdb->last_error);
        }

        $out = '';
        $statement = '';
        $insert = 'INSERT INTO ' . $quoted . ' (' . implode(', ', $names) . ") VALUES\n";
        // This plugin's own row holds the code, and that credential must not be
        // copied into the new site's database.
        $is_options = $table === $wpdb->options || $table === $wpdb->base_prefix . 'options';
        $name_at = $is_options && isset($positions['option_name']) ? $positions['option_name'] : null;
        foreach ($rows as $row) {
            if ($name_at !== null && $row[$name_at] === self::OPTION) {
                continue;
            }
            $values = array();
            foreach ($row as $i => $v) {
                $values[] = self::literal($v, $binary[$i]);
            }
            $tuple = '(' . implode(',', $values) . ')';
            // One statement stays under what a stock max_allowed_packet accepts.
            if ($statement !== '' && strlen($statement) + strlen($tuple) > 1048576) {
                $out .= $insert . $statement . ";\n";
                $statement = '';
            }
            $statement .= ($statement === '' ? '' : ",\n") . $tuple;
        }
        if ($statement !== '') {
            $out .= $insert . $statement . ";\n";
        }
        if (count($rows) < $rows_wanted) {
            $db['table_started'] = false;
        } elseif ($key_columns) {
            $last = end($rows);
            $key = array();
            foreach ($key_columns as $k) {
                $p = $positions[$k];
                $key[] = self::literal($last[$p], $binary[$p]);
            }
            $db['last_key'] = $key;
        } else {
            $db['offset'] += count($rows);
        }
        $wpdb->flush();
        return $out;
    }

    /** How many rows should fit in the room left, going by the table's average row. */
    private function batch_rows($table, $room)
    {
        global $wpdb;
        $status = $wpdb->get_row($wpdb->prepare('SHOW TABLE STATUS WHERE Name = %s', $table), ARRAY_A);
        $average = !empty($status['Avg_row_length']) ? (int) $status['Avg_row_length'] : 1024;
        return max(1, min(2000, (int) (max($room, 65536) / max($average, 64))));
    }

    private static function literal($v, $binary)
    {
        if ($v === null) {
            return 'NULL';
        }
        if ($binary) {
            return $v === '' ? "''" : '0x' . bin2hex($v);
        }
        global $wpdb;
        // Directly, not through $wpdb->prepare or _real_escape: those plant a
        // placeholder for every % and rely on being undone before the query runs.
        if ($wpdb->dbh instanceof mysqli) {
            return "'" . mysqli_real_escape_string($wpdb->dbh, $v) . "'";
        }
        return "'" . str_replace(array('\\', "'", "\0", "\n", "\r", "\x1a"), array('\\\\', "\\'", '\\0', '\\n', '\\r', '\\Z'), $v) . "'";
    }

    // ---- files --------------------------------------------------------------

    private function step_files()
    {
        $buf = '';
        $limit = $this->state['raw'];
        $list = @fopen($this->dir . '/list.txt', 'r');
        if (!$list) {
            return array('fatal' => 'The transfer\'s file list is gone. Generate a new code and start again.');
        }
        fseek($list, $this->state['list_pos']);
        while (strlen($buf) < $limit && $this->time_left()) {
            if ($this->state['cur'] !== null) {
                $buf .= $this->continue_file($limit - strlen($buf));
                continue;
            }
            $line = fgets($list);
            if ($line === false) {
                // The two empty blocks that end a tar archive.
                $buf .= str_repeat("\0", 1024);
                $this->state['phase'] = 'commit';
                break;
            }
            $this->state['list_pos'] = ftell($list);
            $buf .= $this->start_member($line[0], (string) base64_decode(trim(substr($line, 1))));
        }
        fclose($list);
        return $this->queue($buf, 'files');
    }

    private function start_member($type, $rel)
    {
        $abs = $this->root . $rel;
        if ($type === 'c') {
            $content = $this->config_for_transfer();
            if ($content === null) {
                $this->warn('Could not read wp-config.php, so it was not transferred.');
                return '';
            }
            $this->state['members']++;
            return self::tar_header('wp-config.php', strlen($content), 0644, time(), '0')
                . $content . self::tar_padding(strlen($content));
        }
        if ($type === 'd') {
            $this->state['members']++;
            return self::tar_header($rel . '/', 0, 0755, (int) @filemtime($abs), '5');
        }
        if ($type === 'l') {
            $target = @readlink($abs);
            if ($target === false) {
                return '';
            }
            $this->state['members']++;
            return self::tar_header($rel, 0, 0777, time(), '2', $target);
        }
        // Tested now, not at scan time: a live site deletes files in between.
        $size = @filesize($abs);
        if ($size === false || !is_readable($abs)) {
            return '';
        }
        $this->state['members']++;
        $this->state['cur'] = array('rel' => $rel, 'size' => $size, 'off' => 0);
        return self::tar_header($rel, $size, 0644, (int) @filemtime($abs), '0');
    }

    /** More of the file in progress. The header promised its size, so that many bytes follow. */
    private function continue_file($room)
    {
        $cur = &$this->state['cur'];
        $left = $cur['size'] - $cur['off'];
        $want = (int) min($left, max($room, 4096));
        $data = '';
        if ($want > 0) {
            $h = @fopen($this->root . $cur['rel'], 'rb');
            if ($h) {
                if (fseek($h, $cur['off']) === 0) {
                    $data = (string) fread($h, $want);
                }
                fclose($h);
            }
            if ($data === '') {
                // It shrank or vanished mid-copy. The rest of the member still has
                // to be there or every member after it is misread.
                $this->warn($cur['rel'] . ' changed while being copied. Check it on the new server.');
                $data = str_repeat("\0", $want);
            }
        }
        $cur['off'] += strlen($data);
        $this->state['read_bytes'] += strlen($data);
        if ($cur['off'] >= $cur['size']) {
            $data .= self::tar_padding($cur['size']);
            $this->state['cur'] = null;
        }
        unset($cur);
        return $data;
    }

    private static function tar_padding($size)
    {
        $over = $size % 512;
        return $over === 0 ? '' : str_repeat("\0", 512 - $over);
    }

    /** A GNU tar header, preceded by a long-name record when the path needs one. */
    private static function tar_header($name, $size, $mode, $mtime, $type, $link = '')
    {
        $prefix = '';
        if (strlen($name) > 100) {
            $prefix .= self::tar_block('././@LongLink', strlen($name) + 1, 0, 0, 'L', '')
                . $name . "\0" . self::tar_padding(strlen($name) + 1);
            $name = substr($name, 0, 100);
        }
        if (strlen($link) > 100) {
            $prefix .= self::tar_block('././@LongLink', strlen($link) + 1, 0, 0, 'K', '')
                . $link . "\0" . self::tar_padding(strlen($link) + 1);
            $link = substr($link, 0, 100);
        }
        return $prefix . self::tar_block($name, $size, $mode, $mtime, $type, $link);
    }

    private static function tar_block($name, $size, $mode, $mtime, $type, $link)
    {
        if ($size < 8589934592) {
            $size_field = sprintf('%011o', $size) . "\0";
        } else {
            // Octal runs out at 8 GiB. GNU's base-256 form has no such limit.
            $size_field = "\x80" . str_repeat("\0", 3) . pack('N', ($size >> 32) & 0xFFFFFFFF) . pack('N', $size & 0xFFFFFFFF);
        }
        $head = str_pad($name, 100, "\0")
            . sprintf('%07o', $mode) . "\0"
            . "0000000\0"
            . "0000000\0"
            . $size_field
            . sprintf('%011o', max(0, $mtime)) . "\0";
        $tail = $type . str_pad($link, 100, "\0") . "ustar  \0" . str_repeat("\0", 235);
        $sum = 8 * 32;
        foreach (array($head, $tail) as $part) {
            $n = strlen($part);
            for ($i = 0; $i < $n; $i++) {
                $sum += ord($part[$i]);
            }
        }
        return $head . sprintf('%06o', $sum) . "\0 " . $tail . str_repeat("\0", 12);
    }

    // ---- sending ------------------------------------------------------------

    /** Compress a slice and store it, so it survives until Hyperion has confirmed it. */
    private function queue($buf, $stream)
    {
        if ($buf === '') {
            return null;
        }
        $member = self::gzip_member($buf);
        if (@file_put_contents($this->dir . '/pending.bin', $member) === false) {
            return array('fatal' => 'Could not write to the work folder. Is the disk full?');
        }
        $this->state['pending'] = array('stream' => $stream, 'len' => strlen($member), 'sha' => hash('sha256', $member));
        // The state goes down with the cursor already past this slice, so a killed
        // request resends the slice rather than building it twice.
        if (!self::save_state($this->dir, $this->state)) {
            return array('fatal' => 'Could not write to the work folder. Is the disk full?');
        }
        return null;
    }

    /** One gzip member. The importer reads any number of them as one stream. */
    private static function gzip_member($data)
    {
        if (function_exists('gzencode')) {
            return gzencode($data, 4);
        }
        // No zlib in this PHP. Gzip allows stored, uncompressed blocks.
        $out = "\x1f\x8b\x08\0\0\0\0\0\0\xff";
        $len = strlen($data);
        $pos = 0;
        do {
            $n = min(65535, $len - $pos);
            $out .= chr($pos + $n >= $len ? 1 : 0) . pack('v', $n) . pack('v', ~$n & 0xFFFF) . substr($data, $pos, $n);
            $pos += $n;
        } while ($pos < $len);
        return $out . pack('V', crc32($data)) . pack('V', $len);
    }

    private function send_pending()
    {
        $p = $this->state['pending'];
        $body = @file_get_contents($this->dir . '/pending.bin');
        if ($body === false || strlen($body) !== $p['len']) {
            return array('fatal' => 'A piece of the transfer was lost from the work folder. Generate a new code and start again.');
        }
        $sent = $this->state['sent'][$p['stream']];
        $r = $this->panel('PUT', '/import/upload/wp/chunk', $body, array(
            'Content-Type' => 'application/octet-stream',
            'X-Hyperion-Stream' => $p['stream'],
            'X-Hyperion-Offset' => (string) $sent,
            'X-Hyperion-Sha256' => $p['sha'],
        ));
        if ($r['net'] !== '') {
            return array('retry' => 'Waiting for Hyperion: ' . $r['net']);
        }
        $f = self::kv($r['body']);
        $held = isset($f['offset']) ? (int) $f['offset'] : -1;
        if ($r['code'] === 200 || ($r['code'] === 409 && $held === $sent + $p['len'])) {
            // On the 409, Hyperion already has this slice and the reply to it was lost.
            $this->state['sent'][$p['stream']] = $sent + $p['len'];
            $this->state['pending'] = null;
            @unlink($this->dir . '/pending.bin');
            return null;
        }
        if ($r['code'] === 409) {
            return array('fatal' => 'Hyperion and this site disagree about how much has been sent. Generate a new code and start again.');
        }
        if ($r['code'] === 410) {
            return array('fatal' => 'The transfer was cancelled in Hyperion, or its code expired.');
        }
        if ($r['code'] === 507) {
            return array('fatal' => trim($r['body']));
        }
        if ($r['code'] === 422 || $r['code'] >= 500) {
            return array('retry' => 'Waiting for Hyperion: HTTP ' . $r['code']);
        }
        return array('fatal' => 'Hyperion refused the upload (HTTP ' . $r['code'] . '): ' . trim(substr($r['body'], 0, 300)));
    }

    private function step_commit()
    {
        $r = $this->panel('POST', '/import/upload/wp/commit', wp_json_encode(array(
            'db_bytes' => $this->state['sent']['db'],
            'files_bytes' => $this->state['sent']['files'],
            'files_members' => $this->state['members'],
        )), array('Content-Type' => 'application/json'));
        if ($r['net'] !== '' || $r['code'] >= 500) {
            return array('retry' => 'Waiting for Hyperion: ' . ($r['net'] !== '' ? $r['net'] : 'HTTP ' . $r['code']));
        }
        if ($r['code'] !== 200) {
            return array('fatal' => 'Hyperion did not accept the finished transfer: ' . trim(substr($r['body'], 0, 300)));
        }
        $f = self::kv($r['body']);
        return $this->finish(isset($f['job']) ? $f['job'] : '-');
    }

    /** Hyperion has it. Forget the token and the work folder, keep only what to show. */
    private function finish($job)
    {
        $job_url = $job === '-' ? $this->run['url'] . '/import' : $this->run['url'] . '/jobs/' . rawurlencode($job);
        self::remove_dir($this->dir);
        update_option(self::OPTION, array(
            'dir' => $this->dir,
            'finished' => true,
            'job_url' => $job_url,
            'warnings' => $this->state['warnings'],
        ), 'no');
        return array('finished' => true, 'phase' => 'done', 'percent' => 100, 'job_url' => $job_url, 'warnings' => $this->state['warnings']);
    }

    private function panel($method, $path, $body, $headers)
    {
        return self::panel_request($this->run['url'], $this->run['token'], $method, $path, $body, $headers);
    }

    private static function panel_request($url, $token, $method, $path, $body = null, $headers = array())
    {
        $args = array(
            'method' => $method,
            'timeout' => 120,
            'redirection' => 0,
            'user-agent' => 'Hyperion-Migrate/1.0',
            'sslverify' => !self::insecure_allowed(),
            'headers' => array('Authorization' => 'Bearer ' . $token) + $headers,
        );
        if ($body !== null) {
            $args['body'] = $body;
        }
        $r = wp_remote_request($url . $path, $args);
        if (is_wp_error($r)) {
            return array('code' => 0, 'body' => '', 'net' => $r->get_error_message());
        }
        return array('code' => (int) wp_remote_retrieve_response_code($r), 'body' => (string) wp_remote_retrieve_body($r), 'net' => '');
    }

    /** Hyperion's machine replies are `key value` lines. */
    private static function kv($body)
    {
        $out = array();
        foreach (explode("\n", (string) $body) as $line) {
            $parts = explode(' ', trim($line), 2);
            if (count($parts) === 2) {
                $out[$parts[0]] = $parts[1];
            }
        }
        return $out;
    }

    // ---- page ---------------------------------------------------------------

    public static function page()
    {
        if (!self::allowed()) {
            wp_die('You are not allowed to do this.');
        }
        $run = get_option(self::OPTION);
        $running = is_array($run) && !empty($run['dir']);
        ?>
        <style>#hm [hidden] { display: none !important; }</style>
        <div class="wrap" id="hm">
            <h1>Hyperion Migration</h1>
            <p>Copies this site to a Hyperion panel. The site here stays online and unchanged.</p>

            <div id="hm-paste" <?php echo $running ? 'hidden' : ''; ?>>
                <p>In Hyperion, open <strong>Import → WordPress plugin</strong>, generate a code and paste it here.</p>
                <p><textarea id="hm-code" rows="4" class="large-text code" spellcheck="false" autocomplete="off"></textarea></p>
                <p><button type="button" class="button button-primary" id="hm-check">Continue</button></p>
            </div>

            <div id="hm-confirm" hidden>
                <div class="notice notice-info inline"><p id="hm-confirm-text"></p></div>
                <p><button type="button" class="button button-primary" id="hm-start">Start transfer</button>
                <button type="button" class="button" id="hm-back">Back</button></p>
            </div>

            <div id="hm-progress" hidden>
                <p><strong id="hm-label">Starting…</strong> <span id="hm-numbers"></span></p>
                <progress id="hm-bar" max="100" value="0" style="width:100%;max-width:640px;height:1.5em"></progress>
                <p class="description">Keep this tab open. If it closes, come back to this page and the transfer continues where it stopped.</p>
                <p id="hm-waiting" class="description"></p>
                <p><button type="button" class="button" id="hm-retry" hidden>Try again</button>
                <button type="button" class="button-link button-link-delete" id="hm-cancel">Cancel transfer</button></p>
            </div>

            <div id="hm-done" hidden>
                <div class="notice notice-success inline"><p><strong>Hyperion has the site.</strong> It is importing now. <a id="hm-job" target="_blank" rel="noopener">Follow the import in Hyperion</a>.</p></div>
                <p>Once you have checked the new site and pointed DNS at it, you can delete this plugin. It has already removed its temporary files and the code.</p>
                <p><button type="button" class="button" id="hm-again">Transfer again</button></p>
            </div>

            <div id="hm-error" class="notice notice-error inline" hidden><p id="hm-error-text"></p></div>
            <div id="hm-warnings" hidden>
                <h2>Worth checking on the new server</h2>
                <ul id="hm-warning-list" style="list-style:disc;padding-left:1.5em"></ul>
            </div>
        </div>
        <script>
        (function () {
            var ajax = <?php echo wp_json_encode(admin_url('admin-ajax.php')); ?>;
            var nonce = <?php echo wp_json_encode(wp_create_nonce(self::NONCE)); ?>;
            var el = function (id) { return document.getElementById('hm-' + id); };
            var failures = 0, stopped = false;

            function show(section) {
                ['paste', 'confirm', 'progress', 'done'].forEach(function (s) { el(s).hidden = s !== section; });
            }
            function fail(message) {
                el('error-text').textContent = message;
                el('error').hidden = false;
            }
            function warnings(list) {
                if (!list || !list.length) { return; }
                var ul = el('warning-list');
                ul.textContent = '';
                list.forEach(function (w) { var li = document.createElement('li'); li.textContent = w; ul.appendChild(li); });
                el('warnings').hidden = false;
            }
            function human(n) {
                var units = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
                while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
                return (i ? n.toFixed(1) : n) + ' ' + units[i];
            }
            // A reply that is not our JSON means the request died: a memory limit,
            // an execution limit, a web server timeout. Null asks for a smaller slice.
            function post(action, fields) {
                var body = new FormData();
                body.append('action', 'hyperion_migrate_' + action);
                body.append('nonce', nonce);
                Object.keys(fields || {}).forEach(function (k) { body.append(k, fields[k]); });
                return fetch(ajax, { method: 'POST', body: body, credentials: 'same-origin' })
                    .then(function (r) { return r.text(); })
                    .then(function (t) {
                        var data = JSON.parse(t);
                        if (data.nonce) { nonce = data.nonce; }
                        return data;
                    })
                    .catch(function () { return null; });
            }
            function later(fn, seconds) { window.setTimeout(fn, seconds * 1000); }
            function backoff() { return Math.min(30, Math.pow(2, Math.min(failures, 5))); }

            function step(shrink) {
                if (stopped) { return; }
                post('step', shrink ? { shrink: '1' } : {}).then(function (d) {
                    if (stopped) { return; }
                    if (d === null) {
                        failures++;
                        if (failures > 12) {
                            el('waiting').textContent = '';
                            fail('This server keeps stopping the transfer. Nothing is lost, so you can try again now or later.');
                            el('retry').hidden = false;
                            return;
                        }
                        el('waiting').textContent = 'The server stopped a request. Retrying with a smaller piece…';
                        later(function () { step(true); }, backoff());
                        return;
                    }
                    if (d.fatal) { el('retry').hidden = false; warnings(d.warnings); fail(d.fatal); return; }
                    if (d.idle) { show('paste'); return; }
                    if (d.busy) { later(function () { step(false); }, 3); return; }
                    if (d.phase === 'done') {
                        el('job').href = d.job_url;
                        warnings(d.warnings);
                        show('done');
                        return;
                    }
                    el('bar').value = d.percent;
                    el('label').textContent = d.label + ' · ' + d.percent + ' %';
                    el('numbers').textContent = d.total_bytes > 1 ? human(d.done_bytes) + ' of about ' + human(d.total_bytes) : '';
                    if (d.retry) {
                        failures++;
                        el('waiting').textContent = d.retry;
                        later(function () { step(false); }, backoff());
                        return;
                    }
                    failures = 0;
                    el('waiting').textContent = '';
                    step(false);
                });
            }
            function run() {
                failures = 0; stopped = false;
                el('error').hidden = true;
                el('retry').hidden = true;
                show('progress');
                step(false);
            }

            el('check').addEventListener('click', function () {
                el('error').hidden = true;
                post('check', { code: el('code').value }).then(function (d) {
                    if (d === null) { fail('This server did not answer. Try again.'); return; }
                    if (d.fatal) { fail(d.fatal); return; }
                    el('confirm-text').textContent = 'This will send ' + d.site + ', including its database and wp-config.php with its passwords, to the Hyperion panel at ' + d.panel + '. Only continue if that is your panel.';
                    show('confirm');
                });
            });
            el('back').addEventListener('click', function () { show('paste'); });
            el('start').addEventListener('click', function () {
                post('start', { code: el('code').value }).then(function (d) {
                    if (d === null) { fail('This server did not answer. Try again.'); return; }
                    if (d.fatal) { fail(d.fatal); return; }
                    run();
                });
            });
            el('retry').addEventListener('click', run);
            el('cancel').addEventListener('click', function () {
                stopped = true;
                post('cancel').then(function () { el('warnings').hidden = true; el('error').hidden = true; show('paste'); });
            });
            el('again').addEventListener('click', function () {
                post('cancel').then(function () { el('warnings').hidden = true; show('paste'); });
            });
            <?php if ($running) : ?>
            run();
            <?php endif; ?>
        })();
        </script>
        <?php
    }
}

Hyperion_Migrate::boot();
