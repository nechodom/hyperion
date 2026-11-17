<?php
/**
 * Runs the form question module outside WordPress, next to the form guard.
 *
 *   php formmath_harness.php <formguard.php> <formmath.php> <site dir> <script out>
 *
 * <site dir> holds `htdocs/wp-content` and `logs`. Stubs just enough of
 * WordPress and of Elementor Pro for the two modules to run as they do on a
 * site, prints one line per failed expectation and exits non-zero if any.
 * The script the module prints is written to <script out> for a syntax check.
 */
if ($argc < 5) { fwrite(STDERR, "usage: formmath_harness.php <formguard.php> <formmath.php> <site dir> <script out>\n"); exit(2); }
define('ABSPATH', $argv[3] . '/htdocs/');
define('WP_CONTENT_DIR', $argv[3] . '/htdocs/wp-content');

$GLOBALS['hooks'] = array();
$GLOBALS['transients'] = array();
$GLOBALS['locale'] = 'en_US';
$GLOBALS['editor'] = false;
$GLOBALS['admin'] = false;
$GLOBALS['sent'] = null;

function add_action($hook, $cb, $prio = 10, $args = 1) { $GLOBALS['hooks'][$hook][$prio][] = $cb; }
function get_transient($k) {
    if (!isset($GLOBALS['transients'][$k])) { return false; }
    list($v, $until) = $GLOBALS['transients'][$k];
    if ($until <= time()) { unset($GLOBALS['transients'][$k]); return false; }
    return $v;
}
function set_transient($k, $v, $ttl) { $GLOBALS['transients'][$k] = array($v, time() + $ttl); return true; }
function get_locale() { return $GLOBALS['locale']; }
function current_user_can($cap) { return $GLOBALS['editor']; }
function is_admin() { return $GLOBALS['admin']; }
function wp_salt($scheme = 'auth') { return 'harness-salt-' . $scheme; }
function admin_url($path = '') { return 'https://example.com/wp-admin/' . $path; }
function wp_json_encode($v) { return json_encode($v); }
function nocache_headers() {}
function wp_send_json($v) { $GLOBALS['sent'] = $v; }

class Fake_Record {
    public $fields; public $settings;
    function __construct($fields, $settings) { $this->fields = $fields; $this->settings = $settings; }
    function get($k) { return $k === 'fields' ? $this->fields : null; }
    function get_form_settings($k) { return isset($this->settings[$k]) ? $this->settings[$k] : ''; }
}
class Fake_Ajax {
    public $errors = array();
    function add_error($field, $msg = '') { $this->errors[$field] = $msg; return $this; }
}

require $argv[1];
require $argv[2];

$failed = 0;
function check($what, $cond) {
    if (!$cond) { $GLOBALS['failed']++; echo "FAIL: $what\n"; }
}
function run($hook, $record, $ajax) {
    $by_prio = isset($GLOBALS['hooks'][$hook]) ? $GLOBALS['hooks'][$hook] : array();
    ksort($by_prio);
    foreach ($by_prio as $cbs) { foreach ($cbs as $cb) { call_user_func($cb, $record, $ajax); } }
}
function contact($message = 'Table for two on Friday at 7 pm, please.') {
    return new Fake_Record(array(
        'name'    => array('id' => 'name', 'type' => 'text', 'title' => 'Name', 'value' => 'Ann Lee'),
        'email'   => array('id' => 'email', 'type' => 'email', 'title' => 'Email', 'value' => 'ann@example.com'),
        'message' => array('id' => 'message', 'type' => 'textarea', 'title' => 'Message', 'value' => $message),
    ), array('id' => 'c0ffee1', 'form_name' => 'Contact'));
}
/** Submit as Elementor does, with what the script would have put in the form. */
function submit($token, $answer, $record = null, $pre = array()) {
    $_POST = array();
    if ($token !== null) { $_POST['hyp_fm_t'] = $token; }
    if ($answer !== null) { $_POST['hyp_fm_a'] = $answer; }
    $ajax = new Fake_Ajax();
    $ajax->errors = $pre;
    $record = $record ? $record : contact();
    run('elementor_pro/forms/validation', $record, $ajax);
    if (!$ajax->errors) { run('elementor_pro/forms/new_record', $record, $ajax); }
    return $ajax->errors;
}
function fresh() { $GLOBALS['transients'] = array(); $_SERVER['REMOTE_ADDR'] = '203.0.113.7'; }
/** A question and, read back from its words, the answer. */
function ask($lang = 'en', $now = null) {
    $c = Hyperion_Form_Math::issue($lang, $now);
    preg_match('~(\d+) \+ (\d+)~', $c['q'], $m);
    $c['answer'] = (string) ($m[1] + $m[2]);
    $c['a'] = (int) $m[1]; $c['b'] = (int) $m[2];
    return $c;
}

check('validation runs before the guard', isset($GLOBALS['hooks']['elementor_pro/forms/validation'][15], $GLOBALS['hooks']['elementor_pro/forms/validation'][20]));
check('the question is served to visitors and to logged-in users',
    isset($GLOBALS['hooks']['wp_ajax_nopriv_hyperion_fm'], $GLOBALS['hooks']['wp_ajax_hyperion_fm']));
check('the script is printed in the footer', isset($GLOBALS['hooks']['wp_footer']));

// The question.
for ($i = 0; $i < 200; $i++) {
    $c = ask();
    if ($c['a'] < 1 || $c['a'] > 9 || $c['b'] < 1 || $c['b'] > 9) { check("digits out of range: {$c['q']}", false); break; }
}
check('token shape', (bool) preg_match('~^\d{10}\.[0-9a-f]{16}\.[0-9a-f]{32}\.[0-9a-f]{64}$~', $c['t']));
check('the token does not carry the answer in the clear', strpos($c['t'], '.' . $c['answer'] . '.') === false);
foreach (array('en' => 'What is', 'es' => '¿Cuánto es', 'cs' => 'Kolik je', 'de' => 'What is', '' => 'What is') as $lang => $starts) {
    check("question in '$lang'", strpos(Hyperion_Form_Math::issue($lang)['q'], $starts) === 0);
}
$GLOBALS['locale'] = 'cs_CZ';
check('an unknown language falls back to the site language', strpos(Hyperion_Form_Math::issue('xx')['q'], 'Kolik je') === 0);
check('a language that is not text is ignored', strpos(Hyperion_Form_Math::issue(array('cs'))['q'], 'Kolik je') === 0);
$GLOBALS['locale'] = 'en_US';

// The right answer goes through.
fresh();
$c = ask();
check('right answer accepted', submit($c['t'], $c['answer']) === array());
check('an answer that got through is spent', submit($c['t'], $c['answer'], contact('Another question entirely, thanks.')) !== array());
fresh();
$c = ask();
check('spaces around the answer are fine', submit($c['t'], ' ' . $c['answer'] . ' ') === array());
fresh();
$c = ask();
check('a leading zero is fine', submit($c['t'], '0' . $c['answer']) === array());

// The wrong one does not, and is told so under our field.
fresh();
$c = ask();
$e = submit($c['t'], (string) ($c['answer'] + 1));
check('wrong answer refused under the question', array_keys($e) === array('hyp_fm') && $e['hyp_fm'] !== '');
check('one try per question', submit($c['t'], $c['answer']) !== array());
foreach (array('', 'seven', '7abc', '-7', '7.0', '1e1', '9999') as $bad) {
    fresh();
    $c = ask();
    check("answer '$bad' refused", submit($c['t'], $bad) !== array());
}
fresh();
$c = ask();
check('no answer field refused', submit($c['t'], null) !== array());
check('an answer that is not text refused', (function () use ($c) {
    $_POST = array('hyp_fm_t' => $c['t'], 'hyp_fm_a' => array($c['answer']));
    $ajax = new Fake_Ajax();
    run('elementor_pro/forms/validation', contact(), $ajax);
    return $ajax->errors !== array();
})());

// A token we did not issue, or one that ran out.
fresh();
$c = ask();
check('no token refused', submit(null, $c['answer']) !== array());
check('empty token refused', submit('', $c['answer']) !== array());
$p = explode('.', $c['t']);
check('a later expiry breaks the token', submit(($p[0] + 60) . ".$p[1].$p[2].$p[3]", $c['answer']) !== array());
check('another random part breaks the token', submit("$p[0]." . strrev($p[1]) . ".$p[2].$p[3]", $c['answer']) !== array());
check('a made-up token refused', submit(time() + 60 . '.' . str_repeat('a', 16) . '.' . str_repeat('b', 32) . '.' . str_repeat('c', 64), '7') !== array());
$before = count($GLOBALS['transients']);
for ($i = 0; $i < 20; $i++) { submit(time() + 60 . '.' . bin2hex(random_bytes(8)) . '.' . str_repeat('b', 32) . '.' . str_repeat('c', 64), '7'); }
check('made-up tokens store nothing', count($GLOBALS['transients']) === $before);
fresh();
$old = ask('en', time() - 3601);
check('a question older than an hour refused', submit($old['t'], $old['answer']) !== array());
$recent = ask('en', time() - 3000);
check('a question from 50 minutes ago accepted', submit($recent['t'], $recent['answer']) === array());

// Elementor already refused it: the visitor keeps the question.
fresh();
$c = ask();
$e = submit($c['t'], '99', null, array('email' => 'required'));
check('an already refused submission is left alone', array_keys($e) === array('email'));
check('and its question still works', submit($c['t'], $c['answer']) === array());

// The guard refused what was written: the answer stays good for the correction.
fresh();
$c = ask();
$e = submit($c['t'], $c['answer'], contact(''));
check('right answer, empty message: refused by the guard', array_keys($e) === array('message'));
check('the corrected message goes through on the same answer', submit($c['t'], $c['answer']) === array());

// Someone editing the site is testing the form.
fresh();
$GLOBALS['editor'] = true;
check('an editor is never asked', submit(null, null) === array());
$GLOBALS['editor'] = false;

// Things that are not what Elementor passes do not break the page.
fresh();
$_POST = array();
foreach ($GLOBALS['hooks']['elementor_pro/forms/validation'][15] as $cb) {
    call_user_func($cb, null, null);
    call_user_func($cb, contact(), new stdClass());
}
check('junk input ignored', true);

// The visitor is told in the site's language.
foreach (array('en_US' => 'That is not', 'es_ES' => 'La respuesta', 'cs_CZ' => 'To není', 'de_DE' => 'That is not') as $loc => $starts) {
    fresh();
    $GLOBALS['locale'] = $loc;
    $e = submit(null, '1');
    check("message in $loc", isset($e['hyp_fm']) && strpos($e['hyp_fm'], $starts) === 0);
}
$GLOBALS['locale'] = 'en_US';

// Refusals land in the guard's log, under their own rule.
$log = Hyperion_Form_Guard::log_path();
$lines = is_file($log) ? file($log, FILE_IGNORE_NEW_LINES) : array();
$math = array_values(array_filter($lines, function ($l) { $f = explode("\t", $l); return isset($f[1]) && $f[1] === 'math'; }));
check('wrong answers were logged as math', count($math) >= 10);
$f = explode("\t", end($math));
check('a math line has six fields, with the form and the sender', count($f) === 6 && $f[2] === 'Contact' && $f[3] === 'ann@example.com' && $f[4] === '203.0.113.7');

// The endpoint.
$_POST = array('lang' => 'cs');
call_user_func($GLOBALS['hooks']['wp_ajax_nopriv_hyperion_fm'][10][0]);
$s = $GLOBALS['sent'];
check('the endpoint answers with a question and a token, nothing else',
    is_array($s) && array_keys($s) === array('q', 't') && strpos($s['q'], 'Kolik je') === 0);

// The script.
ob_start();
call_user_func($GLOBALS['hooks']['wp_footer'][50][0]);
$html = ob_get_clean();
check('the script is one script element', (bool) preg_match('~^<script id="hyperion-fm">(.*)</script>\s*$~s', $html, $m) && substr_count(strtolower($html), '</script') === 1);
check('it knows where to ask', strpos($html, 'https:\/\/example.com\/wp-admin\/admin-ajax.php') !== false);
check('it carries no question of its own', !preg_match('~\d \+ \d~', $html));
file_put_contents($argv[4], isset($m[1]) ? $m[1] : '');
$GLOBALS['admin'] = true;
ob_start();
call_user_func($GLOBALS['hooks']['wp_footer'][50][0]);
check('nothing is printed in wp-admin', ob_get_clean() === '');
$GLOBALS['admin'] = false;

echo $failed ? "$failed failed\n" : "ok\n";
exit($failed ? 1 : 0);
