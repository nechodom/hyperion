<?php
/**
 * Runs the contact form guard module outside WordPress.
 *
 *   php formguard_harness.php <module.php> <site dir>
 *
 * <site dir> holds `htdocs/wp-content` and `logs`. Stubs just enough of
 * WordPress and of Elementor Pro's form record / ajax handler for the module
 * to run as it does on a site, then prints one line per failed expectation
 * and exits non-zero if there were any.
 */
if ($argc < 3) { fwrite(STDERR, "usage: formguard_harness.php <module.php> <site dir>\n"); exit(2); }
define('ABSPATH', $argv[2] . '/htdocs/');
define('WP_CONTENT_DIR', $argv[2] . '/htdocs/wp-content');

$GLOBALS['hooks'] = array();
$GLOBALS['transients'] = array();
$GLOBALS['locale'] = 'en_US';
$GLOBALS['editor'] = false;

function add_action($hook, $cb, $prio = 10, $args = 1) { $GLOBALS['hooks'][$hook][] = $cb; }
function get_transient($k) {
    if (!isset($GLOBALS['transients'][$k])) { return false; }
    list($v, $until) = $GLOBALS['transients'][$k];
    if ($until <= time()) { unset($GLOBALS['transients'][$k]); return false; }
    return $v;
}
function set_transient($k, $v, $ttl) { $GLOBALS['transients'][$k] = array($v, time() + $ttl); return true; }
function get_locale() { return $GLOBALS['locale']; }
function current_user_can($cap) { return $GLOBALS['editor']; }

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

$failed = 0;
function check($what, $cond) {
    if (!$cond) { $GLOBALS['failed']++; echo "FAIL: $what\n"; }
}

/** A contact form: name, e-mail, phone, message, plus the plumbing Elementor adds. */
function contact($name, $email, $phone, $message, $form = 'c0ffee1') {
    return new Fake_Record(array(
        'name'    => array('id' => 'name', 'type' => 'text', 'title' => 'Name', 'value' => $name),
        'email'   => array('id' => 'email', 'type' => 'email', 'title' => 'Email', 'value' => $email),
        'field_1' => array('id' => 'field_1', 'type' => 'tel', 'title' => 'Phone', 'value' => $phone),
        'message' => array('id' => 'message', 'type' => 'textarea', 'title' => 'Message', 'value' => $message),
        'hp'      => array('id' => 'hp', 'type' => 'honeypot', 'title' => '', 'value' => ''),
        'rc'      => array('id' => 'rc', 'type' => 'recaptcha_v3', 'title' => '', 'value' => ''),
    ), array('id' => $form, 'form_name' => 'Contact'));
}
/** A booking form: the message is one field among several that say something. */
function booking($message, $count = '2 people') {
    return new Fake_Record(array(
        'name'    => array('id' => 'name', 'type' => 'text', 'title' => 'Name', 'value' => 'Ann'),
        'email'   => array('id' => 'email', 'type' => 'email', 'title' => 'E-mail', 'value' => 'ann@example.com'),
        'field_1' => array('id' => 'field_1', 'type' => 'select', 'title' => 'Count', 'value' => $count),
        'field_2' => array('id' => 'field_2', 'type' => 'date', 'title' => 'Date', 'value' => '2026-11-28'),
        'field_4' => array('id' => 'field_4', 'type' => 'textarea', 'title' => 'Message', 'value' => $message),
    ), array('id' => 'b00c1ng', 'form_name' => 'Booking'));
}
/** Submit as Elementor does: validate, and only an accepted record is recorded. */
function submit($record) {
    $ajax = new Fake_Ajax();
    foreach ($GLOBALS['hooks']['elementor_pro/forms/validation'] as $cb) { call_user_func($cb, $record, $ajax); }
    if (!$ajax->errors) {
        foreach ($GLOBALS['hooks']['elementor_pro/forms/new_record'] as $cb) { call_user_func($cb, $record, $ajax); }
    }
    return $ajax->errors;
}
function fresh($ip = '203.0.113.7') { $GLOBALS['transients'] = array(); $_SERVER['REMOTE_ADDR'] = $ip; }

check('both hooks registered',
    !empty($GLOBALS['hooks']['elementor_pro/forms/validation']) && !empty($GLOBALS['hooks']['elementor_pro/forms/new_record']));

// A real enquiry goes through.
fresh();
check('real enquiry accepted', submit(contact('Ann Lee', 'ann@example.com', '5550100123', 'Table for two on Friday at 7 pm, please.')) === array());

// Nothing written: refused, under the message field.
fresh();
$e = submit(contact('Ann', 'ann@example.com', '', ''));
check('empty message refused under the message field', array_keys($e) === array('message') && $e['message'] !== '');
fresh();
check('whitespace-only message refused', submit(contact('Ann', 'ann@example.com', '', "  \r\n ")) !== array());
fresh();
check('four-letter message refused', submit(contact('Ann', 'ann@example.com', '', 'Hola')) !== array());
fresh();
check('ten characters is a message', submit(contact('Ann', 'ann@example.com', '', 'Call me ok')) === array());
fresh();
check('length is counted in characters, not bytes', submit(contact('Ann', 'ann@example.com', '', 'čšřžýáíé')) !== array());

// A booking with a date and a party size is complete without a message.
fresh();
check('booking with no message accepted', submit(booking('')) === array());
fresh();
check('booking with a one-word message accepted', submit(booking('None')) === array());

// The same thing sent twice.
fresh();
$r = contact('Ann Lee', 'ann@example.com', '5550100123', 'Table for two on Friday at 7 pm, please.');
check('first of a pair accepted', submit($r) === array());
check('identical second refused', submit($r) !== array());
check('second with different capitals and spacing refused',
    submit(contact('ann lee', 'ANN@example.com', '5550100123', "Table for two  on Friday at 7 pm, please.")) !== array());
check('a different message from the same person accepted',
    submit(contact('Ann Lee', 'ann@example.com', '5550100123', 'Sorry, make that a table for four.')) === array());
// A refused submission must not make the corrected one a "duplicate".
fresh();
check('empty refused', submit(contact('Ann', 'ann@example.com', '', '')) !== array());
check('then the corrected one accepted', submit(contact('Ann', 'ann@example.com', '', 'Do you open on Sunday?')) === array());
// The same text on another form is another submission.
fresh();
check('form A accepted', submit(contact('Ann', 'a@example.com', '', 'Do you open on Sunday?', 'aaaaaaa')) === array());
check('same text on form B accepted', submit(contact('Ann', 'a@example.com', '', 'Do you open on Sunday?', 'bbbbbbb')) === array());

// Too many from one e-mail address.
fresh();
for ($i = 1; $i <= 3; $i++) {
    $_SERVER['REMOTE_ADDR'] = "198.51.100.$i";
    check("e-mail: message $i accepted", submit(contact('Ann', 'ann@example.com', '', "Question number $i for you")) === array());
}
$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
check('e-mail: fourth in the hour refused', submit(contact('Ann', 'ann@example.com', '', 'Question number 4 for you')) !== array());
check('e-mail: someone else still accepted', submit(contact('Bob', 'bob@example.com', '', 'A question from Bob here')) === array());

// Too many from one address.
fresh('192.0.2.50');
for ($i = 1; $i <= 5; $i++) {
    check("address: message $i accepted", submit(contact('P', "p$i@example.com", '', "Question number $i for you")) === array());
}
check('address: sixth in the hour refused', submit(contact('P', 'p6@example.com', '', 'Question number 6 for you')) !== array());
$_SERVER['REMOTE_ADDR'] = '192.0.2.51';
check('address: another address still accepted', submit(contact('P', 'p7@example.com', '', 'Question number 7 for you')) === array());

// A link where a name belongs.
fresh();
$e = submit(contact('Win big https://example.org/x', 'x@example.com', '', 'A perfectly long message here.'));
check('link in the name refused under the name field', array_keys($e) === array('name'));
fresh();
check('a dotted name is a name', submit(contact('J.Co Smith', 'x@example.com', '', 'A perfectly long message here.')) === array());
fresh();
check('a link in the message is allowed', submit(contact('Ann', 'x@example.com', '', 'See https://example.org/menu for what I mean.')) === array());

// Elementor already refused it: not ours to judge or to count.
fresh();
$ajax = new Fake_Ajax();
$ajax->errors['email'] = 'required';
call_user_func($GLOBALS['hooks']['elementor_pro/forms/validation'][0], contact('Ann', '', '', ''), $ajax);
check('an already refused submission is left alone', array_keys($ajax->errors) === array('email'));

// Someone editing the site is testing the form.
fresh();
$GLOBALS['editor'] = true;
check('an editor is never refused', submit(contact('Ann', 'ann@example.com', '', '')) === array());
$GLOBALS['editor'] = false;

// Things that are not a record do not break the page.
fresh();
$ajax = new Fake_Ajax();
call_user_func($GLOBALS['hooks']['elementor_pro/forms/validation'][0], null, $ajax);
call_user_func($GLOBALS['hooks']['elementor_pro/forms/validation'][0], new Fake_Record('nope', array()), $ajax);
call_user_func($GLOBALS['hooks']['elementor_pro/forms/validation'][0], contact('A', 'a@example.com', '', ''), null);
check('junk input ignored', $ajax->errors === array());

// The visitor is told in the site's language.
foreach (array('en_US' => 'Please', 'es_ES' => 'Por favor', 'cs_CZ' => 'Napište', 'de_DE' => 'Please') as $loc => $starts) {
    fresh();
    $GLOBALS['locale'] = $loc;
    $e = submit(contact('Ann', 'ann@example.com', '', ''));
    check("message in $loc", isset($e['message']) && strpos($e['message'], $starts) === 0);
}
$GLOBALS['locale'] = 'en_US';

// Every refusal above left one line: time, rule, form, e-mail, address.
$log = Hyperion_Form_Guard::log_path();
check('log is beside the docroot', $log === $argv[2] . '/logs/hyperion-formguard.log');
$lines = is_file($log) ? file($log, FILE_IGNORE_NEW_LINES) : array();
check('refusals were logged', count($lines) >= 10);
$rules = array();
foreach ($lines as $l) {
    $f = explode("\t", $l);
    check("log line has five fields: $l", count($f) === 5);
    check("log line starts with a timestamp: $l", (bool) preg_match('~^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$~', $f[0]));
    $rules[$f[1]] = true;
}
ksort($rules);
check('every rule appears in the log: ' . implode(',', array_keys($rules)),
    array_keys($rules) === array('duplicate', 'empty', 'link_in_name', 'rate', 'short'));

// A value with a tab or a newline cannot forge a second line or field.
fresh();
$before = count(file($log));
submit(new Fake_Record(array(
    'email'   => array('id' => 'email', 'type' => 'email', 'title' => 'Email', 'value' => "a@example.com\t9.9.9.9\n2026-01-01T00:00:00\tempty"),
    'message' => array('id' => 'message', 'type' => 'textarea', 'title' => 'Message', 'value' => ''),
), array('id' => 'x', 'form_name' => "Evil\tForm\n")));
$after = file($log, FILE_IGNORE_NEW_LINES);
check('a forged newline adds exactly one line', count($after) === $before + 1);
check('a forged tab adds no field', count(explode("\t", end($after))) === 5);

// The log stays bounded.
fresh();
file_put_contents($log, str_repeat(gmdate('Y-m-d\TH:i:s') . "\tempty\tContact\tx@example.com\t203.0.113.7\n", 4000));
submit(contact('Ann', 'ann@example.com', '', ''));
clearstatcache();
check('log is cut back once it grows: ' . filesize($log), filesize($log) < 100000);
$kept = file($log, FILE_IGNORE_NEW_LINES);
check('the cut keeps whole lines', count(explode("\t", $kept[0])) === 5);

echo $failed ? "$failed failed\n" : "ok\n";
exit($failed ? 1 : 0);
