//! A sum to solve on the site's forms — an optional part of the contact form
//! guard ([`crate::formguard`]). While it is on, every Elementor Pro form asks
//! "What is 3 + 4?" and a submission without the right answer is refused.
//!
//! It is its own module of the Hyperion must-use plugin, not a setting inside
//! the guard's: every module is the same bytes on every site, which is what
//! lets the site scan compare ours by digest.
//!
//! The question is never in the page. A page cache would hand every visitor
//! the same one, so a small script adds the field as soon as the page is
//! parsed and asks `admin-ajax.php` for a sum when the form comes within a
//! screen of the viewport: the question is there before the visitor is, and a
//! form in the footer of every page costs a request only when somebody scrolls
//! to it. Nothing is stored per
//! question: the token carries its expiry and two MACs keyed with the site's
//! own salt, one of them over the answer. A token is spent by a wrong answer
//! and by an accepted submission.
//!
//! What it is good for: simple bots, and a moment of friction. A person who
//! clicked an ad can add two digits.

use crate::wpplugin::Module;
use crate::AdapterError;

/// Bumped whenever [`FORMMATH_TEMPLATE`] changes in a way that matters.
pub const FORMMATH_VERSION: u32 = 2;

/// The module. Static except for `{{VERSION}}`.
const FORMMATH_TEMPLATE: &str = r##"<?php
/**
 * Hyperion form question — loaded by mu-plugins/hyperion.php.
 *
 * Adds a small sum to every Elementor Pro form and refuses a submission
 * without the right answer. Managed by Hyperion — edits are overwritten.
 * Version: {{VERSION}}
 */
if (!defined('ABSPATH')) { exit; }
if (defined('HYPERION_FORMMATH_VERSION') || class_exists('Hyperion_Form_Math', false)) { return; }

define('HYPERION_FORMMATH_VERSION', {{VERSION}});

// Inside a condition for the same reason as the other modules: a top-level
// class is bound when the file is compiled, before the check above runs.
if (!class_exists('Hyperion_Form_Math', false)) {
    class Hyperion_Form_Math {
        const TTL   = 3600;      // seconds a question can be answered for
        const FIELD = 'hyp_fm';  // Elementor shows an error under #form-field-<this>

        public static function boot() {
            // After Elementor's own validators (10), before the guard's
            // content rules (20): no point judging the text of a bot.
            add_action('elementor_pro/forms/validation', array(__CLASS__, 'validate'), 15, 2);
            add_action('elementor_pro/forms/new_record', array(__CLASS__, 'accepted'), 10, 2);
            add_action('wp_ajax_hyperion_fm', array(__CLASS__, 'challenge'));
            add_action('wp_ajax_nopriv_hyperion_fm', array(__CLASS__, 'challenge'));
            add_action('wp_footer', array(__CLASS__, 'script'), 50);
        }

        /** A language we have texts for: the one asked for, else the site's, else English. */
        public static function lang($want) {
            $known = array('en', 'es', 'cs');
            $want = strtolower(substr(is_string($want) ? $want : '', 0, 2));
            if (in_array($want, $known, true)) { return $want; }
            $site = strtolower(substr((string) (function_exists('get_locale') ? get_locale() : 'en'), 0, 2));
            return in_array($site, $known, true) ? $site : 'en';
        }

        public static function text($key, $lang) {
            $t = array(
                'ask' => array(
                    'en' => 'What is %1$d + %2$d?',
                    'es' => '¿Cuánto es %1$d + %2$d?',
                    'cs' => 'Kolik je %1$d + %2$d?',
                ),
                'wrong' => array(
                    'en' => 'That is not the right answer. Please try the new sum.',
                    'es' => 'La respuesta no es correcta. Pruebe con la nueva suma.',
                    'cs' => 'To není správný výsledek. Zkuste prosím nový příklad.',
                ),
                'load' => array(
                    'en' => 'The check could not be loaded. Please reload the page.',
                    'es' => 'No se pudo cargar la comprobación. Vuelva a cargar la página.',
                    'cs' => 'Ověření se nepodařilo načíst. Načtěte prosím stránku znovu.',
                ),
            );
            return isset($t[$key][$lang]) ? $t[$key][$lang] : $t[$key]['en'];
        }

        protected static function mac($what) {
            return hash_hmac('sha256', $what, wp_salt('nonce'));
        }

        /** A new sum: the question in words and the token that knows its answer. */
        public static function issue($lang, $now = null) {
            $now = $now === null ? time() : (int) $now;
            $a = random_int(1, 9);
            $b = random_int(1, 9);
            $exp = $now + self::TTL;
            $rnd = bin2hex(random_bytes(8));
            return array(
                'q' => sprintf(self::text('ask', self::lang($lang)), $a, $b),
                't' => $exp . '.' . $rnd . '.' . substr(self::mac("t|$exp|$rnd"), 0, 32)
                     . '.' . self::mac("a|$exp|$rnd|" . ($a + $b)),
            );
        }

        /** The parts of a token we issued and that has not run out, else null. */
        protected static function parts($token) {
            if (!is_string($token)
                || !preg_match('~^(\d{9,12})\.([0-9a-f]{16})\.([0-9a-f]{32})\.([0-9a-f]{64})$~', $token, $m)) {
                return null;
            }
            if ((int) $m[1] < time()) { return null; }
            if (!hash_equals(substr(self::mac("t|$m[1]|$m[2]"), 0, 32), $m[3])) { return null; }
            return $m;
        }

        protected static function spent_key($token) { return 'hyp_fm_x_' . md5($token); }

        /** Only ever called for a token we issued, so nobody can fill the options table. */
        protected static function spend($m) {
            set_transient(self::spent_key($m[0]), 1, max(1, (int) $m[1] - time()));
        }

        /** Is `$answer` the answer to the question behind `$token`? */
        public static function check($token, $answer) {
            $m = self::parts($token);
            if ($m === null) { return false; }
            if (get_transient(self::spent_key($m[0])) !== false) { return false; }
            $answer = is_string($answer) ? trim($answer) : '';
            if (!preg_match('~^\d{1,3}$~', $answer)) { return false; }
            return hash_equals(self::mac("a|$m[1]|$m[2]|" . (int) $answer), $m[4]);
        }

        protected static function posted($key) {
            return isset($_POST[$key]) && is_string($_POST[$key]) ? $_POST[$key] : '';
        }

        public static function validate($record, $ajax) {
            if (!is_object($ajax) || !method_exists($ajax, 'add_error')) { return; }
            // Already refused by Elementor: the visitor keeps the question.
            if (!empty($ajax->errors)) { return; }
            // Someone building or testing the form.
            if (function_exists('current_user_can') && current_user_can('edit_posts')) { return; }
            $token = self::posted('hyp_fm_t');
            if (self::check($token, self::posted('hyp_fm_a'))) { return; }
            // One try per question, or seventeen tries would always get through.
            $m = self::parts($token);
            if ($m !== null) { self::spend($m); }
            $ajax->add_error(self::FIELD, self::text('wrong', self::lang('')));
            if (class_exists('Hyperion_Form_Guard', false) && method_exists('Hyperion_Form_Guard', 'note')) {
                Hyperion_Form_Guard::note('math', $record);
            }
        }

        /** An answer that got a submission through cannot be used for a second one. */
        public static function accepted($record = null, $ajax = null) {
            $m = self::parts(self::posted('hyp_fm_t'));
            if ($m !== null) { self::spend($m); }
        }

        public static function challenge() {
            if (function_exists('nocache_headers')) { nocache_headers(); }
            wp_send_json(self::issue(self::posted('lang')));
        }

        /**
         * The script that adds the field. Nothing in it depends on the
         * visitor, so it is safe in a cached page.
         */
        public static function script() {
            if (function_exists('is_admin') && is_admin()) { return; }
            $cfg = array(
                'u' => admin_url('admin-ajax.php'),
                'e' => self::text('load', self::lang('')),
            );
            echo '<script id="hyperion-fm">(function(c){' . self::js() . '})(' . wp_json_encode($cfg) . ');</script>' . "\n";
        }

        public static function js() {
            return <<<'JS'
var d=document,io=null;
function fill(w){
  var l=w.querySelector('label'),a=w.querySelector('[name=hyp_fm_a]'),t=w.querySelector('[name=hyp_fm_t]');
  a.value='';t.value='';w.removeAttribute('data-at');w.setAttribute('data-st','load');
  var lang=(d.documentElement.getAttribute('lang')||'').slice(0,2);
  fetch(c.u,{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'action=hyperion_fm&lang='+encodeURIComponent(lang)})
  .then(function(r){return r.json();})
  .then(function(j){
    if(!j||typeof j.q!=='string'||typeof j.t!=='string'){throw new Error('bad reply');}
    l.textContent=j.q;a.setAttribute('aria-label',j.q);t.value=j.t;
    w.setAttribute('data-at',String(Date.now()));w.setAttribute('data-st','ok');
  })
  .catch(function(){l.textContent=c.e;w.setAttribute('data-st','fail');});
}
function need(w){
  var at=Number(w.getAttribute('data-at'));
  if(w.getAttribute('data-st')==='load'){return;}
  if(!at||Date.now()-at>3000000){fill(w);}
}
function add(f){
  var w=f.querySelector('.hyp-fm');
  if(w){return w;}
  var ref=f.querySelector('input.elementor-field-textual');
  w=d.createElement('div');
  w.className='elementor-field-group elementor-column elementor-col-100 elementor-field-type-text hyp-fm';
  var l=d.createElement('label');
  l.className='elementor-field-label';
  l.textContent='…';
  var a=d.createElement('input');
  a.type='text';a.name='hyp_fm_a';a.id='form-field-hyp_fm';a.required=true;a.maxLength=3;
  a.setAttribute('inputmode','numeric');a.setAttribute('autocomplete','off');
  a.className=ref?ref.className:'elementor-field elementor-size-sm elementor-field-textual';
  var t=d.createElement('input');
  t.type='hidden';t.name='hyp_fm_t';
  w.appendChild(l);w.appendChild(a);w.appendChild(t);
  var s=f.querySelector('.elementor-field-type-submit');
  if(s&&s.parentNode){s.parentNode.insertBefore(w,s);}else{f.appendChild(w);}
  if(window.jQuery){
    window.jQuery(f).on('submit_success',function(){fill(w);})
      .on('error',function(){if(w.classList.contains('elementor-error')){fill(w);}});
  }
  return w;
}
function scan(){
  var fs=d.querySelectorAll('form.elementor-form'),i;
  if(!io&&window.IntersectionObserver){
    io=new IntersectionObserver(function(es){
      for(var k=0;k<es.length;k++){
        if(es[k].isIntersecting){io.unobserve(es[k].target);need(add(es[k].target));}
      }
    },{rootMargin:'600px 0px'});
  }
  for(i=0;i<fs.length;i++){
    if(fs[i].querySelector('.hyp-fm')){continue;}
    var w=add(fs[i]);
    if(io){io.observe(fs[i]);}else{need(w);}
  }
}
function form(e){
  return e.target&&e.target.closest?e.target.closest('form.elementor-form'):null;
}
function touch(e){
  var f=form(e);
  if(f){need(add(f));}
}
if(d.readyState==='loading'){d.addEventListener('DOMContentLoaded',scan);}else{scan();}
window.addEventListener('load',scan);
if(window.jQuery){window.jQuery(d).on('elementor/popup/show',scan);}
d.addEventListener('focusin',touch,true);
d.addEventListener('pointerdown',touch,true);
d.addEventListener('submit',function(e){
  var f=form(e);
  if(!f){return;}
  var w=add(f),a=w.querySelector('[name=hyp_fm_a]');
  need(w);
  if(!a.value){
    e.preventDefault();e.stopPropagation();
    a.focus();
  }
},true);
JS;
        }
    }
    Hyperion_Form_Math::boot();
}
"##;

/// The module body with the version marker filled in.
pub fn render_module() -> String {
    FORMMATH_TEMPLATE.replace("{{VERSION}}", &FORMMATH_VERSION.to_string())
}

/// Is the module installed and current?
pub async fn is_installed(root_dir: &str) -> bool {
    crate::wpplugin::module_state(root_dir, Module::FormMath, &render_module()).await
        == crate::wpplugin::FileState::Current
}

/// Write (or rewrite) the module, owned by the site user. `Ok(false)` when the
/// site is not WordPress.
pub async fn install(root_dir: &str, system_user: &str) -> Result<bool, AdapterError> {
    crate::wpplugin::install_module(root_dir, system_user, Module::FormMath, &render_module()).await
}

/// Remove it — best-effort.
pub async fn remove(root_dir: &str) {
    crate::wpplugin::remove_module(root_dir, Module::FormMath).await
}

/// Is any copy of the module on disk, current or not?
pub async fn is_present(root_dir: &str) -> bool {
    crate::wpplugin::module_contents(root_dir, Module::FormMath)
        .await
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_fills_the_version_marker() {
        let php = render_module();
        assert!(!php.contains("{{VERSION}}"), "template token left unfilled");
        assert!(php.contains("class Hyperion_Form_Math"));
        assert!(php.contains(&format!("HYPERION_FORMMATH_VERSION', {FORMMATH_VERSION}")));
    }

    #[tokio::test]
    async fn install_detect_remove_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_str().unwrap();
        assert!(!install(root, "nobody").await.unwrap());
        tokio::fs::create_dir_all(dir.path().join("wp-content"))
            .await
            .unwrap();
        assert!(!is_present(root).await);
        assert!(install(root, "nobody").await.unwrap());
        assert!(is_installed(root).await && is_present(root).await);
        remove(root).await;
        assert!(!is_installed(root).await && !is_present(root).await);
    }
}
