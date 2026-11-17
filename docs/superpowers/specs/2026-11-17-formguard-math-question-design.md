# Contact form guard: an optional sum to solve

Status: approved 2026-11-17

## Why

The contact form guard judges what a visitor wrote. The operator also wants a
check the visitor has to pass before sending: a small sum ("What is 3 + 4?")
on the site's forms, switched on per hosting.

It stops simple bots and adds a moment of friction. It does not stop a person
who clicked an ad and can add two digits; the card says so.

## What

- A second switch on the Contact form guard card, "Ask a sum", usable only
  while the guard is on. Intent lives in `hosting_kv` `formguard_math` and is
  carried by Move/Copy like `formguard_enabled`.
- A new module of the Hyperion must-use plugin, `formmath.php`. The same bytes
  on every site, so the site scan keeps comparing it by digest.
- Every Elementor Pro form on the site gets one extra field before its submit
  button. Texts in English, Spanish and Czech.
- A wrong or missing answer is refused under that field, the visitor gets a
  new sum, and the refusal is logged with the rule `math`.
- Someone who can edit posts is not checked, as with the other rules.

## How

- The question cannot be in the page HTML: a cached page would give everybody
  the same one. A small inline script adds the field when the visitor first
  touches a form and fetches the sum from `admin-ajax.php`.
- No stored state for a question. The token is `expiry.random.auth.mac`, both
  MACs keyed with `wp_salt('nonce')`; the second covers the answer. Valid for
  one hour. A token is spent (a transient until it expires) by a wrong answer
  and by an accepted submission, so it can be neither guessed at nor replayed.
- Without JavaScript the form is refused. Elementor Pro forms need JavaScript
  to submit anyway.
- `FormGuardSet` gains an optional `math`. An older node ignores it and
  re-applies `enabled`, which changes nothing.

## Approaches considered

1. **Separate fixed module (chosen).** Scan-friendly, the guard module stays
   one variant, the loader decides.
2. A flag rendered into `formguard.php`. Two valid bodies for one path; the
   site scan would need a per-site expected digest for it.
3. Render the field in PHP through Elementor's widget output. Breaks under a
   page cache and needs string surgery on Elementor's markup.

## Not in scope

- Choosing forms one by one.
- Form plugins other than Elementor Pro.

## Verification

- `tests/formmath_php.rs` runs the module under real PHP against stubs.
- The hooks and the markup the script relies on were read from Elementor Pro
  4.1.1 (`form-record.php`, `ajax-handler.php`, the form bundle). Not yet
  exercised on a live site.
