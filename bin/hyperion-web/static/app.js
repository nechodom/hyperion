// Panel-wide behaviour shared by every page that extends base.html.
//
// Served from /static/app.js (embedded, hashed `?v=`, immutable, gzip) so the
// browser downloads it once per release instead of inside every HTML page.
// Loaded with `defer` right after htmx: it runs once the document is parsed,
// after htmx is defined and before DOMContentLoaded (when htmx starts
// processing the page), so every listener here is in place as before.

// Block 1 was the only strict-mode block; it keeps that in its own scope
// so concatenation does not turn the later (sloppy) blocks strict.
(function () {
'use strict';


// ============================================================
//  Silence AbortError unhandled-rejection noise. When a form
//  POST navigates away (delete, suspend, …) the browser aborts
//  every in-flight fetch from HTMX polling fragments; those
//  fetches reject with AbortError AFTER the page teardown
//  started, so nothing awaits them and the console logs
//  "Uncaught (in promise)". Navigation-aborted requests are
//  expected, not errors — swallow exactly that class, let every
//  real rejection through.
// ============================================================
window.addEventListener('unhandledrejection', function (ev) {
  const r = ev.reason;
  if (r && (r.name === 'AbortError' || r.code === 20)) ev.preventDefault();
});

// ============================================================
//  Live-log auto-tail. Progress fragments (.log-tail inside a
//  job/install card) are re-swapped by HTMX every 2s. A fresh
//  swap renders the <pre> scrolled to the TOP, so the newest
//  lines — which is exactly what someone watching an install
//  wants — scrolled out of view on every poll. Keep the pane
//  pinned to the bottom across swaps, BUT only when the operator
//  was already at the bottom: if they scrolled up to read an
//  earlier line, don't yank them back down.
// ============================================================
(function () {
  const NEAR = 40; // px from the bottom still counts as "tailing"
  const atBottom = new WeakMap();
  function isNearBottom(el) {
    return (el.scrollHeight - el.scrollTop - el.clientHeight) <= NEAR;
  }
  // Before HTMX rips out the old fragment, remember whether each
  // visible log was tailing. Keyed by the card so it survives the
  // element being replaced (we re-query by selector after swap).
  document.body.addEventListener('htmx:beforeSwap', function (ev) {
    const tgt = ev.target;
    if (!tgt || !tgt.querySelectorAll) return;
    const el = tgt.querySelector('.log-tail');
    atBottom.set(tgt, el ? isNearBottom(el) : true);
  });
  document.body.addEventListener('htmx:afterSwap', function (ev) {
    const tgt = ev.target;
    if (!tgt || !tgt.querySelectorAll) return;
    // Default to "stick to bottom" the first time we see a card
    // (no prior record ⇒ initial load ⇒ show newest lines).
    const stick = atBottom.has(tgt) ? atBottom.get(tgt) : true;
    if (!stick) return;
    const el = tgt.querySelector('.log-tail');
    if (el) el.scrollTop = el.scrollHeight;
  });
})();

// ============================================================
//  Password generator — existing feature, untouched.
//  Generates a strong password into [data-genpw="<input-id>"].
// ============================================================
document.addEventListener('click', function (ev) {
  const btn = ev.target.closest('[data-genpw]');
  if (!btn) return;
  ev.preventDefault();
  const targetId = btn.getAttribute('data-genpw');
  const input = document.getElementById(targetId);
  if (!input) return;
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+';
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  input.value = out;
  input.type = 'text';
  setTimeout(() => { input.type = 'password'; }, 8000);
  const orig = btn.textContent;
  btn.textContent = 'Generated · revealed for 8 s';
  setTimeout(() => { btn.textContent = orig; }, 8000);
});

// ============================================================
//  Theme toggle — auto / light / dark cycles, persisted in
//  localStorage. We apply it before paint by reading and
//  setting :root[data-theme] in a tiny inline head script (this
//  runs deferred so the first paint already has the right theme
//  via prefers-color-scheme — the explicit toggle only kicks in
//  when the operator clicks).
// ============================================================
(function () {
  const STORAGE_KEY = 'hyperion.theme';   // values: '', 'light', 'dark'
  const root = document.documentElement;
  const saved = localStorage.getItem(STORAGE_KEY) || '';

  // applyTheme reads `btn` from this closure (it highlights the
  // active icon inside the toggle button). Function declarations
  // ARE hoisted, but `const btn` is NOT — it sits in the temporal
  // dead zone until the const line evaluates. The old order
  // called applyTheme(saved) BEFORE the `const btn` declaration,
  // so the function body tripped over a TDZ ReferenceError on
  // every page load:
  //   Uncaught ReferenceError: Cannot access 'btn' before initialization
  //     at applyTheme (...)
  // Initialize `btn` FIRST, then apply the saved theme.
  const btn = document.getElementById('theme-toggle');
  applyTheme(saved);
  if (!btn) return;
  btn.addEventListener('click', cycle);
  document.addEventListener('keydown', (ev) => {
    if (!isShortcutContext(ev)) return;
    if (ev.key === 't' || ev.key === 'T') { cycle(); ev.preventDefault(); }
  });

  function cycle() {
    const cur = localStorage.getItem(STORAGE_KEY) || '';
    const next = cur === ''     ? 'light'
              : cur === 'light' ? 'dark'
              :                   '';
    if (next) localStorage.setItem(STORAGE_KEY, next);
    else      localStorage.removeItem(STORAGE_KEY);
    applyTheme(next);
    toast(`Theme: ${next || 'auto (system)'}`, 'info', 1800);
  }
  function applyTheme(t) {
    if (t === 'light' || t === 'dark') root.setAttribute('data-theme', t);
    else                                root.removeAttribute('data-theme');
    // Highlight the active icon
    const dark = btn && btn.querySelector('.theme-dark-icon');
    const light = btn && btn.querySelector('.theme-light-icon');
    const auto = btn && btn.querySelector('.theme-auto-icon');
    if (dark)  dark.style.display  = t === 'dark'  ? '' : 'none';
    if (light) light.style.display = t === 'light' ? '' : 'none';
    if (auto)  auto.style.display  = t === ''      ? '' : 'none';
  }
})();

// ============================================================
//  Toast notifications. Surface flash messages, HTMX errors,
//  and one-off operator feedback. API: window.toast(msg, kind, ms).
// ============================================================
(function () {
  const host = document.getElementById('toasts');
  if (!host) return;

  window.toast = function (msg, kind = 'info', ms = 4000) {
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    el.innerHTML = `
      <span class="toast-msg"></span>
      <button class="toast-close" aria-label="Dismiss">×</button>`;
    el.querySelector('.toast-msg').textContent = msg;
    el.querySelector('.toast-close').addEventListener('click', () => dismiss(el));
    host.appendChild(el);
    if (ms > 0) setTimeout(() => dismiss(el), ms);
  };
  function dismiss(el) {
    if (!el || el.classList.contains('leaving')) return;
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 200);
  }

  // Inline config saves (hx-post + HX-Trigger) surface here without a
  // page reload. The handler answers 204 with
  //   HX-Trigger: {"toast":{"level":"ok|error","text":"…"}}
  // and HTMX dispatches a `toast` event carrying that object. Map the
  // server's level onto the toast kind; a save that reordered the vhost
  // (nginx -t) or hit a validation error arrives on the SAME channel, as
  // an error toast, so the operator never loses feedback to the missing
  // reload.
  document.body.addEventListener('toast', (ev) => {
    const d = ev.detail || {};
    const kind = d.level === 'error' ? 'error' : (d.level === 'ok' ? 'success' : 'info');
    window.toast(d.text || 'Saved.', kind, kind === 'error' ? 7000 : 3500);
  });

  // Auto-surface HTMX errors as red toasts.
  document.addEventListener('htmx:responseError', (ev) => {
    const code = ev.detail?.xhr?.status ?? '???';
    window.toast(`Request failed (${code}). Try again, or check the audit log for details.`, 'error');
  });
  document.addEventListener('htmx:sendError', () => {
    window.toast('Network error — couldn’t reach the server. Check your connection and try again.', 'error');
  });

  // Translate ?flash= / ?flash_error= query params into toasts on page load
  // so handlers don't have to render their own flash divs.
  const params = new URLSearchParams(location.search);
  const ok = params.get('flash');
  const er = params.get('flash_error');
  if (ok) window.toast(ok, 'success', 5000);
  if (er) window.toast(er, 'error', 7000);
  if (ok || er) {
    // Drop the flash from the URL so a refresh doesn't replay it.
    params.delete('flash'); params.delete('flash_error');
    const q = params.toString();
    history.replaceState(null, '', location.pathname + (q ? '?' + q : '') + location.hash);
  }
})();

// ============================================================
//  Command palette — Cmd+K / Ctrl+K. Static index of nav routes
//  + dynamic search via /api/search when the input is non-empty.
//  Keyboard: ↑ ↓ to move, Enter to follow, Esc to close.
// ============================================================
(function () {
  const STATIC_ITEMS = [
    { group: 'Pages', label: 'Dashboard',       href: '/',           keys: ['dashboard', 'home', 'overview'] },
    { group: 'Pages', label: 'Hostings',        href: '/hostings',   keys: ['hostings', 'sites', 'domains'] },
    { group: 'Pages', label: 'Add a website',   href: '/hostings/new', keys: ['new', 'create', 'add', 'hosting', 'website', 'site'] },
    { group: 'Pages', label: 'Stats',           href: '/stats',      keys: ['stats', 'metrics', 'bandwidth'] },
    { group: 'Pages', label: 'Profiles',        href: '/profiles',   keys: ['profiles', 'limits', 'templates'] },
    { group: 'Pages', label: 'Service health',  href: '/services',   keys: ['services', 'health', 'systemctl'] },
    { group: 'Pages', label: 'Audit log',       href: '/audit',      keys: ['audit', 'log', 'history'] },
    { group: 'Pages', label: 'Email log',       href: '/emails',     keys: ['email', 'mail', 'smtp', 'sent', 'inbox', 'outbox'] },
    { group: 'Pages', label: 'Users',           href: '/admin/users',keys: ['users', 'admin', 'rbac', 'roles'] },
    { group: 'Pages', label: 'My profile',      href: '/profile',    keys: ['profile', 'me', 'account', '2fa'] },
    { group: 'Pages', label: 'Settings',        href: '/settings',   keys: ['settings', 'config', 'agent', 'smtp', 'slack', 'api', 'api keys', 'backups', 'trash', 'retention', 'letters', 'alerts', 'bans', 'geoip', 'updates', 'previews', '2fa'] },
    { group: 'Pages', label: 'Nodes / install', href: '/install',    keys: ['nodes', 'install', 'invite', 'enroll'] },
    { group: 'Actions', label: 'Show keyboard shortcuts', action: 'shortcuts', keys: ['shortcuts', 'keys', 'help'] },
    { group: 'Actions', label: 'Sign out',      action: 'logout',    keys: ['logout', 'signout', 'exit'] },
  ];

  const backdrop = document.getElementById('cmdk');
  const input    = document.getElementById('cmdk-input');
  const list     = document.getElementById('cmdk-list');
  if (!backdrop || !input || !list) return;

  let items = STATIC_ITEMS.slice();
  let active = 0;
  let dynamicFetch = null;

  function open() {
    backdrop.classList.add('open');
    input.value = '';
    items = STATIC_ITEMS.slice();
    active = 0;
    render();
    setTimeout(() => input.focus(), 30);
  }
  function close() {
    backdrop.classList.remove('open');
  }
  function render() {
    list.innerHTML = '';
    if (items.length === 0) {
      list.innerHTML = '<li class="cmdk-empty">No matches. Try a different search.</li>';
      return;
    }
    let lastGroup = '';
    items.forEach((it, idx) => {
      if (it.group !== lastGroup) {
        const h = document.createElement('li');
        h.className = 'cmdk-group';
        h.textContent = it.group;
        list.appendChild(h);
        lastGroup = it.group;
      }
      const li = document.createElement('li');
      li.role = 'option';
      const btn = document.createElement('button');
      btn.className = 'cmdk-item' + (idx === active ? ' active' : '');
      btn.dataset.idx = String(idx);
      btn.innerHTML = `<span>${escapeHtml(it.label)}</span>` +
        (it.meta ? `<span class="cmdk-meta">${escapeHtml(it.meta)}</span>` : '');
      btn.addEventListener('click', () => activate(idx));
      btn.addEventListener('mouseenter', () => { active = idx; updateActive(); });
      li.appendChild(btn);
      list.appendChild(li);
    });
  }
  function updateActive() {
    list.querySelectorAll('.cmdk-item').forEach((el) => {
      el.classList.toggle('active', Number(el.dataset.idx) === active);
    });
    const cur = list.querySelector('.cmdk-item.active');
    if (cur) cur.scrollIntoView({ block: 'nearest' });
  }
  function activate(idx) {
    const it = items[idx];
    if (!it) return;
    close();
    if (it.action === 'theme') {
      document.getElementById('theme-toggle')?.click();
    } else if (it.action === 'shortcuts') {
      document.getElementById('shortcuts')?.classList.add('open');
    } else if (it.action === 'logout') {
      // Build a tiny form so we go through the CSRF-exempt POST /logout.
      const f = document.createElement('form');
      f.method = 'post';
      f.action = '/logout';
      document.body.appendChild(f);
      f.submit();
    } else if (it.href) {
      location.assign(it.href);
    }
  }
  function filterStatic(q) {
    const needle = q.trim().toLowerCase();
    if (!needle) return STATIC_ITEMS.slice();
    return STATIC_ITEMS.filter((it) =>
      it.label.toLowerCase().includes(needle) ||
      it.keys.some((k) => k.includes(needle))
    );
  }
  async function liveSearch(q) {
    const needle = q.trim();
    if (needle.length < 2) return [];
    if (dynamicFetch) dynamicFetch.abort?.();
    const ac = new AbortController();
    dynamicFetch = ac;
    try {
      const r = await fetch(`/api/search?q=${encodeURIComponent(needle)}`, {
        signal: ac.signal,
        headers: { 'accept': 'application/json' },
      });
      if (!r.ok) return [];
      const j = await r.json();
      const out = [];
      for (const h of (j.hostings || [])) {
        out.push({ group: 'Hostings', label: h.domain, href: `/hostings/${encodeURIComponent(h.domain)}`, meta: h.state, keys: [h.domain] });
      }
      for (const u of (j.users || [])) {
        out.push({ group: 'Users', label: u.username, href: '/admin/users', meta: u.role, keys: [u.username] });
      }
      return out;
    } catch (e) {
      return [];
    }
  }
  input.addEventListener('input', async () => {
    const q = input.value;
    items = filterStatic(q);
    active = 0;
    render();
    if (q.trim().length >= 2) {
      const live = await liveSearch(q);
      if (input.value === q) {
        items = [...live, ...filterStatic(q)];
        active = 0;
        render();
      }
    }
  });
  input.addEventListener('keydown', (ev) => {
    if (ev.key === 'ArrowDown') { active = Math.min(active + 1, items.length - 1); updateActive(); ev.preventDefault(); }
    else if (ev.key === 'ArrowUp')   { active = Math.max(active - 1, 0); updateActive(); ev.preventDefault(); }
    else if (ev.key === 'Enter')     { activate(active); ev.preventDefault(); }
    else if (ev.key === 'Escape')    { close(); ev.preventDefault(); }
  });
  backdrop.addEventListener('click', (ev) => {
    if (ev.target === backdrop) close();
  });

  document.addEventListener('keydown', (ev) => {
    if ((ev.metaKey || ev.ctrlKey) && (ev.key === 'k' || ev.key === 'K')) {
      ev.preventDefault();
      backdrop.classList.contains('open') ? close() : open();
    }
  });

  // Expose for the shortcut overlay.
  window.openCommandPalette = open;
})();

// ============================================================
//  Keyboard shortcuts overlay + global navigation shortcuts.
// ============================================================
(function () {
  const overlay = document.getElementById('shortcuts');
  if (!overlay) return;
  function show() { overlay.classList.add('open'); }
  function hide() { overlay.classList.remove('open'); }
  overlay.addEventListener('click', (ev) => { if (ev.target === overlay) hide(); });

  let lastG = 0;
  document.addEventListener('keydown', (ev) => {
    if (!isShortcutContext(ev)) return;
    if (ev.key === 'Escape') {
      document.querySelectorAll('.cmdk-backdrop.open, .shortcuts-backdrop.open')
        .forEach((el) => el.classList.remove('open'));
      return;
    }
    if (ev.key === '?') { show(); ev.preventDefault(); return; }
    if (ev.key === 'g') { lastG = Date.now(); return; }
    if (Date.now() - lastG < 900 && ev.key.length === 1) {
      const k = ev.key.toLowerCase();
      const map = { h: '/hostings', d: '/', s: '/stats', u: '/admin/users', a: '/audit', p: '/profiles', n: '/install' };
      if (map[k]) { location.assign(map[k]); ev.preventDefault(); }
      lastG = 0;
      return;
    }
    if (ev.key === 'n' || ev.key === 'N') { location.assign('/hostings/new'); ev.preventDefault(); }
    // GitHub/Vercel convention: bare "/" focuses the page's primary
    // search input. Only fires when one exists on the current page,
    // and only outside other text inputs (isShortcutContext guard).
    if (ev.key === '/') {
      const s = document.querySelector('input[type="search"]');
      if (s) {
        s.focus();
        s.select();
        ev.preventDefault();
      }
    }
  });
})();

// Mark inputs as `.touched` after first blur so the red ":invalid"
// border only shows up AFTER the user has interacted — fresh fields
// stay neutral on a freshly-loaded form.
document.addEventListener('blur', (ev) => {
  const t = ev.target;
  if (!t) return;
  if (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT') {
    t.classList.add('touched');
  }
}, true);
// Also mark every field as touched on submit attempt so the user
// can see what failed validation if the browser refuses to submit.
document.addEventListener('submit', (ev) => {
  const f = ev.target;
  if (!f || !f.querySelectorAll) return;
  f.querySelectorAll('input, textarea, select').forEach((el) => el.classList.add('touched'));
}, true);

// Shared: only fire global shortcuts when the user isn't typing.
function isShortcutContext(ev) {
  if (ev.metaKey || ev.ctrlKey || ev.altKey) return false;
  const t = ev.target;
  if (!t) return true;
  const tag = (t.tagName || '').toLowerCase();
  if (tag === 'input' || tag === 'textarea' || tag === 'select') return false;
  if (t.isContentEditable) return false;
  return true;
}

// ============================================================
//  Interactive sparklines — hover tooltips with value + time.
//  Every <svg class="spark-svg" data-points='[...]'> gets a marker
//  dot + vertical line + tooltip that follow the mouse to the
//  nearest data point. The data-points array carries {x, y, v, t}
//  in viewBox coords (0..600 wide, 0..60 tall).
// ============================================================
(function () {
  const NS = 'http://www.w3.org/2000/svg';

  function init(svg) {
    let points;
    try { points = JSON.parse(svg.dataset.points); } catch (_) { return; }
    if (!Array.isArray(points) || points.length < 2) return;

    // Tooltip lives in the spark-card parent (or any positioned
    // ancestor we make). We make the SVG's direct parent the
    // anchor so positioning math is uniform.
    const host = svg.parentElement;
    if (!host) return;
    if (getComputedStyle(host).position === 'static') {
      host.style.position = 'relative';
    }
    const tip = document.createElement('div');
    tip.className = 'spark-tip';
    tip.style.display = 'none';
    host.appendChild(tip);

    // Transparent hitbox covering the whole viewBox — guarantees the
    // SVG receives mousemove anywhere in its bounds, not just over
    // the painted area. Inserted FIRST so subsequent paints overlay
    // it visually but it still captures events (with pointer-events:
    // all from CSS).
    const hit = document.createElementNS(NS, 'rect');
    hit.setAttribute('x', '0'); hit.setAttribute('y', '0');
    hit.setAttribute('width', '600'); hit.setAttribute('height', '60');
    hit.setAttribute('class', 'spark-hitbox');
    svg.insertBefore(hit, svg.firstChild);

    // SVG-side marker dot + vertical crosshair line.
    const vline = document.createElementNS(NS, 'line');
    vline.setAttribute('y1', '0'); vline.setAttribute('y2', '60');
    vline.setAttribute('class', 'spark-vline');
    vline.style.display = 'none';
    svg.appendChild(vline);
    const dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('r', '3');
    dot.setAttribute('class', 'spark-dot');
    dot.style.display = 'none';
    svg.appendChild(dot);

    function nearest(svgX) {
      let best = points[0], bestDist = Math.abs(points[0].x - svgX);
      for (const p of points) {
        const d = Math.abs(p.x - svgX);
        if (d < bestDist) { best = p; bestDist = d; }
      }
      return best;
    }

    svg.addEventListener('mousemove', (ev) => {
      const r = svg.getBoundingClientRect();
      if (r.width === 0) return;
      const svgX = ((ev.clientX - r.left) / r.width) * 600;
      const p = nearest(svgX);
      dot.setAttribute('cx', p.x);
      dot.setAttribute('cy', p.y);
      dot.style.display = '';
      vline.setAttribute('x1', p.x);
      vline.setAttribute('x2', p.x);
      vline.style.display = '';
      // Tip position in CSS pixels relative to the host.
      const pxX = (p.x / 600) * r.width;
      const pxY = (p.y / 60) * r.height;
      tip.style.display = '';
      tip.innerHTML = `<strong>${escapeText(p.v)}</strong><span class="spark-tip-t">${escapeText(p.t)}</span>`;
      // Clamp so the tooltip stays inside the host.
      const tipW = tip.offsetWidth || 100;
      let left = pxX + 10;
      if (left + tipW > r.width) left = pxX - tipW - 10;
      tip.style.left = Math.max(2, left) + 'px';
      tip.style.top = Math.max(2, pxY - 34) + 'px';
    });
    svg.addEventListener('mouseleave', () => {
      tip.style.display = 'none';
      dot.style.display = 'none';
      vline.style.display = 'none';
    });
  }

  function escapeText(s) {
    return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  }

  function mountAll() {
    document.querySelectorAll('svg.spark-svg[data-points]').forEach((el) => {
      if (el.dataset.sparkMounted === '1') return;
      el.dataset.sparkMounted = '1';
      init(el);
    });
  }
  mountAll();
  // Re-mount after HTMX swaps so dynamically-loaded sparklines also wire up.
  document.addEventListener('htmx:afterSettle', mountAll);
  // The live-refresh driver swaps innerHTML without htmx; re-arm hover there too.
  document.addEventListener('live-refresh-swapped', mountAll);
})();
})();

(function () {
  'use strict';
  // Legacy role hierarchy — still honoured for the few items whose SERVER gate
  // is role-based, not capability-based (Background jobs = is_admin_or_higher,
  // Nodes/install = is_super_admin). Capability-gated items use data-require-caps.
  const RANK = { 'viewer': 0, 'operator': 1, 'admin': 2, 'super_admin': 3 };
  // Most-restrictive defaults while the fetch is in flight (viewer role, no
  // caps, tenant scope), so a slow network only ever REVEALS items, never
  // briefly flashes a privileged one to someone who can't use it.
  document.body.dataset.role = 'viewer';
  document.body.dataset.caps = '';
  document.body.dataset.scopeAll = 'false';
  // Deployment mode is NOT a permission, so the pessimistic default above
  // is wrong for it: hiding cluster chrome pre-fetch would make a real
  // master flash its nodes UI off on every page load. Seed from the last
  // known value instead, so the steady state never flickers in either
  // direction; a first visit in a fresh browser assumes master, which only
  // ever shows too much for one frame rather than hiding something real.
  try { document.body.dataset.mode = localStorage.getItem('hyperionMode') || 'master'; }
  catch (_) { document.body.dataset.mode = 'master'; }
  apply();

  fetch('/api/me/role', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : null)
    .then(me => {
      let role = 'viewer', caps = [], scopeAll = false;
      if (me && typeof me === 'object') {
        role = (me.role || 'viewer').trim();
        if (Array.isArray(me.caps)) caps = me.caps;
        scopeAll = !!me.scope_all;
      }
      document.body.dataset.role = role;
      document.body.dataset.caps = caps.join(' ');
      document.body.dataset.scopeAll = scopeAll ? 'true' : 'false';
      const mode = (me && typeof me.mode === 'string' && me.mode.trim()) || 'master';
      document.body.dataset.mode = mode;
      try { localStorage.setItem('hyperionMode', mode); } catch (_) {}
      // Friendly label for the user-pill — keep in sync with role_label()
      // in handlers/mod.rs.
      const ROLE_LABELS = { super_admin: 'Owner', admin: 'Administrator', operator: 'Operator', customer: 'Customer', viewer: 'Read-only' };
      const pill = document.getElementById('sidebar-role');
      if (pill) pill.textContent = ROLE_LABELS[role] || role;
      apply();
    })
    .catch(() => apply());
  // Content swapped in without a page load (the hosting detail's in-place
  // saves) has not been through the gates above yet.
  document.addEventListener('live-refresh-swapped', () => apply());

  function apply() {
    const role = document.body.dataset.role || 'viewer';
    const myRank = RANK[role] ?? 0;
    const caps = new Set((document.body.dataset.caps || '').split(/\s+/).filter(Boolean));
    const scopeAll = document.body.dataset.scopeAll === 'true';
    const standalone = document.body.dataset.mode === 'standalone';
    const show = (el, ok) => { el.style.display = ok ? '' : 'none'; };

    // Cluster chrome on a one-server install is noise, not information:
    // node pickers with one entry, "Node" columns that always say the same
    // thing, enrollment invites nobody will redeem. This is presentation
    // only — like every rule here it is NOT a security boundary, so nothing
    // that needs enforcing may rely on it.
    document.querySelectorAll('[data-cluster-only]').forEach(el => show(el, !standalone));
    document.querySelectorAll('[data-standalone-only]').forEach(el => show(el, standalone));

    // Legacy role-rank minimum (data-role-min="admin").
    document.querySelectorAll('[data-role-min]').forEach(el => {
      show(el, myRank >= (RANK[el.dataset.roleMin] ?? 99));
    });
    // Legacy negative role allowlist (data-hide-roles="customer,viewer").
    document.querySelectorAll('[data-hide-roles]').forEach(el => {
      const hide = (el.dataset.hideRoles || '').split(',').map(s => s.trim()).filter(Boolean);
      show(el, !hide.includes(role));
    });
    // Capability gating — the real one. Show only if the user holds ALL the
    // listed caps (space/comma separated) AND, when data-require-scope-all is
    // present, all-hostings scope. Mirrors the server can()/scope_all() gates
    // so the UI never offers something that would 403/redirect. Works for
    // custom roles AND built-ins (both report their caps via /api/me/role).
    document.querySelectorAll('[data-require-caps]').forEach(el => {
      const need = (el.dataset.requireCaps || '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
      let ok = need.every(c => caps.has(c));
      if (ok && el.hasAttribute('data-require-scope-all') && !scopeAll) ok = false;
      show(el, ok);
    });
    // data-require-scope-all on its own (admin-scope only, no specific cap).
    document.querySelectorAll('[data-require-scope-all]:not([data-require-caps])').forEach(el => {
      show(el, scopeAll);
    });
    if (role === 'customer') document.body.classList.add('role-customer');
    // Collapse any nav section whose links are now all hidden, so a lone
    // section label ("Security") never lingers above an empty group.
    document.querySelectorAll('.nav-section').forEach(sec => {
      const links = sec.querySelectorAll('.nav-link');
      if (!links.length) return;
      const anyVisible = Array.from(links).some(a => a.style.display !== 'none');
      sec.style.display = anyVisible ? '' : 'none';
    });
  }
})();

(function () {
  'use strict';
  const backdrop = document.getElementById('app-modal-backdrop');
  const modal = document.getElementById('app-modal');
  const titleEl = document.getElementById('app-modal-title-text');
  const bodyEl = document.getElementById('app-modal-body');
  const cancelBtn = document.getElementById('app-modal-cancel');
  const confirmBtn = document.getElementById('app-modal-confirm');
  const requireRow = document.getElementById('app-modal-require-row');
  const requireTokenEl = document.getElementById('app-modal-require-token');
  const requireInput = document.getElementById('app-modal-require-input');
  if (!backdrop || !modal) return;
  let requireToken = null;

  let pendingForm = null;
  let lastFocused = null;

  function open(form) {
    pendingForm = form;
    lastFocused = document.activeElement;
    const title = form.dataset.confirmTitle || 'Are you sure?';
    const body = form.dataset.confirmBody || '';
    const confirmLabel = form.dataset.confirmConfirmLabel || 'Confirm';
    const variant = (form.dataset.confirmVariant || 'primary').toLowerCase();
    titleEl.textContent = title;
    bodyEl.textContent = body;
    confirmBtn.textContent = confirmLabel;
    confirmBtn.classList.remove('danger', 'primary');
    confirmBtn.classList.add(variant === 'danger' ? 'danger' : 'primary');
    // Type-to-confirm gate. data-confirm-require="<token>" forces the
    // operator to type <token> exactly before the Confirm button
    // unlocks. We use the hosting domain for delete (and similar
    // destructive actions); typo or wrong domain → button stays
    // disabled. Way harder to accidentally delete the wrong site.
    requireToken = form.dataset.confirmRequire || null;
    if (requireToken) {
      requireTokenEl.textContent = requireToken;
      requireInput.value = '';
      requireRow.style.display = '';
      confirmBtn.disabled = true;
      confirmBtn.style.opacity = '0.5';
      confirmBtn.style.cursor = 'not-allowed';
    } else {
      requireRow.style.display = 'none';
      confirmBtn.disabled = false;
      confirmBtn.style.opacity = '';
      confirmBtn.style.cursor = '';
    }
    backdrop.style.display = 'flex';
    // Focus: type-to-confirm input first (intent is to type), else
    // Cancel button (safer default — Enter on Confirm requires
    // explicit intent).
    setTimeout(() => {
      if (requireToken) requireInput.focus();
      else cancelBtn.focus();
    }, 0);
    document.body.style.overflow = 'hidden';
  }

  requireInput.addEventListener('input', () => {
    if (!requireToken) return;
    const match = requireInput.value === requireToken;
    confirmBtn.disabled = !match;
    confirmBtn.style.opacity = match ? '' : '0.5';
    confirmBtn.style.cursor = match ? '' : 'not-allowed';
  });
  requireInput.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !confirmBtn.disabled) {
      ev.preventDefault();
      confirmBtn.click();
    }
  });
  function close() {
    backdrop.style.display = 'none';
    document.body.style.overflow = '';
    pendingForm = null;
    if (lastFocused && lastFocused.focus) lastFocused.focus();
  }
  cancelBtn.addEventListener('click', close);
  backdrop.addEventListener('click', ev => {
    // Click outside the modal panel cancels.
    if (ev.target === backdrop) close();
  });
  document.addEventListener('keydown', ev => {
    if (backdrop.style.display !== 'flex') return;
    if (ev.key === 'Escape') { ev.preventDefault(); close(); }
  });
  confirmBtn.addEventListener('click', () => {
    const f = pendingForm;
    close();
    if (!f) return;
    // Mark as confirmed so our submit handler lets it through.
    f.dataset.confirmed = '1';
    // Defensive: if the form was disconnected while the dialog was open
    // (a live-refresh region swapped under it — held off above, but belt
    // and braces), submit() on a detached form is a silent no-op. Find the
    // live form for the same action + hidden fields and submit that.
    let target = f;
    if (!f.isConnected) {
      const action = f.getAttribute('action');
      const hidden = {};
      f.querySelectorAll('input[type=hidden]').forEach(i => { hidden[i.name] = i.value; });
      target = [...document.querySelectorAll(`form[action="${action}"]`)].find(g =>
        Object.entries(hidden).every(([n, v]) => {
          const el = g.querySelector(`input[name="${n}"]`);
          return el && el.value === v;
        })) || null;
      if (target) target.dataset.confirmed = '1';
    }
    if (!target) return;
    if (target.requestSubmit) {
      target.requestSubmit();
    } else {
      target.submit();
    }
  });

  // Capture-phase submit listener so we intercept BEFORE any
  // legacy onsubmit attribute fires. Forms that already confirmed
  // pass through without re-prompting.
  document.addEventListener('submit', ev => {
    const form = ev.target;
    if (!form || !form.dataset || !form.dataset.confirmTitle) return;
    if (form.dataset.confirmed === '1') {
      // Reset for next submit attempt.
      delete form.dataset.confirmed;
      return;
    }
    ev.preventDefault();
    ev.stopPropagation();
    open(form);
  }, true);
})();

(function () {
  'use strict';
  const btn = document.getElementById('bell-btn');
  const badge = document.getElementById('bell-badge');
  const dropdown = document.getElementById('bell-dropdown');
  const list = document.getElementById('bell-list');
  const markAllBtn = document.getElementById('bell-mark-all');
  if (!btn || !dropdown || !list) return;

  function position() {
    // Horizontal anchor: right-aligned to the viewport edge.
    // On narrow viewports we ignore the bell position and pin the
    // dropdown to both edges with margin — otherwise on phones
    // (where the sidebar is collapsed to a top bar and the bell
    // sits near right edge), the dropdown would render off-screen.
    const r = btn.getBoundingClientRect();
    if (window.innerWidth <= 520) {
      // Full-width-ish on phones — overrides CSS that already
      // does the same at 480px, but covers the 481–520 range.
      dropdown.style.left = '8px';
      dropdown.style.right = '8px';
      dropdown.style.width = 'auto';
    } else {
      // Left-anchor to the bell, then CLAMP so the whole dropdown
      // stays on-screen. The bell lives in the LEFT sidebar, so the
      // old right-anchor (right = innerWidth - bell.right) pushed a
      // 22rem-wide dropdown off the LEFT edge — its left half was
      // clipped by the viewport. Align the dropdown's left with the
      // bell and slide it right only as far as needed to fit.
      dropdown.style.right = '';
      dropdown.style.width = '';
      const width = dropdown.offsetWidth || 352;
      let left = Math.min(r.left, window.innerWidth - width - 8);
      left = Math.max(8, left);
      dropdown.style.left = left + 'px';
    }
    // Vertical anchor: the bell lives in the sidebar FOOTER, so on
    // desktop it sits near the bottom of the viewport — a downward
    // dropdown spills off-screen and the operator sees nothing
    // (the reported bug). Open UPWARD when there isn't enough room
    // below and there is room above; otherwise fall back to down
    // (e.g. the mobile top-bar layout where the bell is up high).
    // Must run AFTER the dropdown is visible so offsetHeight is real
    // — the caller unhides first.
    const gap = 8;
    const h = dropdown.offsetHeight || 0;
    const roomBelow = window.innerHeight - r.bottom;
    const roomAbove = r.top;
    if (roomBelow < h + gap && roomAbove > roomBelow) {
      // Flip up: pin the dropdown's bottom just above the bell.
      dropdown.style.top = '';
      dropdown.style.bottom = (window.innerHeight - r.top + gap) + 'px';
    } else {
      dropdown.style.bottom = '';
      dropdown.style.top = (r.bottom + gap) + 'px';
    }
  }

  function csrfToken() {
    // The session_csrf token is available via a cookie set by axum.
    // Fallback: try meta. If neither, /api endpoints accept session-
    // cookie auth and we'll just send an empty token.
    const m = document.cookie.match(/(?:^|; )hyperion_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  async function refresh(silent = false) {
    try {
      const r = await fetch('/api/notifications/feed?limit=10', {
        credentials: 'same-origin',
        headers: { 'accept': 'application/json' },
      });
      if (!r.ok) {
        if (!silent) toast?.('Couldn’t load notifications. Try again in a moment.', 'error');
        return;
      }
      const j = await r.json();
      renderFeed(j);
    } catch (_) { /* swallow */ }
  }

  function renderFeed(feed) {
    const total = feed.unread_total || 0;
    if (total > 0) {
      badge.hidden = false;
      badge.textContent = total > 99 ? '99+' : String(total);
    } else {
      badge.hidden = true;
    }
    list.innerHTML = '';
    if (!feed.items || feed.items.length === 0) {
      const li = document.createElement('li');
      li.className = 'bell-empty';
      li.textContent = 'No notifications yet.';
      list.appendChild(li);
      return;
    }
    for (const n of feed.items) {
      const li = document.createElement('li');
      li.className = 'bell-item' + (n.read_at ? '' : ' unread') + ' sev-' + escape(n.severity);
      const a = document.createElement('a');
      // Through the panel's open route: it marks the row read, THEN
      // redirects. A fetch fired on click raced the navigation and was
      // often cancelled, leaving the alert unread.
      a.href = '/notifications/' + encodeURIComponent(n.id) + '/open';
      a.className = 'bell-link';
      a.dataset.id = String(n.id);
      a.innerHTML =
        `<span class="bell-dot"></span>` +
        `<span class="bell-text">` +
          `<strong>${escape(n.title)}</strong>` +
          (n.body ? `<br><span class="bell-body">${escape(n.body)}</span>` : '') +
          `<span class="bell-meta">${fmtAgo(n.created_at)}</span>` +
        `</span>`;
      li.appendChild(a);
      list.appendChild(li);
    }
    // The feed just grew from "Loading…" to its full height; if the
    // dropdown is open, re-anchor so an upward flip stays pinned
    // above the bell instead of overflowing once content settles.
    if (!dropdown.hidden) position();
  }

  async function markAll() {
    try {
      await fetch('/api/notifications/mark-all-read', {
        method: 'POST',
        credentials: 'same-origin',
      });
      refresh(true);
    } catch (_) { /* swallow */ }
  }

  markAllBtn?.addEventListener('click', (ev) => {
    ev.stopPropagation();
    markAll();
  });

  btn.addEventListener('click', (ev) => {
    ev.stopPropagation();
    const open = !dropdown.hidden;
    if (open) {
      dropdown.hidden = true;
      btn.setAttribute('aria-expanded', 'false');
    } else {
      // Unhide BEFORE position() so it can measure the real
      // offsetHeight and decide whether to open up or down.
      dropdown.hidden = false;
      position();
      btn.setAttribute('aria-expanded', 'true');
      refresh(true);
    }
  });
  document.addEventListener('click', (ev) => {
    if (dropdown.hidden) return;
    if (dropdown.contains(ev.target) || btn.contains(ev.target)) return;
    dropdown.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
  });
  window.addEventListener('resize', () => { if (!dropdown.hidden) position(); });

  function escape(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }
  function fmtAgo(unix) {
    const now = Math.floor(Date.now() / 1000);
    const dt = now - unix;
    if (dt < 60) return 'just now';
    if (dt < 3600) return Math.floor(dt / 60) + 'm ago';
    if (dt < 86400) return Math.floor(dt / 3600) + 'h ago';
    return Math.floor(dt / 86400) + 'd ago';
  }

  // Poll quietly every 60s for new notifications (mostly so the
  // badge ticks up without a refresh). 60s is gentle on the server
  // and matches the existing scheduler tick cadence.
  // Not from a hidden tab — it catches up as soon as it is looked at.
  refresh(true);
  setInterval(() => { if (!document.hidden) refresh(true); }, 60_000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(true); });
})();

// ============================================================
//  Trash sidebar badge — separate poll from the notification
//  bell so a slow notification probe doesn't delay the trash
//  count and vice versa. /api/trash-count returns {"count": N}.
//  Hidden when N == 0 so the sidebar stays quiet on empty
//  clusters.
// ============================================================
(function () {
  'use strict';
  const badge = document.getElementById('nav-trash-badge');
  if (!badge) return;
  async function pollTrash() {
    try {
      const r = await fetch('/api/trash-count', {
        credentials: 'same-origin',
        headers: { 'accept': 'application/json' },
      });
      if (!r.ok) return;
      const j = await r.json();
      const n = Number(j.count || 0);
      if (n > 0) {
        badge.hidden = false;
        badge.textContent = n > 99 ? '99+' : String(n);
      } else {
        badge.hidden = true;
      }
    } catch (_) { /* swallow */ }
  }
  // A hidden tab does not poll (each poll can be a cluster fan-out on a
  // cold cache); it checks once as soon as it is looked at again.
  pollTrash();
  setInterval(() => { if (!document.hidden) pollTrash(); }, 60_000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) pollTrash(); });
})();

// ============================================================
//  Session watchdog. A page left open past its session showed a
//  fully-populated panel that was, in fact, logged out — every
//  number on it stale, every button about to bounce to /login.
//  That is worse than being logged out visibly: it looks live.
//
//  /api/me/role sits behind the auth middleware, so an expired
//  session answers with a redirect to the login page rather than
//  JSON. `fetch` follows that redirect transparently, so the tell
//  is the FINAL url, not the status.
// ============================================================
(function () {
  'use strict';
  let goneAlready = false;
  async function check() {
    if (document.hidden || goneAlready) return;
    try {
      const r = await fetch('/api/me/role', {
        credentials: 'same-origin',
        headers: { 'accept': 'application/json' },
      });
      const loggedOut = r.status === 401
        || /\/login(\?|$)/.test(new URL(r.url, location.href).pathname + location.search)
        || new URL(r.url, location.href).pathname === '/login';
      if (!loggedOut) return;
      goneAlready = true;
      // Carry where they were, so signing back in returns them to it
      // instead of the dashboard.
      const back = encodeURIComponent(location.pathname + location.search);
      location.href = '/login?error=expired&next=' + back;
    } catch (_) {
      // Network blip — say nothing. Bouncing someone to /login because
      // their wifi dropped for two seconds would be its own bug.
    }
  }
  setInterval(check, 60_000);
  // Coming back to a tab is exactly when a session has most likely
  // lapsed, so check then rather than waiting out the interval.
  document.addEventListener('visibilitychange', () => { if (!document.hidden) check(); });
})();

// ============================================================
//  Click-to-copy. Any element with `data-copy="<text>"` copies it
//  and says so in place. Generic on purpose — connection details,
//  paths and hostnames are all things an operator is about to
//  paste somewhere, and selecting them by hand from a sentence is
//  fiddly and error-prone.
//
//  navigator.clipboard needs a secure context; on plain HTTP it is
//  undefined. Fall back to the old execCommand path rather than
//  silently doing nothing, since a panel reached by IP over http
//  is exactly where someone is setting up their first site.
// ============================================================
(function () {
  'use strict';
  function flash(el, msg, ok) {
    const prev = el.getAttribute('data-copy-label') || el.textContent;
    el.setAttribute('data-copy-label', prev);
    el.classList.add(ok ? 'copied' : 'copy-failed');
    const badge = el.querySelector('.copy-hint');
    if (badge) badge.textContent = msg;
    setTimeout(() => {
      el.classList.remove('copied', 'copy-failed');
      if (badge) badge.textContent = 'click to copy';
    }, 1600);
  }
  async function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    if (!ok) throw new Error('copy rejected');
  }
  document.addEventListener('click', async (e) => {
    const el = e.target.closest('[data-copy]');
    if (!el) return;
    try {
      await copy(el.getAttribute('data-copy') || '');
      flash(el, 'copied', true);
    } catch (_) {
      flash(el, 'press ctrl+C', false);
    }
  });
})();

// ============================================================
//  Sidebar status dots — monitoring / WordPress updates / certs.
//  One request for all three, so the dots can never disagree with
//  each other, and a hiccup in one RPC does not turn the sidebar
//  red. Green means "checked, nothing wrong" — which is only
//  honest if we have actually heard back, so nothing is painted
//  until a response arrives.
// ============================================================
(function () {
  'use strict';
  const targets = [
    ['nav-monitoring-dot', 'monitors_down', 'site', 'down'],
    ['nav-wp-dot', 'wp_outdated', 'site', 'waiting on you for WordPress updates'],
    ['nav-certs-dot', 'certs_expiring', 'certificate', 'expiring within 14 days'],
  ];
  if (!targets.some(([id]) => document.getElementById(id))) return;
  function paint(el, n, noun, suffix) {
    if (!el) return;
    el.hidden = false;
    if (n > 0) {
      el.textContent = n > 99 ? '99+' : String(n);
      el.className = 'nav-status-dot bad';
      el.title = n + ' ' + noun + (n === 1 ? '' : 's') + ' ' + suffix;
    } else {
      el.textContent = '';
      el.className = 'nav-status-dot good';
      el.title = 'Nothing needs attention';
    }
  }
  async function poll() {
    if (document.hidden) return;
    try {
      const r = await fetch('/api/nav-status', {
        credentials: 'same-origin',
        headers: { 'accept': 'application/json' },
      });
      if (!r.ok) return;
      const j = await r.json();
      targets.forEach(([id, key, noun, suffix]) =>
        paint(document.getElementById(id), Number(j[key] || 0), noun, suffix));
    } catch (_) { /* leave the dots as they were */ }
  }
  poll();
  setInterval(poll, 60_000);
})();

// ============================================================
//  Running jobs: the bottom progress toast AND the sidebar badge.
//  One poll of /api/jobs-active feeds both — the badge used to have
//  its own 10-second poll of /api/jobs-running-count, the same
//  query, on every page, hidden tab or not. Hidden when 0 so a
//  quiet cluster doesn't draw the eye.
// ============================================================
(function () {
  'use strict';
  const box = document.getElementById('job-toast');
  const badge = document.getElementById('nav-jobs-badge');
  if (!box && !badge) return;
  // /api/jobs-active lists at most this many.
  const LIST_CAP = 50;
  function setBadge(n) {
    if (!badge) return;
    badge.hidden = n === 0;
    badge.textContent = n >= LIST_CAP ? LIST_CAP + '+' : String(n);
  }
  function el(tag, css) { const e = document.createElement(tag); if (css) e.style.cssText = css; return e; }
  function human(k) { return (k || 'job').replace(/_/g, ' '); }
  async function poll() {
    try {
      const r = await fetch('/api/jobs-active', { credentials: 'same-origin', headers: { accept: 'application/json' } });
      if (!r.ok) return false;
      const jobs = await r.json();
      setBadge(Array.isArray(jobs) ? jobs.length : 0);
      if (!box) return Array.isArray(jobs) && jobs.length > 0;
      if (!Array.isArray(jobs) || !jobs.length) { box.hidden = true; box.replaceChildren(); return false; }
      box.hidden = false;
      const frag = document.createDocumentFragment();
      const head = el('div', 'font-size:.7rem;letter-spacing:.04em;text-transform:uppercase;opacity:.7;padding:0 2px');
      head.textContent = jobs.length + ' job' + (jobs.length > 1 ? 's' : '') + ' running';
      frag.appendChild(head);
      jobs.forEach(function (j) {
        const pct = Math.max(0, Math.min(100, Number(j.pct) || 0));
        const a = el('a', 'display:block;text-decoration:none;color:inherit;background:var(--surface-1,#1c1c20);border:1px solid var(--border,#333);border-radius:8px;padding:.5rem .6rem;box-shadow:0 4px 14px rgba(0,0,0,.3)');
        a.href = '/jobs/' + encodeURIComponent(j.id);
        const t = el('div', 'font-size:.82rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis');
        t.textContent = (j.label || human(j.kind)) + (j.target ? (' · ' + j.target) : '');
        const s = el('div', 'font-size:.72rem;opacity:.7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin:.15rem 0 .35rem');
        s.textContent = (j.step ? j.step + ' · ' : '') + pct + '%';
        const bar = el('div', 'height:5px;background:var(--border,#333);border-radius:3px;overflow:hidden');
        const fill = el('div', 'height:100%;width:' + pct + '%;background:var(--accent,#6aa3ff);transition:width .4s ease');
        bar.appendChild(fill);
        a.appendChild(t); a.appendChild(s); a.appendChild(bar);
        frag.appendChild(a);
      });
      box.replaceChildren(frag);
      return true;
    } catch (_) { /* swallow */ }
    return false;
  }
  // Adaptive cadence. This ran every three seconds on EVERY page, whether
  // or not anything was running — a browser left open was twenty requests a
  // minute, for ever, to say "still nothing". Three seconds is right while
  // a job is in flight and the bar is moving; when idle, half a minute is
  // plenty for a job started elsewhere to show up. A hidden tab does not
  // poll at all, and checks once as soon as it comes back.
  const BUSY_MS = 3000;
  const IDLE_MS = 30000;
  let timer = null;
  function schedule(ms) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(run, ms);
  }
  async function run() {
    if (document.hidden) {
      schedule(IDLE_MS);
      return;
    }
    const busy = await poll();
    schedule(busy ? BUSY_MS : IDLE_MS);
  }
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) schedule(0);
  });
  schedule(0);
})();

// Flicker-free live refresh. Any element with `data-live-refresh="<secs>"` and
// an `id` re-fetches THIS page in the background and swaps ONLY that element's
// innerHTML from the fresh copy — no full-page reload, so scroll, focus, and
// everything outside the region are untouched (that's what caused the flicker).
(function () {
  'use strict';
  const nodes = document.querySelectorAll('[data-live-refresh][id]');
  if (!nodes.length) return;
  let lastClick = 0;
  document.addEventListener('click', () => { lastClick = Date.now(); }, true);
  function inputFocused(root) {
    const a = document.activeElement;
    if (!a || !root.contains(a)) return false;
    const t = (a.tagName || '').toLowerCase();
    return t === 'input' || t === 'textarea' || t === 'select' || a.isContentEditable;
  }
  const ticks = [];
  nodes.forEach((node) => {
    const secs = parseInt(node.getAttribute('data-live-refresh'), 10);
    if (!secs || secs < 2) return;
    const id = node.id;
    async function tick(force) {
      // Skip while hidden, mid-interaction, or typing inside the region.
      // `force` (bfcache restore) bypasses the click cooldown but still
      // respects hidden + focus so we never clobber what the user is doing.
      if (document.hidden) return;
      // Not on screen — a region inside a tab panel nobody has opened. This
      // refetches the WHOLE page to swap one region, so it was a full render
      // of the hosting detail every fifteen seconds for an operator sitting
      // on a different tab. `offsetParent` is null for `display:none`.
      if (!node.offsetParent && node.style.position !== 'fixed') return;
      if (!force && Date.now() - lastClick < 4000) return;
      if (inputFocused(node)) return;
      // Never swap the region out from under an OPEN confirm dialog. The
      // form the dialog is about to submit lives inside a live-refresh
      // region (the backup Delete / Restore / DB-only buttons all do), and
      // replacing innerHTML disconnects it. The confirmed submit then calls
      // requestSubmit() on a form no longer in the document, which browsers
      // silently ignore — so the operator confirms "Delete backup" and
      // nothing happens. Hold the refresh while any dialog is up.
      const confirmModal = document.getElementById('app-modal-backdrop');
      if (confirmModal && confirmModal.style.display === 'flex') return;
      try {
        // no-store: the whole point is to defeat the stale HTTP cache the
        // user had to F5 past. Always pull a fresh render.
        const r = await fetch(location.href, { credentials: 'same-origin', cache: 'no-store' });
        if (!r.ok) return;
        const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
        const fresh = doc.getElementById(id);
        const cur = document.getElementById(id);
        // Re-check after the await: a dialog may have opened while the
        // fetch was in flight, and swapping now would disconnect its form
        // just the same.
        if (confirmModal && confirmModal.style.display === 'flex') return;
        if (fresh && cur && fresh.innerHTML !== cur.innerHTML) {
          cur.innerHTML = fresh.innerHTML;
          document.dispatchEvent(new CustomEvent('live-refresh-swapped'));
        }
      } catch (_) { /* swallow — try again next tick */ }
    }
    ticks.push(tick);
    // The interval is re-read from the attribute rather than captured, so a
    // control on the page can retune it live — see the refresh picker on
    // /stats. One timer, restarted; never two racing each other.
    let timer = null;
    // An explicit "0" means paused (the /stats picker's "Paused"); anything
    // else unusable falls back to the interval the page shipped with.
    function paused() { return node.getAttribute('data-live-refresh') === '0'; }
    function period() {
      const v = parseInt(node.getAttribute('data-live-refresh'), 10);
      return (!v || v < 2) ? secs * 1000 : v * 1000;
    }
    function arm() {
      if (timer) clearInterval(timer);
      timer = paused() ? null : setInterval(tick, period());
    }
    arm();
    node.addEventListener('live-refresh-changed', arm);
    document.addEventListener('visibilitychange', () => {
      if (timer) clearInterval(timer);
      timer = null;
      // Nothing ticks while hidden — a background tab polling every 5 s is
      // just load on the box for a page nobody is looking at.
      if (!document.hidden) { arm(); if (!paused()) tick(true); }
    });
  });
  // Back/forward navigation restores a frozen page from the bfcache with
  // whatever data it had when the user left — the exact "I had to F5 to see
  // the new backup" case. Refresh every region promptly on restore.
  window.addEventListener('pageshow', (e) => {
    if (e.persisted) ticks.forEach((t) => t(true));
  });
})();

// Visibility-gated htmx polling. An element marked
// `data-poll-visible data-poll-ms="30000"` with `hx-trigger="poll-tick"` is
// asked to refresh on that cadence, but ONLY while it is actually on screen.
//
// htmx's own `every 30s` cannot do this. Its polling loop fires on a timer
// with no visibility test at all, and a `display:none` element polls exactly
// as hard as a visible one — the per-hosting jobs panel lives on the Backups
// tab and was reaching the owning node every thirty seconds for an operator
// sitting on Overview. htmx does support a `[expr]` trigger filter, which
// would gate it, but that filter is compiled with `Function()`; our CSP
// grants no 'unsafe-eval', so the compile throws, htmx catches it, drops the
// filter and polls anyway. Failing open is the worst case: the gate looks
// present in the markup and does nothing.
//
// So the cadence lives here, next to the rules it has to share:
// nothing ticks in a hidden browser tab, and nothing ticks for a panel whose
// UI tab is closed. Opening the tab resumes on the next beat — no catch-up
// burst, because the panel re-renders from scratch anyway.
(function () {
  // One timer for the page, not one per element: the elements are swapped
  // out by htmx on every refresh (hx-swap="outerHTML"), so a per-element
  // interval would keep firing against a detached node while the fresh one
  // armed a second timer. Re-querying each beat sidesteps that entirely.
  const BEAT_MS = 1000;
  const last = new Map();
  setInterval(function () {
    if (document.hidden) return;
    const now = Date.now();
    document.querySelectorAll('[data-poll-visible][id]').forEach(function (node) {
      // `offsetParent` is null for display:none — the closed-tab case.
      if (!node.offsetParent) return;
      const ms = parseInt(node.getAttribute('data-poll-ms'), 10) || 30000;
      const key = node.id;
      const prev = last.get(key);
      if (prev && now - prev < ms) return;
      last.set(key, now);
      // First sighting: record the time and wait a full period rather than
      // firing at once. The panel was rendered with the page, so its content
      // is already current; an immediate hit would just duplicate that.
      if (!prev) return;
      if (window.htmx) window.htmx.trigger(node, 'poll-tick');
    });
  }, BEAT_MS);
})();
