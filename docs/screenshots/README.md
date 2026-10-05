## Screenshots

Drop the screenshot PNGs in this folder (exact filenames matter
— the top-level README references them by
name). Currently embedded in the README:

- `dashboard.png` — the dashboard page.
- `stats.png`     — the /stats cluster overview.
- `hostings.png`  — the /hostings list.
- `hosting.png`   — one site's detail page (Overview tab).

They are taken from the local devpanel with demo data, not from a real
server, at 1600x1000 CSS px, 2x, dark theme:

```
DEVSERVER_DEMO=1 DEVSERVER_PORT=8191 \
  cargo test -p hyperion-web --test devserver -- --ignored --nocapture
```

`DEVSERVER_DEMO` seeds seven sites, one suspended, and a few hours of node and per-site metrics. The dev
machine is not a server, so before capturing, replace its hostname and public
IP with `node-1` / `203.0.113.10` and drop the "services down" and "DNS
mismatch" banners; both only say that the laptop has no nginx and the demo
domains do not resolve.

Adding more screenshots? Drop the file here and add a cell to one of the
Markdown tables under "Screenshots" in the top-level README.md.

After replacing / refreshing the files:

```
git add docs/screenshots/*.png
git commit -m "docs: refresh README screenshots"
git push
```

GitHub serves the images straight from the README — no CDN, no
build step. GitHub scales them to the table cell.
