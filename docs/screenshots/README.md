## Screenshots

Drop the three PNGs in this folder (exact filenames matter — the
top-level README's `<img src="...">` references them by name):

- `dashboard.png` — the "Welcome back, admin." dashboard page.
- `hostings.png`  — the /hostings list (with or without rows).
- `stats.png`    — the /stats cluster overview.

After replacing / refreshing the files:

```
git add docs/screenshots/*.png
git commit -m "docs: refresh README screenshots"
git push
```

GitHub serves the images straight from the README — no CDN, no
build step. Re-sizes are handled by the `<img width="100%">`
attribute in the README's screenshot table.
