## Screenshots

Drop the screenshot PNGs in this folder (exact filenames matter
— the top-level README's `<img src="...">` references them by
name). Currently embedded in the README:

- `dashboard.png` — the "Welcome back, admin." dashboard page.
- `stats.png`    — the /stats cluster overview.

Adding more screenshots? Drop the file here, add a corresponding
`<td>` cell to the screenshot `<table>` in the top-level
README.md, and update the table's `width` percentages so they
still sum to ~100%.

After replacing / refreshing the files:

```
git add docs/screenshots/*.png
git commit -m "docs: refresh README screenshots"
git push
```

GitHub serves the images straight from the README — no CDN, no
build step. Re-sizes are handled by the `<img width="100%">`
attribute in the README's screenshot table.
