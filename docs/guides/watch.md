# Watch TUI

```bash
ares watch probe quick 127.0.0.1
ares watch pipeline fixtures/pipeline-example.yaml
```

Live terminal UI (ratatui) over the same pipelines as `ares probe` / `ares pipeline`.

## Controls (typical)

- Filter by severity / CDN / port when the UI exposes those keys (see on-screen help).
- Quit with `q` / Ctrl+C.

## When to use

- Long scans where you want a live surface instead of scrolling NDJSON.
- Demo / teaching — first viewport is the running job, not a report dump.

For automation / CI prefer `ares probe … -q --format csv` without watch.
