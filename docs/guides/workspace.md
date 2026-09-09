# Living workspace

AresBird keeps a **workspace graph** across scans/probes so hosts, open ports, and findings accumulate.

## Defaults

| Source | Value |
|--------|--------|
| Flag | `--workspace <id>` |
| Env | `ARES_WORKSPACE` |
| Fallback | `default` |
| Skip | `--ephemeral` (do not read/write workspace) |

Store file: `%APPDATA%\aresbird\runs.db` (or `ARES_STORE_PATH` / `ARES_DATA_DIR`).

## Typical flow

```bash
ares probe quick 10.0.0.5 --save
ares scan 10.0.0.5 -p apps --script-pack default
ares report workspace
ares report graph --workspace
```

Use a named lab:

```bash
ares --workspace lab-dmz probe web 10.0.0.0/24 --save
ares --workspace lab-dmz report workspace
```

## Tips

- `--save` persists a **named run**; workspace merge happens unless `--ephemeral`.
- `ares report list` shows recent runs; workspace rows use key `workspace:<id>`.
- Clear/reset by using a new workspace id or deleting the store DB.
