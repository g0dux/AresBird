# CI — fail on new misconfig findings

AresBird can gate CI with `--fail-on-new` (exit **2** when findings ≥ `--min-severity` appear vs the last saved `active-misconfig` run).

## Store location

| Env | Purpose |
|-----|---------|
| `ARES_DATA_DIR` | Directory for `runs.db` (default: OS data dir `/aresbird`) |
| `ARES_STORE_PATH` | Full path to `runs.db` (overrides `ARES_DATA_DIR`) |
| `ARES_NOTIFY_URL` | Optional webhook for scripts |

```bash
ares report list --name active-misconfig
ares report show
ares report prune --keep 10 --name active-misconfig
```

## Local

```bash
# Linux/macOS
TARGET=example.com PORTS=web MIN_SEV=medium ./scripts/ci-misconfig.sh

# Windows PowerShell
$env:TARGET = "example.com"
$env:PORTS = "web"
.\scripts\ci-misconfig.ps1
```

Or call the CLI directly:

```bash
export ARES_DATA_DIR=./.ares-data
ares test example.com -p web --no-path-probes --save -q          # baseline / previous
ares test example.com -p web --no-path-probes --save \
  --fail-on-new --min-severity medium -q --format csv            # exit 2 if delta
```

## GitHub Actions

Workflow: [`.github/workflows/ares-misconfig.yml`](../.github/workflows/ares-misconfig.yml)

- Manual `workflow_dispatch` with `target` / `ports` / `min_severity`
- Caches `.ares-data` between runs as the baseline store
- Optional `secrets.ARES_NOTIFY_URL` for `--notify`

Only point `TARGET` at systems you own or are authorized to test.
