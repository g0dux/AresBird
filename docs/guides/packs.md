# Script packs

Opt-in NSE-style observes after open ports are known.

```bash
ares scripts list
ares scripts info default
ares scan 10.0.0.5 -p apps --script-pack default
ares probe quick 10.0.0.5 --script-pack web
```

## Shipped packs

| Pack | Focus |
|------|--------|
| `default` | Broad safe builtins + `echo-open` example script |
| `web` | HTTP / app health builtins + `http-headers` script |
| `infra` | DBs, queues, containers, SSH banner |
| `cloud` | Docker / K8s / etcd / Consul / MinIO / Grafana / Prometheus |
| `db` | MySQL, Postgres, Mongo, Redis, MSSQL, … |
| `exposure` | High-risk unauth / network-exposed services |

Root: `./packs` or `ARES_PACKS_DIR`.

## Author a pack

1. Copy `packs/_template/` → `packs/my-pack/`.
2. Edit `pack.json` (`id`, `builtins`, `safe`).
3. Optional: add script dirs with `plugin.json` + `run.ps1` / command (see [plugin-abi.md](../plugin-abi.md)).
4. `ares scripts list` → `ares scan … --script-pack my-pack`.

Builtins are Rust observe wrappers (no shell). Scripts emit NDJSON `Event` lines.

Use `command_windows` + `command_unix` in `plugin.json` so packs run on both OSes (`resolved_command()` picks one).

**Safe packs** skip categories tagged `aggressive`.
