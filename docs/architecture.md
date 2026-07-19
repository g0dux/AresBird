# AresBird architecture

See the workspace crates under `crates/`:

- **ares-core** — events, asset graph (`merge_from`), jobs, timing, port parsing
- **ares-net** — TCP connect scanner, UDP selective probe, host discovery (ICMP/TCP + optional ARP), rate limiter, SYN-raw (ARP next-hop + cookie tracking)
- **ares-proto** — HTTP/TLS/SMB + app observe (DBs, Neo4j+Bolt/ClickHouse, MinIO/S3, Grafana/Kibana/Prometheus/Jenkins, ZK, RDP, RabbitMQ mgmt, messaging, LDAP/Kerberos/VNC, Docker/etcd/Consul/K8s, …), ASN/CDN, webhooks; TLS cert scrape + version/cipher/ALPN; HTTP `session_get` / `session_browse` cookie jars
- **ares-probe** — service detection / OS fingerprint (banner + TTL + cert hints)
- **ares-output** — tables, JSON/NDJSON, INTEL (ASN/CDN/PTR), diff, SQLite run store + living **workspace** upsert
- **ares-plugin-api** — Capability model + Module trait
- **ares-modules** — built-in discover/scan/service/fingerprint/recon/talk/asn/path/active-misconfig
- **ares-cli** — `ares` binary (`probe`, `talk --repl`, workspace flags)

Timing modes: `quiet|normal|fast|insane|stealth` — stealth/quiet add inter-probe jitter, shuffle target order, bland HTTP User-Agent, and slower path delays.

## Workspace vs runs

- **`--save`** → immutable UUID run (CI / `--fail-on-new` / diff).
- **Workspace** (`workspace:<name>`, default `default` via `--workspace` / `ARES_WORKSPACE`) → living asset graph merged after each module/pipeline unless `--ephemeral`.
- Inspect: `ares report workspace`, `ares report graph --workspace`.

## Talk REPL

`ares talk <url> --repl` opens an HTTP(S) observe loop (GET paths, shared cookie jar, transcript).

Also:

```bash
ares talk 127.0.0.1:6379 --proto redis --repl   # duplex Redis read-only (PING/INFO/GET/…)
ares talk 127.0.0.1 --proto ssh --repl           # SSH banner/probe (no shell/auth)
```

Non-HTTP shells (full SSH channel) remain out of scope — Redis is duplex TCP; SSH is observe-only.

## Script packs (optional NSE-style)

Opt-in only — never runs unless `--script-pack <id>` is set.

```bash
ares scripts list
ares scan 10.0.0.5 -p apps --script-pack default
ares probe quick 10.0.0.5 --script-pack default
ares scan 10.0.0.5 -p web --script-pack web
ares scan 10.0.0.5 -p apps --script-pack infra
```

Layout: `packs/<id>/pack.json` (+ optional `*/plugin.json` scripts). Default pack ships **builtins** in Rust (`ftp-banner`, `ssh-banner`, `http-server`, `smtp-banner`, `redis-info`) plus example `echo-open` script. Packs with `safe: true` skip `categories: ["aggressive"]`. Env: `ARES_PACKS_DIR`. Scaffold: `packs/_template/`.

This sits beside talk/misconfig — it does not replace `ares test`.

Path probes (`ares test --path-profile web|api|all`, `paths_file`, pipeline `extra`): curated wordlists + content fingerprints; no redirect follow on path GETs.


## Pipelines

YAML playbooks under `fixtures/` run ordered modules. Resume:

```bash
ares pipeline run fixtures/pipeline-example.yaml --save
ares pipeline run fixtures/pipeline-example.yaml --resume <run-id> --from-step 1
ares pipeline run fixtures/pipeline-misconfig.yaml --save
ares pipeline run fixtures/pipeline-misconfig-web.yaml
ares probe web 10.0.0.5 --save
```

`--resume` seeds the asset graph and injects `skip_pairs` into `scan` steps.
`--from-step N` skips earlier pipeline steps (0-based).

| Fixture | Flow |
|---------|------|
| `pipeline-apps.yaml` | discover → scan/service `apps` |
| `pipeline-infra.yaml` | discover → scan/service `infra` |
| `pipeline-misconfig.yaml` | apps + `active-misconfig` |
| `pipeline-misconfig-infra.yaml` | infra + misconfig (no HTTP paths) |
| `pipeline-misconfig-web.yaml` | web + HTTP(S) misconfig |

See [fixtures/README.md](../fixtures/README.md).

## Port presets

| Preset | Use |
|--------|-----|
| `top100` / `top1000` | Classic / expanded TCP sets |
| `apps` | DB, cache, messaging, LDAP, VNC, … (AresBird observes) |
| `infra` | DNS / AD / SMB / RDP / WinRM |
| `web` | Common HTTP(S) listeners |
| `all` | 1–65535 |

```bash
ares scan 10.0.0.5 -p apps --service
ares proto list
ares pipeline run fixtures/pipeline-apps.yaml
ares pipeline run fixtures/pipeline-infra.yaml
ares pipeline run fixtures/pipeline-misconfig.yaml --save
```
