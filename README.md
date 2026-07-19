# AresBird

High-performance **network interaction engine** (Swiss-army knife) written in Rust.

**vs Nmap:** AresBird complements — stronger on talk/misconfig/pipelines; TCP connect + selective UDP is solid on Windows, but not a replacement for classic NSE/`-O`/`-sS` depth. Use `--syn` half-open only on Linux+raw; UDP silence = `open|filtered` without ICMP.

**Optional NSE-style packs:** `ares scan … --script-pack default` runs observe-only builtins + pack scripts after open ports (off by default). See `ares scripts list`.

## Install

### From source (any OS)

```bash
git clone https://github.com/g0dux/AresBird.git
cd AresBird
cargo install --path crates/ares-cli
ares doctor
```

### Windows (Smart App Control)

Prefer a target dir outside Desktop:

```powershell
$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\aresbird-target"
cargo build -p ares-cli --release
# if SAC blocks release build scripts (os error 4551):
cargo build -p ares-cli --profile dist
. .\scripts\path-aresbird.ps1          # release → dist → debug
# . .\scripts\path-aresbird.ps1 -PersistUser
ares doctor
```

### GitHub Releases

Tagged builds (`v*`) publish Linux / Windows / macOS archives via `.github/workflows/release.yml`.

Download from: https://github.com/g0dux/AresBird/releases

## Quick start

```bash
ares scan 127.0.0.1 -p top100 --mode fast --service
ares scan 127.0.0.1 -p apps --script-pack default
ares scan 127.0.0.1 -p web --script-pack web
ares scripts list
ares scripts info redis-info
ares probe quick 127.0.0.1
ares probe quick 127.0.0.1 --script-pack default
ares probe web example.com --save
ares watch probe quick 127.0.0.1
ares report workspace
ares report graph --workspace
ares talk https://example.com/ --repl
ares talk 127.0.0.1:6379 --proto redis --repl
ares talk 127.0.0.1 --proto ssh --repl
# ssh --repl = observe-only (banner|algs|probe); not an interactive shell
# guides: docs/guides/ (workspace, watch, packs, talk-repl)
ares scan 127.0.0.1 -p top100 --discover
ares scan 127.0.0.1 -p 80,443 --show-closed --show-filtered
ares scan 127.0.0.1 -p apps --service
ares proto list
ares discover 192.168.0.0/24
ares discover 192.168.0.0/24 -p 22,80,443
ares discover 192.168.0.0/24 --arp
ares asn 1.1.1.1
ares scan 127.0.0.1 -p top100 --mode stealth
ares scan 127.0.0.1 -p top100 --udp --udp-ports 53,123,161
ares scan 127.0.0.1 -p top100 --mode fast --save
# stealth: shuffle + jitter + slow PPS; quiet is similar but a bit faster
# depois: ares scan 127.0.0.1 -p top100 --resume <run-id>
ares path 127.0.0.1 --max-hops 10
ares proto dns localhost
ares fp example.com
ares talk https://example.com/
# HTTP/HTTPS follows redirects (301/302/…) up to 5 hops; cookies stay on redirects
ares talk https://example.com/ --session
ares talk https://example.com/ --session --follow /,/robots.txt,/login
ares talk http://example.com/
ares proto redis 127.0.0.1
ares proto list
ares doctor
ares proto docker 127.0.0.1
ares proto etcd 127.0.0.1
ares proto consul 127.0.0.1
ares proto mssql 127.0.0.1
ares proto kubernetes 127.0.0.1
ares proto oracle 127.0.0.1
ares proto couchdb 127.0.0.1
ares proto zookeeper 127.0.0.1
ares proto cassandra 127.0.0.1
ares proto rdp 127.0.0.1
ares proto neo4j 127.0.0.1
ares proto clickhouse 127.0.0.1
ares proto minio 127.0.0.1
ares proto bolt 127.0.0.1
ares proto rabbitmq 127.0.0.1
ares proto grafana 127.0.0.1
ares proto kibana 127.0.0.1
ares proto prometheus 127.0.0.1
ares proto jenkins 127.0.0.1
ares plugin list
ares plugin run echo-lab 127.0.0.1
ares pipeline run fixtures/pipeline-example.yaml --save
ares pipeline run fixtures/pipeline-smart.yaml --var target=127.0.0.1 --var profile=web --save
ares pipeline run fixtures/pipeline-apps.yaml
ares pipeline run fixtures/pipeline-misconfig.yaml --save
# depois: ares pipeline run fixtures/pipeline-example.yaml --resume <run-id> --from-step 1
ares test 127.0.0.1 -p 80,8080 --path-profile web
ares test example.com -p web --paths-file fixtures/paths-web-extra.txt --save
ares proto winrm 127.0.0.1
ares proto snmp 127.0.0.1
# CI: exit 2 if new medium+ findings vs last active-misconfig run
ares test example.com -p 443 --no-path-probes --save --fail-on-new --min-severity medium -q --format csv
# optional webhook on new findings
ares test example.com -p 443 --save --fail-on-new --notify https://hooks.example/ares --notify-on new
ares report list
ares report last --min-severity medium
ares report last --format md
ares report show
ares report graph --format mermaid
ares report prune --keep 20
ares report export --min-severity high --format csv
ares report export --format md --out report.md
```

> **Windows / Smart App Control:** target dir is `%LOCALAPPDATA%\aresbird-target` (not Desktop). TLS is **ring-only** (no `aws-lc-sys`). If `cargo build --release` fails with os error **4551** (SAC blocked a `build-script-build`), use `cargo build -p ares-cli --profile dist` or fall back to debug + `. .\scripts\path-aresbird.ps1 -DebugBuild`.

## Commands

| Command | Purpose |
|---------|---------|
| `discover` | Host discovery (ping + TCP probes; `-p` probe ports; `--arp` on Linux+raw) |
| `scan` | TCP connect (`-p …`; `--udp` / `--discover` / `--pn` / `--syn` / `--show-closed` / `--script-pack`) |
| `scripts` | List / info for optional NSE-style packs under `packs/` |
| `probe` | Intent profile: `web`\|`apps`\|`infra`\|`quick` → discover/scan/service/misconfig (`--script-pack`) |
| `watch` | Live TUI for `watch probe` / `watch pipeline` (filter sev/cdn/port) |
| `service` | Banner / service detection + OS hints |
| `fp` | TLS + HTTPS GET (follows redirects) + banners + OS hints |
| `talk` | Interact (HTTP/H2/SSH/TLS/SMB + DBs/…); `--repl` HTTP cookie session |
| `recon` | DNS enrichment + light subdomain enum |
| `asn` | ASN / PTR / CDN enrichment (Team Cymru DNS) |
| `path` | Traceroute / path hops |
| `proto` | Protocol helpers + `ares proto list` (includes docker/etcd/consul) |
| `doctor` | Environment check (store, features, env vars) |
| `test` | Misconfig (HTTP + data stores/messaging + LDAP/WinRM/Kerberos/VNC/SNMP exposure) |
| `plugin` | List / info / run modules (+ external `plugins/*/plugin.json`) |
| `report` | List / show / `workspace` / prune / last / diff / `export` / `graph` (`--workspace`) |
| `pipeline` | YAML playbooks (`--resume`, `--from-step`, `--var`, `when`/`on_fail`/`open`) |

Global: `--workspace NAME` / `ARES_WORKSPACE` (living graph merge); `--ephemeral` skips workspace I/O. `--save` still writes immutable CI runs.

External plugins: `plugins/<name>/plugin.json` with `command` and/or `library`.
On Windows, if both exist, `command` is preferred by default (SAC-friendly). Scripts can
emit NDJSON events (`"emit":"ndjson"`) and receive `ARES_CONTEXT_JSON` / stdin.
`ares plugin list --cap interact` · `ares plugin run NAME host -p 80 --extra '{}'`
Scaffold: copy `plugins/_template/`. See [docs/plugin-abi.md](docs/plugin-abi.md).

SYN: `ares scan ... --syn` uses **syn-compat** on Windows; true **syn-raw** needs Linux + `cargo build -p ares-cli --features raw` (root/CAP_NET_RAW). Raw SYN resolves next-hop MAC via **ARP** (on-link or default gateway) and maps replies with source-port + seq cookie.

```bash
# Linux (root): L2 discover + SYN-raw
cargo build -p ares-cli --release --features raw
sudo ./target/release/ares discover 192.168.1.0/24 --arp
sudo ./target/release/ares scan 192.168.1.10 -p top100 --syn
```

## CI (fail on new findings)

```bash
# Linux/macOS
TARGET=example.com ./scripts/ci-misconfig.sh
# Windows
$env:TARGET="example.com"; .\scripts\ci-misconfig.ps1
```

Exit **2** = new findings ≥ `--min-severity` vs last saved run. Store: `ARES_DATA_DIR` or `ARES_STORE_PATH`.  
Manage runs: `ares report list|show|delete|prune`. See [docs/ci.md](docs/ci.md) and `.github/workflows/ares-misconfig.yml`.

## Architecture

Guides: [docs/guides/](docs/guides/) · Architecture: [docs/architecture.md](docs/architecture.md)

Cargo workspace under `crates/`:

- `ares-core` — fabric (events, asset graph, jobs, timing, ports)
- `ares-net` — TCP connect, UDP, discovery, traceroute, rate limit
- `ares-proto` — HTTP, DNS, SSH banner, TLS (rustls)
- `ares-probe` — service detection / OS fingerprint helpers
- `ares-output` — tables, JSON/NDJSON, diff, SQLite run store
- `ares-plugin-api` — Capability model + Module trait + dynamic plugin loader
- `ares-modules` — built-in discover / scan / service / fingerprint / recon / talk / path / active
- `ares-cli` — `ares` binary

## License

**GPL-3.0** — você pode usar, estudar, modificar e redistribuir AresBird livremente.

Não pode fechar o código em um fork proprietário: alterações e obras derivadas precisam permanecer sob GPL-3.0 (com atribuição). Ver [LICENSE](LICENSE).
