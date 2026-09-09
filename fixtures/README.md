# Fixtures — example YAML pipelines for AresBird

| File | Purpose |
|------|---------|
| `pipeline-example.yaml` | Small discover/scan/service/talk demo |
| `pipeline-smart.yaml` | **Vars + `ports: open` + `when` + `on_fail`** |
| `pipeline-apps.yaml` | Discover + scan/service `-p apps` |
| `pipeline-infra.yaml` | Discover + scan/service `-p infra` |
| `pipeline-misconfig.yaml` | Apps surface + `active-misconfig` |
| `pipeline-misconfig-infra.yaml` | Identity surface + misconfig (no path probes) |
| `pipeline-misconfig-web.yaml` | Web ports + HTTP(S) misconfig (`path_profile: web`) |
| `paths-web-extra.txt` | Example extra path wordlist |

```bash
ares pipeline run fixtures/pipeline-smart.yaml --var target=127.0.0.1 --var profile=web --save
ares pipeline run fixtures/pipeline-misconfig.yaml --save
ares test example.com -p web --path-profile web --paths-file fixtures/paths-web-extra.txt --save
ares report last --min-severity medium
```

## Smart pipeline keys

| Key | Meaning |
|-----|---------|
| `vars` / `--var k=v` | `${name}` substitution in strings |
| `ports: open` | Unique open ports from the graph |
| `ports: open:web` | Open ∩ preset/list |
| `when.open_any` | Skip unless any port is open |
| `when.open_ports` | Skip unless one of these ports is open |
| `when.min_open` / `findings_gte` | Threshold gates |
| `on_fail` | `abort` (default) · `continue` · `skip_rest` |

`active-misconfig` path extras:

| Key | Meaning |
|-----|---------|
| `path_probes` | Enable/disable (default true) |
| `path_delay_ms` | Delay between GETs |
| `path_profile` | `default` \| `api` \| `web` \| `all` |
| `paths_file` | Extra wordlist file |
| `paths` | Inline YAML array of paths |

Path probes use **no redirect follow** + content fingerprints (not soft-404 HTML).

For CI (`--fail-on-new`), see [docs/ci.md](../docs/ci.md) and `scripts/ci-misconfig.*`.
