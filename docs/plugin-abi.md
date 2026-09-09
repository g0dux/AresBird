# AresBird Native Plugin ABI v1

Export these C symbols from a `cdylib`:

| Symbol | Signature |
|--------|-----------|
| `ares_plugin_api_version` | `() -> u32` (must return `1`) |
| `ares_plugin_name` | `() -> *const c_char` |
| `ares_plugin_description` | `() -> *const c_char` |
| `ares_plugin_run` | `(*const c_char) -> *mut c_char` |
| `ares_plugin_free` | `(*mut c_char)` |

`ares_plugin_run` receives request JSON:

```json
{"targets":["127.0.0.1"],"ports":[80],"extra":{}}
```

and must return heap JSON freed via `ares_plugin_free`:

```json
{"ok":true,"events":[{"type":"log","level":"info","message":"..."}]}
```

## Manifest (`plugins/<name>/plugin.json`)

| Field | Meaning |
|-------|---------|
| `name` | Plugin id |
| `description` | Short description |
| `version` | Semver string (informational) |
| `author` | Maintainer (informational) |
| `library` | Native DLL/SO name or path |
| `command` | Script / shell command fallback (`cmd /C` / `sh -c`) |
| `command_windows` | Windows-only command (preferred on Windows) |
| `command_unix` | Unix/macOS command (preferred on Linux/macOS) |
| `prefer` | `"command"` or `"native"` — on **Windows**, if both `library` and `command*` exist and `prefer` is unset, **command wins** (SAC-friendly) |
| `timeout_secs` | Script timeout (default 30) |
| `emit` | `"log"` (default) or `"ndjson"` — one `Event` JSON object per stdout line |
| `default_ports` | Used when `ares plugin run` omits `-p` |
| `aliases` | Alternate names shown in `plugin info` |
| `capabilities` | `passive`, `discover`, `scan`, `interact`, `active` / `misconfig` |

Dirs starting with `_` or `.` are skipped (use `_template` as a scaffold).

## Script context

Every script plugin receives:

| Env / IO | Content |
|----------|---------|
| `ARES_TARGETS` | comma-separated targets |
| `ARES_PORTS` | comma-separated ports |
| `ARES_PLUGIN_NAME` | plugin name |
| `ARES_EXTRA_JSON` | `--extra` object |
| `ARES_CONTEXT_JSON` | full `{plugin,targets,ports,extra}` |
| **stdin** | same JSON + newline |

With `"emit": "ndjson"`, each non-empty stdout line is parsed as an Ares `Event` (serde tagged: `"type":"log"`, `"type":"banner"`, …). Unparseable lines become `log` events.

The `Event` wire shape is a versioned contract (`ares_core::EVENT_SCHEMA_VERSION`, currently `1`). The `"type"` tag is the snake_case variant name; the full stable set is enumerated by `Event::KINDS` (`job_started`, `job_finished`, `host_up`, `host_down`, `port_result`, `banner`, `service_detected`, `dns_record`, `tls_cert`, `session_opened`, `session_closed`, `probe_result`, `misconfig_finding`, `os_guess`, `asn_info`, `path_hop`, `stats`, `log`). Additive variants/fields keep v1; renames/removals bump the version.

## CLI

```bash
ares plugin list
ares plugin list --cap interact
ares plugin info echo-lab
ares plugin run echo-lab 127.0.0.1 -p 80,443 --extra '{"path":"/"}'
```

## Windows / Smart App Control

Native loads try, in order:

1. Plugin directory
2. `%LOCALAPPDATA%\aresbird-plugins\`
3. `%LOCALAPPDATA%\aresbird-target\{debug,release}\`

If load fails, AresBird may **copy** an existing DLL into `aresbird-plugins` and retry (`ARES_PLUGIN_COPY_LOCAL=1` forces this; on Windows it is enabled by default).

Useful env vars:

| Env | Effect |
|-----|--------|
| `ARES_PLUGINS_DIR` | Override plugins root |
| `ARES_PLUGIN_PREFER_COMMAND=1` | Always use script `command` when present |
| `ARES_PLUGIN_COPY_LOCAL=1` | Force copy-to-LocalAppData retry |

## Example

```bash
cargo build -p ares-plugin-hello
mkdir %LOCALAPPDATA%\aresbird-plugins
copy %LOCALAPPDATA%\aresbird-target\debug\ares_plugin_hello.dll %LOCALAPPDATA%\aresbird-plugins\
```

Or prefer script on SAC-heavy machines:

```json
{
  "name": "native-hello",
  "prefer": "command",
  "library": "ares_plugin_hello.dll",
  "command": "echo fallback"
}
```

Scaffold: copy `plugins/_template/` to a new folder and edit `plugin.json` + `run.*`.
