//! Dynamic plugin discovery / loading.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use ares_core::event::Event;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::native::try_load_native;
use crate::{Capability, Module, Permissions, PluginRegistry};

#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub description: Option<String>,
    pub version: Option<String>,
    /// Optional relative path to a shared library (.dll / .so / .dylib)
    pub library: Option<String>,
    /// Optional shell command for script-style plugins
    pub command: Option<String>,
    /// `"command"` | `"native"` — default: try native first (on Windows, prefer command when both exist)
    pub prefer: Option<String>,
    /// Script plugin run timeout (seconds). Default 30.
    pub timeout_secs: Option<u64>,
    /// How to interpret stdout: `"log"` (default) or `"ndjson"` (one Event JSON per line).
    #[serde(default, alias = "emit_mode")]
    pub emit: Option<String>,
    /// Ports applied when the runner does not pass `-p`.
    #[serde(default)]
    pub default_ports: Vec<u16>,
    /// Alternate names shown in `plugin info` (not registered as separate modules).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Author / maintainer (informational).
    pub author: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Pack tags: `safe`, `default`, `aggressive`, …
    #[serde(default)]
    pub categories: Vec<String>,
    /// Port protocol filter for script packs: `tcp` | `udp` | `any` (default tcp).
    #[serde(default)]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredPlugin {
    pub manifest: PluginManifest,
    pub dir: PathBuf,
}

/// Resolve plugin root: `ARES_PLUGINS_DIR` or `<cwd>/plugins`.
pub fn resolve_plugins_root() -> PathBuf {
    if let Ok(p) = std::env::var("ARES_PLUGINS_DIR") {
        let path = PathBuf::from(p);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    std::env::current_dir()
        .unwrap_or_default()
        .join("plugins")
}

/// Scan `plugins/*/plugin.json` and return manifests.
pub fn discover_plugin_dir(root: impl AsRef<Path>) -> Vec<DiscoveredPlugin> {
    let root = root.as_ref();
    let mut out = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // Skip scaffold / private dirs
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.starts_with('_') || name.starts_with('.') {
                continue;
            }
        }
        let manifest_path = path.join("plugin.json");
        if !manifest_path.exists() {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<PluginManifest>(&text) {
                out.push(DiscoveredPlugin {
                    manifest,
                    dir: path,
                });
            }
        }
    }
    out
}

fn prefer_command(manifest: &PluginManifest) -> bool {
    if std::env::var_os("ARES_PLUGIN_PREFER_COMMAND").is_some() {
        return true;
    }
    match manifest
        .prefer
        .as_deref()
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("command") | Some("script") => return true,
        Some("native") | Some("library") => return false,
        _ => {}
    }
    // Windows: SAC often blocks plugin DLLs from Desktop — prefer script when both exist.
    cfg!(windows) && manifest.command.is_some() && manifest.library.is_some()
}

pub fn map_capabilities(names: &[String]) -> Vec<Capability> {
    let mut out = Vec::new();
    for n in names {
        match n.to_ascii_lowercase().as_str() {
            "discover" | "recon" => out.push(Capability::Discover),
            "scan" => out.push(Capability::Scan),
            "passive" => out.push(Capability::Passive),
            "interact" | "talk" => out.push(Capability::Interact),
            "active" | "activetest" | "test" | "misconfig" => out.push(Capability::ActiveTest),
            _ => {}
        }
    }
    if out.is_empty() {
        out.push(Capability::Passive);
    }
    out
}

fn emit_ndjson(emit: Option<&str>) -> bool {
    matches!(
        emit.map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("ndjson") | Some("events") | Some("jsonl")
    )
}

fn emit_stdout_lines(ctx: &crate::ModuleCtx, stdout: &str, as_ndjson: bool) {
    if stdout.trim().is_empty() {
        return;
    }
    if !as_ndjson {
        ctx.emit(Event::Log {
            level: "info".into(),
            message: stdout.trim().to_string(),
        });
        return;
    }
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > 65_536 {
            ctx.emit(Event::Log {
                level: "warn".into(),
                message: format!("plugin ndjson line too long ({} bytes), skipped", line.len()),
            });
            continue;
        }
        match serde_json::from_str::<Event>(line) {
            Ok(ev) => ctx.emit(ev),
            Err(_) => {
                // Allow wrapper: {"ok":true,"events":[...]} per line is rare; treat as log
                ctx.emit(Event::Log {
                    level: "info".into(),
                    message: line.to_string(),
                });
            }
        }
    }
}

/// External script plugin — runs a command with targets as env / stdin context.
pub struct ScriptPlugin {
    pub name: String,
    pub description: String,
    pub command: String,
    pub workdir: PathBuf,
    pub timeout_secs: u64,
    pub capabilities: Vec<Capability>,
    pub emit_ndjson: bool,
    pub default_ports: Vec<u16>,
}

impl Module for ScriptPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
    fn permissions(&self) -> Permissions {
        Permissions {
            filesystem: true,
            ..Default::default()
        }
    }
    fn run(&self, ctx: crate::ModuleCtx) -> crate::BoxFuture<'_, anyhow::Result<()>> {
        let command = self.command.clone();
        let workdir = self.workdir.clone();
        let name = self.name.clone();
        let timeout_secs = self.timeout_secs;
        let emit_ndjson = self.emit_ndjson;
        let default_ports = self.default_ports.clone();
        Box::pin(async move {
            let ports: Vec<u16> = if ctx.ports.is_empty() {
                default_ports
            } else {
                ctx.ports.clone()
            };
            let targets = ctx.targets.join(",");
            let ports_s = ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let extra = serde_json::to_string(&ctx.extra).unwrap_or_else(|_| "{}".into());
            let context = serde_json::json!({
                "plugin": name,
                "targets": ctx.targets,
                "ports": ports,
                "extra": ctx.extra,
                "pack": ctx.extra.get("pack").cloned().unwrap_or(serde_json::Value::Null),
                "open_ports": ctx.extra.get("open_ports").cloned().unwrap_or(serde_json::Value::Null),
            });
            let context_s = serde_json::to_string(&context).unwrap_or_else(|_| "{}".into());
            let open_ports_env = ctx
                .extra
                .get("open_ports_csv")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            ctx.emit(Event::Log {
                level: "info".into(),
                message: format!("dynamic plugin `{name}` exec: {command} ({targets})"),
            });
            let mut cmd = if cfg!(windows) {
                let mut c = tokio::process::Command::new("cmd");
                c.args(["/C", &command]);
                c
            } else {
                let mut c = tokio::process::Command::new("sh");
                c.args(["-c", &command]);
                c
            };
            cmd.current_dir(&workdir);
            cmd.env("ARES_TARGETS", &targets);
            cmd.env("ARES_PORTS", &ports_s);
            cmd.env("ARES_PLUGIN_NAME", &name);
            cmd.env("ARES_EXTRA_JSON", &extra);
            cmd.env("ARES_CONTEXT_JSON", &context_s);
            if !open_ports_env.is_empty() {
                cmd.env("ARES_OPEN_PORTS", &open_ports_env);
            }
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => anyhow::bail!("plugin `{name}` spawn failed: {e}"),
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(context_s.as_bytes()).await;
                let _ = stdin.write_all(b"\n").await;
                drop(stdin);
            }
            let out = match timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await
            {
                Ok(Ok(o)) => o,
                Ok(Err(e)) => anyhow::bail!("plugin `{name}` wait failed: {e}"),
                Err(_) => anyhow::bail!("plugin `{name}` timed out after {timeout_secs}s"),
            };
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            emit_stdout_lines(&ctx, &stdout, emit_ndjson);
            if !stderr.trim().is_empty() {
                ctx.emit(Event::Log {
                    level: "warn".into(),
                    message: stderr.trim().to_string(),
                });
            }
            if !out.status.success() {
                anyhow::bail!("plugin `{name}` exited with {}", out.status);
            }
            Ok(())
        })
    }
}

fn register_script(registry: &mut PluginRegistry, plugin: &DiscoveredPlugin, command: String) {
    if let Some(m) = script_plugin_from(plugin, command) {
        if std::env::var_os("ARES_QUIET").is_none() {
            eprintln!(
                "[plugin] loaded script `{}` from {}",
                m.name,
                plugin.dir.display()
            );
        }
        registry.register(Arc::new(m));
    }
}

/// Build a script plugin from a discovered manifest (shared with script packs).
pub fn script_plugin_from(plugin: &DiscoveredPlugin, command: String) -> Option<ScriptPlugin> {
    Some(ScriptPlugin {
        name: plugin.manifest.name.clone(),
        description: plugin
            .manifest
            .description
            .clone()
            .unwrap_or_else(|| "external plugin".into()),
        command,
        workdir: plugin.dir.clone(),
        timeout_secs: plugin.manifest.timeout_secs.unwrap_or(30).min(60),
        capabilities: map_capabilities(&plugin.manifest.capabilities),
        emit_ndjson: emit_ndjson(plugin.manifest.emit.as_deref()),
        default_ports: plugin.manifest.default_ports.clone(),
    })
}

/// Register discovered script + native plugins into the registry.
pub fn register_discovered(registry: &mut PluginRegistry, root: impl AsRef<Path>) -> usize {
    let found = discover_plugin_dir(root);
    let mut n = 0;
    for plugin in found {
        let want_command_first = prefer_command(&plugin.manifest);
        let caps = map_capabilities(&plugin.manifest.capabilities);

        if want_command_first {
            if let Some(command) = plugin.manifest.command.clone() {
                register_script(registry, &plugin, command);
                n += 1;
                continue;
            }
        }

        if let Some(library) = plugin.manifest.library.clone() {
            match try_load_native(&plugin.dir, &library) {
                Ok(mut native) => {
                    native.capabilities = caps;
                    if let Some(desc) = &plugin.manifest.description {
                        if !desc.is_empty() {
                            native.description = desc.clone();
                        }
                    }
                    if std::env::var_os("ARES_QUIET").is_none() {
                        eprintln!(
                            "[plugin] loaded native `{}` from {}",
                            native.name,
                            native.path.display()
                        );
                    }
                    registry.register(Arc::new(native));
                    n += 1;
                    continue;
                }
                Err(e) => {
                    if std::env::var_os("ARES_QUIET").is_none() {
                        eprintln!(
                            "[plugin] native `{}` failed ({e}); {}",
                            plugin.manifest.name,
                            if plugin.manifest.command.is_some() {
                                "falling back to command"
                            } else {
                                "no command fallback — skipped (tip: set ARES_PLUGIN_PREFER_COMMAND=1 or copy DLL to %LOCALAPPDATA%\\aresbird-plugins)"
                            }
                        );
                    }
                }
            }
        }

        if !want_command_first {
            if let Some(command) = plugin.manifest.command.clone() {
                register_script(registry, &plugin, command);
                n += 1;
            }
        }
    }
    n
}
