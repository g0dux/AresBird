//! Native dynamic plugin ABI (C FFI) for AresBird.
//!
//! Expected exports from a plugin shared library:
//! - `ares_plugin_api_version() -> u32`
//! - `ares_plugin_name() -> *const c_char`
//! - `ares_plugin_description() -> *const c_char`
//! - `ares_plugin_run(req_json: *const c_char) -> *mut c_char`  (JSON response, heap)
//! - `ares_plugin_free(ptr: *mut c_char)`
//!
//! Request JSON: `{"targets":["1.2.3.4"],"ports":[80],"extra":{}}`
//! Response JSON: `{"ok":true,"events":[{...Event as serde...}]}`

use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

use ares_core::event::Event;
use libloading::Library;
use serde::{Deserialize, Serialize};

use crate::{Capability, Module, ModuleCtx, Permissions};

pub const NATIVE_ABI_VERSION: u32 = 1;

type FnApiVersion = unsafe extern "C" fn() -> u32;
type FnName = unsafe extern "C" fn() -> *const c_char;
type FnDesc = unsafe extern "C" fn() -> *const c_char;
type FnRun = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type FnFree = unsafe extern "C" fn(*mut c_char);

#[derive(Debug, Serialize)]
struct NativeRequest {
    targets: Vec<String>,
    ports: Vec<u16>,
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NativeResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    events: Vec<Event>,
    #[serde(default)]
    error: Option<String>,
}

pub struct NativePlugin {
    pub name: String,
    pub description: String,
    pub path: PathBuf,
    pub capabilities: Vec<Capability>,
    _lib: Library,
    run: FnRun,
    free: FnFree,
}

unsafe impl Send for NativePlugin {}
unsafe impl Sync for NativePlugin {}

impl NativePlugin {
    /// Open a native plugin library and resolve required symbols.
    pub unsafe fn open(path: &Path) -> anyhow::Result<Self> {
        let lib =
            Library::new(path).map_err(|e| anyhow::anyhow!("load {}: {e}", path.display()))?;

        let api_version: libloading::Symbol<FnApiVersion> =
            lib.get(b"ares_plugin_api_version\0")
                .map_err(|e| anyhow::anyhow!("missing ares_plugin_api_version: {e}"))?;
        let ver = api_version();
        if ver != NATIVE_ABI_VERSION {
            anyhow::bail!(
                "plugin ABI mismatch: got {ver}, want {NATIVE_ABI_VERSION} ({})",
                path.display()
            );
        }

        let name_fn: libloading::Symbol<FnName> = lib
            .get(b"ares_plugin_name\0")
            .map_err(|e| anyhow::anyhow!("missing ares_plugin_name: {e}"))?;
        let desc_fn: libloading::Symbol<FnDesc> = lib
            .get(b"ares_plugin_description\0")
            .map_err(|e| anyhow::anyhow!("missing ares_plugin_description: {e}"))?;
        let run: libloading::Symbol<FnRun> = lib
            .get(b"ares_plugin_run\0")
            .map_err(|e| anyhow::anyhow!("missing ares_plugin_run: {e}"))?;
        let free: libloading::Symbol<FnFree> = lib
            .get(b"ares_plugin_free\0")
            .map_err(|e| anyhow::anyhow!("missing ares_plugin_free: {e}"))?;

        let name = cstr_to_string(name_fn())?;
        let description = cstr_to_string(desc_fn()).unwrap_or_else(|_| "native plugin".into());

        Ok(Self {
            name,
            description,
            path: path.to_path_buf(),
            capabilities: vec![Capability::Passive, Capability::Interact],
            run: *run,
            free: *free,
            _lib: lib,
        })
    }
}

fn cstr_to_string(ptr: *const c_char) -> anyhow::Result<String> {
    if ptr.is_null() {
        anyhow::bail!("null cstring");
    }
    unsafe { Ok(CStr::from_ptr(ptr).to_string_lossy().into_owned()) }
}

impl Module for NativePlugin {
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
    fn run(&self, ctx: ModuleCtx) -> crate::BoxFuture<'_, anyhow::Result<()>> {
        let run = self.run;
        let free = self.free;
        let name = self.name.clone();
        Box::pin(async move {
            let req = NativeRequest {
                targets: ctx.targets.clone(),
                ports: ctx.ports.clone(),
                extra: ctx.extra.clone(),
            };
            let req_json = serde_json::to_string(&req)?;
            let c_req = CString::new(req_json)?;
            ctx.emit(Event::Log {
                level: "info".into(),
                message: format!("native plugin `{name}` run"),
            });

            let resp_ptr = unsafe { run(c_req.as_ptr()) };
            if resp_ptr.is_null() {
                anyhow::bail!("plugin `{name}` returned null");
            }
            let resp_str = unsafe { CStr::from_ptr(resp_ptr) }
                .to_string_lossy()
                .into_owned();
            unsafe { free(resp_ptr) };

            let parsed: NativeResponse = serde_json::from_str(&resp_str)
                .map_err(|e| anyhow::anyhow!("plugin `{name}` bad JSON: {e} | {resp_str}"))?;
            for ev in parsed.events {
                ctx.emit(ev);
            }
            if let Some(err) = parsed.error {
                anyhow::bail!("plugin `{name}`: {err}");
            }
            if !parsed.ok {
                anyhow::bail!("plugin `{name}` reported ok=false");
            }
            Ok(())
        })
    }
}

fn copy_local_enabled() -> bool {
    matches!(
        std::env::var("ARES_PLUGIN_COPY_LOCAL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        true
    ) || cfg!(windows)
}

fn safe_plugin_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|p| p.join("aresbird-plugins"))
}

/// Best-effort copy of a DLL into `%LOCALAPPDATA%/aresbird-plugins` for SAC-friendly loads.
fn try_copy_to_safe_dir(source: &Path, library: &str) -> Option<PathBuf> {
    let dir = safe_plugin_dir()?;
    let _ = fs::create_dir_all(&dir);
    let stem = Path::new(library)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("plugin");
    let dest = dir.join(format!("{stem}.dll"));
    match fs::copy(source, &dest) {
        Ok(_) => {
            eprintln!(
                "[plugin] copied {} → {} (SAC-friendly path)",
                source.display(),
                dest.display()
            );
            Some(dest)
        }
        Err(e) => {
            eprintln!(
                "[plugin] copy to LocalAppData failed ({}): {e}",
                dest.display()
            );
            None
        }
    }
}

fn build_candidates(dir: &Path, library: &str) -> Vec<PathBuf> {
    let path = if Path::new(library).is_absolute() {
        PathBuf::from(library)
    } else {
        dir.join(library)
    };

    let mut candidates = vec![
        path.clone(),
        dir.join(format!("{library}.dll")),
        dir.join(format!("lib{library}.so")),
        dir.join(format!("lib{library}.dylib")),
        dir.join(library).with_extension("dll"),
        dir.join(library).with_extension("so"),
    ];

    if let Some(local) = dirs::data_local_dir() {
        let stem = Path::new(library)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(library);
        candidates.push(local.join("aresbird-plugins").join(format!("{stem}.dll")));
        candidates.push(local.join("aresbird-plugins").join(library));
        candidates.push(local.join("aresbird-target").join("debug").join(library));
        candidates.push(
            local
                .join("aresbird-target")
                .join("debug")
                .join(format!("{stem}.dll")),
        );
        candidates.push(local.join("aresbird-target").join("release").join(library));
        candidates.push(
            local
                .join("aresbird-target")
                .join("release")
                .join(format!("{stem}.dll")),
        );
        // Legacy AresProbe paths (pre-rebrand)
        candidates.push(local.join("aresprobe-plugins").join(format!("{stem}.dll")));
        candidates.push(local.join("aresprobe-plugins").join(library));
        candidates.push(local.join("aresprobe-target").join("debug").join(library));
        candidates.push(local.join("aresprobe-target").join("release").join(library));
    }

    candidates
}

/// Try to load a native library for a discovered plugin.
pub fn try_load_native(dir: &Path, library: &str) -> anyhow::Result<NativePlugin> {
    let candidates = build_candidates(dir, library);
    let mut last_err = None;
    let mut tried = Vec::new();

    for cand in &candidates {
        if !cand.exists() {
            continue;
        }
        tried.push(cand.display().to_string());
        match unsafe { NativePlugin::open(cand) } {
            Ok(p) => return Ok(p),
            Err(e) => last_err = Some(e),
        }
    }

    // On Windows (or when ARES_PLUGIN_COPY_LOCAL=1), copy an existing DLL into LocalAppData and retry.
    if copy_local_enabled() {
        let source = candidates.iter().find(|p| p.exists()).cloned();
        if let Some(src) = source {
            // Skip if already under aresbird-plugins
            let already_safe = safe_plugin_dir()
                .map(|d| src.starts_with(d))
                .unwrap_or(false);
            if !already_safe {
                if let Some(dest) = try_copy_to_safe_dir(&src, library) {
                    tried.push(dest.display().to_string());
                    match unsafe { NativePlugin::open(&dest) } {
                        Ok(p) => return Ok(p),
                        Err(e) => last_err = Some(e),
                    }
                }
            }
        }
    }

    let hint = if tried.is_empty() {
        format!(
            "library not found: {library} (searched plugin dir + %LOCALAPPDATA%\\aresbird-plugins)"
        )
    } else {
        format!(
            "failed to load `{library}` after trying: {}; last error: {}",
            tried.join(", "),
            last_err
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".into())
        )
    };
    Err(anyhow::anyhow!("{hint}"))
}
