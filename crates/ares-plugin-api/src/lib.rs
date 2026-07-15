//! Plugin API — versioned capabilities for the AresBird canivete.

pub mod loader;
pub mod native;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ares_core::event::Event;
use ares_core::graph::AssetGraph;
use ares_core::timing::ScanMode;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

pub use loader::{
    discover_plugin_dir, map_capabilities, register_discovered, resolve_plugins_root,
    script_plugin_from, DiscoveredPlugin, PluginManifest, ScriptPlugin,
};
pub use native::{try_load_native, NativePlugin, NATIVE_ABI_VERSION};

pub const API_VERSION: u32 = 1;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Passive,
    Discover,
    Scan,
    Interact,
    ActiveTest,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Permissions {
    pub raw_socket: bool,
    pub dns: bool,
    pub outbound_http: bool,
    pub filesystem: bool,
}

#[derive(Clone)]
pub struct ModuleCtx {
    pub cancel: CancellationToken,
    pub mode: ScanMode,
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub graph: Arc<Mutex<AssetGraph>>,
    pub emit: Arc<dyn Fn(Event) + Send + Sync>,
    pub active_allowed: bool,
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ModuleCtx {
    pub fn emit(&self, event: Event) {
        (self.emit)(event);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn capabilities(&self) -> &[Capability];
    fn permissions(&self) -> Permissions {
        Permissions::default()
    }
    fn api_version(&self) -> u32 {
        API_VERSION
    }
    fn run(&self, ctx: ModuleCtx) -> BoxFuture<'_, anyhow::Result<()>>;
}

/// In-process plugin registry.
#[derive(Clone)]
pub struct PluginRegistry {
    modules: Vec<Arc<dyn Module>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn register(&mut self, module: Arc<dyn Module>) {
        self.modules.push(module);
    }

    pub fn list(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Module>> {
        self.modules.iter().find(|m| m.name() == name).cloned()
    }

    pub fn by_capability(&self, cap: Capability) -> Vec<Arc<dyn Module>> {
        self.modules
            .iter()
            .filter(|m| m.capabilities().contains(&cap))
            .cloned()
            .collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
