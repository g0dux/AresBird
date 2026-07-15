//! AresBird core — network interaction fabric models, events, graph, and orchestration.

pub mod error;
pub mod event;
pub mod graph;
pub mod job;
pub mod model;
pub mod orchestrator;
pub mod ports;
pub mod timing;

pub use error::{CoreError, Result};
pub use event::{Event, EventBus, EventCollector};
pub use graph::{AssetGraph, GraphEdge, GraphExport, GraphNode};
pub use job::{Job, JobId, JobStatus};
pub use model::*;
pub use orchestrator::Orchestrator;
pub use ports::{parse_ports, port_preset_names, PortSpec, APPS, INFRA, TOP100, WEB};
pub use timing::{
    jitter_delay_ms, shuffle_inplace, AdaptiveController, ScanMode, TimingProfile,
};
