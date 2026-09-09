use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::event::{Event, EventBus, EventCollector};
use crate::graph::AssetGraph;
use crate::job::{Job, JobStatus};
use crate::timing::ScanMode;

/// Central orchestrator — owns the bus, graph, and active job lifecycle.
pub struct Orchestrator {
    pub job: Mutex<Job>,
    pub bus: EventBus,
    pub graph: Arc<Mutex<AssetGraph>>,
    pub collector: Arc<Mutex<EventCollector>>,
    pub cancel: CancellationToken,
}

impl Orchestrator {
    pub fn new(
        name: impl Into<String>,
        mode: ScanMode,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let (bus, rx) = EventBus::new();
        let job = Job::new(name, mode);
        (
            Self {
                job: Mutex::new(job),
                bus,
                graph: Arc::new(Mutex::new(AssetGraph::new())),
                collector: Arc::new(Mutex::new(EventCollector::new())),
                cancel: CancellationToken::new(),
            },
            rx,
        )
    }

    pub fn job_id(&self) -> uuid::Uuid {
        self.job.lock().id
    }

    pub fn start(&self) {
        let mut job = self.job.lock();
        job.mark_running();
        self.bus.emit(Event::JobStarted {
            job_id: job.id,
            started_at: Utc::now(),
        });
    }

    pub fn finish_ok(&self) {
        let mut job = self.job.lock();
        job.mark_completed();
        self.bus.emit(Event::JobFinished {
            job_id: job.id,
            finished_at: Utc::now(),
            status: "completed".into(),
        });
    }

    pub fn finish_err(&self, err: impl Into<String>) {
        let msg = err.into();
        let mut job = self.job.lock();
        job.mark_failed(&msg);
        self.bus.emit(Event::JobFinished {
            job_id: job.id,
            finished_at: Utc::now(),
            status: format!("failed: {msg}"),
        });
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
        let mut job = self.job.lock();
        if job.status == JobStatus::Running {
            job.mark_cancelled();
            self.bus.emit(Event::JobFinished {
                job_id: job.id,
                finished_at: Utc::now(),
                status: "cancelled".into(),
            });
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn emit(&self, event: Event) {
        self.graph.lock().apply(&event);
        self.collector.lock().push(event.clone());
        self.bus.emit(event);
    }

    pub fn take_collector(&self) -> EventCollector {
        self.collector.lock().clone()
    }

    pub fn graph_snapshot(&self) -> AssetGraph {
        self.graph.lock().clone()
    }
}

/// Background task that drains the bus into the collector + graph (when CLI owns rx).
pub async fn drain_events(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
    graph: Arc<Mutex<AssetGraph>>,
    collector: Arc<Mutex<EventCollector>>,
) {
    while let Some(event) = rx.recv().await {
        graph.lock().apply(&event);
        collector.lock().push(event);
    }
}
