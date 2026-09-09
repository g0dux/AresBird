use std::path::{Path, PathBuf};

use anyhow::Context;
use ares_core::event::{Event, EventCollector};
use ares_core::graph::AssetGraph;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRun {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub events_json: String,
    pub graph_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub event_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunStats {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub event_count: usize,
    pub hosts_up: usize,
    pub ports_open: usize,
    pub findings: usize,
    pub os_guesses: usize,
}

pub struct RunStore {
    path: PathBuf,
    #[cfg(feature = "sqlite")]
    conn: rusqlite::Connection,
}

impl RunStore {
    pub fn open_default() -> anyhow::Result<Self> {
        if let Ok(p) = std::env::var("ARES_STORE_PATH") {
            let path = PathBuf::from(p);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            return Self::open(path);
        }
        let dir = if let Ok(d) = std::env::var("ARES_DATA_DIR") {
            PathBuf::from(d)
        } else {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("aresbird")
        };
        std::fs::create_dir_all(&dir)?;
        Self::open(dir.join("runs.db"))
    }

    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(feature = "sqlite")]
        {
            let conn = rusqlite::Connection::open(&path)
                .with_context(|| format!("open sqlite {}", path.display()))?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    graph_json TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_runs_name ON runs(name);",
            )?;
            // Best-effort additive column for DBs created before event_count existed
            let _ = conn.execute_batch(
                "ALTER TABLE runs ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0;",
            );
            Ok(Self { path, conn })
        }
        #[cfg(not(feature = "sqlite"))]
        {
            let _ = path;
            anyhow::bail!("sqlite feature disabled")
        }
    }

    #[cfg(feature = "sqlite")]
    pub fn save(
        &self,
        name: &str,
        collector: &EventCollector,
        graph: &AssetGraph,
    ) -> anyhow::Result<Uuid> {
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let events_json = serde_json::to_string(&collector.events)?;
        let graph_json = serde_json::to_string(graph)?;
        let event_count = collector.events.len() as i64;
        self.conn.execute(
            "INSERT INTO runs (id, name, created_at, events_json, graph_json, event_count)
             VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                id.to_string(),
                name,
                created_at.to_rfc3339(),
                events_json,
                graph_json,
                event_count
            ],
        )?;
        Ok(id)
    }

    #[cfg(feature = "sqlite")]
    pub fn list(&self, limit: usize) -> anyhow::Result<Vec<(Uuid, String, DateTime<Utc>)>> {
        Ok(self
            .list_meta(limit, None)?
            .into_iter()
            .map(|m| (m.id, m.name, m.created_at))
            .collect())
    }

    #[cfg(feature = "sqlite")]
    pub fn list_meta(
        &self,
        limit: usize,
        name_filter: Option<&str>,
    ) -> anyhow::Result<Vec<RunMeta>> {
        let limit = limit.max(1) as i64;
        let rows = if let Some(name) = name_filter {
            let pattern = format!("%{name}%");
            let mut stmt = self.conn.prepare(
                "SELECT id, name, created_at, COALESCE(event_count, 0)
                 FROM runs
                 WHERE name LIKE ?1
                 ORDER BY created_at DESC
                 LIMIT ?2",
            )?;
            let mapped = stmt.query_map(rusqlite::params![pattern, limit], map_meta_row)?;
            mapped.collect::<Result<Vec<_>, _>>()?
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, name, created_at, COALESCE(event_count, 0)
                 FROM runs
                 ORDER BY created_at DESC
                 LIMIT ?1",
            )?;
            let mapped = stmt.query_map([limit], map_meta_row)?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        rows.into_iter().map(parse_meta).collect()
    }

    #[cfg(feature = "sqlite")]
    pub fn count(&self) -> anyhow::Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM runs", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    #[cfg(feature = "sqlite")]
    pub fn load(&self, id: Uuid) -> anyhow::Result<(EventCollector, AssetGraph)> {
        let mut stmt = self
            .conn
            .prepare("SELECT events_json, graph_json FROM runs WHERE id = ?1")?;
        let (events_json, graph_json): (String, String) =
            stmt.query_row([id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let events: Vec<Event> = serde_json::from_str(&events_json)?;
        let graph: AssetGraph = serde_json::from_str(&graph_json)?;
        let mut collector = EventCollector::new();
        collector.events = events;
        Ok((collector, graph))
    }

    #[cfg(feature = "sqlite")]
    pub fn load_name(&self, id: Uuid) -> anyhow::Result<(String, DateTime<Utc>)> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, created_at FROM runs WHERE id = ?1")?;
        let (name, created): (String, String) =
            stmt.query_row([id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok((
            name,
            DateTime::parse_from_rfc3339(&created)?.with_timezone(&Utc),
        ))
    }

    #[cfg(feature = "sqlite")]
    pub fn latest_named(&self, name: &str) -> anyhow::Result<Option<Uuid>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM runs WHERE name = ?1 ORDER BY created_at DESC LIMIT 1")?;
        let mut rows = stmt.query_map([name], |row| {
            let id: String = row.get(0)?;
            Ok(id)
        })?;
        if let Some(r) = rows.next() {
            let id = r?;
            return Ok(Some(Uuid::parse_str(&id)?));
        }
        Ok(None)
    }

    /// Canonical store name for a living workspace graph.
    pub fn workspace_name(id: &str) -> String {
        let id = id.trim();
        let id = if id.is_empty() { "default" } else { id };
        format!("workspace:{id}")
    }

    /// Load the latest workspace graph (empty graph if none).
    #[cfg(feature = "sqlite")]
    pub fn load_workspace(&self, id: &str) -> anyhow::Result<AssetGraph> {
        let name = Self::workspace_name(id);
        match self.latest_named(&name)? {
            Some(rid) => {
                let (_c, g) = self.load(rid)?;
                Ok(g)
            }
            None => Ok(AssetGraph::new()),
        }
    }

    /// Upsert workspace: replace prior `workspace:<id>` rows with a fresh save.
    #[cfg(feature = "sqlite")]
    pub fn upsert_workspace(
        &self,
        id: &str,
        collector: &EventCollector,
        graph: &AssetGraph,
    ) -> anyhow::Result<Uuid> {
        let name = Self::workspace_name(id);
        self.conn
            .execute("DELETE FROM runs WHERE name = ?1", [&name])?;
        self.save(&name, collector, graph)
    }

    #[cfg(not(feature = "sqlite"))]
    pub fn load_workspace(&self, _id: &str) -> anyhow::Result<AssetGraph> {
        Ok(AssetGraph::new())
    }

    #[cfg(not(feature = "sqlite"))]
    pub fn upsert_workspace(
        &self,
        _id: &str,
        _collector: &EventCollector,
        _graph: &AssetGraph,
    ) -> anyhow::Result<Uuid> {
        anyhow::bail!("sqlite feature disabled")
    }

    #[cfg(feature = "sqlite")]
    pub fn delete(&self, id: Uuid) -> anyhow::Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM runs WHERE id = ?1", [id.to_string()])?;
        Ok(n > 0)
    }

    /// Keep the newest `keep` runs globally (delete older). Returns deleted count.
    #[cfg(feature = "sqlite")]
    pub fn prune_keep(&self, keep: usize) -> anyhow::Result<usize> {
        let keep = keep.max(1) as i64;
        let n = self.conn.execute(
            "DELETE FROM runs WHERE id NOT IN (
                SELECT id FROM (
                    SELECT id FROM runs ORDER BY created_at DESC LIMIT ?1
                )
             )",
            [keep],
        )?;
        Ok(n)
    }

    /// Keep the newest `keep` runs for a given module name. Returns deleted count.
    #[cfg(feature = "sqlite")]
    pub fn prune_named(&self, name: &str, keep: usize) -> anyhow::Result<usize> {
        if keep == 0 {
            return self.delete_named(name);
        }
        let keep = keep as i64;
        let n = self.conn.execute(
            "DELETE FROM runs WHERE name = ?1 AND id NOT IN (
                SELECT id FROM (
                    SELECT id FROM runs WHERE name = ?1 ORDER BY created_at DESC LIMIT ?2
                )
             )",
            rusqlite::params![name, keep],
        )?;
        Ok(n)
    }

    /// Delete every run with this exact name.
    #[cfg(feature = "sqlite")]
    pub fn delete_named(&self, name: &str) -> anyhow::Result<usize> {
        let n = self
            .conn
            .execute("DELETE FROM runs WHERE name = ?1", [name])?;
        Ok(n)
    }

    #[cfg(feature = "sqlite")]
    pub fn stats(&self, id: Uuid) -> anyhow::Result<RunStats> {
        let (name, created_at) = self.load_name(id)?;
        let (collector, graph) = self.load(id)?;
        let mut hosts_up = 0usize;
        let mut ports_open = 0usize;
        let mut findings = 0usize;
        let mut os_guesses = 0usize;
        for e in &collector.events {
            match e {
                Event::HostUp { .. } => hosts_up += 1,
                Event::PortResult {
                    state: ares_core::model::PortState::Open,
                    ..
                } => ports_open += 1,
                Event::MisconfigFinding { .. } => findings += 1,
                Event::OsGuess { .. } => os_guesses += 1,
                _ => {}
            }
        }
        // Prefer graph counts when present
        if !graph.hosts.is_empty() {
            hosts_up = graph.hosts.values().filter(|h| h.up).count();
            ports_open = graph
                .hosts
                .values()
                .map(|h| {
                    h.ports
                        .values()
                        .filter(|p| p.state == ares_core::model::PortState::Open)
                        .count()
                })
                .sum();
            let g_findings = graph.finding_count();
            if g_findings > 0 {
                findings = g_findings;
            }
        }
        Ok(RunStats {
            id,
            name,
            created_at,
            event_count: collector.events.len(),
            hosts_up,
            ports_open,
            findings,
            os_guesses,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(feature = "sqlite")]
fn map_meta_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, String, String, i64)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

#[cfg(feature = "sqlite")]
fn parse_meta(
    (id, name, created, event_count): (String, String, String, i64),
) -> anyhow::Result<RunMeta> {
    Ok(RunMeta {
        id: Uuid::parse_str(&id)?,
        name,
        created_at: DateTime::parse_from_rfc3339(&created)?.with_timezone(&Utc),
        event_count: event_count.max(0) as u64,
    })
}
