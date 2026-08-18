//! Agent-turn conflict domains and their live queue.
//!
//! Interactive turns can address any target, so they take the exclusive
//! barrier. Background scans take the shared barrier plus a lock for their
//! exact target: scans of different targets may run together, while a scan can
//! never race an interactive turn or another scan of the same target.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::{
    Mutex as AsyncMutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock,
};

#[derive(Clone, Default)]
pub struct TurnGate {
    barrier: Arc<RwLock<()>>,
    targets: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
    registry: Arc<Mutex<TurnRegistry>>,
}

#[derive(Default)]
struct TurnRegistry {
    next_id: u64,
    entries: Vec<TurnEntry>,
}

struct TurnEntry {
    id: u64,
    kind: String,
    conflict_domain: String,
    queued_at_ms: i64,
    started_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TurnSnapshot {
    pub kind: String,
    pub conflict_domain: String,
    pub state: &'static str,
    pub age_ms: i64,
    pub queued_at_ms: i64,
    pub started_at_ms: Option<i64>,
}

struct Registration {
    id: u64,
    registry: Arc<Mutex<TurnRegistry>>,
}

impl Registration {
    fn new(gate: &TurnGate, kind: &str, conflict_domain: String) -> Self {
        let mut registry = gate.registry.lock().expect("turn registry poisoned");
        registry.next_id += 1;
        let id = registry.next_id;
        registry.entries.push(TurnEntry {
            id,
            kind: kind.to_string(),
            conflict_domain,
            queued_at_ms: chrono::Utc::now().timestamp_millis(),
            started_at_ms: None,
        });
        Self { id, registry: gate.registry.clone() }
    }

    fn mark_active(&self) {
        let mut registry = self.registry.lock().expect("turn registry poisoned");
        if let Some(entry) = registry.entries.iter_mut().find(|entry| entry.id == self.id) {
            entry.started_at_ms = Some(chrono::Utc::now().timestamp_millis());
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().expect("turn registry poisoned");
        registry.entries.retain(|entry| entry.id != self.id);
    }
}

pub struct InteractiveTurnGuard {
    _barrier: OwnedRwLockWriteGuard<()>,
    _registration: Registration,
}

pub struct TargetTurnGuard {
    _barrier: OwnedRwLockReadGuard<()>,
    _target: OwnedMutexGuard<()>,
    _registration: Registration,
}

pub enum TurnGuard {
    Interactive { _guard: InteractiveTurnGuard },
    Target { _guard: TargetTurnGuard },
}

impl TurnGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize an interactive chat/webhook turn against every other turn.
    pub async fn acquire_interactive(&self, kind: &str) -> InteractiveTurnGuard {
        let registration = Registration::new(self, kind, "all targets".into());
        let barrier = self.barrier.clone().write_owned().await;
        registration.mark_active();
        InteractiveTurnGuard { _barrier: barrier, _registration: registration }
    }

    /// Serialize a background turn with the same target while allowing scans
    /// of unrelated targets to proceed concurrently.
    pub async fn acquire_target(
        &self,
        kind: &str,
        target: &crate::domain::FqTarget,
    ) -> TargetTurnGuard {
        let key = target.to_string();
        let registration = Registration::new(self, kind, key.clone());
        let barrier = self.barrier.clone().read_owned().await;
        let lock = {
            let mut locks = self.targets.lock().expect("turn-gate target map poisoned");
            locks.entry(key).or_default().clone()
        };
        let target = lock.lock_owned().await;
        registration.mark_active();
        TargetTurnGuard { _barrier: barrier, _target: target, _registration: registration }
    }

    pub async fn acquire_for_target(
        &self,
        kind: &str,
        target: Option<&crate::domain::FqTarget>,
    ) -> TurnGuard {
        match target {
            Some(target) => TurnGuard::Target { _guard: self.acquire_target(kind, target).await },
            None => TurnGuard::Interactive { _guard: self.acquire_interactive(kind).await },
        }
    }

    pub fn snapshot(&self, now_ms: i64) -> Vec<TurnSnapshot> {
        let registry = self.registry.lock().expect("turn registry poisoned");
        registry
            .entries
            .iter()
            .map(|entry| {
                let (state, since) = match entry.started_at_ms {
                    Some(started) => ("active", started),
                    None => ("queued", entry.queued_at_ms),
                };
                TurnSnapshot {
                    kind: entry.kind.clone(),
                    conflict_domain: entry.conflict_domain.clone(),
                    state,
                    age_ms: now_ms.saturating_sub(since),
                    queued_at_ms: entry.queued_at_ms,
                    started_at_ms: entry.started_at_ms,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str) -> crate::domain::FqTarget {
        crate::domain::FqTarget::try_new("project", "prod", name).unwrap()
    }

    #[tokio::test]
    async fn different_targets_run_together_same_target_serializes_and_reports_queue() {
        let gate = TurnGate::new();
        let a = target("a");
        let b = target("b");
        let active_a = gate.acquire_target("scan", &a).await;
        let _active_b = gate.acquire_target("scan", &b).await;

        let gate2 = gate.clone();
        let same = a.clone();
        let waiter = tokio::spawn(async move { gate2.acquire_target("scan", &same).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        let status = gate.snapshot(chrono::Utc::now().timestamp_millis());
        assert_eq!(status.iter().filter(|turn| turn.state == "active").count(), 2);
        assert_eq!(status.iter().filter(|turn| turn.state == "queued").count(), 1);
        assert!(status.iter().all(|turn| turn.kind == "scan"));
        drop(active_a);
        waiter.await.unwrap();
    }

    #[tokio::test]
    async fn interactive_turn_excludes_target_turns_and_disappears_on_drop() {
        let gate = TurnGate::new();
        let interactive = gate.acquire_interactive("chat").await;
        let gate2 = gate.clone();
        let waiter = tokio::spawn(async move { gate2.acquire_target("scan", &target("a")).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        assert_eq!(gate.snapshot(chrono::Utc::now().timestamp_millis()).len(), 2);
        drop(interactive);
        let target_guard = waiter.await.unwrap();
        assert_eq!(gate.snapshot(chrono::Utc::now().timestamp_millis()).len(), 1);
        drop(target_guard);
        assert!(gate.snapshot(chrono::Utc::now().timestamp_millis()).is_empty());
    }
}
