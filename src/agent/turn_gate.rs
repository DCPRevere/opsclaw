//! Agent-turn conflict domains.
//!
//! Interactive turns can address any target, so they take the exclusive
//! barrier. Background scans take the shared barrier plus a lock for their
//! exact target: scans of different targets may run together, while a scan can
//! never race an interactive turn or another scan of the same target.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{
    Mutex as AsyncMutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock,
};

#[derive(Clone, Default)]
pub struct TurnGate {
    barrier: Arc<RwLock<()>>,
    targets: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
}

pub struct TargetTurnGuard {
    _barrier: OwnedRwLockReadGuard<()>,
    _target: OwnedMutexGuard<()>,
}

pub enum TurnGuard {
    Interactive(OwnedRwLockWriteGuard<()>),
    Target(TargetTurnGuard),
}

impl TurnGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize an interactive chat/webhook turn against every other turn.
    pub async fn acquire_interactive(&self) -> OwnedRwLockWriteGuard<()> {
        self.barrier.clone().write_owned().await
    }

    /// Serialize a background turn with the same target while allowing scans
    /// of unrelated targets to proceed concurrently.
    pub async fn acquire_target(&self, target: &crate::domain::FqTarget) -> TargetTurnGuard {
        let barrier = self.barrier.clone().read_owned().await;
        let key = target.to_string();
        let lock = {
            let mut locks = self.targets.lock().expect("turn-gate target map poisoned");
            locks.entry(key).or_default().clone()
        };
        let target = lock.lock_owned().await;
        TargetTurnGuard { _barrier: barrier, _target: target }
    }

    pub async fn acquire_for_target(&self, target: Option<&crate::domain::FqTarget>) -> TurnGuard {
        match target {
            Some(target) => TurnGuard::Target(self.acquire_target(target).await),
            None => TurnGuard::Interactive(self.acquire_interactive().await),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str) -> crate::domain::FqTarget {
        crate::domain::FqTarget::try_new("project", "prod", name).unwrap()
    }

    #[tokio::test]
    async fn different_targets_run_together_same_target_serializes() {
        let gate = TurnGate::new();
        let a = target("a");
        let b = target("b");
        let _a = gate.acquire_target(&a).await;
        let _b = gate.acquire_target(&b).await;

        let gate2 = gate.clone();
        let same = a.clone();
        let waiter = tokio::spawn(async move { gate2.acquire_target(&same).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(_a);
        waiter.await.unwrap();
    }

    #[tokio::test]
    async fn interactive_turn_excludes_target_turns() {
        let gate = TurnGate::new();
        let _interactive = gate.acquire_interactive().await;
        let gate2 = gate.clone();
        let waiter = tokio::spawn(async move { gate2.acquire_target(&target("a")).await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(_interactive);
        waiter.await.unwrap();
    }
}
