//! Snapshot persistence — save and load [`TargetSnapshot`] as JSON files.

use crate::tools::discovery::TargetSnapshot;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Return the directory used for OpsClaw snapshots (`~/.opsclaw/snapshots/`).
fn snapshots_dir() -> Result<PathBuf> {
    let user_dirs = directories::UserDirs::new().context("Cannot determine home directory")?;
    Ok(user_dirs.home_dir().join(".opsclaw").join("snapshots"))
}

/// Return the path for a specific target's snapshot file.
pub fn snapshot_path(target_name: &str) -> Result<PathBuf> {
    Ok(snapshots_dir()?.join(format!("{target_name}.json")))
}

/// Persist a snapshot to `~/.opsclaw/snapshots/<target_name>.json`.
pub fn save_snapshot(target_name: &str, snapshot: &TargetSnapshot) -> Result<()> {
    let dir = snapshots_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create snapshots directory: {}", dir.display()))?;

    let path = dir.join(format!("{target_name}.json"));
    let json =
        serde_json::to_string_pretty(snapshot).context("Failed to serialize snapshot to JSON")?;
    std::fs::write(&path, json)
        .with_context(|| format!("Failed to write snapshot to {}", path.display()))?;
    Ok(())
}

/// Load a previously saved snapshot, returning `None` if the file doesn't exist.
pub fn load_snapshot(target_name: &str) -> Result<Option<TargetSnapshot>> {
    let path = snapshot_path(target_name)?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read snapshot from {}", path.display()))?;
    let snapshot: TargetSnapshot =
        serde_json::from_str(&data).context("Failed to deserialize snapshot JSON")?;
    Ok(Some(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snapshot() -> TargetSnapshot {
        use crate::tools::discovery::*;
        use chrono::Utc;

        TargetSnapshot {
            scanned_at: Utc::now(),
            os: OsInfo {
                uname: "Linux test 5.15.0".into(),
                distro_name: "Ubuntu".into(),
                distro_version: "22.04".into(),
            },
            containers: vec![ContainerInfo {
                id: "abc123".into(),
                name: "sacra-api".into(),
                image: "sacra/api:latest".into(),
                status: "Up 5 hours".into(),
                ports: "0.0.0.0:33000->8080/tcp".into(),
                running_for: "5 hours".into(),
            }],
            services: vec![],
            listening_ports: vec![],
            disk: vec![],
            memory: MemoryInfo {
                total_mb: 8000,
                used_mb: 4000,
                free_mb: 2000,
                available_mb: 4000,
            },
            load: LoadInfo {
                load_1: 0.5,
                load_5: 0.3,
                load_15: 0.2,
                uptime: "up 42 days".into(),
            },
        }
    }

    #[test]
    fn roundtrip_snapshot_via_serde() {
        let snap = sample_snapshot();
        let json = serde_json::to_string_pretty(&snap).unwrap();
        let parsed: TargetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.os.distro_name, "Ubuntu");
        assert_eq!(parsed.containers.len(), 1);
        assert_eq!(parsed.containers[0].name, "sacra-api");
    }
}
