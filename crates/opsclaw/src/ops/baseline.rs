//! Baseline learning — rolling statistics, anomaly detection, and disk projection.
//!
//! Tracks metric observations over a sliding window per target, computes
//! mean/stddev/trend, detects anomalies beyond a configurable sigma threshold,
//! and projects disk-full timelines via linear regression.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::tools::discovery::TargetSnapshot;
use crate::tools::monitoring::{Alert, AlertCategory, AlertSeverity};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// A single metric observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
}

/// Direction of a metric over its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trend {
    Rising,
    Falling,
    Stable,
}

impl fmt::Display for Trend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Trend::Rising => write!(f, "Rising"),
            Trend::Falling => write!(f, "Falling"),
            Trend::Stable => write!(f, "Stable"),
        }
    }
}

/// Rolling statistics for a named metric on a specific target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBaseline {
    pub name: String,
    pub target: String,
    pub points: VecDeque<MetricPoint>,
    pub max_points: usize,
}

impl MetricBaseline {
    pub fn new(name: &str, target: &str, max_points: usize) -> Self {
        Self {
            name: name.to_string(),
            target: target.to_string(),
            points: VecDeque::new(),
            max_points,
        }
    }

    /// Record a new value, evicting the oldest if the window is full.
    pub fn record(&mut self, value: f64) {
        if self.points.len() >= self.max_points {
            self.points.pop_front();
        }
        self.points.push_back(MetricPoint {
            timestamp: Utc::now(),
            value,
        });
    }

    pub fn mean(&self) -> f64 {
        if self.points.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.points.iter().map(|p| p.value).sum();
        sum / self.points.len() as f64
    }

    pub fn stddev(&self) -> f64 {
        if self.points.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance: f64 = self.points.iter().map(|p| (p.value - mean).powi(2)).sum::<f64>()
            / (self.points.len() - 1) as f64;
        variance.sqrt()
    }

    pub fn min(&self) -> f64 {
        self.points
            .iter()
            .map(|p| p.value)
            .fold(f64::INFINITY, f64::min)
    }

    pub fn max(&self) -> f64 {
        self.points
            .iter()
            .map(|p| p.value)
            .fold(f64::NEG_INFINITY, f64::max)
    }

    pub fn latest(&self) -> Option<f64> {
        self.points.back().map(|p| p.value)
    }

    /// Returns `true` if `value` is more than `sigma` standard deviations from the mean.
    pub fn is_anomalous(&self, value: f64, sigma: f64) -> bool {
        let sd = self.stddev();
        if sd <= 0.0 || self.points.len() < 2 {
            return false;
        }
        let deviation = (value - self.mean()).abs();
        deviation > sigma * sd
    }

    /// Determine the trend by computing the slope of a simple linear regression.
    pub fn trend(&self) -> Trend {
        if self.points.len() < 3 {
            return Trend::Stable;
        }
        let slope = self.linear_slope();
        let sd = self.stddev();
        // Only declare a trend if the slope per-observation exceeds 10% of one stddev.
        let threshold = if sd > 0.0 { sd * 0.1 } else { 1e-9 };
        if slope > threshold {
            Trend::Rising
        } else if slope < -threshold {
            Trend::Falling
        } else {
            Trend::Stable
        }
    }

    /// Slope of the least-squares fit (value vs index).
    fn linear_slope(&self) -> f64 {
        let n = self.points.len() as f64;
        if n < 2.0 {
            return 0.0;
        }
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_xx = 0.0;
        for (i, p) in self.points.iter().enumerate() {
            let x = i as f64;
            sum_x += x;
            sum_y += p.value;
            sum_xy += x * p.value;
            sum_xx += x * x;
        }
        let denom = n * sum_xx - sum_x * sum_x;
        if denom.abs() < 1e-12 {
            return 0.0;
        }
        (n * sum_xy - sum_x * sum_y) / denom
    }
}

// ---------------------------------------------------------------------------
// Metric extraction from snapshots
// ---------------------------------------------------------------------------

/// Extract numeric metrics from a [`TargetSnapshot`].
pub fn extract_metrics(snapshot: &TargetSnapshot) -> Vec<(String, f64)> {
    let mut metrics = Vec::new();

    // CPU load
    metrics.push(("cpu.load_1".to_string(), snapshot.load.load_1));
    metrics.push(("cpu.load_5".to_string(), snapshot.load.load_5));

    // Memory
    if snapshot.memory.total_mb > 0 {
        let used_pct =
            (snapshot.memory.used_mb as f64 / snapshot.memory.total_mb as f64) * 100.0;
        metrics.push(("memory.used_percent".to_string(), used_pct));
    }
    metrics.push((
        "memory.available_mb".to_string(),
        snapshot.memory.available_mb as f64,
    ));

    // Disk per mount point
    for d in &snapshot.disk {
        let key = format!("disk.{}.used_percent", sanitize_mount(&d.mount_point));
        metrics.push((key, f64::from(d.use_percent)));
    }

    // Counts
    metrics.push((
        "containers.count".to_string(),
        snapshot.containers.len() as f64,
    ));
    metrics.push((
        "services.count".to_string(),
        snapshot.services.len() as f64,
    ));
    metrics.push((
        "ports.count".to_string(),
        snapshot.listening_ports.len() as f64,
    ));

    metrics
}

/// Replace `/` with `_` in mount points for use as metric keys.
fn sanitize_mount(mount: &str) -> String {
    if mount == "/" {
        return "root".to_string();
    }
    mount
        .trim_start_matches('/')
        .replace('/', "_")
}

// ---------------------------------------------------------------------------
// Anomaly alerts
// ---------------------------------------------------------------------------

/// An anomaly detected by comparing a current value against its baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub metric: String,
    pub current: f64,
    pub mean: f64,
    pub stddev: f64,
    pub sigma: f64,
    pub trend: Trend,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Disk projection
// ---------------------------------------------------------------------------

/// If disk usage is rising, estimate how many days until 100% based on linear regression.
/// Returns `None` if the trend is not rising or there is insufficient data.
pub fn project_disk_full_days(baseline: &MetricBaseline) -> Option<f64> {
    if baseline.points.len() < 3 || baseline.trend() != Trend::Rising {
        return None;
    }

    let latest = baseline.latest()?;
    if latest >= 100.0 {
        return Some(0.0);
    }

    let slope = baseline.linear_slope();
    if slope <= 0.0 {
        return None;
    }

    // slope is per-observation. We need observations per day.
    // Estimate interval from first and last timestamps.
    let first_ts = baseline.points.front()?.timestamp;
    let last_ts = baseline.points.back()?.timestamp;
    let span_secs = (last_ts - first_ts).num_seconds() as f64;
    if span_secs <= 0.0 {
        return None;
    }
    let obs_per_day = (baseline.points.len() as f64 - 1.0) / (span_secs / 86400.0);
    if obs_per_day <= 0.0 {
        return None;
    }

    let remaining_pct = 100.0 - latest;
    let observations_to_full = remaining_pct / slope;
    let days = observations_to_full / obs_per_day;

    if days > 0.0 { Some(days) } else { None }
}

// ---------------------------------------------------------------------------
// Baseline store
// ---------------------------------------------------------------------------

/// Default sliding window size: 288 = 24h at 5-minute intervals.
const DEFAULT_MAX_POINTS: usize = 288;

/// Persisted baseline store — one per target, keyed by metric name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStore {
    baselines: HashMap<String, MetricBaseline>,
    #[serde(skip)]
    file_path: PathBuf,
}

impl BaselineStore {
    /// Load an existing store from `path`, or return a new empty store if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let data = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read baseline store: {}", path.display()))?;
            let mut store: BaselineStore = serde_json::from_str(&data)
                .with_context(|| format!("Failed to parse baseline store: {}", path.display()))?;
            store.file_path = path.to_path_buf();
            Ok(store)
        } else {
            Ok(Self {
                baselines: HashMap::new(),
                file_path: path.to_path_buf(),
            })
        }
    }

    /// Persist the store to its file path.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create baselines directory: {}",
                    parent.display()
                )
            })?;
        }
        let json =
            serde_json::to_string_pretty(self).context("Failed to serialize baseline store")?;
        std::fs::write(&self.file_path, json).with_context(|| {
            format!(
                "Failed to write baseline store: {}",
                self.file_path.display()
            )
        })?;
        Ok(())
    }

    /// Record a set of metric observations for a target.
    pub fn record(&mut self, target: &str, metrics: &[(String, f64)]) {
        for (name, value) in metrics {
            let key = format!("{target}.{name}");
            let baseline = self.baselines.entry(key).or_insert_with(|| {
                MetricBaseline::new(name, target, DEFAULT_MAX_POINTS)
            });
            baseline.record(*value);
        }
    }

    /// Check all provided metrics for anomalies, returning alerts for any that exceed
    /// the given sigma threshold.
    pub fn check_anomalies(
        &self,
        target: &str,
        metrics: &[(String, f64)],
        sigma: f64,
    ) -> Vec<AnomalyAlert> {
        let mut anomalies = Vec::new();
        for (name, value) in metrics {
            let key = format!("{target}.{name}");
            if let Some(baseline) = self.baselines.get(&key) {
                if baseline.is_anomalous(*value, sigma) {
                    let mean = baseline.mean();
                    let sd = baseline.stddev();
                    let deviation = if sd > 0.0 {
                        (*value - mean).abs() / sd
                    } else {
                        0.0
                    };
                    let trend = baseline.trend();

                    use std::fmt::Write as _;
                    let mut msg = format!(
                        "{name} is {value:.1} (normally {mean:.1} \u{00b1} {sd:.1}, {deviation:.1}\u{03c3}, {trend})"
                    );

                    // Append disk projection for disk metrics.
                    if name.starts_with("disk.") && name.ends_with(".used_percent") {
                        if let Some(days) = project_disk_full_days(baseline) {
                            let _ = write!(msg, " \u{2014} projected full in {days:.0} days");
                        }
                    }

                    anomalies.push(AnomalyAlert {
                        metric: name.clone(),
                        current: *value,
                        mean,
                        stddev: sd,
                        sigma: deviation,
                        trend,
                        message: msg,
                    });
                }
            }
        }
        anomalies
    }

    /// Produce a human-readable baseline summary for LLM context.
    pub fn summary(&self, target: &str) -> String {
        use std::fmt::Write;
        let prefix = format!("{target}.");
        let mut lines: Vec<_> = self
            .baselines
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .collect();
        lines.sort_by_key(|(k, _)| (*k).clone());

        if lines.is_empty() {
            return format!("No baseline data for target '{target}'.\n");
        }

        let mut out = String::new();
        let _ = writeln!(
            out,
            "Baselines ({} window, {} metrics):",
            if lines.first().map_or(0, |(_, b)| b.max_points) == DEFAULT_MAX_POINTS {
                "24h".to_string()
            } else {
                format!("{}-point", lines.first().map_or(0, |(_, b)| b.max_points))
            },
            lines.len()
        );

        for (_, baseline) in &lines {
            let current = baseline.latest().unwrap_or(0.0);
            let mean = baseline.mean();
            let sd = baseline.stddev();
            let trend = baseline.trend();
            let obs = baseline.points.len();

            let anomaly_flag = if baseline.is_anomalous(current, 3.0) {
                let dev = if sd > 0.0 {
                    (current - mean).abs() / sd
                } else {
                    0.0
                };
                format!("\u{26a0}\u{fe0f} {dev:.1}\u{03c3}")
            } else {
                "OK".to_string()
            };

            let mut line = format!(
                "  {name:<25} current={current:<8.1}  mean={mean:<8.1}  stddev={sd:<8.1}  trend={trend:<8}  {anomaly_flag}  ({obs} obs)",
                name = baseline.name,
            );

            // Disk projection for disk metrics.
            if baseline.name.starts_with("disk.") && baseline.name.ends_with(".used_percent") {
                if let Some(days) = project_disk_full_days(baseline) {
                    let _ = write!(line, "  projected full in {days:.0} days");
                }
            }

            let _ = writeln!(out, "{line}");
        }
        out
    }

    /// Return the path the store was loaded from or will be saved to.
    pub fn path(&self) -> &Path {
        &self.file_path
    }

    /// Remove all baselines for a given target. Returns `true` if any were removed.
    pub fn reset_target(&mut self, target: &str) -> bool {
        let prefix = format!("{target}.");
        let before = self.baselines.len();
        self.baselines.retain(|k, _| !k.starts_with(&prefix));
        self.baselines.len() < before
    }

    /// Remove all baselines.
    pub fn reset_all(&mut self) {
        self.baselines.clear();
    }
}

/// Return the directory used for baseline stores (`~/.opsclaw/baselines/`).
pub fn baselines_dir() -> Result<PathBuf> {
    let user_dirs = directories::UserDirs::new().context("Cannot determine home directory")?;
    Ok(user_dirs.home_dir().join(".opsclaw").join("baselines"))
}

/// Return the path for a specific target's baseline file.
pub fn baseline_path(target_name: &str) -> Result<PathBuf> {
    Ok(baselines_dir()?.join(format!("{target_name}.json")))
}

/// Convert [`AnomalyAlert`]s into monitoring [`Alert`]s.
pub fn anomalies_to_alerts(anomalies: &[AnomalyAlert]) -> Vec<Alert> {
    anomalies
        .iter()
        .map(|a| {
            let severity = if a.sigma >= 5.0 {
                AlertSeverity::Critical
            } else {
                AlertSeverity::Warning
            };
            Alert {
                severity,
                category: AlertCategory::MetricAnomaly,
                message: a.message.clone(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_baseline(values: &[f64]) -> MetricBaseline {
        let mut b = MetricBaseline::new("test", "host1", 100);
        for v in values {
            b.record(*v);
        }
        b
    }

    #[test]
    fn mean_and_stddev() {
        let b = make_baseline(&[10.0, 20.0, 30.0]);
        assert!((b.mean() - 20.0).abs() < 1e-9);
        assert!((b.stddev() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn min_max_latest() {
        let b = make_baseline(&[5.0, 15.0, 10.0]);
        assert!((b.min() - 5.0).abs() < 1e-9);
        assert!((b.max() - 15.0).abs() < 1e-9);
        assert!((b.latest().unwrap() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn empty_baseline_safe() {
        let b = MetricBaseline::new("empty", "host", 10);
        assert!((b.mean()).abs() < 1e-9);
        assert!((b.stddev()).abs() < 1e-9);
        assert!(b.latest().is_none());
        assert_eq!(b.trend(), Trend::Stable);
        assert!(!b.is_anomalous(42.0, 3.0));
    }

    #[test]
    fn anomaly_detection_within_range() {
        let b = make_baseline(&[10.0, 10.0, 10.0, 10.0, 10.0, 11.0, 9.0, 10.0, 10.0, 10.0]);
        // Value close to mean should not be anomalous
        assert!(!b.is_anomalous(10.5, 3.0));
    }

    #[test]
    fn anomaly_detection_outside_range() {
        let b = make_baseline(&[10.0, 10.0, 10.0, 10.0, 10.0, 11.0, 9.0, 10.0, 10.0, 10.0]);
        // Value far from mean should be anomalous
        assert!(b.is_anomalous(50.0, 3.0));
    }

    #[test]
    fn trend_rising() {
        let b = make_baseline(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]);
        assert_eq!(b.trend(), Trend::Rising);
    }

    #[test]
    fn trend_falling() {
        let b = make_baseline(&[10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0]);
        assert_eq!(b.trend(), Trend::Falling);
    }

    #[test]
    fn trend_stable() {
        let b = make_baseline(&[10.0, 10.0, 10.0, 10.0, 10.0]);
        assert_eq!(b.trend(), Trend::Stable);
    }

    #[test]
    fn window_eviction() {
        let mut b = MetricBaseline::new("test", "host", 5);
        for i in 0..10 {
            b.record(f64::from(i));
        }
        assert_eq!(b.points.len(), 5);
        assert!((b.points.front().unwrap().value - 5.0).abs() < 1e-9);
    }

    #[test]
    fn extract_metrics_basic() {
        use crate::tools::discovery::*;

        let snap = TargetSnapshot {
            scanned_at: Utc::now(),
            os: OsInfo {
                uname: String::new(),
                distro_name: String::new(),
                distro_version: String::new(),
            },
            containers: vec![
                ContainerInfo {
                    id: "1".into(),
                    name: "web".into(),
                    image: "img".into(),
                    status: "Up".into(),
                    ports: String::new(),
                    running_for: String::new(),
                },
            ],
            services: vec![],
            listening_ports: vec![],
            disk: vec![DiskInfo {
                filesystem: "/dev/sda1".into(),
                size: "50G".into(),
                used: "30G".into(),
                available: "20G".into(),
                use_percent: 60,
                mount_point: "/".into(),
            }],
            memory: MemoryInfo {
                total_mb: 8000,
                used_mb: 4000,
                free_mb: 2000,
                available_mb: 4000,
            },
            load: LoadInfo {
                load_1: 1.5,
                load_5: 1.2,
                load_15: 0.8,
                uptime: String::new(),
            },
            kubernetes: None,
        };

        let metrics = extract_metrics(&snap);
        let find = |name: &str| metrics.iter().find(|(n, _)| n == name).map(|(_, v)| *v);

        assert!((find("cpu.load_1").unwrap() - 1.5).abs() < 1e-9);
        assert!((find("cpu.load_5").unwrap() - 1.2).abs() < 1e-9);
        assert!((find("memory.used_percent").unwrap() - 50.0).abs() < 1e-9);
        assert!((find("memory.available_mb").unwrap() - 4000.0).abs() < 1e-9);
        assert!((find("disk.root.used_percent").unwrap() - 60.0).abs() < 1e-9);
        assert!((find("containers.count").unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn disk_projection_rising() {
        // Simulate disk usage rising from 50% to 80% over 30 observations
        // spaced 5 minutes apart.
        let mut b = MetricBaseline::new("disk.root.used_percent", "host", 288);
        let start = Utc::now() - chrono::Duration::minutes(150);
        for i in 0..31 {
            let ts = start + chrono::Duration::minutes(i * 5);
            b.points.push_back(MetricPoint {
                timestamp: ts,
                value: 50.0 + i as f64,
            });
        }
        let days = project_disk_full_days(&b);
        assert!(days.is_some());
        let days = days.unwrap();
        // From 80% to 100% = 20 pct remaining, slope ~1 pct per 5 min = 288 pct/day
        // So ~20/288 ≈ 0.07 days — but let's just check it's a positive, reasonable number.
        assert!(days > 0.0);
        assert!(days < 1.0); // should fill within a day at this rate
    }

    #[test]
    fn disk_projection_stable_returns_none() {
        let b = make_baseline(&[50.0, 50.0, 50.0, 50.0, 50.0]);
        assert!(project_disk_full_days(&b).is_none());
    }

    #[test]
    fn store_record_and_check() {
        let dir = std::env::temp_dir().join("opsclaw_test_baseline");
        let path = dir.join("test.json");
        let _ = std::fs::remove_file(&path);

        let mut store = BaselineStore::load(&path).unwrap();

        // Record 10 observations with slight variance so stddev > 0.
        for i in 0..10 {
            let val = 1.0 + (i % 3) as f64 * 0.1; // 1.0, 1.1, 1.2, 1.0, 1.1, ...
            store.record("myhost", &[("cpu.load_1".to_string(), val)]);
        }

        // A value within range should produce no anomalies.
        let anomalies = store.check_anomalies("myhost", &[("cpu.load_1".to_string(), 1.2)], 3.0);
        assert!(anomalies.is_empty());

        // A value way outside range should produce an anomaly.
        let anomalies = store.check_anomalies("myhost", &[("cpu.load_1".to_string(), 50.0)], 3.0);
        assert_eq!(anomalies.len(), 1);
        assert!(anomalies[0].message.contains("cpu.load_1"));
    }

    #[test]
    fn store_persistence_roundtrip() {
        let dir = std::env::temp_dir().join("opsclaw_test_baseline_rt");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roundtrip.json");
        let _ = std::fs::remove_file(&path);

        let mut store = BaselineStore::load(&path).unwrap();
        store.record("host", &[("cpu.load_1".to_string(), 2.5)]);
        store.save().unwrap();

        let loaded = BaselineStore::load(&path).unwrap();
        let anomalies = loaded.check_anomalies("host", &[("cpu.load_1".to_string(), 2.5)], 3.0);
        assert!(anomalies.is_empty());

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn store_reset_target() {
        let path = std::env::temp_dir().join("opsclaw_test_reset.json");
        let _ = std::fs::remove_file(&path);

        let mut store = BaselineStore::load(&path).unwrap();
        store.record("host1", &[("cpu.load_1".to_string(), 1.0)]);
        store.record("host2", &[("cpu.load_1".to_string(), 2.0)]);
        assert!(store.reset_target("host1"));
        assert!(store.check_anomalies("host1", &[("cpu.load_1".to_string(), 1.0)], 3.0).is_empty());
        // host2 should still be present
        assert!(!store.baselines.is_empty());
    }

    #[test]
    fn summary_output() {
        let path = std::env::temp_dir().join("opsclaw_test_summary.json");
        let _ = std::fs::remove_file(&path);

        let mut store = BaselineStore::load(&path).unwrap();
        for i in 0..10 {
            store.record("myhost", &[("cpu.load_1".to_string(), 1.0 + f64::from(i) * 0.01)]);
        }
        let summary = store.summary("myhost");
        assert!(summary.contains("cpu.load_1"));
        assert!(summary.contains("Baselines"));
    }

    #[test]
    fn anomalies_to_alerts_severity() {
        let anomalies = vec![
            AnomalyAlert {
                metric: "cpu.load_1".to_string(),
                current: 10.0,
                mean: 1.0,
                stddev: 0.5,
                sigma: 18.0, // >= 5 → Critical
                trend: Trend::Rising,
                message: "high".to_string(),
            },
            AnomalyAlert {
                metric: "memory.used_percent".to_string(),
                current: 70.0,
                mean: 60.0,
                stddev: 2.0,
                sigma: 3.5, // < 5 → Warning
                trend: Trend::Stable,
                message: "moderate".to_string(),
            },
        ];
        let alerts = anomalies_to_alerts(&anomalies);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert_eq!(alerts[0].category, AlertCategory::MetricAnomaly);
        assert_eq!(alerts[1].severity, AlertSeverity::Warning);
    }
}
