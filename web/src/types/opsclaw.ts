export interface Target {
  name: string;
  type: 'ssh' | 'local' | 'k8s';
  host?: string;
  autonomy: 'dry-run' | 'approve' | 'auto';
  last_scan?: string;
  health_status: 'Healthy' | 'Warning' | 'Critical' | 'Unknown';
}

export interface HealthCheck {
  target_name: string;
  checked_at: string;
  status: 'Healthy' | 'Warning' | 'Critical';
  alerts: Alert[];
}

export interface Alert {
  severity: string;
  category: string;
  message: string;
}

export interface Incident {
  incident_id: string;
  timestamp: string;
  target_name: string;
  severity: string;
  llm_assessment: string;
  suggested_actions: string[];
  resolution?: string;
  similar_incidents?: string[];
}

export interface Runbook {
  id: string;
  name: string;
  description: string;
  trigger_conditions?: string[];
  steps: RunbookStep[];
  execution_count: number;
  success_rate: number;
}

export interface RunbookStep {
  description: string;
  command?: string;
  on_failure: string;
}

export interface RunbookExecution {
  id: string;
  runbook_id: string;
  target_name: string;
  started_at: string;
  finished_at?: string;
  status: 'success' | 'failure' | 'running';
  output?: string;
}

export interface BaselineMetric {
  name: string;
  current: number;
  mean: number;
  stddev: number;
  trend: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  target_name?: string;
  action_type: string;
  command: string;
  dry_run: boolean;
  result: string;
  hash: string;
  prev_hash: string;
}

export interface TargetSnapshot {
  containers: { name: string; status: string; image: string }[];
  services: { name: string; status: string; port?: number }[];
  ports: number[];
  disk_usage_pct: number;
  memory_usage_pct: number;
  load_avg: number[];
}

export interface Probe {
  name: string;
  type: string;
  status: 'ok' | 'warning' | 'critical';
  last_check: string;
  detail?: string;
}
