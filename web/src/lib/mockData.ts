import type {
  Target,
  HealthCheck,
  Incident,
  Runbook,
  RunbookExecution,
  BaselineMetric,
  AuditEntry,
  TargetSnapshot,
  Probe,
} from '@/types/opsclaw';

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

export const mockTargets: Target[] = [
  {
    name: 'web-prod-01',
    type: 'ssh',
    host: '10.0.1.12',
    autonomy: 'approve',
    last_scan: '2026-03-17T08:42:00Z',
    health_status: 'Healthy',
  },
  {
    name: 'web-prod-02',
    type: 'ssh',
    host: '10.0.1.13',
    autonomy: 'approve',
    last_scan: '2026-03-17T08:41:30Z',
    health_status: 'Warning',
  },
  {
    name: 'db-primary',
    type: 'ssh',
    host: '10.0.2.5',
    autonomy: 'dry-run',
    last_scan: '2026-03-17T08:40:00Z',
    health_status: 'Healthy',
  },
  {
    name: 'k8s-staging',
    type: 'k8s',
    host: 'staging.k8s.internal',
    autonomy: 'auto',
    last_scan: '2026-03-17T08:38:00Z',
    health_status: 'Critical',
  },
  {
    name: 'localhost',
    type: 'local',
    autonomy: 'auto',
    last_scan: '2026-03-17T08:43:00Z',
    health_status: 'Healthy',
  },
  {
    name: 'cache-redis',
    type: 'ssh',
    host: '10.0.3.8',
    autonomy: 'dry-run',
    health_status: 'Unknown',
  },
];

// ---------------------------------------------------------------------------
// Health checks
// ---------------------------------------------------------------------------

export const mockHealthChecks: HealthCheck[] = [
  { target_name: 'web-prod-01', checked_at: '2026-03-17T08:42:00Z', status: 'Healthy', alerts: [] },
  { target_name: 'web-prod-01', checked_at: '2026-03-17T08:32:00Z', status: 'Healthy', alerts: [] },
  { target_name: 'web-prod-01', checked_at: '2026-03-17T08:22:00Z', status: 'Warning', alerts: [{ severity: 'warning', category: 'memory', message: 'Memory usage above 80%' }] },
  { target_name: 'web-prod-02', checked_at: '2026-03-17T08:41:30Z', status: 'Warning', alerts: [{ severity: 'warning', category: 'disk', message: 'Disk usage at 87%' }] },
  { target_name: 'web-prod-02', checked_at: '2026-03-17T08:31:30Z', status: 'Healthy', alerts: [] },
  { target_name: 'k8s-staging', checked_at: '2026-03-17T08:38:00Z', status: 'Critical', alerts: [{ severity: 'critical', category: 'pod', message: '3 pods in CrashLoopBackOff' }, { severity: 'warning', category: 'memory', message: 'Node memory pressure' }] },
];

// ---------------------------------------------------------------------------
// Target snapshots
// ---------------------------------------------------------------------------

export const mockSnapshots: Record<string, TargetSnapshot> = {
  'web-prod-01': {
    containers: [
      { name: 'nginx', status: 'running', image: 'nginx:1.25' },
      { name: 'app', status: 'running', image: 'myapp:v2.4.1' },
    ],
    services: [
      { name: 'nginx', status: 'active', port: 443 },
      { name: 'myapp', status: 'active', port: 8080 },
    ],
    ports: [22, 443, 8080],
    disk_usage_pct: 54,
    memory_usage_pct: 68,
    load_avg: [1.2, 1.5, 1.3],
  },
  'web-prod-02': {
    containers: [
      { name: 'nginx', status: 'running', image: 'nginx:1.25' },
      { name: 'app', status: 'running', image: 'myapp:v2.4.1' },
    ],
    services: [
      { name: 'nginx', status: 'active', port: 443 },
      { name: 'myapp', status: 'active', port: 8080 },
    ],
    ports: [22, 443, 8080],
    disk_usage_pct: 87,
    memory_usage_pct: 72,
    load_avg: [2.1, 1.8, 1.6],
  },
  'k8s-staging': {
    containers: [
      { name: 'api-7f8d9', status: 'CrashLoopBackOff', image: 'api:staging-latest' },
      { name: 'worker-3a2b1', status: 'CrashLoopBackOff', image: 'worker:staging-latest' },
      { name: 'web-5c4d3', status: 'running', image: 'web:staging-latest' },
    ],
    services: [
      { name: 'api', status: 'degraded', port: 8080 },
      { name: 'worker', status: 'failed' },
      { name: 'web', status: 'active', port: 3000 },
    ],
    ports: [80, 443, 8080, 3000],
    disk_usage_pct: 41,
    memory_usage_pct: 91,
    load_avg: [4.8, 3.9, 3.2],
  },
};

// ---------------------------------------------------------------------------
// Baseline metrics (time series samples)
// ---------------------------------------------------------------------------

export const mockBaselines: Record<string, BaselineMetric[]> = {
  'web-prod-01': [
    { name: 'cpu_pct', current: 32, mean: 28, stddev: 8, trend: 'stable' },
    { name: 'memory_pct', current: 68, mean: 62, stddev: 10, trend: 'rising' },
    { name: 'disk_pct', current: 54, mean: 52, stddev: 3, trend: 'stable' },
  ],
  'web-prod-02': [
    { name: 'cpu_pct', current: 45, mean: 35, stddev: 12, trend: 'rising' },
    { name: 'memory_pct', current: 72, mean: 60, stddev: 14, trend: 'rising' },
    { name: 'disk_pct', current: 87, mean: 70, stddev: 8, trend: 'rising' },
  ],
  'k8s-staging': [
    { name: 'cpu_pct', current: 88, mean: 40, stddev: 15, trend: 'spike' },
    { name: 'memory_pct', current: 91, mean: 55, stddev: 18, trend: 'spike' },
    { name: 'disk_pct', current: 41, mean: 38, stddev: 5, trend: 'stable' },
  ],
};

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

export const mockProbes: Record<string, Probe[]> = {
  'web-prod-01': [
    { name: 'HTTPS', type: 'http', status: 'ok', last_check: '2026-03-17T08:42:00Z', detail: '200 OK (142ms)' },
    { name: 'TLS Cert', type: 'tls', status: 'ok', last_check: '2026-03-17T08:42:00Z', detail: 'Expires in 84 days' },
  ],
  'web-prod-02': [
    { name: 'HTTPS', type: 'http', status: 'ok', last_check: '2026-03-17T08:41:30Z', detail: '200 OK (189ms)' },
    { name: 'TLS Cert', type: 'tls', status: 'warning', last_check: '2026-03-17T08:41:30Z', detail: 'Expires in 12 days' },
  ],
  'k8s-staging': [
    { name: 'API Health', type: 'http', status: 'critical', last_check: '2026-03-17T08:38:00Z', detail: '503 Service Unavailable' },
    { name: 'Ingress', type: 'http', status: 'ok', last_check: '2026-03-17T08:38:00Z', detail: '200 OK (52ms)' },
  ],
};

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export const mockIncidents: Incident[] = [
  {
    incident_id: 'inc-001',
    timestamp: '2026-03-17T07:15:00Z',
    target_name: 'k8s-staging',
    severity: 'critical',
    llm_assessment: 'Multiple pods entering CrashLoopBackOff after latest staging deployment. Root cause appears to be a missing environment variable DATABASE_URL in the new deployment manifest. The api and worker pods fail on startup when attempting to connect to the database.',
    suggested_actions: ['Roll back deployment to previous version', 'Add DATABASE_URL to staging ConfigMap', 'Redeploy with corrected manifest'],
    similar_incidents: ['inc-archive-042'],
  },
  {
    incident_id: 'inc-002',
    timestamp: '2026-03-17T06:30:00Z',
    target_name: 'web-prod-02',
    severity: 'warning',
    llm_assessment: 'Disk usage on web-prod-02 has reached 87% and is trending upward. Primary contributor is log files in /var/log/nginx/ that have not been rotated. At current growth rate, disk will be full within 3 days.',
    suggested_actions: ['Rotate and compress nginx logs', 'Enable logrotate for /var/log/nginx/', 'Consider increasing volume size'],
  },
  {
    incident_id: 'inc-003',
    timestamp: '2026-03-16T22:10:00Z',
    target_name: 'web-prod-01',
    severity: 'warning',
    llm_assessment: 'Transient memory spike to 92% caused by a runaway background job. The job completed and memory returned to normal levels. No user-facing impact detected.',
    suggested_actions: ['Add memory limits to background job configuration', 'Set up OOM kill alerts'],
    resolution: 'Self-resolved. Added memory limit config in follow-up PR.',
  },
  {
    incident_id: 'inc-004',
    timestamp: '2026-03-16T14:00:00Z',
    target_name: 'db-primary',
    severity: 'warning',
    llm_assessment: 'Slow query log shows 3 queries exceeding 5s threshold during peak traffic. All queries target the orders table with missing index on customer_id column.',
    suggested_actions: ['Add index on orders.customer_id', 'Review query patterns for N+1 issues'],
    resolution: 'Index added. Query times dropped below 100ms.',
  },
];

// ---------------------------------------------------------------------------
// Runbooks
// ---------------------------------------------------------------------------

export const mockRunbooks: Runbook[] = [
  {
    id: 'rb-001',
    name: 'Restart unhealthy containers',
    description: 'Identifies containers in failed or unhealthy state and restarts them with backoff.',
    trigger_conditions: ['container_status == "unhealthy"', 'restart_count < 3'],
    steps: [
      { description: 'Identify unhealthy containers', command: 'docker ps --filter health=unhealthy', on_failure: 'abort' },
      { description: 'Restart container', command: 'docker restart {{container_id}}', on_failure: 'log_and_continue' },
      { description: 'Verify health', command: 'docker inspect --format="{{.State.Health.Status}}" {{container_id}}', on_failure: 'escalate' },
    ],
    execution_count: 14,
    success_rate: 0.86,
  },
  {
    id: 'rb-002',
    name: 'Rotate and compress logs',
    description: 'Compresses log files older than 24h and removes archives older than 7 days.',
    trigger_conditions: ['disk_usage_pct > 80'],
    steps: [
      { description: 'Find logs older than 24h', command: 'find /var/log -name "*.log" -mtime +1', on_failure: 'abort' },
      { description: 'Compress old logs', command: 'gzip {{log_file}}', on_failure: 'log_and_continue' },
      { description: 'Remove archives older than 7 days', command: 'find /var/log -name "*.gz" -mtime +7 -delete', on_failure: 'log_and_continue' },
    ],
    execution_count: 8,
    success_rate: 1.0,
  },
  {
    id: 'rb-003',
    name: 'TLS certificate renewal',
    description: 'Checks certificate expiry and triggers renewal via certbot if within 14 days.',
    trigger_conditions: ['tls_days_remaining < 14'],
    steps: [
      { description: 'Check certificate expiry', command: 'openssl x509 -enddate -noout -in /etc/ssl/certs/server.crt', on_failure: 'abort' },
      { description: 'Renew certificate', command: 'certbot renew --cert-name {{domain}}', on_failure: 'escalate' },
      { description: 'Reload web server', command: 'systemctl reload nginx', on_failure: 'escalate' },
    ],
    execution_count: 3,
    success_rate: 1.0,
  },
  {
    id: 'rb-004',
    name: 'K8s pod restart on CrashLoopBackOff',
    description: 'Deletes pods stuck in CrashLoopBackOff to allow scheduler to recreate them.',
    trigger_conditions: ['pod_status == "CrashLoopBackOff"', 'restart_count > 5'],
    steps: [
      { description: 'List crashing pods', command: 'kubectl get pods --field-selector=status.phase!=Running -n {{namespace}}', on_failure: 'abort' },
      { description: 'Delete crashing pod', command: 'kubectl delete pod {{pod_name}} -n {{namespace}}', on_failure: 'log_and_continue' },
      { description: 'Wait for reschedule', command: 'kubectl wait --for=condition=ready pod -l app={{app_label}} -n {{namespace}} --timeout=120s', on_failure: 'escalate' },
    ],
    execution_count: 6,
    success_rate: 0.67,
  },
];

export const mockRunbookExecutions: RunbookExecution[] = [
  { id: 'exec-001', runbook_id: 'rb-001', target_name: 'web-prod-01', started_at: '2026-03-17T04:12:00Z', finished_at: '2026-03-17T04:12:45Z', status: 'success', output: 'Restarted container app. Health check passed.' },
  { id: 'exec-002', runbook_id: 'rb-002', target_name: 'web-prod-02', started_at: '2026-03-17T06:35:00Z', finished_at: '2026-03-17T06:36:10Z', status: 'success', output: 'Compressed 12 log files. Freed 2.1 GB.' },
  { id: 'exec-003', runbook_id: 'rb-004', target_name: 'k8s-staging', started_at: '2026-03-17T07:20:00Z', finished_at: '2026-03-17T07:22:30Z', status: 'failure', output: 'Pod api-7f8d9 deleted but new pod also entered CrashLoopBackOff. Escalated.' },
  { id: 'exec-004', runbook_id: 'rb-001', target_name: 'web-prod-01', started_at: '2026-03-16T22:15:00Z', finished_at: '2026-03-16T22:15:30Z', status: 'success', output: 'No unhealthy containers found. No action taken.' },
];

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export const mockAuditEntries: AuditEntry[] = [
  { id: 'aud-001', timestamp: '2026-03-17T08:42:00Z', target_name: 'web-prod-01', action_type: 'health_check', command: 'opsclaw scan web-prod-01', dry_run: false, result: 'success', hash: 'a1b2c3d4', prev_hash: '00000000' },
  { id: 'aud-002', timestamp: '2026-03-17T07:20:00Z', target_name: 'k8s-staging', action_type: 'runbook_exec', command: 'kubectl delete pod api-7f8d9 -n staging', dry_run: false, result: 'failure', hash: 'e5f6g7h8', prev_hash: 'a1b2c3d4' },
  { id: 'aud-003', timestamp: '2026-03-17T06:35:00Z', target_name: 'web-prod-02', action_type: 'runbook_exec', command: 'gzip /var/log/nginx/access.log.1', dry_run: false, result: 'success', hash: 'i9j0k1l2', prev_hash: 'e5f6g7h8' },
  { id: 'aud-004', timestamp: '2026-03-17T06:30:00Z', target_name: 'web-prod-02', action_type: 'incident_create', command: 'opsclaw incident create --target web-prod-02 --severity warning', dry_run: false, result: 'success', hash: 'm3n4o5p6', prev_hash: 'i9j0k1l2' },
  { id: 'aud-005', timestamp: '2026-03-17T04:12:00Z', target_name: 'web-prod-01', action_type: 'runbook_exec', command: 'docker restart app', dry_run: false, result: 'success', hash: 'q7r8s9t0', prev_hash: 'm3n4o5p6' },
  { id: 'aud-006', timestamp: '2026-03-16T23:00:00Z', target_name: 'db-primary', action_type: 'command', command: 'psql -c "CREATE INDEX idx_orders_customer ON orders(customer_id)"', dry_run: true, result: 'dry-run', hash: 'u1v2w3x4', prev_hash: 'q7r8s9t0' },
  { id: 'aud-007', timestamp: '2026-03-16T22:15:00Z', target_name: 'web-prod-01', action_type: 'runbook_exec', command: 'docker ps --filter health=unhealthy', dry_run: false, result: 'success', hash: 'y5z6a7b8', prev_hash: 'u1v2w3x4' },
  { id: 'aud-008', timestamp: '2026-03-16T22:10:00Z', target_name: 'web-prod-01', action_type: 'incident_create', command: 'opsclaw incident create --target web-prod-01 --severity warning', dry_run: false, result: 'success', hash: 'c9d0e1f2', prev_hash: 'y5z6a7b8' },
];
