import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  HardDrive,
  Cpu,
  MemoryStick,
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Container,
} from 'lucide-react';
import {
  mockTargets,
  mockHealthChecks,
  mockSnapshots,
  mockBaselines,
  mockProbes,
  mockIncidents,
} from '@/lib/mockData';
import type { Probe } from '@/types/opsclaw';

function probeStatusColor(status: Probe['status']): string {
  switch (status) {
    case 'ok':
      return 'text-[#00e68a]';
    case 'warning':
      return 'text-[#ffaa00]';
    case 'critical':
      return 'text-[#ff4466]';
    default:
      return 'text-[#556080]';
  }
}

function ProbeIcon({ status }: { status: Probe['status'] }) {
  switch (status) {
    case 'ok':
      return <CheckCircle className="h-4 w-4 text-[#00e68a]" />;
    case 'warning':
      return <AlertTriangle className="h-4 w-4 text-[#ffaa00]" />;
    case 'critical':
      return <XCircle className="h-4 w-4 text-[#ff4466]" />;
  }
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function Sparkline({ current, mean, stddev }: { current: number; mean: number; stddev: number }) {
  const max = 100;
  const barW = Math.min(current, max);
  const meanPos = Math.min(mean, max);
  const color =
    current > mean + 2 * stddev
      ? '#ff4466'
      : current > mean + stddev
        ? '#ffaa00'
        : '#00e68a';

  return (
    <div className="relative w-full h-2 bg-[#0a0a18] rounded-full overflow-hidden">
      <div className="h-full rounded-full transition-all duration-500" style={{ width: `${barW}%`, background: color }} />
      <div className="absolute top-0 h-full w-px bg-[#556080]" style={{ left: `${meanPos}%` }} title={`mean: ${mean}`} />
    </div>
  );
}

export default function TargetDetail() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();

  // TODO: replace with real API call
  const target = mockTargets.find((t) => t.name === name);
  const snapshot = name ? mockSnapshots[name] : undefined;
  const baselines = name ? mockBaselines[name] : undefined;
  const probes = name ? mockProbes[name] : undefined;
  const healthChecks = mockHealthChecks.filter((h) => h.target_name === name);
  const incidents = mockIncidents.filter((i) => i.target_name === name);

  if (!target) {
    return (
      <div className="p-6 animate-fade-in">
        <button onClick={() => navigate('/targets')} className="flex items-center gap-2 text-[#556080] hover:text-white transition-colors mb-4">
          <ArrowLeft className="h-4 w-4" /> Back to targets
        </button>
        <div className="rounded-xl bg-[#ff446615] border border-[#ff446630] p-4 text-[#ff6680]">
          Target not found: {name}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/targets')} className="p-2 rounded-xl hover:bg-[#0080ff15] transition-colors">
          <ArrowLeft className="h-5 w-5 text-[#556080]" />
        </button>
        <div>
          <h1 className="text-xl font-bold text-white">{target.name}</h1>
          <p className="text-sm text-[#556080]">{target.type.toUpperCase()} &middot; {target.host ?? 'localhost'} &middot; {target.autonomy}</p>
        </div>
      </div>

      {/* Snapshot */}
      {snapshot && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { icon: Cpu, label: 'Load', value: snapshot.load_avg.map((v) => v.toFixed(1)).join(' / '), color: '#0080ff' },
            { icon: MemoryStick, label: 'Memory', value: `${snapshot.memory_usage_pct}%`, color: snapshot.memory_usage_pct > 80 ? '#ff4466' : '#00e68a' },
            { icon: HardDrive, label: 'Disk', value: `${snapshot.disk_usage_pct}%`, color: snapshot.disk_usage_pct > 80 ? '#ffaa00' : '#00e68a' },
            { icon: Activity, label: 'Open Ports', value: snapshot.ports.join(', '), color: '#a855f7' },
          ].map(({ icon: Icon, label, value, color }) => (
            <div key={label} className="glass-card p-4">
              <div className="flex items-center gap-2 mb-2">
                <Icon className="h-4 w-4" style={{ color }} />
                <span className="text-xs text-[#556080] uppercase tracking-wider">{label}</span>
              </div>
              <p className="text-sm font-semibold text-white">{value}</p>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Baseline Metrics */}
        {baselines && (
          <div className="glass-card p-5">
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Baseline Metrics</h2>
            <div className="space-y-4">
              {baselines.map((m) => (
                <div key={m.name}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-[#556080]">{m.name.replace('_', ' ')}</span>
                    <span className="text-white font-mono">{m.current}% <span className="text-[#556080]">(mean {m.mean}%)</span></span>
                  </div>
                  <Sparkline current={m.current} mean={m.mean} stddev={m.stddev} />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Active Probes */}
        {probes && (
          <div className="glass-card p-5">
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Active Probes</h2>
            <div className="space-y-3">
              {probes.map((p) => (
                <div key={p.name} className="flex items-center justify-between py-2 px-3 rounded-xl" style={{ background: 'rgba(10, 10, 26, 0.5)' }}>
                  <div className="flex items-center gap-2">
                    <ProbeIcon status={p.status} />
                    <span className="text-sm text-white">{p.name}</span>
                  </div>
                  <span className={`text-xs ${probeStatusColor(p.status)}`}>{p.detail}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Health Timeline */}
        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Health Timeline</h2>
          {healthChecks.length === 0 ? (
            <p className="text-sm text-[#334060]">No health checks recorded</p>
          ) : (
            <div className="space-y-2">
              {healthChecks.map((hc, i) => (
                <div key={i} className="flex items-center gap-3 py-2 px-3 rounded-xl" style={{ background: 'rgba(10, 10, 26, 0.5)' }}>
                  <span className={`inline-block h-2 w-2 rounded-full ${hc.status === 'Healthy' ? 'bg-[#00e68a]' : hc.status === 'Warning' ? 'bg-[#ffaa00]' : 'bg-[#ff4466]'}`} />
                  <span className="text-xs text-[#556080] font-mono">{formatTime(hc.checked_at)}</span>
                  <span className="text-xs text-white capitalize">{hc.status}</span>
                  {hc.alerts.length > 0 && (
                    <span className="text-xs text-[#ffaa00]">{hc.alerts.length} alert(s)</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Containers & Services */}
        {snapshot && (
          <div className="glass-card p-5">
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Containers &amp; Services</h2>
            <div className="space-y-2">
              {snapshot.containers.map((c) => (
                <div key={c.name} className="flex items-center gap-3 py-2 px-3 rounded-xl" style={{ background: 'rgba(10, 10, 26, 0.5)' }}>
                  <Container className="h-4 w-4 text-[#0080ff]" />
                  <span className="text-sm text-white flex-1">{c.name}</span>
                  <span className={`text-xs ${c.status === 'running' ? 'text-[#00e68a]' : 'text-[#ff4466]'}`}>{c.status}</span>
                  <span className="text-xs text-[#334060]">{c.image}</span>
                </div>
              ))}
              {snapshot.services.map((s) => (
                <div key={s.name} className="flex items-center gap-3 py-2 px-3 rounded-xl" style={{ background: 'rgba(10, 10, 26, 0.5)' }}>
                  <Activity className="h-4 w-4 text-[#a855f7]" />
                  <span className="text-sm text-white flex-1">{s.name}</span>
                  <span className={`text-xs ${s.status === 'active' ? 'text-[#00e68a]' : s.status === 'degraded' ? 'text-[#ffaa00]' : 'text-[#ff4466]'}`}>{s.status}</span>
                  {s.port && <span className="text-xs text-[#334060]">:{s.port}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Recent Incidents */}
      <div className="glass-card p-5">
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Recent Incidents</h2>
        {incidents.length === 0 ? (
          <p className="text-sm text-[#334060]">No incidents for this target</p>
        ) : (
          <div className="space-y-3">
            {incidents.map((inc) => (
              <div key={inc.incident_id} className="py-3 px-4 rounded-xl border border-[#1a1a3e]/50" style={{ background: 'rgba(10, 10, 26, 0.5)' }}>
                <div className="flex items-center gap-3 mb-2">
                  <span className={`inline-block h-2 w-2 rounded-full ${inc.severity === 'critical' ? 'bg-[#ff4466]' : 'bg-[#ffaa00]'}`} />
                  <span className="text-xs text-[#556080] font-mono">{formatTime(inc.timestamp)}</span>
                  <span className="text-xs text-white capitalize">{inc.severity}</span>
                  {inc.resolution && <span className="text-xs text-[#00e68a] ml-auto">Resolved</span>}
                </div>
                <p className="text-sm text-[#8090b0] line-clamp-2">{inc.llm_assessment}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
