import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Server, Wifi, Monitor, Box } from 'lucide-react';
import { getOpsclawTargets } from '@/lib/api';
import type { Target } from '@/types/opsclaw';

function statusColor(status: Target['health_status']): string {
  switch (status) {
    case 'Healthy':
      return 'bg-[#00e68a]';
    case 'Warning':
      return 'bg-[#ffaa00]';
    case 'Critical':
      return 'bg-[#ff4466]';
    default:
      return 'bg-[#334060]';
  }
}

function statusBorder(status: Target['health_status']): string {
  switch (status) {
    case 'Healthy':
      return 'border-[#00e68a30]';
    case 'Warning':
      return 'border-[#ffaa0030]';
    case 'Critical':
      return 'border-[#ff446630]';
    default:
      return 'border-[#33406030]';
  }
}

function typeIcon(type: Target['type']) {
  switch (type) {
    case 'ssh':
      return Wifi;
    case 'k8s':
      return Box;
    case 'local':
      return Monitor;
    default:
      return Server;
  }
}

function formatTime(iso?: string): string {
  if (!iso) return 'Never';
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    getOpsclawTargets()
      .then(setTargets)
      .catch((err) => setError(err.message));
  }, []);

  if (error) {
    return (
      <div className="p-6 animate-fade-in">
        <div className="rounded-xl bg-[#ff446615] border border-[#ff446630] p-4 text-[#ff6680]">
          Failed to load targets: {error}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Targets</h1>
        <span className="text-sm text-[#556080]">{targets.length} targets</span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 stagger-children">
        {targets.map((target) => {
          const Icon = typeIcon(target.type);
          return (
            <button
              key={target.name}
              onClick={() => navigate(`/targets/${encodeURIComponent(target.name)}`)}
              className={`glass-card p-5 text-left border ${statusBorder(target.health_status)} transition-all duration-300 hover:scale-[1.02] hover:bg-[#0080ff08] animate-slide-in-up`}
            >
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 rounded-xl bg-[#0080ff15]">
                  <Icon className="h-5 w-5 text-[#0080ff]" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white truncate">{target.name}</p>
                  <p className="text-xs text-[#556080]">{target.host ?? 'localhost'}</p>
                </div>
                <span className={`inline-block h-2.5 w-2.5 rounded-full ${statusColor(target.health_status)} glow-dot`} />
              </div>

              <div className="flex items-center gap-4 text-xs text-[#556080]">
                <span className="uppercase">{target.type}</span>
                <span className="capitalize">{target.autonomy}</span>
              </div>

              <div className="mt-2 text-xs text-[#334060]">
                Last scan: {formatTime(target.last_scan)}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
