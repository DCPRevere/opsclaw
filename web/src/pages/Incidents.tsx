import { useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronUp, Filter } from 'lucide-react';
import { mockIncidents } from '@/lib/mockData';
import type { Incident } from '@/types/opsclaw';

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'bg-[#ff4466] text-white';
    case 'warning':
      return 'bg-[#ffaa00] text-black';
    default:
      return 'bg-[#334060] text-white';
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

export default function Incidents() {
  // TODO: replace with real API call
  const [incidents, setIncidents] = useState<Incident[]>(mockIncidents);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filterTarget, setFilterTarget] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterResolved, setFilterResolved] = useState<string>('all');
  const [resolveText, setResolveText] = useState<Record<string, string>>({});

  const targets = Array.from(new Set(incidents.map((i) => i.target_name)));

  const filtered = incidents.filter((i) => {
    if (filterTarget !== 'all' && i.target_name !== filterTarget) return false;
    if (filterSeverity !== 'all' && i.severity !== filterSeverity) return false;
    if (filterResolved === 'resolved' && !i.resolution) return false;
    if (filterResolved === 'unresolved' && i.resolution) return false;
    return true;
  });

  const handleResolve = (id: string) => {
    const text = resolveText[id];
    if (!text?.trim()) return;
    // TODO: replace with real API call
    setIncidents((prev) =>
      prev.map((i) => (i.incident_id === id ? { ...i, resolution: text.trim() } : i)),
    );
    setResolveText((prev) => ({ ...prev, [id]: '' }));
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-[#ffaa00]" />
          <h1 className="text-xl font-bold text-white">Incidents</h1>
        </div>
        <span className="text-sm text-[#556080]">{filtered.length} incident(s)</span>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Filter className="h-4 w-4 text-[#556080]" />
        <select
          value={filterTarget}
          onChange={(e) => setFilterTarget(e.target.value)}
          className="bg-[#0a0a18] border border-[#1a1a3e] text-white text-xs rounded-lg px-3 py-1.5"
        >
          <option value="all">All targets</option>
          {targets.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-[#0a0a18] border border-[#1a1a3e] text-white text-xs rounded-lg px-3 py-1.5"
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="warning">Warning</option>
        </select>
        <select
          value={filterResolved}
          onChange={(e) => setFilterResolved(e.target.value)}
          className="bg-[#0a0a18] border border-[#1a1a3e] text-white text-xs rounded-lg px-3 py-1.5"
        >
          <option value="all">All statuses</option>
          <option value="resolved">Resolved</option>
          <option value="unresolved">Unresolved</option>
        </select>
      </div>

      {/* Table */}
      <div className="space-y-2">
        {filtered.length === 0 ? (
          <div className="glass-card p-6 text-center text-[#334060] text-sm">No incidents match your filters</div>
        ) : (
          filtered.map((inc) => {
            const expanded = expandedId === inc.incident_id;
            return (
              <div key={inc.incident_id} className="glass-card overflow-hidden">
                <button
                  onClick={() => setExpandedId(expanded ? null : inc.incident_id)}
                  className="w-full flex items-center gap-4 p-4 text-left hover:bg-[#0080ff08] transition-colors"
                >
                  <span className="text-xs text-[#556080] font-mono w-36 flex-shrink-0">{formatTime(inc.timestamp)}</span>
                  <span className="text-sm text-white w-32 flex-shrink-0 truncate">{inc.target_name}</span>
                  <span className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full ${severityColor(inc.severity)}`}>{inc.severity}</span>
                  <span className="text-sm text-[#8090b0] flex-1 truncate">{inc.llm_assessment.slice(0, 80)}...</span>
                  <span className={`text-xs ${inc.resolution ? 'text-[#00e68a]' : 'text-[#ffaa00]'}`}>
                    {inc.resolution ? 'Resolved' : 'Open'}
                  </span>
                  {expanded ? <ChevronUp className="h-4 w-4 text-[#556080]" /> : <ChevronDown className="h-4 w-4 text-[#556080]" />}
                </button>

                {expanded && (
                  <div className="px-4 pb-4 space-y-4 border-t border-[#1a1a3e]/50 pt-4 animate-fade-in">
                    <div>
                      <h3 className="text-xs font-semibold text-[#556080] uppercase tracking-wider mb-2">Assessment</h3>
                      <p className="text-sm text-[#8090b0] leading-relaxed">{inc.llm_assessment}</p>
                    </div>

                    <div>
                      <h3 className="text-xs font-semibold text-[#556080] uppercase tracking-wider mb-2">Suggested Actions</h3>
                      <ul className="space-y-1">
                        {inc.suggested_actions.map((action, i) => (
                          <li key={i} className="text-sm text-white flex items-start gap-2">
                            <span className="text-[#0080ff] mt-0.5">&#x2022;</span>
                            {action}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {inc.similar_incidents && inc.similar_incidents.length > 0 && (
                      <div>
                        <h3 className="text-xs font-semibold text-[#556080] uppercase tracking-wider mb-2">Similar Past Incidents</h3>
                        <div className="flex gap-2">
                          {inc.similar_incidents.map((s) => (
                            <span key={s} className="text-xs bg-[#0080ff15] text-[#0080ff] px-2 py-1 rounded-lg">{s}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    {inc.resolution ? (
                      <div>
                        <h3 className="text-xs font-semibold text-[#556080] uppercase tracking-wider mb-2">Resolution</h3>
                        <p className="text-sm text-[#00e68a]">{inc.resolution}</p>
                      </div>
                    ) : (
                      <div className="flex gap-2">
                        <input
                          type="text"
                          placeholder="Resolution notes..."
                          value={resolveText[inc.incident_id] ?? ''}
                          onChange={(e) => setResolveText((prev) => ({ ...prev, [inc.incident_id]: e.target.value }))}
                          className="flex-1 bg-[#0a0a18] border border-[#1a1a3e] text-white text-sm rounded-lg px-3 py-2 focus:border-[#0080ff] focus:outline-none transition-colors"
                        />
                        <button
                          onClick={() => handleResolve(inc.incident_id)}
                          className="px-4 py-2 bg-[#00e68a20] text-[#00e68a] text-sm font-medium rounded-lg hover:bg-[#00e68a30] transition-colors"
                        >
                          Resolve
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
