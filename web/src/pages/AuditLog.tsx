import { useState } from 'react';
import { Shield, Search, Link } from 'lucide-react';
import { mockAuditEntries } from '@/lib/mockData';
import type { AuditEntry } from '@/types/opsclaw';

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function resultColor(result: string): string {
  switch (result) {
    case 'success':
      return 'text-[#00e68a]';
    case 'failure':
      return 'text-[#ff4466]';
    case 'dry-run':
      return 'text-[#a855f7]';
    default:
      return 'text-[#556080]';
  }
}

export default function AuditLog() {
  // TODO: replace with real API call
  const [entries] = useState<AuditEntry[]>(mockAuditEntries);
  const [search, setSearch] = useState('');
  const [filterTarget, setFilterTarget] = useState<string>('all');
  const [filterAction, setFilterAction] = useState<string>('all');

  const targets = Array.from(new Set(entries.map((e) => e.target_name).filter((t): t is string => t != null)));
  const actionTypes = Array.from(new Set(entries.map((e) => e.action_type)));

  const filtered = entries.filter((e) => {
    if (filterTarget !== 'all' && e.target_name !== filterTarget) return false;
    if (filterAction !== 'all' && e.action_type !== filterAction) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        e.command.toLowerCase().includes(q) ||
        e.action_type.toLowerCase().includes(q) ||
        (e.target_name?.toLowerCase().includes(q) ?? false)
      );
    }
    return true;
  });

  // Check hash chain integrity
  const chainValid = entries.every((e, i) => {
    if (i === 0) return true;
    const prev = entries[i - 1];
    return prev != null && e.prev_hash === prev.hash;
  });

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-5 w-5 text-[#0080ff]" />
          <h1 className="text-xl font-bold text-white">Audit Log</h1>
        </div>
        <div className="flex items-center gap-2">
          <Link className="h-4 w-4" style={{ color: chainValid ? '#00e68a' : '#ff4466' }} />
          <span className={`text-xs ${chainValid ? 'text-[#00e68a]' : 'text-[#ff4466]'}`}>
            Hash chain: {chainValid ? 'Valid' : 'Broken'}
          </span>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[#556080]" />
          <input
            type="text"
            placeholder="Search commands..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#0a0a18] border border-[#1a1a3e] text-white text-xs rounded-lg pl-9 pr-3 py-2 focus:border-[#0080ff] focus:outline-none transition-colors"
          />
        </div>
        <select
          value={filterTarget}
          onChange={(e) => setFilterTarget(e.target.value)}
          className="bg-[#0a0a18] border border-[#1a1a3e] text-white text-xs rounded-lg px-3 py-2"
        >
          <option value="all">All targets</option>
          {targets.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select
          value={filterAction}
          onChange={(e) => setFilterAction(e.target.value)}
          className="bg-[#0a0a18] border border-[#1a1a3e] text-white text-xs rounded-lg px-3 py-2"
        >
          <option value="all">All actions</option>
          {actionTypes.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <span className="text-xs text-[#556080]">{filtered.length} entries</span>
      </div>

      {/* Entries */}
      <div className="glass-card overflow-hidden">
        {/* Header */}
        <div className="grid grid-cols-[140px_100px_100px_1fr_80px_80px] gap-2 px-4 py-3 border-b border-[#1a1a3e]/50 text-[10px] text-[#556080] uppercase tracking-wider font-semibold">
          <span>Timestamp</span>
          <span>Target</span>
          <span>Action</span>
          <span>Command</span>
          <span>Result</span>
          <span>Hash</span>
        </div>

        {filtered.length === 0 ? (
          <div className="p-6 text-center text-sm text-[#334060]">No entries match your filters</div>
        ) : (
          <div className="divide-y divide-[#1a1a3e]/30">
            {filtered.map((entry) => (
              <div
                key={entry.id}
                className={`grid grid-cols-[140px_100px_100px_1fr_80px_80px] gap-2 px-4 py-3 text-xs items-center transition-colors hover:bg-[#0080ff08] ${entry.dry_run ? 'bg-[#a855f708]' : ''}`}
              >
                <span className="text-[#556080] font-mono">{formatTime(entry.timestamp)}</span>
                <span className="text-white truncate">{entry.target_name ?? '-'}</span>
                <span className="text-[#8090b0]">{entry.action_type}</span>
                <span className="text-white font-mono truncate" title={entry.command}>
                  {entry.dry_run && <span className="text-[#a855f7] mr-1">[DRY]</span>}
                  {entry.command}
                </span>
                <span className={resultColor(entry.result)}>{entry.result}</span>
                <span className="text-[#334060] font-mono">{entry.hash.slice(0, 8)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
