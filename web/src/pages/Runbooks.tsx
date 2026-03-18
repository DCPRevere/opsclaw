import { useState } from 'react';
import { BookOpen, Play, ChevronDown, ChevronUp, CheckCircle, XCircle, Clock } from 'lucide-react';
import { mockRunbooks, mockRunbookExecutions } from '@/lib/mockData';
import type { Runbook, RunbookExecution } from '@/types/opsclaw';

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function successRateColor(rate: number): string {
  if (rate >= 0.9) return 'text-[#00e68a]';
  if (rate >= 0.7) return 'text-[#ffaa00]';
  return 'text-[#ff4466]';
}

function executionStatusIcon(status: RunbookExecution['status']) {
  switch (status) {
    case 'success':
      return <CheckCircle className="h-4 w-4 text-[#00e68a]" />;
    case 'failure':
      return <XCircle className="h-4 w-4 text-[#ff4466]" />;
    case 'running':
      return <Clock className="h-4 w-4 text-[#0080ff] animate-spin" />;
  }
}

export default function Runbooks() {
  // TODO: replace with real API call
  const [runbooks] = useState<Runbook[]>(mockRunbooks);
  const [executions] = useState<RunbookExecution[]>(mockRunbookExecutions);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <BookOpen className="h-5 w-5 text-[#0080ff]" />
          <h1 className="text-xl font-bold text-white">Runbooks</h1>
        </div>
        <button className="px-4 py-2 bg-[#0080ff20] text-[#0080ff] text-sm font-medium rounded-lg hover:bg-[#0080ff30] transition-colors">
          Init Default Runbooks
        </button>
      </div>

      <div className="space-y-4 stagger-children">
        {runbooks.map((rb) => {
          const expanded = expandedId === rb.id;
          const rbExecutions = executions.filter((e) => e.runbook_id === rb.id);

          return (
            <div key={rb.id} className="glass-card overflow-hidden animate-slide-in-up">
              <button
                onClick={() => setExpandedId(expanded ? null : rb.id)}
                className="w-full flex items-center gap-4 p-5 text-left hover:bg-[#0080ff08] transition-colors"
              >
                <div className="p-2 rounded-xl bg-[#0080ff15]">
                  <Play className="h-4 w-4 text-[#0080ff]" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white">{rb.name}</p>
                  <p className="text-xs text-[#556080] truncate">{rb.description}</p>
                </div>
                <div className="flex items-center gap-6 text-xs">
                  <div className="text-center">
                    <p className="text-white font-mono">{rb.execution_count}</p>
                    <p className="text-[#334060]">runs</p>
                  </div>
                  <div className="text-center">
                    <p className={`font-mono ${successRateColor(rb.success_rate)}`}>{(rb.success_rate * 100).toFixed(0)}%</p>
                    <p className="text-[#334060]">success</p>
                  </div>
                </div>
                {expanded ? <ChevronUp className="h-4 w-4 text-[#556080]" /> : <ChevronDown className="h-4 w-4 text-[#556080]" />}
              </button>

              {expanded && (
                <div className="px-5 pb-5 space-y-5 border-t border-[#1a1a3e]/50 pt-4 animate-fade-in">
                  {/* Trigger Conditions */}
                  {rb.trigger_conditions && rb.trigger_conditions.length > 0 && (
                    <div>
                      <h3 className="text-xs font-semibold text-[#556080] uppercase tracking-wider mb-2">Trigger Conditions</h3>
                      <div className="flex flex-wrap gap-2">
                        {rb.trigger_conditions.map((tc, i) => (
                          <span key={i} className="text-xs bg-[#a855f715] text-[#a855f7] px-2 py-1 rounded-lg font-mono">{tc}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Steps */}
                  <div>
                    <h3 className="text-xs font-semibold text-[#556080] uppercase tracking-wider mb-2">Steps</h3>
                    <div className="space-y-2">
                      {rb.steps.map((step, i) => (
                        <div key={i} className="py-2 px-3 rounded-xl" style={{ background: 'rgba(10, 10, 26, 0.5)' }}>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs text-[#0080ff] font-mono w-5">{i + 1}.</span>
                            <span className="text-sm text-white">{step.description}</span>
                          </div>
                          {step.command && (
                            <p className="text-xs text-[#556080] font-mono ml-7">{step.command}</p>
                          )}
                          <p className="text-[10px] text-[#334060] ml-7 mt-1">On failure: {step.on_failure}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Execution History */}
                  {rbExecutions.length > 0 && (
                    <div>
                      <h3 className="text-xs font-semibold text-[#556080] uppercase tracking-wider mb-2">Execution History</h3>
                      <div className="space-y-2">
                        {rbExecutions.map((exec) => (
                          <div key={exec.id} className="flex items-center gap-3 py-2 px-3 rounded-xl" style={{ background: 'rgba(10, 10, 26, 0.5)' }}>
                            {executionStatusIcon(exec.status)}
                            <span className="text-xs text-[#556080] font-mono">{formatTime(exec.started_at)}</span>
                            <span className="text-xs text-white">{exec.target_name}</span>
                            <span className={`text-xs capitalize ${exec.status === 'success' ? 'text-[#00e68a]' : exec.status === 'failure' ? 'text-[#ff4466]' : 'text-[#0080ff]'}`}>{exec.status}</span>
                            {exec.output && <span className="text-xs text-[#334060] truncate flex-1">{exec.output}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
