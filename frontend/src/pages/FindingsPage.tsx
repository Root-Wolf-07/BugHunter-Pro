import { useEffect, useState } from 'react';
import { ChevronDown, ChevronUp, Zap } from 'lucide-react';
import { findingsApi, remediationApi, type Finding, type FindingStatus, type Severity } from '../api';

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ff4757', HIGH: '#ff6b35', MEDIUM: '#ffa502', LOW: '#2ed573', INFO: '#1e90ff',
};
const STATUS_OPTS: FindingStatus[] = ['NEW', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'];
const SEV_OPTS: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function FindingDetail({ finding, onStatusChange }: {
  finding: Finding;
  onStatusChange: () => void;
}) {
  const [generating, setGenerating] = useState(false);
  const [remResult, setRemResult] = useState<string>('');

  const handleGenerate = async () => {
    setGenerating(true);
    setRemResult('');
    try {
      const action = await remediationApi.generate(finding.id);
      setRemResult(action.description || 'Remediation plan generated. View in Remediation page.');
      onStatusChange();
    } catch (e: any) {
      setRemResult('Failed to generate: ' + (e?.response?.data?.detail || e?.message));
    } finally {
      setGenerating(false);
    }
  };

  const handleStatus = async (status: FindingStatus) => {
    await findingsApi.updateStatus(finding.id, status).catch(() => {});
    onStatusChange();
  };

  return (
    <div
      className="mt-2 ml-4 p-4 rounded-md animate-slide-in"
      style={{ background: '#0d1117', border: '1px solid #21262d' }}
    >
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>Category</label>
          <span className="text-sm" style={{ color: '#e6edf3' }}>{finding.category}</span>
        </div>
        <div>
          <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>Confidence</label>
          <span className="text-sm" style={{ color: '#e6edf3' }}>{finding.confidence}</span>
        </div>
        {finding.affected_component && (
          <div className="col-span-2">
            <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>Affected Component</label>
            <span className="text-sm font-mono" style={{ color: '#58a6ff' }}>{finding.affected_component}</span>
          </div>
        )}
      </div>

      {finding.description && (
        <div className="mb-3">
          <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>Description</label>
          <p className="text-sm" style={{ color: '#c9d1d9' }}>{finding.description}</p>
        </div>
      )}

      {finding.ai_explanation && (
        <div className="mb-3 p-3 rounded-md" style={{ background: 'rgba(88,166,255,0.05)', border: '1px solid rgba(88,166,255,0.15)' }}>
          <label className="text-xs flex items-center gap-1 mb-1.5" style={{ color: '#58a6ff' }}>
            <Zap size={11} /> AI Explanation
          </label>
          <p className="text-sm" style={{ color: '#c9d1d9' }}>{finding.ai_explanation}</p>
        </div>
      )}

      {finding.evidence && (
        <div className="mb-3">
          <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>Evidence</label>
          <div className="terminal-text text-xs">{finding.evidence}</div>
        </div>
      )}

      {finding.remediation && (
        <div className="mb-3">
          <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>Recommended Fix</label>
          <p className="text-sm" style={{ color: '#c9d1d9' }}>{finding.remediation}</p>
        </div>
      )}

      {finding.root_cause && (
        <div className="mb-3">
          <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>Root Cause</label>
          <p className="text-sm" style={{ color: '#c9d1d9' }}>{finding.root_cause}</p>
        </div>
      )}

      <div className="flex items-center gap-3 pt-3 border-t" style={{ borderColor: '#21262d' }}>
        <label className="text-xs" style={{ color: '#8b949e' }}>Status:</label>
        <select
          className="select-field text-xs py-1"
          style={{ width: 'auto' }}
          value={finding.status}
          onChange={e => handleStatus(e.target.value as FindingStatus)}
        >
          {STATUS_OPTS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>

        <button
          className="btn-primary text-xs py-1 px-3 ml-auto flex items-center gap-1.5"
          onClick={handleGenerate}
          disabled={generating}
        >
          <Zap size={12} className={generating ? 'scanning' : ''} />
          {generating ? 'Generating…' : 'Generate Remediation'}
        </button>
      </div>

      {remResult && (
        <div
          className="mt-2 p-2 rounded text-xs"
          style={{ background: 'rgba(88,166,255,0.05)', color: '#58a6ff' }}
        >
          {remResult}
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding, onUpdate }: { finding: Finding; onUpdate: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const color = SEV_COLORS[finding.severity] || '#8b949e';

  return (
    <div className="border-b" style={{ borderColor: '#21262d' }}>
      <div
        className="flex items-center gap-3 px-5 py-3 cursor-pointer hover:bg-white/5 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <span
          className="text-xs px-2 py-0.5 rounded font-bold w-20 text-center flex-shrink-0"
          style={{ color, background: `${color}20` }}
        >
          {finding.severity}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate" style={{ color: '#e6edf3' }}>{finding.title}</p>
          <p className="text-xs" style={{ color: '#8b949e' }}>
            {finding.category} · {finding.detected_by} · {new Date(finding.detected_at).toLocaleDateString()}
          </p>
        </div>
        <span
          className="text-xs px-1.5 py-0.5 rounded"
          style={{ background: '#21262d', color: '#8b949e' }}
        >
          {finding.status}
        </span>
        {expanded ? <ChevronUp size={14} style={{ color: '#8b949e', flexShrink: 0 }} /> : <ChevronDown size={14} style={{ color: '#8b949e', flexShrink: 0 }} />}
      </div>
      {expanded && <FindingDetail finding={finding} onStatusChange={() => { setExpanded(false); onUpdate(); }} />}
    </div>
  );
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [search, setSearch] = useState('');

  const load = () => {
    const params: any = { limit: 200 };
    if (filterSev) params.severity = filterSev;
    if (filterStatus) params.status = filterStatus;
    setLoading(true);
    findingsApi.list(params).then(setFindings).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(load, [filterSev, filterStatus]);

  const filtered = findings.filter(f =>
    !search || f.title.toLowerCase().includes(search.toLowerCase()) ||
    f.category.toLowerCase().includes(search.toLowerCase())
  );

  const counts = findings.reduce((acc: Record<string, number>, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="max-w-5xl mx-auto animate-slide-in">
      <div className="mb-6">
        <h2 className="text-xl font-bold" style={{ color: '#e6edf3' }}>Findings</h2>
        <div className="flex gap-4 mt-2">
          {SEV_OPTS.map(s => (
            <span key={s} className="text-xs" style={{ color: SEV_COLORS[s] }}>
              {counts[s] || 0} {s}
            </span>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <input
          className="input-field flex-1"
          placeholder="Search findings…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select className="select-field" style={{ width: 140 }} value={filterSev} onChange={e => setFilterSev(e.target.value)}>
          <option value="">All Severities</option>
          {SEV_OPTS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="select-field" style={{ width: 160 }} value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
          <option value="">All Statuses</option>
          {STATUS_OPTS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div className="card">
        {loading ? (
          <div className="p-12 text-center" style={{ color: '#484f58' }}>Loading findings…</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center" style={{ color: '#484f58' }}>
            {findings.length === 0 ? 'No findings yet. Run a scan to discover vulnerabilities.' : 'No findings match the current filters.'}
          </div>
        ) : (
          filtered.map(f => <FindingRow key={f.id} finding={f} onUpdate={load} />)
        )}
      </div>
    </div>
  );
}
