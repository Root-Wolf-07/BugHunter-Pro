import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Bug, Radar, Target as TargetIcon, TrendingUp, ShieldAlert, ArrowRight } from 'lucide-react';
import { statsApi, scansApi, findingsApi, type DashboardStats, type Scan, type Finding } from '../api';

function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) return <div className="text-xs" style={{ color: '#484f58' }}>No findings yet</div>;
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const colors: Record<string, string> = {
    CRITICAL: '#ff4757', HIGH: '#ff6b35', MEDIUM: '#ffa502', LOW: '#2ed573', INFO: '#1e90ff'
  };
  return (
    <div className="flex rounded overflow-hidden h-2 w-full gap-px">
      {order.map(s => {
        const count = counts[s] || 0;
        if (!count) return null;
        const pct = (count / total) * 100;
        return (
          <div key={s} style={{ background: colors[s], width: `${pct}%` }} title={`${s}: ${count}`} />
        );
      })}
    </div>
  );
}

function StatCard({
  icon: Icon, label, value, sub, color = '#58a6ff'
}: {
  icon: any; label: string; value: number | string; sub?: string; color?: string;
}) {
  return (
    <div className="stat-card animate-slide-in">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium" style={{ color: '#8b949e' }}>{label}</span>
        <Icon size={16} style={{ color }} />
      </div>
      <div className="text-3xl font-bold" style={{ color }}>{value}</div>
      {sub && <div className="text-xs" style={{ color: '#484f58' }}>{sub}</div>}
    </div>
  );
}

function ScanRow({ scan }: { scan: Scan }) {
  const navigate = useNavigate();
  const STATUS_COLOR: Record<string, string> = {
    RUNNING: '#ffa502', COMPLETED: '#2ed573', FAILED: '#ff4757', PENDING: '#8b949e', CANCELLED: '#484f58'
  };
  const total = scan.findings_count;
  return (
    <div
      className="flex items-center gap-4 py-3 border-b cursor-pointer hover:bg-white/5 px-2 rounded transition-colors"
      style={{ borderColor: '#21262d' }}
      onClick={() => navigate('/scans')}
    >
      <span className="text-xs font-mono" style={{ color: '#484f58' }}>{scan.id.slice(0, 8)}</span>
      <span
        className="text-xs px-2 py-0.5 rounded font-medium"
        style={{
          color: STATUS_COLOR[scan.status] || '#8b949e',
          background: `${STATUS_COLOR[scan.status]}20` || '#21262d',
        }}
      >
        {scan.status === 'RUNNING' && <span className="scanning inline-block w-1.5 h-1.5 rounded-full mr-1.5" style={{ background: '#ffa502' }} />}
        {scan.status}
      </span>
      <span className="flex-1 text-xs" style={{ color: '#8b949e' }}>
        {scan.tools_used?.join(', ') || '-'}
      </span>
      <span className="text-xs font-semibold" style={{ color: total > 0 ? '#ff6b35' : '#8b949e' }}>
        {total} findings
      </span>
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  const navigate = useNavigate();
  const SEV_COLOR: Record<string, string> = {
    CRITICAL: '#ff4757', HIGH: '#ff6b35', MEDIUM: '#ffa502', LOW: '#2ed573', INFO: '#1e90ff'
  };
  return (
    <div
      className="flex items-center gap-3 py-2 border-b cursor-pointer hover:bg-white/5 px-2 rounded"
      style={{ borderColor: '#21262d' }}
      onClick={() => navigate('/findings')}
    >
      <span
        className="text-xs px-1.5 py-0.5 rounded font-bold w-20 text-center"
        style={{ color: SEV_COLOR[f.severity], background: `${SEV_COLOR[f.severity]}20` }}
      >
        {f.severity}
      </span>
      <span className="flex-1 text-sm truncate" style={{ color: '#e6edf3' }}>{f.title}</span>
      <span className="text-xs" style={{ color: '#8b949e' }}>{f.detected_by}</span>
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [recentFindings, setRecentFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([
      statsApi.dashboard().catch(() => null),
      scansApi.list({ limit: 5 }).catch(() => []),
      findingsApi.list({ limit: 8 }).catch(() => []),
    ]).then(([s, scans, findings]) => {
      setStats(s);
      setRecentScans(scans || []);
      setRecentFindings(findings || []);
    }).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="text-4xl mb-3 scanning">🐺</div>
          <p style={{ color: '#8b949e' }}>Loading Bug Hunter…</p>
        </div>
      </div>
    );
  }

  const finding_counts = stats?.findings?.by_severity || {};
  const total_findings = stats?.findings?.total || 0;

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-slide-in">
      {/* Hero */}
      <div
        className="rounded-xl p-6 flex items-center gap-4"
        style={{
          background: 'linear-gradient(135deg, #0d1117 0%, #161b22 60%, #1c2130 100%)',
          border: '1px solid #30363d',
        }}
      >
        <span className="text-5xl">🐺</span>
        <div>
          <h2 className="text-xl font-bold" style={{ color: '#58a6ff' }}>Bug Hunter AI</h2>
          <p className="text-sm mt-0.5" style={{ color: '#8b949e' }}>
            Local-first AI Cybersecurity Assistant — Find • Explain • Fix • Verify
          </p>
          <p className="text-xs mt-2 flex items-center gap-1" style={{ color: '#484f58' }}>
            <ShieldAlert size={12} />
            All analysis runs locally — no data sent to cloud
          </p>
        </div>
        <div className="ml-auto flex gap-3">
          <button className="btn-primary flex items-center gap-2" onClick={() => navigate('/targets')}>
            <Radar size={14} /> New Scan
          </button>
          <button className="btn-ghost flex items-center gap-2" onClick={() => navigate('/findings')}>
            <Bug size={14} /> View Findings
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          icon={TargetIcon} label="Targets" value={stats?.targets?.total || 0}
          sub={`${stats?.targets?.active || 0} active`}
          color="#58a6ff"
        />
        <StatCard
          icon={Radar} label="Scans" value={stats?.scans?.total || 0}
          sub={`${stats?.scans?.running || 0} running`}
          color="#ffa502"
        />
        <StatCard
          icon={Bug} label="Findings" value={total_findings}
          sub={`${finding_counts['CRITICAL'] || 0} critical`}
          color="#ff4757"
        />
        <StatCard
          icon={TrendingUp} label="Completed" value={stats?.scans?.completed || 0}
          sub={`${stats?.scans?.failed || 0} failed`}
          color="#2ed573"
        />
      </div>

      {/* Severity overview */}
      {total_findings > 0 && (
        <div className="card p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-sm" style={{ color: '#e6edf3' }}>Severity Overview</h3>
            <div className="flex gap-4 text-xs" style={{ color: '#8b949e' }}>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s => (
                <span key={s}>{s}: {finding_counts[s] || 0}</span>
              ))}
            </div>
          </div>
          <SeverityBar counts={finding_counts} />
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-sm" style={{ color: '#e6edf3' }}>Recent Scans</h3>
            <button
              className="text-xs flex items-center gap-1"
              style={{ color: '#58a6ff' }}
              onClick={() => navigate('/scans')}
            >
              View all <ArrowRight size={12} />
            </button>
          </div>
          {recentScans.length === 0 ? (
            <p className="text-sm text-center py-6" style={{ color: '#484f58' }}>
              No scans yet. <span style={{ color: '#58a6ff', cursor: 'pointer' }} onClick={() => navigate('/targets')}>Start a scan →</span>
            </p>
          ) : (
            recentScans.map(s => <ScanRow key={s.id} scan={s} />)
          )}
        </div>

        {/* Recent Findings */}
        <div className="card p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-sm" style={{ color: '#e6edf3' }}>Latest Findings</h3>
            <button
              className="text-xs flex items-center gap-1"
              style={{ color: '#58a6ff' }}
              onClick={() => navigate('/findings')}
            >
              View all <ArrowRight size={12} />
            </button>
          </div>
          {recentFindings.length === 0 ? (
            <p className="text-sm text-center py-6" style={{ color: '#484f58' }}>No findings yet.</p>
          ) : (
            recentFindings.map(f => <FindingRow key={f.id} f={f} />)
          )}
        </div>
      </div>

      {/* Tool status */}
      {stats?.tools && (
        <div className="card p-5">
          <h3 className="font-semibold text-sm mb-3" style={{ color: '#e6edf3' }}>Security Tool Status</h3>
          <div className="grid grid-cols-4 gap-3">
            {Object.entries(stats.tools).map(([tool, ok]) => (
              <div
                key={tool}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-xs font-medium"
                style={{
                  background: ok ? 'rgba(46,213,115,0.1)' : 'rgba(255,71,87,0.1)',
                  border: `1px solid ${ok ? 'rgba(46,213,115,0.3)' : 'rgba(255,71,87,0.3)'}`,
                  color: ok ? '#2ed573' : '#ff4757',
                }}
              >
                <span>{ok ? '✓' : '✗'}</span>
                <span className="uppercase">{tool}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
