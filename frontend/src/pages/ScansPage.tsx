import { useEffect, useState, useCallback } from 'react';
import { RefreshCw, XCircle, Download } from 'lucide-react';
import { scansApi, reportsApi, type Scan, type ScanStatus } from '../api';

const STATUS_STYLES: Record<ScanStatus, { color: string; bg: string; label: string }> = {
  PENDING:   { color: '#8b949e', bg: '#21262d', label: 'Pending' },
  RUNNING:   { color: '#ffa502', bg: 'rgba(255,165,2,0.1)', label: 'Running' },
  COMPLETED: { color: '#2ed573', bg: 'rgba(46,213,115,0.1)', label: 'Completed' },
  FAILED:    { color: '#ff4757', bg: 'rgba(255,71,87,0.1)', label: 'Failed' },
  CANCELLED: { color: '#484f58', bg: '#21262d', label: 'Cancelled' },
};

const SEV_COLORS: Record<string, string> = {
  critical: '#ff4757', high: '#ff6b35', medium: '#ffa502', low: '#2ed573', info: '#1e90ff',
};

function ScanCard({ scan, onRefresh }: { scan: Scan; onRefresh: () => void }) {
  const s = STATUS_STYLES[scan.status] || STATUS_STYLES.PENDING;
  const duration = scan.completed_at
    ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.created_at).getTime()) / 1000)
    : null;

  const handleDownload = async (fmt: string) => {
    const resp = await reportsApi.generate(scan.id, fmt);
    const ext = fmt === 'markdown' ? 'md' : fmt;
    const url = URL.createObjectURL(new Blob([resp.data]));
    const a = document.createElement('a'); a.href = url;
    a.download = `bug-hunter-${scan.id.slice(0, 8)}.${ext}`;
    a.click(); URL.revokeObjectURL(url);
  };

  const handleCancel = async () => {
    await scansApi.cancel(scan.id).catch(() => {});
    onRefresh();
  };

  return (
    <div className="card p-5 animate-slide-in" style={{ transition: 'opacity 0.3s' }}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2">
            <span
              className="text-xs px-2 py-0.5 rounded font-semibold"
              style={{ color: s.color, background: s.bg }}
            >
              {scan.status === 'RUNNING' && (
                <span className="scanning inline-block w-1.5 h-1.5 rounded-full mr-1.5" style={{ background: '#ffa502' }} />
              )}
              {s.label}
            </span>
            <span className="font-mono text-xs" style={{ color: '#484f58' }}>
              #{scan.id.slice(0, 8)}
            </span>
          </div>
          <div className="text-xs mt-1.5" style={{ color: '#8b949e' }}>
            Tools: <span style={{ color: '#58a6ff' }}>{scan.tools_used?.join(', ') || '-'}</span>
          </div>
          <div className="text-xs" style={{ color: '#484f58' }}>
            {new Date(scan.created_at).toLocaleString()}
            {duration !== null && <span> • {duration}s</span>}
          </div>
        </div>

        <div className="flex gap-2">
          {scan.status === 'RUNNING' && (
            <button className="btn-danger text-xs py-1 px-2" onClick={handleCancel}>
              <XCircle size={12} className="inline mr-1" />Cancel
            </button>
          )}
          {scan.status === 'COMPLETED' && (
            <div className="relative group">
              <button className="btn-ghost text-xs py-1 px-2">
                <Download size={12} className="inline mr-1" />Report
              </button>
              <div
                className="absolute right-0 top-full mt-1 rounded-md shadow-xl z-10 hidden group-hover:block"
                style={{ background: '#161b22', border: '1px solid #30363d', width: 120 }}
              >
                {['html', 'json', 'markdown'].map(fmt => (
                  <button
                    key={fmt}
                    onClick={() => handleDownload(fmt)}
                    className="block w-full text-left px-3 py-2 text-xs hover:bg-white/5"
                    style={{ color: '#e6edf3' }}
                  >
                    {fmt.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Findings summary */}
      {scan.findings_count > 0 && (
        <div className="mt-3 pt-3 border-t flex gap-4" style={{ borderColor: '#21262d' }}>
          {[
            { k: 'critical', v: scan.critical_count },
            { k: 'high', v: scan.high_count },
            { k: 'medium', v: scan.medium_count },
            { k: 'low', v: scan.low_count },
            { k: 'info', v: scan.info_count },
          ].filter(x => x.v > 0).map(({ k, v }) => (
            <span key={k} className="text-xs font-semibold" style={{ color: SEV_COLORS[k] }}>
              {v} {k}
            </span>
          ))}
          <span className="ml-auto text-xs" style={{ color: '#8b949e' }}>
            {scan.findings_count} total
          </span>
        </div>
      )}

      {scan.error_message && (
        <div
          className="mt-3 p-2 rounded text-xs"
          style={{ background: 'rgba(255,71,87,0.1)', color: '#ff4757' }}
        >
          {scan.error_message}
        </div>
      )}
    </div>
  );
}

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    scansApi.list({ limit: 50 }).then(setScans).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    // Auto-refresh while running scans exist
    const iv = setInterval(() => {
      setScans(prev => {
        const hasRunning = prev.some(s => s.status === 'RUNNING' || s.status === 'PENDING');
        if (hasRunning) load();
        return prev;
      });
    }, 5000);
    return () => clearInterval(iv);
  }, [load]);

  const running = scans.filter(s => s.status === 'RUNNING' || s.status === 'PENDING');
  const done = scans.filter(s => s.status !== 'RUNNING' && s.status !== 'PENDING');

  return (
    <div className="max-w-4xl mx-auto animate-slide-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold" style={{ color: '#e6edf3' }}>Scans</h2>
          <p className="text-sm mt-1" style={{ color: '#8b949e' }}>
            {scans.length} scan{scans.length !== 1 ? 's' : ''} total
          </p>
        </div>
        <button className="btn-ghost flex items-center gap-2 text-xs" onClick={load}>
          <RefreshCw size={14} className={loading ? 'scanning' : ''} /> Refresh
        </button>
      </div>

      {loading && scans.length === 0 ? (
        <div className="text-center py-12" style={{ color: '#484f58' }}>Loading scans…</div>
      ) : scans.length === 0 ? (
        <div className="card p-12 text-center">
          <p style={{ color: '#484f58' }}>No scans yet. Add a target to get started.</p>
        </div>
      ) : (
        <>
          {running.length > 0 && (
            <div className="mb-4">
              <h3 className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: '#ffa502' }}>
                Active ({running.length})
              </h3>
              <div className="space-y-3">
                {running.map(s => <ScanCard key={s.id} scan={s} onRefresh={load} />)}
              </div>
            </div>
          )}
          {done.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold mb-2 uppercase tracking-wider" style={{ color: '#8b949e' }}>
                Completed ({done.length})
              </h3>
              <div className="space-y-3">
                {done.map(s => <ScanCard key={s.id} scan={s} onRefresh={load} />)}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
