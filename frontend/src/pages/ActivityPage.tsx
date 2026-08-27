import { useEffect, useState, useRef } from 'react';
import { activityApi, type ActivityLog } from '../api';

const LEVEL_STYLES: Record<string, { color: string; bg: string }> = {
  INFO:     { color: '#58a6ff', bg: 'rgba(88,166,255,0.08)' },
  WARNING:  { color: '#ffa502', bg: 'rgba(255,165,2,0.08)' },
  ERROR:    { color: '#ff4757', bg: 'rgba(255,71,87,0.08)' },
  DEBUG:    { color: '#8b949e', bg: 'transparent' },
  SUCCESS:  { color: '#2ed573', bg: 'rgba(46,213,115,0.08)' },
};

function LogEntry({ log }: { log: ActivityLog }) {
  const s = LEVEL_STYLES[log.level] || LEVEL_STYLES.INFO;
  return (
    <div
      className="flex gap-3 px-4 py-2.5 border-b text-xs hover:bg-white/5"
      style={{ borderColor: '#21262d' }}
    >
      <span className="font-mono flex-shrink-0" style={{ color: '#484f58', width: 80 }}>
        {new Date(log.created_at).toLocaleTimeString()}
      </span>
      <span
        className="flex-shrink-0 px-1.5 py-0.5 rounded font-bold"
        style={{ color: s.color, background: s.bg, width: 60, textAlign: 'center' }}
      >
        {log.level}
      </span>
      <span className="flex-shrink-0 font-mono" style={{ color: '#8b949e', width: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {log.event_type}
      </span>
      <span style={{ color: '#c9d1d9', flex: 1 }}>{log.message}</span>
    </div>
  );
}

export default function ActivityPage() {
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);

  const load = () => {
    activityApi.list({ limit: 200 })
      .then(setLogs)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  return (
    <div className="max-w-6xl mx-auto animate-slide-in">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold" style={{ color: '#e6edf3' }}>Activity Log</h2>
          <p className="text-sm mt-0.5" style={{ color: '#8b949e' }}>All Bug Hunter events — stored locally</p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs cursor-pointer" style={{ color: '#8b949e' }}>
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={e => setAutoScroll(e.target.checked)}
            />
            Auto-scroll
          </label>
          <button className="btn-ghost text-xs" onClick={load}>Refresh</button>
        </div>
      </div>

      <div
        className="card overflow-hidden"
        style={{ height: 'calc(100vh - 200px)', display: 'flex', flexDirection: 'column' }}
      >
        {/* Header row */}
        <div
          className="flex gap-3 px-4 py-2 text-xs font-semibold border-b"
          style={{ borderColor: '#21262d', color: '#484f58', background: '#0d1117', flexShrink: 0 }}
        >
          <span style={{ width: 80 }}>TIME</span>
          <span style={{ width: 60 }}>LEVEL</span>
          <span style={{ width: 180 }}>EVENT TYPE</span>
          <span>MESSAGE</span>
        </div>

        <div className="overflow-y-auto flex-1">
          {loading && logs.length === 0 ? (
            <div className="text-center py-12" style={{ color: '#484f58' }}>Loading…</div>
          ) : logs.length === 0 ? (
            <div className="text-center py-12" style={{ color: '#484f58' }}>No activity yet.</div>
          ) : (
            <>
              {logs.map(l => <LogEntry key={l.id} log={l} />)}
              <div ref={bottomRef} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
