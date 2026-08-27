import { useEffect, useState } from 'react';
import { CheckCircle, XCircle, ShieldCheck, RotateCcw } from 'lucide-react';
import { remediationApi, type RemediationAction } from '../api';

const STATUS_STYLES: Record<string, { color: string; label: string }> = {
  PENDING:  { color: '#ffa502', label: 'Pending Review' },
  APPROVED: { color: '#2ed573', label: 'Approved' },
  REJECTED: { color: '#ff4757', label: 'Rejected' },
  APPLIED:  { color: '#58a6ff', label: 'Applied' },
  VERIFIED_FIXED: { color: '#39d353', label: 'Verified Fixed' },
  VERIFIED_NOT_FIXED: { color: '#ff6b35', label: 'Not Fixed' },
};

function ActionCard({ action, onUpdate }: { action: RemediationAction; onUpdate: () => void }) {
  const [loading, setLoading] = useState('');
  const s = STATUS_STYLES[action.status] || { color: '#8b949e', label: action.status };

  const act = async (fn: () => Promise<any>, key: string) => {
    setLoading(key);
    try { await fn(); onUpdate(); } catch { } finally { setLoading(''); }
  };

  return (
    <div className="card p-5 animate-slide-in">
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs px-2 py-0.5 rounded font-medium" style={{ color: s.color, background: `${s.color}20` }}>
              {s.label}
            </span>
            <span className="text-xs font-mono" style={{ color: '#484f58' }}>#{action.id.slice(0, 8)}</span>
          </div>
          <h4 className="font-medium text-sm" style={{ color: '#e6edf3' }}>{action.title}</h4>
          <p className="text-xs mt-0.5" style={{ color: '#8b949e' }}>Type: {action.action_type}</p>
        </div>
      </div>

      {action.description && (
        <p className="text-sm mb-3" style={{ color: '#c9d1d9' }}>{action.description}</p>
      )}

      {action.steps && action.steps.length > 0 && (
        <div className="mb-3">
          <label className="text-xs block mb-2" style={{ color: '#8b949e' }}>Remediation Steps</label>
          <ol className="space-y-1">
            {action.steps.map((step, i) => (
              <li key={i} className="flex gap-2 text-sm">
                <span className="text-xs font-bold flex-shrink-0" style={{ color: '#58a6ff' }}>{i + 1}.</span>
                <span style={{ color: '#c9d1d9' }}>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {action.patch_diff && (
        <div className="mb-3">
          <label className="text-xs block mb-1" style={{ color: '#8b949e' }}>
            Patch Diff {action.target_file && <span style={{ color: '#58a6ff' }}>— {action.target_file}</span>}
          </label>
          <pre
            className="text-xs p-3 rounded overflow-x-auto"
            style={{ background: '#0d1117', border: '1px solid #21262d', color: '#7ee787', fontFamily: 'JetBrains Mono, monospace' }}
          >{action.patch_diff}</pre>
          <p
            className="text-xs mt-1 flex items-center gap-1"
            style={{ color: '#ffa502' }}
          >
            ⚠ Approve only after reviewing the diff. A backup will be created automatically.
          </p>
        </div>
      )}

      {action.verification_result && (
        <div
          className="mb-3 p-3 rounded-md text-xs"
          style={{
            background: action.verification_result.passed ? 'rgba(46,213,115,0.08)' : 'rgba(255,71,87,0.08)',
            border: `1px solid ${action.verification_result.passed ? 'rgba(46,213,115,0.2)' : 'rgba(255,71,87,0.2)'}`,
            color: action.verification_result.passed ? '#2ed573' : '#ff4757',
          }}
        >
          {action.verification_result.passed ? '✓' : '✗'} Verification ({action.verification_result.method}):&nbsp;
          {action.verification_result.notes}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2 pt-3 border-t" style={{ borderColor: '#21262d' }}>
        {action.status === 'PENDING' && (
          <>
            <button
              className="btn-primary text-xs flex items-center gap-1.5"
              disabled={loading === 'approve'}
              onClick={() => act(() => remediationApi.approve(action.id), 'approve')}
            >
              <CheckCircle size={12} />
              {loading === 'approve' ? 'Approving…' : 'Approve'}
            </button>
            <button
              className="btn-danger text-xs flex items-center gap-1.5"
              disabled={loading === 'reject'}
              onClick={() => act(() => remediationApi.reject(action.id), 'reject')}
            >
              <XCircle size={12} />
              {loading === 'reject' ? 'Rejecting…' : 'Reject'}
            </button>
          </>
        )}
        {(action.status === 'APPROVED' || action.status === 'APPLIED') && (
          <button
            className="btn-ghost text-xs flex items-center gap-1.5"
            disabled={loading === 'verify'}
            onClick={() => act(() => remediationApi.verify(action.id), 'verify')}
          >
            <RotateCcw size={12} className={loading === 'verify' ? 'scanning' : ''} />
            {loading === 'verify' ? 'Verifying…' : 'Verify Fix'}
          </button>
        )}
      </div>
    </div>
  );
}

export default function RemediationPage() {
  const [actions, setActions] = useState<RemediationAction[]>([]);
  const [loading, setLoading] = useState(true);

  // Fetch all remediation actions across findings
  const load = () => {
    // The API is finding-scoped; we load via /findings first
    import('../api').then(({ findingsApi: fa }) => {
      fa.list({ limit: 200 }).then(async findings => {
        const all: RemediationAction[] = [];
        for (const f of findings.slice(0, 20)) {
          try {
            const acts = await remediationApi.list(f.id);
            all.push(...acts);
          } catch {}
        }
        setActions(all.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()));
      }).finally(() => setLoading(false));
    });
  };

  useEffect(load, []);

  const pending = actions.filter(a => a.status === 'PENDING');
  const others = actions.filter(a => a.status !== 'PENDING');

  return (
    <div className="max-w-4xl mx-auto animate-slide-in">
      <div className="mb-6">
        <h2 className="text-xl font-bold flex items-center gap-2" style={{ color: '#e6edf3' }}>
          <ShieldCheck size={20} style={{ color: '#2ed573' }} />
          Remediation
        </h2>
        <p className="text-sm mt-1" style={{ color: '#8b949e' }}>
          Review AI-generated remediation plans. Approve or reject patches. Verify fixes are applied.
        </p>
      </div>

      {loading ? (
        <div className="text-center py-12" style={{ color: '#484f58' }}>Loading…</div>
      ) : actions.length === 0 ? (
        <div className="card p-12 text-center">
          <ShieldCheck size={32} className="mx-auto mb-3" style={{ color: '#484f58' }} />
          <p style={{ color: '#484f58' }}>No remediation actions yet.</p>
          <p className="text-sm mt-1" style={{ color: '#484f58' }}>
            Open a finding and click "Generate Remediation" to get started.
          </p>
        </div>
      ) : (
        <>
          {pending.length > 0 && (
            <div className="mb-6">
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: '#ffa502' }}>
                Pending Review ({pending.length})
              </h3>
              <div className="space-y-4">
                {pending.map(a => <ActionCard key={a.id} action={a} onUpdate={load} />)}
              </div>
            </div>
          )}
          {others.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: '#8b949e' }}>
                History ({others.length})
              </h3>
              <div className="space-y-4">
                {others.map(a => <ActionCard key={a.id} action={a} onUpdate={load} />)}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
