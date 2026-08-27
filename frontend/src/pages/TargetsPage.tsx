import { useEffect, useState } from 'react';
import { Plus, Trash2, Shield, AlertCircle, ExternalLink } from 'lucide-react';
import { targetsApi, scansApi, type Target } from '../api';

const TOOLS = ['nmap', 'nuclei', 'nikto', 'ffuf'];

function NewTargetForm({ onCreated }: { onCreated: (t: Target) => void }) {
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [type, setType] = useState('hostname');
  const [desc, setDesc] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [selectedTools, setSelectedTools] = useState(['nmap', 'nuclei', 'nikto']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const toggleTool = (t: string) =>
    setSelectedTools(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authorized) { setError('You must confirm authorization before scanning.'); return; }
    if (!value.trim()) { setError('Target value is required.'); return; }
    setLoading(true);
    setError('');
    try {
      const target = await targetsApi.create({
        name: name || value,
        value: value.trim(),
        target_type: type,
        description: desc,
        authorization_confirmed: true,
        is_active: true,
      });
      onCreated(target);
      // Kick off scan
      if (selectedTools.length > 0) {
        await scansApi.create({
          target_id: target.id,
          tools: selectedTools,
          authorization_confirmed: true,
        });
      }
      setName(''); setValue(''); setDesc(''); setAuthorized(false);
    } catch (ex: any) {
      setError(ex?.response?.data?.detail || 'Failed to create target.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card p-6 mb-6">
      <h3 className="font-semibold mb-4 flex items-center gap-2" style={{ color: '#e6edf3' }}>
        <Plus size={16} style={{ color: '#58a6ff' }} />
        Add Target & Start Scan
      </h3>

      <div
        className="flex gap-2 items-start p-3 rounded-md mb-4 text-xs"
        style={{ background: 'rgba(255,107,53,0.08)', border: '1px solid rgba(255,107,53,0.2)', color: '#ff6b35' }}
      >
        <AlertCircle size={14} style={{ flexShrink: 0, marginTop: 1 }} />
        <span>Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may be illegal.</span>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs mb-1" style={{ color: '#8b949e' }}>Target Name</label>
            <input
              className="input-field"
              placeholder="My Lab Server"
              value={name}
              onChange={e => setName(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs mb-1" style={{ color: '#8b949e' }}>Target Type</label>
            <select className="select-field" value={type} onChange={e => setType(e.target.value)}>
              <option value="hostname">Hostname / Domain</option>
              <option value="ip_address">IP Address</option>
              <option value="url">URL</option>
              <option value="cidr">CIDR Range</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs mb-1" style={{ color: '#8b949e' }}>
            Target Value <span style={{ color: '#ff4757' }}>*</span>
          </label>
          <input
            className="input-field"
            placeholder="192.168.1.1 or example.local or https://app.local"
            value={value}
            onChange={e => setValue(e.target.value)}
            required
          />
        </div>

        <div>
          <label className="block text-xs mb-2" style={{ color: '#8b949e' }}>Scan Tools</label>
          <div className="flex gap-2 flex-wrap">
            {TOOLS.map(t => (
              <button
                key={t}
                type="button"
                onClick={() => toggleTool(t)}
                className="px-3 py-1 rounded text-xs font-medium transition-all"
                style={{
                  background: selectedTools.includes(t) ? 'rgba(88,166,255,0.2)' : '#21262d',
                  border: selectedTools.includes(t) ? '1px solid #58a6ff' : '1px solid #30363d',
                  color: selectedTools.includes(t) ? '#58a6ff' : '#8b949e',
                }}
              >
                {t.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-xs mb-1" style={{ color: '#8b949e' }}>Description (optional)</label>
          <input
            className="input-field"
            placeholder="Notes about this target…"
            value={desc}
            onChange={e => setDesc(e.target.value)}
          />
        </div>

        <label className="flex items-center gap-2 cursor-pointer text-xs">
          <input
            type="checkbox"
            checked={authorized}
            onChange={e => setAuthorized(e.target.checked)}
            className="accent-blue-500"
          />
          <span style={{ color: authorized ? '#2ed573' : '#ff6b35' }}>
            <Shield size={12} className="inline mr-1" />
            I confirm I am authorized to scan this target
          </span>
        </label>

        {error && (
          <p className="text-xs" style={{ color: '#ff4757' }}>{error}</p>
        )}

        <button
          type="submit"
          disabled={loading || !authorized}
          className="btn-primary w-full"
          style={{ opacity: loading || !authorized ? 0.5 : 1, cursor: loading || !authorized ? 'not-allowed' : 'pointer' }}
        >
          {loading ? 'Starting…' : '🚀 Add Target & Start Scan'}
        </button>
      </form>
    </div>
  );
}

export default function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    targetsApi.list().then(setTargets).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(load, []);

  const remove = async (id: string) => {
    if (!confirm('Delete this target?')) return;
    await targetsApi.delete(id).catch(() => {});
    load();
  };

  return (
    <div className="max-w-4xl mx-auto animate-slide-in">
      <div className="mb-6">
        <h2 className="text-xl font-bold" style={{ color: '#e6edf3' }}>Targets</h2>
        <p className="text-sm mt-1" style={{ color: '#8b949e' }}>
          Add authorized scan targets and kick off security assessments.
        </p>
      </div>

      <NewTargetForm onCreated={load} />

      <div className="card">
        <div className="px-5 py-4 border-b" style={{ borderColor: '#21262d' }}>
          <h3 className="font-semibold text-sm" style={{ color: '#e6edf3' }}>
            Registered Targets ({targets.length})
          </h3>
        </div>

        {loading ? (
          <div className="p-8 text-center" style={{ color: '#484f58' }}>Loading…</div>
        ) : targets.length === 0 ? (
          <div className="p-8 text-center" style={{ color: '#484f58' }}>
            No targets yet. Add your first authorized target above.
          </div>
        ) : (
          <div className="divide-y" style={{ borderColor: '#21262d' }}>
            {targets.map(t => (
              <div key={t.id} className="px-5 py-4 flex items-center gap-4 hover:bg-white/5 transition-colors">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm" style={{ color: '#e6edf3' }}>{t.name}</span>
                    <span
                      className="text-xs px-1.5 py-0.5 rounded"
                      style={{ background: '#21262d', color: '#8b949e' }}
                    >
                      {t.target_type}
                    </span>
                    {t.authorization_confirmed && (
                      <span
                        className="text-xs px-1.5 py-0.5 rounded"
                        style={{ background: 'rgba(46,213,115,0.1)', color: '#2ed573' }}
                      >
                        <Shield size={10} className="inline mr-1" />authorized
                      </span>
                    )}
                  </div>
                  <div className="text-xs mt-0.5 flex items-center gap-1" style={{ color: '#58a6ff' }}>
                    <ExternalLink size={10} />
                    {t.value}
                  </div>
                  {t.description && (
                    <p className="text-xs mt-0.5 truncate" style={{ color: '#8b949e' }}>{t.description}</p>
                  )}
                </div>
                <span className="text-xs" style={{ color: '#484f58' }}>
                  {new Date(t.created_at).toLocaleDateString()}
                </span>
                <button
                  onClick={() => remove(t.id)}
                  className="p-1.5 rounded hover:bg-red-500/10 transition-colors"
                  style={{ color: '#484f58' }}
                  title="Delete target"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
