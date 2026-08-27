import { useState } from 'react';
import { Save, Eye, EyeOff } from 'lucide-react';
import { api } from '../api';

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card p-5 mb-4">
      <h3 className="font-semibold text-sm mb-4 pb-2 border-b" style={{ color: '#e6edf3', borderColor: '#21262d' }}>
        {title}
      </h3>
      {children}
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <label className="block text-xs mb-1 font-medium" style={{ color: '#8b949e' }}>{label}</label>
      {children}
      {hint && <p className="text-xs mt-1" style={{ color: '#484f58' }}>{hint}</p>}
    </div>
  );
}

export default function SettingsPage() {
  const [ollamaHost, setOllamaHost] = useState('http://localhost:11434');
  const [model, setModel] = useState('llama3');
  const [port, setPort] = useState('8787');
  const [requireAuth, setRequireAuth] = useState(true);
  const [autoApply, setAutoApply] = useState(false);
  const [logLevel, setLogLevel] = useState('INFO');
  const [saved, setSaved] = useState(false);
  const [showHost, setShowHost] = useState(false);

  const handleSave = async () => {
    try {
      await api.post('/settings/', {
        ollama_host: ollamaHost,
        ollama_model: model,
        app_port: parseInt(port),
        require_authorization: requireAuth,
        auto_apply_fixes: autoApply,
        log_level: logLevel,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {}
  };

  return (
    <div className="max-w-2xl mx-auto animate-slide-in">
      <div className="mb-6">
        <h2 className="text-xl font-bold" style={{ color: '#e6edf3' }}>Settings</h2>
        <p className="text-sm mt-1" style={{ color: '#8b949e' }}>Configure Bug Hunter AI</p>
      </div>

      <Section title="AI Engine (Ollama)">
        <Field label="Ollama Host URL" hint="The address of your local Ollama server">
          <div className="relative">
            <input
              className="input-field pr-10"
              type={showHost ? 'text' : 'text'}
              value={ollamaHost}
              onChange={e => setOllamaHost(e.target.value)}
            />
            <button
              className="absolute right-2 top-1/2 -translate-y-1/2"
              onClick={() => setShowHost(v => !v)}
              style={{ color: '#8b949e' }}
            >
              {showHost ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </Field>
        <Field label="AI Model" hint="Model name from your Ollama installation (e.g. llama3, mistral, phi3)">
          <input
            className="input-field"
            value={model}
            onChange={e => setModel(e.target.value)}
            placeholder="llama3"
          />
        </Field>
      </Section>

      <Section title="Server">
        <Field label="Port" hint="Port Bug Hunter's FastAPI server listens on">
          <input
            className="input-field"
            type="number"
            value={port}
            onChange={e => setPort(e.target.value)}
          />
        </Field>
        <Field label="Log Level">
          <select className="select-field" value={logLevel} onChange={e => setLogLevel(e.target.value)}>
            <option>DEBUG</option>
            <option>INFO</option>
            <option>WARNING</option>
            <option>ERROR</option>
          </select>
        </Field>
      </Section>

      <Section title="Safety & Authorization">
        <Field label="Require Authorization Confirmation" hint="Require users to confirm authorization before each scan">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={requireAuth}
              onChange={e => setRequireAuth(e.target.checked)}
              className="accent-blue-500"
            />
            <span className="text-sm" style={{ color: requireAuth ? '#2ed573' : '#8b949e' }}>
              {requireAuth ? 'Enabled (recommended)' : 'Disabled'}
            </span>
          </label>
        </Field>
        <Field label="Auto-Apply Patches" hint="Automatically apply approved patches. Keep disabled unless fully automated lab setup.">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={autoApply}
              onChange={e => setAutoApply(e.target.checked)}
              className="accent-blue-500"
            />
            <span className="text-sm" style={{ color: autoApply ? '#ffa502' : '#8b949e' }}>
              {autoApply ? 'Enabled (use carefully)' : 'Disabled (default)'}
            </span>
          </label>
        </Field>
      </Section>

      <div
        className="p-4 rounded-md mb-4 text-xs"
        style={{ background: 'rgba(88,166,255,0.06)', border: '1px solid rgba(88,166,255,0.15)', color: '#58a6ff' }}
      >
        🔒 All data is stored locally in SQLite. Bug Hunter AI never connects to external servers or telemetry.
        Your scans, findings, and AI analysis remain on this machine.
      </div>

      <button
        className="btn-primary w-full flex items-center justify-center gap-2"
        onClick={handleSave}
      >
        <Save size={14} />
        {saved ? '✓ Settings Saved!' : 'Save Settings'}
      </button>
    </div>
  );
}
