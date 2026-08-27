import { useEffect, useState } from 'react';
import { CheckCircle, XCircle, ExternalLink } from 'lucide-react';
import { toolsApi } from '../api';

const TOOL_INFO: Record<string, {
  description: string;
  linux: string;
  macos: string;
  docs: string;
}> = {
  nmap: {
    description: 'Network Mapper — port scanning, service detection, OS fingerprinting',
    linux: 'sudo apt install nmap',
    macos: 'brew install nmap',
    docs: 'https://nmap.org',
  },
  nuclei: {
    description: 'Template-based vulnerability scanner for CVEs and misconfigurations',
    linux: 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    macos: 'brew install nuclei',
    docs: 'https://nuclei.projectdiscovery.io',
  },
  nikto: {
    description: 'Web server scanner — dangerous files, outdated software, insecure configs',
    linux: 'sudo apt install nikto',
    macos: 'brew install nikto',
    docs: 'https://cirt.net/Nikto2',
  },
  ffuf: {
    description: 'Fast web fuzzer for authorized content/path discovery',
    linux: 'go install github.com/ffuf/ffuf/v2@latest',
    macos: 'brew install ffuf',
    docs: 'https://github.com/ffuf/ffuf',
  },
  ollama: {
    description: 'Local AI inference engine powering Bug Hunter AI analysis',
    linux: 'curl -fsSL https://ollama.com/install.sh | sh',
    macos: 'brew install ollama',
    docs: 'https://ollama.com',
  },
};

export default function ToolsPage() {
  const [status, setStatus] = useState<Record<string, any>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    toolsApi.status().then(setStatus).catch(() => {}).finally(() => setLoading(false));
  }, []);

  return (
    <div className="max-w-4xl mx-auto animate-slide-in">
      <div className="mb-6">
        <h2 className="text-xl font-bold" style={{ color: '#e6edf3' }}>Security Tools</h2>
        <p className="text-sm mt-1" style={{ color: '#8b949e' }}>
          Install the required tools to unlock full scanning capabilities.
        </p>
      </div>

      <div className="space-y-3">
        {Object.entries(TOOL_INFO).map(([tool, info]) => {
          const installed = status[tool]?.installed ?? status[tool] ?? null;
          const version = status[tool]?.version;

          return (
            <div key={tool} className="card p-5">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span
                    className="flex items-center gap-1.5 px-3 py-1 rounded font-bold text-sm"
                    style={{
                      background: installed === true ? 'rgba(46,213,115,0.1)' : installed === false ? 'rgba(255,71,87,0.1)' : '#21262d',
                      color: installed === true ? '#2ed573' : installed === false ? '#ff4757' : '#8b949e',
                      border: `1px solid ${installed === true ? 'rgba(46,213,115,0.3)' : installed === false ? 'rgba(255,71,87,0.3)' : '#30363d'}`,
                    }}
                  >
                    {installed === true ? <CheckCircle size={13} /> : installed === false ? <XCircle size={13} /> : null}
                    {tool.toUpperCase()}
                  </span>
                  {version && <span className="text-xs" style={{ color: '#484f58' }}>{version}</span>}
                  {loading && installed === null && (
                    <span className="text-xs scanning" style={{ color: '#484f58' }}>checking…</span>
                  )}
                </div>
                <a
                  href={info.docs}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs"
                  style={{ color: '#58a6ff' }}
                >
                  Docs <ExternalLink size={11} />
                </a>
              </div>

              <p className="text-sm mb-3" style={{ color: '#8b949e' }}>{info.description}</p>

              {installed === false && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs block mb-1" style={{ color: '#484f58' }}>Linux / Debian</label>
                    <code
                      className="block text-xs p-2 rounded"
                      style={{ background: '#0d1117', border: '1px solid #21262d', color: '#7ee787', fontFamily: 'JetBrains Mono, monospace' }}
                    >
                      {info.linux}
                    </code>
                  </div>
                  <div>
                    <label className="text-xs block mb-1" style={{ color: '#484f58' }}>macOS</label>
                    <code
                      className="block text-xs p-2 rounded"
                      style={{ background: '#0d1117', border: '1px solid #21262d', color: '#7ee787', fontFamily: 'JetBrains Mono, monospace' }}
                    >
                      {info.macos}
                    </code>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
