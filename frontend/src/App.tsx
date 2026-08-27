import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';
import {
  LayoutDashboard, Target, Radar, Bug, ShieldCheck,
  Activity, Settings, Wrench, ChevronRight, Wifi, WifiOff,
  AlertCircle
} from 'lucide-react';

import DashboardPage from './pages/DashboardPage';
import TargetsPage from './pages/TargetsPage';
import ScansPage from './pages/ScansPage';
import FindingsPage from './pages/FindingsPage';
import RemediationPage from './pages/RemediationPage';
import ActivityPage from './pages/ActivityPage';
import ToolsPage from './pages/ToolsPage';
import SettingsPage from './pages/SettingsPage';
import { api } from './api';

const NAV_ITEMS = [
  { to: '/',            icon: LayoutDashboard,  label: 'Dashboard',    end: true },
  { to: '/targets',     icon: Target,           label: 'Targets' },
  { to: '/scans',       icon: Radar,            label: 'Scans' },
  { to: '/findings',    icon: Bug,              label: 'Findings' },
  { to: '/remediation', icon: ShieldCheck,      label: 'Remediation' },
  { to: '/activity',   icon: Activity,         label: 'Activity Log' },
  { to: '/tools',       icon: Wrench,           label: 'Tools' },
  { to: '/settings',    icon: Settings,         label: 'Settings' },
];

function Sidebar() {
  const [serverOk, setServerOk] = useState<boolean | null>(null);

  useEffect(() => {
    const check = () =>
      api.get('/health').then(() => setServerOk(true)).catch(() => setServerOk(false));
    check();
    const iv = setInterval(check, 10000);
    return () => clearInterval(iv);
  }, []);

  return (
    <aside
      className="fixed left-0 top-0 h-full w-56 flex flex-col gap-1 z-30"
      style={{ background: '#0d1117', borderRight: '1px solid #21262d' }}
    >
      {/* Logo */}
      <div className="px-4 py-5 border-b" style={{ borderColor: '#21262d' }}>
        <div className="flex items-center gap-2.5">
          <span className="text-2xl">🐺</span>
          <div>
            <h1 className="font-bold text-sm leading-tight" style={{ color: '#58a6ff' }}>
              Bug Hunter AI
            </h1>
            <p className="text-xs" style={{ color: '#8b949e' }}>Find · Fix · Verify</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        {NAV_ITEMS.map(({ to, icon: Icon, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `nav-link${isActive ? ' active' : ''}`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Server status */}
      <div className="px-4 py-3 border-t" style={{ borderColor: '#21262d' }}>
        <div className="flex items-center gap-2 text-xs" style={{ color: '#8b949e' }}>
          {serverOk === null ? (
            <span className="scanning" style={{ color: '#8b949e' }}>Connecting…</span>
          ) : serverOk ? (
            <>
              <Wifi size={12} style={{ color: '#2ed573' }} />
              <span style={{ color: '#2ed573' }}>Server online</span>
            </>
          ) : (
            <>
              <WifiOff size={12} style={{ color: '#ff4757' }} />
              <span style={{ color: '#ff4757' }}>Server offline</span>
            </>
          )}
        </div>
        <p className="text-xs mt-1" style={{ color: '#484f58', fontSize: '0.7rem' }}>
          All data stored locally
        </p>
      </div>
    </aside>
  );
}

function BreadcrumbHeader() {
  const loc = useLocation();
  const parts = loc.pathname.split('/').filter(Boolean);
  return (
    <header
      className="fixed top-0 left-56 right-0 h-12 flex items-center px-6 z-20 gap-1 text-sm"
      style={{ background: '#0d1117', borderBottom: '1px solid #21262d', color: '#8b949e' }}
    >
      <span style={{ color: '#58a6ff' }}>Bug Hunter</span>
      {parts.map((p, i) => (
        <span key={i} className="flex items-center gap-1">
          <ChevronRight size={14} />
          <span style={{ color: i === parts.length - 1 ? '#e6edf3' : '#8b949e' }}>
            {p.charAt(0).toUpperCase() + p.slice(1)}
          </span>
        </span>
      ))}
    </header>
  );
}

function AuthorizationWarning() {
  const [dismissed, setDismissed] = useState(
    () => sessionStorage.getItem('auth-warning-dismissed') === '1'
  );
  if (dismissed) return null;
  return (
    <div
      className="fixed bottom-4 right-4 max-w-sm p-4 rounded-lg z-50 flex gap-3 animate-slide-in"
      style={{ background: '#1c1600', border: '1px solid #ff6b35' }}
    >
      <AlertCircle size={18} style={{ color: '#ff6b35', flexShrink: 0, marginTop: 2 }} />
      <div>
        <p className="text-xs font-semibold" style={{ color: '#ff6b35' }}>
          Authorization Required
        </p>
        <p className="text-xs mt-1" style={{ color: '#8b949e' }}>
          Only scan systems you own or are explicitly authorized to test.
        </p>
      </div>
      <button
        onClick={() => { sessionStorage.setItem('auth-warning-dismissed', '1'); setDismissed(true); }}
        className="text-xs ml-auto self-start"
        style={{ color: '#8b949e' }}
      >
        ✕
      </button>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-grid" style={{ background: '#0d1117' }}>
        <Sidebar />
        <div className="ml-56 flex-1 flex flex-col">
          <BreadcrumbHeader />
          <main className="pt-12 p-6 flex-1">
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/targets" element={<TargetsPage />} />
              <Route path="/scans" element={<ScansPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/remediation" element={<RemediationPage />} />
              <Route path="/activity" element={<ActivityPage />} />
              <Route path="/tools" element={<ToolsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </main>
        </div>
        <AuthorizationWarning />
      </div>
    </BrowserRouter>
  );
}
