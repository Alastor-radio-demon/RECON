import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation, useParams } from 'react-router-dom';
import './styles/recon.css';
import { HOSTS, HISTORY, grade, GC, SEV, SEVC, type Finding } from './data/demo';
import { createScan, getScan, type Scan } from './lib/api';

const NAV = [
  ['scan', 'Scan'],
  ['overview', 'Overview'],
  ['hosts', 'Hosts'],
  ['history', 'History'],
] as const;

const AppStateContext = React.createContext<{
  loaded: boolean;
  setLoaded: (value: boolean) => void;
  cidr: string;
  setCidr: (value: string) => void;
  preset: 'quick' | 'full';
  setPreset: (value: 'quick' | 'full') => void;
  auth: boolean;
  setAuth: (value: boolean) => void;
  host: string | null;
  setHost: (value: string | null) => void;
  scan: Scan | null;
  setScan: (value: Scan | null) => void;
  sortKey: 'ip' | 'os' | 'ports' | 'vulns' | 'score';
  setSortKey: (value: 'ip' | 'os' | 'ports' | 'vulns' | 'score') => void;
  sortDir: 1 | -1;
  setSortDir: (value: 1 | -1) => void;
  filter: string;
  setFilter: (value: string) => void;
  gradeFilter: 'all' | 'A' | 'B' | 'C' | 'D' | 'F';
  setGradeFilter: (value: 'all' | 'A' | 'B' | 'C' | 'D' | 'F') => void;
  scanning: boolean;
  setScanning: (value: boolean) => void;
  timer: number | null;
  setTimer: (value: number | null) => void;
} | null>(null);

function AppStateProvider({ children }: { children: React.ReactNode }) {
  const [loaded, setLoaded] = React.useState(false);
  const [cidr, setCidr] = React.useState('192.168.1.0/24');
  const [preset, setPreset] = React.useState<'quick' | 'full'>('quick');
  const [auth, setAuth] = React.useState(true);
  const [host, setHost] = React.useState<string | null>(null);
  const [scan, setScan] = React.useState<Scan | null>(null);
  const [sortKey, setSortKey] = React.useState<'ip' | 'os' | 'ports' | 'vulns' | 'score'>('score');
  const [sortDir, setSortDir] = React.useState<1 | -1>(1);
  const [filter, setFilter] = React.useState('');
  const [gradeFilter, setGradeFilter] = React.useState<'all' | 'A' | 'B' | 'C' | 'D' | 'F'>('all');
  const [scanning, setScanning] = React.useState(false);
  const [timer, setTimer] = React.useState<number | null>(null);

  const value = React.useMemo(
    () => ({ loaded, setLoaded, cidr, setCidr, preset, setPreset, auth, setAuth, host, setHost, scan, setScan, sortKey, setSortKey, sortDir, setSortDir, filter, setFilter, gradeFilter, setGradeFilter, scanning, setScanning, timer, setTimer }),
    [loaded, cidr, preset, auth, host, scan, sortKey, sortDir, filter, gradeFilter, scanning, timer],
  );

  return <AppStateContext.Provider value={value}>{children}</AppStateContext.Provider>;
}

function useAppState() {
  const context = React.useContext(AppStateContext);
  if (!context) {
    throw new Error('AppStateContext is missing');
  }
  return context;
}

interface DisplayPort {
  port: number;
  protocol: string;
  service: string;
  product: string | null;
  version: string | null;
}

interface DisplayHost {
  key: string;
  ip: string;
  hostname: string | null;
  status: 'pending' | 'scanning' | 'done';
  os: string | null;
  score: number | null;
  grade: string | null;
  riskReasons: string[] | null;
  ports: DisplayPort[];
  vulns: Finding[] | null;
}

function getDisplayHosts(scan: Scan | null, cidr: string): DisplayHost[] {
  if (scan) {
    return scan.hosts.map((host) => ({
      key: host.ip,
      ip: host.ip,
      hostname: host.hostname,
      status: host.status,
      os: null,
      score: host.score,
      grade: host.grade,
      riskReasons: host.risk_reasons,
      ports: host.ports,
      vulns: null,
    }));
  }

  const base = cidr.split('/')[0].split('.').slice(0, 3).join('.');
  return HOSTS.map((host) => ({
    key: String(host.n),
    ip: `${base}.${host.n}`,
    hostname: host.name,
    status: 'done',
    os: host.os,
    score: host.score,
    grade: grade(host.score),
    riskReasons: null,
    ports: host.ports.map((port) => ({
      port: port.port,
      protocol: port.proto,
      service: port.service,
      product: port.product,
      version: null,
    })),
    vulns: host.vulns,
  }));
}

function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const state = useAppState();
  const [menuOpen, setMenuOpen] = React.useState(false);
  const menuRef = React.useRef<HTMLDivElement | null>(null);

  React.useEffect(() => {
    const onPointerDown = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, []);

  const handleLogout = () => {
    setMenuOpen(false);
    navigate('/login');
  };

  const handleChangeAccount = () => {
    setMenuOpen(false);
    navigate('/login');
  };

  const currentView = React.useMemo(() => {
    const path = location.pathname;
    if (path.startsWith('/hosts/') && path !== '/hosts') return 'hosts';
    if (path === '/overview') return 'overview';
    if (path === '/hosts') return 'hosts';
    if (path === '/history') return 'history';
    return 'scan';
  }, [location.pathname]);

  const go = React.useCallback((view: string, hostId?: string | number | null) => {
    if (hostId !== undefined) state.setHost(hostId == null ? null : String(hostId));
    if (view === 'scan') navigate('/');
    else if (view === 'overview') navigate('/overview');
    else if (view === 'hosts') navigate('/hosts');
    else if (view === 'history') navigate('/history');
  }, [navigate, state]);

  const nav = NAV.map(([key, label]) => {
    const selected = currentView === key || (currentView === 'hosts' && key === 'hosts');
    const hostCount = state.scan ? state.scan.hosts.length : HOSTS.length;
    const badge = key === 'hosts' && state.loaded ? <span className="pill">{hostCount}</span> : null;
    return (
      <button key={key} data-go={key} aria-current={selected ? 'page' : undefined} onClick={() => go(key)}>
        {label}
        {badge}
      </button>
    );
  });

  if (location.pathname === '/login') {
    return <LoginPage />;
  }

  if (location.pathname === '/register') {
    return <RegisterPage />;
  }

  return (
    <div className="app">
      <aside>
        <div className="brand">
          <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true">
            <circle cx="14" cy="14" r="12" fill="none" stroke="var(--accent)" strokeWidth="2" />
            <circle cx="14" cy="14" r="6" fill="none" stroke="var(--accent)" strokeWidth="1.5" opacity=".6" />
            <circle cx="14" cy="14" r="2.2" fill="var(--accent)" />
          </svg>
          <b>RECON</b>
        </div>
        <nav id="nav" aria-label="Main">{nav}</nav>
        <div className="side-foot">
          <span className="pill">{state.scan ? 'Live scan' : 'Demo data'}</span>
          <p style={{ margin: '10px 0 0' }}>Scan only networks you own or are authorized to test.</p>
        </div>
      </aside>
      <div className="account-row account-top" aria-label="Account actions" ref={menuRef}>
          <button
            className="account-button"
            type="button"
            onClick={() => setMenuOpen((open) => !open)}
            aria-label="Account menu"
            aria-expanded={menuOpen}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm0 2c-4.42 0-8 2.24-8 5v1h16v-1c0-2.76-3.58-5-8-5Z"/>
            </svg>
          </button>

          {menuOpen && (
            <div className="account-menu" role="menu" aria-label="Account menu">
              <div className="account-summary">
                <div className="account-avatar">A</div>
                <div>
                  <strong>Security Analyst</strong>
                  <span>analyst@recon.local</span>
                </div>
              </div>
              <button type="button" className="menu-item" onClick={() => { setMenuOpen(false); navigate('/overview'); }}>
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm0 2c-4.42 0-8 2.24-8 5v1h16v-1c0-2.76-3.58-5-8-5Z" /></svg>
                <span>Profile</span>
              </button>
              <button type="button" className="menu-item" onClick={() => { setMenuOpen(false); navigate('/overview'); }}>
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2a2.5 2.5 0 0 1 2.5 2.5V5h1.5a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3H8a3 3 0 0 1-3-3V8a3 3 0 0 1 3-3h1.5V4.5A2.5 2.5 0 0 1 12 2Zm0 1.5a1 1 0 0 0-1 1V5h2v-.5a1 1 0 0 0-1-1Zm-3.5 6.5h7v1.5h-7Zm0 3h7v1.5h-7Z" /></svg>
                <span>Account</span>
              </button>
              <button type="button" className="menu-item" onClick={() => { setMenuOpen(false); navigate('/overview'); }}>
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19.14 12.94a7.49 7.49 0 0 0 .05-.94.7.7 0 0 0 0-.2l1.72-1.34-1.67-2.9-2.09.62a7.19 7.19 0 0 0-1.65-1l-.35-2.14H9.85l-.35 2.14a7.19 7.19 0 0 0-1.65 1l-2.09-.62-1.67 2.9 1.72 1.34a.7.7 0 0 0 0 .2.7.7 0 0 0 0 .2l-1.72 1.34 1.67 2.9 2.09-.62a7.19 7.19 0 0 0 1.65 1l.35 2.14h4.3l.35-2.14a7.19 7.19 0 0 0 1.65-1l2.09.62 1.67-2.9Zm-7.14 2.56A3.5 3.5 0 1 1 15.5 12a3.5 3.5 0 0 1-3.5 3.5Z" /></svg>
                <span>Settings</span>
              </button>
              <div className="menu-divider" />
              <button type="button" className="menu-item danger" onClick={handleChangeAccount}>
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 7a5 5 0 0 1 10 0v1h1.5A1.5 1.5 0 0 1 22 9.5v8A1.5 1.5 0 0 1 20.5 19H9.5A1.5 1.5 0 0 1 8 17.5v-8A1.5 1.5 0 0 1 9.5 8H10V7Zm5 2.5a2.5 2.5 0 0 0-2.5 2.5.5.5 0 0 0 .5.5h4a.5.5 0 0 0 .5-.5A2.5 2.5 0 0 0 14 9.5Zm-9.5 7.5h4.5v1.5H4.5A1.5 1.5 0 0 1 3 16.5v-6A1.5 1.5 0 0 1 4.5 9H6v1.5H4.5v6h4.5V9H9v7.5H4.5Z" /></svg>
                <span>Change account</span>
              </button>
              <button type="button" className="menu-item danger" onClick={handleLogout}>
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 5h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-7v-2h7V7h-7Zm-1.71 4.29L4.41 12l3.88 2.71L9.29 13l-1.3-1h7.35v-2H7.99l1.3-1Z" /></svg>
                <span>Disconnect</span>
              </button>
            </div>
          )}
      </div>
      <main id="main">
        <Routes>
          <Route path="/" element={<ScanPage />} />
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/hosts" element={<HostsPage />} />
          <Route path="/hosts/:n" element={<HostDetailPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

function EmptyState() {
  const navigate = useNavigate();
  const state = useAppState();

  return (
    <div className="panel empty">
      <h2>No scan results yet</h2>
      <p>Scan a network to see live hosts, open services, and known vulnerabilities here.</p>
      <div className="actions" style={{ justifyContent: 'center' }}>
        <button className="btn" onClick={() => navigate('/')}>Start a scan</button>
        <button className="btn ghost" onClick={() => { state.setScan(null); state.setLoaded(true); navigate('/overview'); }}>Load demo results</button>
      </div>
    </div>
  );
}

function ScanPage() {
  const navigate = useNavigate();
  const state = useAppState();
  const [error, setError] = React.useState('');
  const [progress, setProgress] = React.useState(0);
  const [log, setLog] = React.useState<string[]>([]);
  const [found, setFound] = React.useState(0);
  const [blips, setBlips] = React.useState<Array<{ cx: number; cy: number; color: string }>>([]);
  const activeScanId = React.useRef<string | null>(null);
  const pollTimer = React.useRef<number | null>(null);
  const scanIsComplete = state.scan?.status === 'completed'
    && state.scan.hosts.every((host) => host.status === 'done');

  const handleStart = async () => {
    const value = (document.getElementById('cidr') as HTMLInputElement | null)?.value.trim() ?? '';
    const match = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
    if (!match) {
      setError('Enter a range like 192.168.1.0/24.');
      return;
    }
    const octets = match.slice(1, 5).map(Number);
    const prefix = Number(match[5]);
    if (octets.some((n) => n > 255) || prefix > 32) {
      setError('That address is not valid. Each part must be 0 to 255.');
      return;
    }
    if (prefix < 24) {
      setError('Ranges larger than /24 are blocked in this version. Try a /24 or smaller.');
      return;
    }
    if (octets[0] === 127 || octets[0] >= 224 || (octets[0] === 169 && octets[1] === 254)) {
      setError('Loopback, multicast, and link-local ranges cannot be scanned.');
      return;
    }
    state.setCidr(value);
    state.setScan(null);
    setError('');
    setProgress(0);
    setFound(0);
    setBlips([]);
    setLog(['Starting host discovery...']);
    state.setScanning(true);
    state.setLoaded(false);

    try {
      const scan = await createScan(value, state.auth);
      activeScanId.current = scan.id;
      state.setScan(scan);
      state.setCidr(scan.cidr);

      let pollInFlight = false;
      let lastKnownStatus = scan.status;
      const stopPolling = () => {
        if (pollTimer.current !== null) window.clearInterval(pollTimer.current);
        pollTimer.current = null;
        activeScanId.current = null;
        state.setTimer(null);
        state.setScanning(false);
      };
      const poll = async () => {
        const scanId = activeScanId.current;
        if (!scanId || pollInFlight) return;
        console.log('[scan poll] requesting status', { scanId, lastKnownStatus });
        pollInFlight = true;
        try {
          const updatedScan = await getScan(scanId);
          lastKnownStatus = updatedScan.status;
          console.log('[scan poll] received status', { scanId, status: updatedScan.status });
          state.setScan(updatedScan);
          setError('');
          setFound(updatedScan.hosts.length);

          const total = updatedScan.hosts.length;
          const done = updatedScan.hosts.filter((host) => host.status === 'done').length;
          const isComplete = updatedScan.status === 'completed' && done === total;
          setProgress(total ? Math.round((done / total) * 100) : isComplete ? 100 : 0);
          setBlips(updatedScan.hosts.map((host, index) => {
            const addressPart = Number(host.ip.split('.').slice(-1)[0]);
            const seed = Number.isFinite(addressPart) ? addressPart : index + 1;
            const angle = (seed * 47) % 360 * Math.PI / 180;
            const radius = 30 + ((seed * 13) % 100);
            return {
              cx: 150 + radius * Math.sin(angle),
              cy: 150 - radius * Math.cos(angle),
              color: 'var(--accent)',
            };
          }));
          setLog((previous) => {
            if (!total) {
              return isComplete ? ['Discovery completed: no live hosts found.'] : ['Waiting for host discovery...'];
            }
            const discoveryLine = `Discovery found ${total} live hosts.`;
            const next = previous.includes(discoveryLine) ? previous : [...previous, discoveryLine];
            return [...next.filter((line) => !line.startsWith('Port scans complete:')), `Port scans complete: ${done}/${total}`];
          });

          if (updatedScan.status === 'failed') {
            setError(updatedScan.error || 'Scan failed.');
            state.setLoaded(true);
            stopPolling();
          } else if (isComplete) {
            state.setLoaded(true);
            stopPolling();
            navigate('/overview');
          }
        } catch (pollError) {
          setError(pollError instanceof Error ? pollError.message : 'Failed to retrieve scan status.');
        } finally {
          pollInFlight = false;
        }
      };

      pollTimer.current = window.setInterval(() => void poll(), 2000);
      state.setTimer(pollTimer.current);
      void poll();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Request failed');
      state.setScanning(false);
    }
  };

  return (
    <>
      <h1>New scan</h1>
      <p className="sub">Enter a network range. RECON finds live hosts and checks their open services.</p>
      <div className="row cols-scan">
        <div className="panel">
          <label className="f" htmlFor="cidr">Network range (CIDR)</label>
          <input id="cidr" className="mono" type="text" defaultValue={state.cidr} autoComplete="off" spellCheck={false} placeholder="192.168.1.0/24" />
          <div className="hint">Up to 254 hosts (/24). Private ranges are allowed in lab mode.</div>
          <div style={{ marginTop: 16 }}>
            <span className="f" style={{ display: 'block', fontWeight: 600 }}>Scan depth</span>
            <div className="seg">
              <label>
                <input type="radio" name="preset" value="quick" checked={state.preset === 'quick'} onChange={() => state.setPreset('quick')} />
                Quick
                <small>Top 100 ports, about 6 min</small>
              </label>
              <label>
                <input type="radio" name="preset" value="full" checked={state.preset === 'full'} onChange={() => state.setPreset('full')} />
                Full
                <small>Top 1000 ports, about 25 min</small>
              </label>
            </div>
          </div>
          <label className="chk">
            <input type="checkbox" checked={state.auth} onChange={(e) => state.setAuth(e.target.checked)} />
            <span>I own this network or have written permission to scan it.</span>
          </label>
          <p className="err" role="alert">{error || (state.scan?.status === 'failed' ? state.scan.error : '')}</p>
          <div className="actions">
            <button className="btn" onClick={handleStart} disabled={state.scanning}>Start scan</button>
            <button className="btn ghost" onClick={() => { state.setScan(null); state.setLoaded(true); navigate('/overview'); }}>Skip and load demo results</button>
          </div>
        </div>
        <div className="panel">
          <svg className="radar" viewBox="0 0 300 300" role="img" aria-label="Scan radar">
            <defs>
              <radialGradient id="rg">
                <stop offset="0" stopColor="var(--accent)" stopOpacity="0" />
                <stop offset="1" stopColor="var(--accent)" stopOpacity="0.35" />
              </radialGradient>
            </defs>
            <g fill="none" stroke="var(--line)" strokeWidth="1">
              <circle cx="150" cy="150" r="140" />
              <circle cx="150" cy="150" r="93" />
              <circle cx="150" cy="150" r="47" />
              <line x1="150" y1="10" x2="150" y2="290" />
              <line x1="10" y1="150" x2="290" y2="150" />
            </g>
            <g id="sweepg" style={{ display: state.scanning ? '' : 'none' }}>
              <path className="sweep" d="M150 150 L150 10 A140 140 0 0 0 80 28.8 Z" fill="url(#rg)" />
            </g>
            <g>
              {blips.map((b, index) => (
                <circle key={`${b.cx}-${b.cy}-${index}`} className="blip" cx={b.cx} cy={b.cy} r="4.5" fill={b.color} />
              ))}
            </g>
            <circle cx="150" cy="150" r="3.5" fill="var(--accent)" />
          </svg>
          <div
            className="bar"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={state.scan?.status === 'discovering' && !state.scan.hosts.length ? undefined : progress}
            aria-valuetext={state.scan?.status === 'discovering' && !state.scan.hosts.length ? 'Starting host discovery' : `${progress}%`}
          >
            <i style={{ display: 'block', height: '100%', width: `${state.scan?.status === 'discovering' && !state.scan.hosts.length ? 18 : progress}%`, background: 'var(--accent)', transition: 'width .2s linear' }} />
          </div>
          <div className="stats">
            <span>{!state.scan ? 'Ready to scan' : state.scan.status === 'failed' ? 'Scan failed' : scanIsComplete ? 'Done' : state.scan.status === 'discovering' && !state.scan.hosts.length ? 'Starting discovery' : state.scan.status === 'discovering' ? 'Scanning hosts' : 'Scanning ports'}</span>
            <span>{found} hosts found</span>
          </div>
          <ul className="log" aria-live="polite">
            {log.map((line, index) => (
              <li key={`${line}-${index}`}>{line}</li>
            ))}
          </ul>
        </div>
      </div>
    </>
  );
}

function OverviewPage() {
  const navigate = useNavigate();
  const state = useAppState();
  const base = state.cidr.split('.').slice(0, 3).join('.');
  const scan = state.scan;
  const hosts = getDisplayHosts(scan, state.cidr);
  const isRealScan = scan !== null;
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const hostData = isRealScan ? null : HOSTS.flatMap((host) => host.vulns.map((finding) => ({ ...finding, host })));
  hostData?.forEach((finding) => { sevCounts[finding.sev] += 1; });
  const ports = hosts.reduce((total, host) => total + host.ports.length, 0);
  const avg = isRealScan
    ? scan.network_score
    : hosts.length
      ? Math.round(hosts.reduce((sum, host) => sum + (host.score ?? 0), 0) / hosts.length)
      : null;
  const rank = isRealScan ? scan.network_grade : avg === null ? null : grade(avg);
  const totalFindings = hostData?.length || 1;
  const kev = hostData?.filter((finding) => finding.kev).length ?? 0;
  const C = 2 * Math.PI * 42;
  let offset = 0;
  const circles = SEV.map((level) => {
    const length = (sevCounts[level] / totalFindings) * C;
    const circle = <circle key={level} cx="55" cy="55" r="42" fill="none" stroke={SEVC[level]} strokeWidth="16" strokeDasharray={`${length} ${C - length}`} strokeDashoffset={-offset} transform="rotate(-90 55 55)" />;
    offset += length;
    return circle;
  });

  const serviceMap: Record<string, number> = {};
  hosts.forEach((host) => {
    host.ports.forEach((p) => {
      serviceMap[p.service] = (serviceMap[p.service] || 0) + 1;
    });
  });
  const topServices = Object.entries(serviceMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxService = topServices[0]?.[1] ?? 1;
  const worst = isRealScan ? [] : [...hosts].sort((a, b) => (a.score ?? 0) - (b.score ?? 0)).slice(0, 5);

  const cells = Array.from({ length: 256 }, (_, index) => {
    const host = hosts.find((item) => Number(item.ip.split('.').slice(-1)[0]) === index);
    if (host) {
      const gradeValue = host.score === null ? null : grade(host.score);
      return (
        <button
          key={`cell-${index}`}
          className="live"
          style={gradeValue ? { background: GC[gradeValue] } : { background: 'var(--accent)' }}
          title={`${host.ip} ${host.hostname ?? ''}${gradeValue ? ` · grade ${gradeValue}` : ` · ${host.status}`}`}
          aria-label={`${host.ip}${host.hostname ? ` ${host.hostname}` : ''}${gradeValue ? `, grade ${gradeValue}` : `, ${host.status}`}`}
          onClick={() => { state.setHost(host.key); navigate('/hosts/' + encodeURIComponent(host.key)); }}
        />
      );
    }
    return <button key={`empty-${index}`} className={index === 0 || index === 255 ? 'dim' : undefined} aria-hidden="true" title={`${base}.${index}`} />;
  });

  return (
    <>
      <h1>Network overview</h1>
      <p className="sub">{state.cidr}{state.scan ? ` · scanned ${new Date(state.scan.created_at).toLocaleString()}` : ''}. Select a square or a host to see its details.</p>
      <div className="demo">{isRealScan ? 'Real scan results. Risk analysis is not yet available.' : 'Showing demo data. Nothing here came from a real scan.'}</div>
      <div className="top">
        <div>
          <span className={rank ? `grade g-${rank}` : 'grade'} aria-label={rank ? `Network grade ${rank}` : 'Grade not yet analyzed'}>{rank ?? '—'}</span>
          <div>
            <div className="num">{avg ?? '—'}{avg !== null && <span className="lbl">/100</span>}</div>
            <div className="lbl">{avg === null ? 'Not yet analyzed' : 'Network score'}</div>
          </div>
        </div>
        <div>
          <div className="num">{hosts.length}</div>
          <div className="lbl">Live hosts</div>
        </div>
        <div>
          <div className="num">{ports}</div>
          <div className="lbl">Open ports</div>
        </div>
        <div>
          <div className="num">{hostData?.length ?? '—'}</div>
          <div className="lbl">Findings</div>
        </div>
        <div>
          <div className="num" style={{ color: 'var(--crit)' }}>{hostData === null ? '—' : kev}</div>
          <div className="lbl">Known exploited</div>
        </div>
      </div>
      <div className="row cols-ov" style={{ marginBottom: 16 }}>
        <div className="panel">
          <h2>Subnet map</h2>
          <div className="grid16">{cells}</div>
          <div className="legend">
            {!isRealScan && (['A', 'B', 'C', 'D', 'F'] as const).map((label) => (
              <span key={label}><i style={{ background: GC[label] }} />Grade {label}</span>
            ))}
            {isRealScan && <span><i style={{ background: 'var(--accent)' }} />Live host</span>}
            <span><i style={{ background: 'var(--cell)' }} />No response</span>
          </div>
          <div className="hint">Each square is one address, .0 to .255, left to right, top to bottom.</div>
        </div>
        <div className="panel">
          <h2>{isRealScan ? 'Discovered hosts' : 'Riskiest hosts'}</h2>
          <ul className="worst">
            {isRealScan ? hosts.slice(0, 5).map((host) => (
              <li key={host.key}>
                <button onClick={() => { state.setHost(host.key); navigate('/hosts/' + encodeURIComponent(host.key)); }}>
                  <span className="nm">
                    <span className="mono">{host.ip}</span>
                    <small>{host.hostname ?? 'Hostname not identified'} · {host.status} · {host.ports.length} open ports</small>
                  </span>
                </button>
              </li>
            )) : worst.map((host) => (
              <li key={host.key}>
                <button onClick={() => { state.setHost(host.key); navigate('/hosts/' + encodeURIComponent(host.key)); }}>
                  {host.score === null ? '—' : G(grade(host.score))}
                  <span className="nm">
                    <span className="mono">{host.ip}</span>
                    <small>{host.hostname} · {host.vulns?.length ?? 0} findings</small>
                  </span>
                  <span className="lbl">{host.score}</span>
                </button>
              </li>
            ))}
            {isRealScan && !hosts.length && <li className="lbl">No live hosts found.</li>}
          </ul>
        </div>
      </div>
      <div className="row cols-2">
        <div className="panel">
          <h2>Findings by severity</h2>
          {hostData === null ? <p className="lbl" style={{ margin: 0 }}>Not yet analyzed</p> : (
            <div className="donutwrap">
              <svg width="110" height="110" viewBox="0 0 110 110" role="img" aria-label="Severity chart">
                {circles}
                <text x="55" y="60" textAnchor="middle" fontSize="20" fontWeight="700" fill="var(--text)">{hostData.length}</text>
              </svg>
              <ul>
                {SEV.map((level) => (
                  <li key={level}><span><span className="dot" style={{ background: SEVC[level] }} />{level[0].toUpperCase() + level.slice(1)}</span><b>{sevCounts[level]}</b></li>
                ))}
              </ul>
            </div>
          )}
        </div>
        <div className="panel">
          <h2>Most common services</h2>
          {topServices.map(([service, count]) => (
            <div className="hbar" key={service}>
              <span className="mono">{service}</span>
              <span className="t"><i style={{ width: `${(count / maxService) * 100}%` }} /></span>
              <b>{count}</b>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function HostsPage() {
  const navigate = useNavigate();
  const state = useAppState();
  const hosts = getDisplayHosts(state.scan, state.cidr);

  const filtered = hosts.filter((host) => {
    const matchGrade = host.score === null || state.gradeFilter === 'all' || grade(host.score) === state.gradeFilter;
    const haystack = `${host.ip} ${host.hostname ?? ''} ${host.os ?? ''} ${host.status}`.toLowerCase();
    return matchGrade && haystack.includes(state.filter.toLowerCase());
  });

  const sorted = [...filtered].sort((a, b) => {
    const key = state.sortKey;
    const valueA = key === 'ip' ? a.ip : key === 'os' ? a.os ?? '' : key === 'ports' ? a.ports.length : key === 'vulns' ? a.vulns?.length ?? -1 : a.score ?? -1;
    const valueB = key === 'ip' ? b.ip : key === 'os' ? b.os ?? '' : key === 'ports' ? b.ports.length : key === 'vulns' ? b.vulns?.length ?? -1 : b.score ?? -1;
    if (typeof valueA === 'string' && typeof valueB === 'string') {
      return valueA.localeCompare(valueB) * state.sortDir;
    }
    return ((valueA > valueB ? 1 : valueA < valueB ? -1 : 0) * state.sortDir) as number;
  });

  const renderSortButton = (key: 'ip' | 'os' | 'ports' | 'vulns' | 'score', label: string) => (
    <th aria-sort={state.sortKey === key ? (state.sortDir > 0 ? 'ascending' : 'descending') : 'none'}>
      <button onClick={() => { state.setSortDir(state.sortKey === key ? (state.sortDir * -1 as 1 | -1) : 1); state.setSortKey(key); }}>{label}{state.sortKey === key ? (state.sortDir > 0 ? ' ▲' : ' ▼') : ''}</button>
    </th>
  );

  return (
    <>
      <h1>Hosts</h1>
      <p className="sub">Every live address found in the last scan. Sort by any column.</p>
      <div className="panel">
        <div className="tools">
          <input id="q" type="text" placeholder="Filter by address, name, or OS" value={state.filter} onChange={(e) => state.setFilter(e.target.value)} aria-label="Filter hosts" />
          <select id="gf" aria-label="Filter by grade" value={state.gradeFilter} onChange={(e) => state.setGradeFilter(e.target.value as 'all' | 'A' | 'B' | 'C' | 'D' | 'F')}>
            <option value="all">All grades</option>
            {['A', 'B', 'C', 'D', 'F'].map((gradeValue) => (
              <option key={gradeValue} value={gradeValue}>Grade {gradeValue}</option>
            ))}
          </select>
        </div>
        <div className="tw">
          <table>
            <thead>
              <tr>
                {renderSortButton('ip', 'Host')}
                {renderSortButton('os', 'Operating system')}
                {renderSortButton('ports', 'Open ports')}
                {renderSortButton('vulns', 'Findings')}
                {renderSortButton('score', 'Grade')}
              </tr>
            </thead>
            <tbody>
              {sorted.length ? sorted.map((host) => (
                <tr className="click" tabIndex={0} key={host.key} onClick={() => navigate('/hosts/' + encodeURIComponent(host.key))} onKeyDown={(e) => { if (e.key === 'Enter') navigate('/hosts/' + encodeURIComponent(host.key)); }}>
                  <td><span className="mono">{host.ip}</span><div className="lbl">{host.hostname ?? host.status}</div></td>
                      <td>{host.os ?? <span className="lbl">Not yet analyzed</span>}</td>
                  <td>{host.ports.length}</td>
                  <td>{host.vulns === null ? <span className="lbl">Not yet analyzed</span> : host.vulns.length ? (
                    <span className="mini">
                      {SEV.filter((level) => host.vulns?.some((finding) => finding.sev === level)).map((level) => (
                        <span key={level} style={{ background: SEVC[level], color: level === 'medium' ? '#211800' : '#fff' }}>
                          {host.vulns?.filter((finding) => finding.sev === level).length}
                        </span>
                      ))}
                    </span>
                  ) : <span className="lbl">None</span>}</td>
                      <td>{host.grade === null ? <span className="lbl">Not yet analyzed</span> : <>{G(host.grade)} {host.score !== null && <span className="lbl">{host.score}</span>}</>}</td>
                </tr>
              )) : (
                <tr><td colSpan={5} className="lbl" style={{ padding: '26px 12px' }}>No hosts match this filter. Clear the search or choose All grades.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

function HostDetailPage() {
  const navigate = useNavigate();
  const { n } = useParams();
  const state = useAppState();
  const hostId = n ?? state.host;
  const host = getDisplayHosts(state.scan, state.cidr).find((item) => item.key === hostId || item.ip === hostId);
  if (!host) {
    return <div className="panel empty"><h2>Host not found</h2></div>;
  }
  const rank = host.grade;
  const findings = host.vulns === null ? null : [...host.vulns].sort((a, b) => SEV.indexOf(a.sev) - SEV.indexOf(b.sev) || b.cvss - a.cvss);

  return (
    <>
      <button className="back" onClick={() => navigate('/hosts')}>← All hosts</button>
      <div className="hd">
        <span className={rank ? `grade g-${rank}` : 'grade'} aria-label={rank ? `Grade ${rank}` : 'Grade not yet analyzed'}>{rank ?? '—'}</span>
        <div>
          <h1 className="mono" style={{ margin: 0 }}>{host.ip}</h1>
          <div className="lbl">{host.hostname ?? 'Hostname not identified'} · {host.os ?? 'OS not yet analyzed'} · {host.score === null ? 'Score not yet analyzed' : `score ${host.score}/100`} · {host.status}</div>
        </div>
      </div>
      <div className="panel" style={{ marginBottom: 16 }}>
        <h2>{findings === null ? 'Findings' : `Findings (${findings.length})`}</h2>
        {findings === null ? <p className="lbl" style={{ margin: 0 }}>Not yet analyzed</p> : findings.length ? (
          <div className="tw">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Port</th>
                  <th>CVSS</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((v) => (
                  <tr key={v.id}>
                    <td><span className={`sev s-${v.sev}`}>{v.sev}</span></td>
                    <td>
                      <b>{v.title}</b>
                      {v.kev ? <span className="kev" title="Listed in the CISA Known Exploited Vulnerabilities catalog">KEV</span> : null}
                      <div className="lbl mono">{v.id}</div>
                    </td>
                    <td className="mono">{v.port}</td>
                    <td>{v.cvss.toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="lbl" style={{ margin: 0 }}>No findings on this host. Its open services match no known issues.</p>}
      </div>
      <div className="row cols-2">
        <div className="panel">
          <h2>Open ports ({host.ports.length})</h2>
          <div className="tw">
            <table>
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                {host.ports.map((port) => (
                  <tr key={`${host.key}-${port.port}-${port.service}`}>
                    <td className="mono">{port.port}/{port.protocol}</td>
                    <td>{port.service}</td>
                    <td>{[port.product, port.version].filter(Boolean).join(' ') || 'Not identified'}</td>
                  </tr>
                ))}
                {!host.ports.length && <tr><td colSpan={3} className="lbl">No open ports reported.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
        <div className="panel">
          <h2>What to fix first</h2>
          {findings === null ? <p className="lbl" style={{ margin: 0 }}>Not yet analyzed</p> : findings.length ? (
            <ol className="recs">
              {findings.map((v) => <li key={`fix-${v.id}`}>{v.fix}</li>)}
            </ol>
          ) : <p className="lbl" style={{ margin: 0 }}>Nothing to fix. Keep the system patched and re-scan after changes.</p>}
          <h2>Risk factors</h2>
          {host.riskReasons === null ? <p className="lbl" style={{ margin: 0 }}>Not yet analyzed</p> : host.riskReasons.length ? (
            <ul className="recs">
              {host.riskReasons.map((reason, index) => <li key={`${host.key}-risk-${index}`}>{reason}</li>)}
            </ul>
          ) : <p className="lbl" style={{ margin: 0 }}>No risk factors found</p>}
        </div>
      </div>
    </>
  );
}

function HistoryPage() {
  const navigate = useNavigate();

  return (
    <>
      <h1>Scan history</h1>
      <p className="sub">Earlier scans, newest first. Open one to review its results.</p>
      <div className="panel">
        <div className="tw">
          <table>
            <thead>
              <tr>
                <th>Started</th>
                <th>Range</th>
                <th>Hosts</th>
                <th>Findings</th>
                <th>Grade</th>
                <th>Duration</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {HISTORY.map((row, index) => (
                <tr key={`${row.when}-${row.cidr}`}>
                  <td>{row.when}</td>
                  <td className="mono">{row.cidr}</td>
                  <td>{row.hosts}</td>
                  <td>{row.find}</td>
                  <td>{G(row.g)}</td>
                  <td>{row.dur}</td>
                  <td>{index === 0 ? <button className="btn ghost" onClick={() => navigate('/overview')}>Open</button> : <span className="lbl">Archived</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

function G(value: string) {
  return <span className={`grade sm g-${value}`} aria-label={`Grade ${value}`}>{value}</span>;
}

function LoginPage() {
  const navigate = useNavigate();

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="auth-brand" aria-label="RECON account login">
          <svg width="36" height="36" viewBox="0 0 28 28" aria-hidden="true">
            <circle cx="14" cy="14" r="12" fill="none" stroke="var(--accent)" strokeWidth="2" />
            <circle cx="14" cy="14" r="6" fill="none" stroke="var(--accent)" strokeWidth="1.5" opacity=".6" />
            <circle cx="14" cy="14" r="2.2" fill="var(--accent)" />
          </svg>
          <span>RECON</span>
        </div>
        <h1 className="auth-title">Login</h1>
        <form className="auth-form" onSubmit={(event) => { event.preventDefault(); navigate('/'); }}>
          <div className="field">
            <label htmlFor="login-email">Email</label>
            <input id="login-email" type="email" defaultValue="analyst@recon.local" />
          </div>
          <div className="field">
            <label htmlFor="login-password">Password</label>
            <input id="login-password" type="password" defaultValue="********" />
          </div>
          <div className="auth-actions">
            <button className="btn" type="submit">Sign in</button>
            <button className="btn ghost" type="button" onClick={() => navigate('/register')}>Create account</button>
          </div>
        </form>
      </div>
    </div>
  );
}

function RegisterPage() {
  const navigate = useNavigate();

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="auth-brand" aria-label="RECON account registration">
          <svg width="36" height="36" viewBox="0 0 28 28" aria-hidden="true">
            <circle cx="14" cy="14" r="12" fill="none" stroke="var(--accent)" strokeWidth="2" />
            <circle cx="14" cy="14" r="6" fill="none" stroke="var(--accent)" strokeWidth="1.5" opacity=".6" />
            <circle cx="14" cy="14" r="2.2" fill="var(--accent)" />
          </svg>
          <span>RECON</span>
        </div>
        <h1 className="auth-title">Register</h1>
        <form className="auth-form" onSubmit={(event) => { event.preventDefault(); navigate('/'); }}>
          <div className="field">
            <label htmlFor="register-name">Full name</label>
            <input id="register-name" type="text" defaultValue="Security Analyst" />
          </div>
          <div className="field">
            <label htmlFor="register-email">Email</label>
            <input id="register-email" type="email" defaultValue="analyst@recon.local" />
          </div>
          <div className="field">
            <label htmlFor="register-password">Password</label>
            <input id="register-password" type="password" defaultValue="********" />
          </div>
          <div className="auth-actions">
            <button className="btn" type="submit">Create account</button>
            <button className="btn ghost" type="button" onClick={() => navigate('/login')}>Back to login</button>
          </div>
        </form>
      </div>
    </div>
  );
}

function App() {
  return (
    <AppStateProvider>
      <BrowserRouter>
        <AppLayout />
      </BrowserRouter>
    </AppStateProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
