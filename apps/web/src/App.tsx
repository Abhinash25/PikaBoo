import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Server,
  Database,
  Layers,
  Activity,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Lock,
  Terminal,
  FileCode,
  Radio,
  Clock,
  ArrowUpRight,
  Zap,
  Key,
  UserCheck,
  LogOut,
  Trash2,
  Smartphone,
  Laptop,
  Globe,
  KeyRound,
  ExternalLink,
  Copy,
  Check,
  AlertCircle,
  XCircle,
} from 'lucide-react';
import {
  HealthCheckResponse,
  SystemInfoResponse,
  UserProfileDto,
  SessionItemDto,
} from '../../../packages/shared-types/src/api';
import { VpnManager } from './components/VpnManager';

interface DiagnosticEvent {
  step:
    | 'OAUTH_START'
    | 'REDIS_STATE'
    | 'GOOGLE_AUTH_URL'
    | 'CALLBACK_RECEIVED'
    | 'TOKEN_EXCHANGE'
    | 'OIDC_VERIFY'
    | 'DB_IDENTITY'
    | 'SESSION_CREATE'
    | 'COOKIES_ISSUED'
    | 'AUTH_ME';
  status: 'PASS' | 'FAIL' | 'INFO';
  category?: string;
  details?: string;
  timestamp: string;
}

interface DiagnosticResponse {
  oauthConfiguration: {
    googleClientIdConfigured: boolean;
    googleClientSecretConfigured: boolean;
    isPlaceholderClientId: boolean;
    resolvedRedirectUri: string;
    currentOrigin: string;
    allowedRedirectUris: string[];
  };
  services: {
    database: string;
    redis: string;
  };
  history: DiagnosticEvent[];
}

export default function App() {
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null);
  const [systemInfo, setSystemInfo] = useState<SystemInfoResponse | null>(null);
  const [currentUser, setCurrentUser] = useState<UserProfileDto | null>(null);
  const [sessions, setSessions] = useState<SessionItemDto[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [authLoading, setAuthLoading] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());
  const [activeTab, setActiveTab] = useState<'auth' | 'overview' | 'schema' | 'security' | 'prober'>('auth');
  const [probeResult, setProbeResult] = useState<{ endpoint: string; status: number; latencyMs: number; data: unknown } | null>(null);
  const [probing, setProbing] = useState(false);
  const [rbacMessage, setRbacMessage] = useState<string | null>(null);
  const [authMessage, setAuthMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [diagnostics, setDiagnostics] = useState<DiagnosticResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const authPopupRef = useRef<Window | null>(null);

  // Read CSRF Token from document cookies
  const getCsrfToken = (): string => {
    const match = document.cookie.match(new RegExp('(^| )pg_csrf_token=([^;]+)'));
    return match ? match[2] : '';
  };

  const fetchCurrentUser = async () => {
    try {
      const res = await fetch('/api/v1/auth/me');
      if (res.ok) {
        const json = await res.json();
        setCurrentUser(json.data.user);
        setActiveSessionId(json.data.sessionId);
        fetchSessions();
      } else {
        setCurrentUser(null);
        setSessions([]);
      }
    } catch {
      setCurrentUser(null);
    }
  };

  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/v1/auth/sessions');
      if (res.ok) {
        const json = await res.json();
        setSessions(json.data || []);
      }
    } catch {
      // ignore
    }
  };

  const fetchDiagnostics = async () => {
    try {
      const res = await fetch('/api/v1/auth/diagnostics');
      if (res.ok) {
        const json = await res.json();
        setDiagnostics(json.data);
      }
    } catch (err) {
      console.error('Error fetching diagnostics:', err);
    }
  };

  const fetchHealthAndSystem = async () => {
    setIsLoading(true);
    try {
      const [healthRes, systemRes] = await Promise.all([
        fetch('/health'),
        fetch('/api/v1/system/info'),
      ]);

      if (healthRes.ok) {
        const hData = await healthRes.json();
        setHealthData(hData);
      }
      if (systemRes.ok) {
        const sData = await systemRes.json();
        setSystemInfo(sData.data);
      }
      setLastRefreshed(new Date());
    } catch (err) {
      console.error('Error fetching telemetry:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHealthAndSystem();
    fetchCurrentUser();
    fetchDiagnostics();

    // Check URL parameters for redirect errors
    const params = new URLSearchParams(window.location.search);
    const authError = params.get('auth_error');
    if (authError) {
      setAuthMessage({
        type: 'error',
        text: `Authentication Error: ${authError}`,
      });
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    const interval = setInterval(() => {
      fetchHealthAndSystem();
      fetchDiagnostics();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  // Listen for popup cross-window postMessage events with strict origin & source checks
  useEffect(() => {
    const handleOAuthMessage = (event: MessageEvent) => {
      // 1. Strict Origin Validation
      if (event.origin !== window.location.origin) {
        return;
      }

      // 2. Source Window Validation
      if (authPopupRef.current && event.source !== authPopupRef.current) {
        return;
      }

      // 3. Process Status Event (No secrets/tokens accepted over postMessage)
      if (event.data?.type === 'OAUTH_AUTH_SUCCESS') {
        if (authPopupRef.current) {
          authPopupRef.current.close();
        }
        authPopupRef.current = null;
        fetchCurrentUser();
        fetchDiagnostics();
        setAuthMessage({
          type: 'success',
          text: 'Google Sign-In completed successfully! Authenticated session established.',
        });
      } else if (event.data?.type === 'OAUTH_AUTH_ERROR') {
        if (authPopupRef.current) {
          authPopupRef.current.close();
        }
        authPopupRef.current = null;
        fetchDiagnostics();
        setAuthMessage({
          type: 'error',
          text: `Google Sign-In failed: ${event.data.error || 'Authentication error'}`,
        });
      }
    };
    window.addEventListener('message', handleOAuthMessage);
    return () => window.removeEventListener('message', handleOAuthMessage);
  }, []);

  const handleStartGoogleLogin = async () => {
    setAuthLoading(true);
    setAuthMessage(null);

    try {
      // 1. Fetch authorization URL from server
      const res = await fetch('/api/v1/auth/google/start?mode=json');
      if (!res.ok) {
        throw new Error(`Failed to initiate OAuth flow: HTTP ${res.status}`);
      }
      const data = await res.json();

      if (data.isPlaceholderClientId) {
        setAuthMessage({
          type: 'info',
          text: 'Notice: Application is currently using a placeholder Google Client ID. Real Google OAuth requires registering your Google Client ID and Secret in .env and adding the Authorized Redirect URI in Google Cloud Console.',
        });
      }

      // 2. Open Google OAuth provider URL directly in popup
      const authWindow = window.open(
        data.url,
        'oauth_popup',
        'width=550,height=650,left=200,top=100,menubar=no,toolbar=no'
      );

      if (authWindow) {
        authPopupRef.current = authWindow;
      } else {
        // If popup blocked, fallback to top-level navigation
        window.location.href = data.url;
      }
    } catch (err) {
      setAuthMessage({
        type: 'error',
        text: `Error initiating Google Sign-In: ${(err as Error).message}`,
      });
    } finally {
      setAuthLoading(false);
      fetchDiagnostics();
    }
  };

  const handleLogout = async () => {
    setAuthLoading(true);
    try {
      const csrfToken = getCsrfToken();
      await fetch('/api/v1/auth/logout', {
        method: 'POST',
        headers: {
          'X-CSRF-Token': csrfToken,
        },
      });
      setCurrentUser(null);
      setSessions([]);
      setAuthMessage({ type: 'info', text: 'Logged out successfully.' });
      fetchDiagnostics();
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleRotateRefreshToken = async () => {
    setAuthLoading(true);
    try {
      const csrfToken = getCsrfToken();
      const res = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: {
          'X-CSRF-Token': csrfToken,
        },
      });
      if (res.ok) {
        const json = await res.json();
        setCurrentUser(json.data.user);
        await fetchSessions();
        setAuthMessage({ type: 'success', text: 'Refresh Token rotated successfully within Token Family.' });
      } else {
        const json = await res.json();
        setAuthMessage({ type: 'error', text: `Refresh error: ${json.error?.message || 'Failed'}` });
      }
    } catch (err) {
      setAuthMessage({ type: 'error', text: `Network error: ${(err as Error).message}` });
    } finally {
      setAuthLoading(false);
    }
  };

  const handleRevokeSession = async (sessionId: string) => {
    try {
      const csrfToken = getCsrfToken();
      const res = await fetch(`/api/v1/auth/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: {
          'X-CSRF-Token': csrfToken,
        },
      });
      if (res.ok) {
        fetchSessions();
        setAuthMessage({ type: 'info', text: 'Session revoked.' });
      }
    } catch (err) {
      console.error('Error revoking session:', err);
    }
  };

  const testAdminRbac = async () => {
    setRbacMessage(null);
    try {
      const res = await fetch('/api/v1/admin/users');
      const json = await res.json();
      if (res.ok) {
        setRbacMessage(`200 OK: User is Admin. Retrieved ${json.data.total} user records.`);
      } else {
        setRbacMessage(`HTTP ${res.status}: ${json.error?.message || 'Access Denied (RBAC Protected)'}`);
      }
    } catch (err) {
      setRbacMessage(`Network error: ${(err as Error).message}`);
    }
  };

  const runProbe = async (endpoint: string) => {
    setProbing(true);
    const start = performance.now();
    try {
      const res = await fetch(endpoint);
      const latency = Math.round(performance.now() - start);
      const data = await res.json();
      setProbeResult({
        endpoint,
        status: res.status,
        latencyMs: latency,
        data,
      });
    } catch (err) {
      const latency = Math.round(performance.now() - start);
      setProbeResult({
        endpoint,
        status: 500,
        latencyMs: latency,
        data: { error: (err as Error).message },
      });
    } finally {
      setProbing(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Compute status for the 10 OAuth debug checklist items
  const getStepStatus = (stepName: DiagnosticEvent['step']): 'PASS' | 'FAIL' | 'PENDING' => {
    if (!diagnostics?.history) return 'PENDING';
    const matches = diagnostics.history.filter((e) => e.step === stepName);
    if (matches.length === 0) return 'PENDING';
    const last = matches[matches.length - 1];
    return last.status === 'PASS' ? 'PASS' : 'FAIL';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-semibold tracking-tight text-white">Privacy Gateway</h1>
                <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  Phase 2 OAuth Verified
                </span>
              </div>
              <p className="text-xs text-slate-400">Zero-Log Architecture & Token Family Security</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {currentUser ? (
              <div className="flex items-center gap-3 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5">
                <div className="w-6 h-6 rounded-full bg-cyan-600 flex items-center justify-center text-xs font-semibold text-white">
                  {currentUser.displayName ? currentUser.displayName[0] : currentUser.email[0].toUpperCase()}
                </div>
                <div className="hidden sm:block text-left">
                  <div className="text-xs font-medium text-slate-200">{currentUser.email}</div>
                  <div className="text-[10px] text-cyan-400 uppercase font-semibold">{currentUser.role}</div>
                </div>
                <button
                  id="logout-btn"
                  onClick={handleLogout}
                  disabled={authLoading}
                  className="p-1 text-slate-400 hover:text-rose-400 transition"
                  title="Log out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <button
                id="header-login-btn"
                onClick={handleStartGoogleLogin}
                disabled={authLoading}
                className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 active:bg-blue-700 rounded-lg shadow-sm transition disabled:opacity-50"
              >
                <Globe className={`w-3.5 h-3.5 ${authLoading ? 'animate-spin' : ''}`} />
                <span>Sign in with Google</span>
              </button>
            )}

            <button
              id="refresh-btn"
              onClick={() => {
                fetchHealthAndSystem();
                fetchDiagnostics();
              }}
              disabled={isLoading}
              className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 active:bg-slate-900 rounded-lg border border-slate-700 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* User Alert Banner */}
        {authMessage && (
          <div
            className={`p-4 rounded-xl border flex items-center justify-between text-sm ${
              authMessage.type === 'success'
                ? 'bg-emerald-950/80 border-emerald-800 text-emerald-300'
                : authMessage.type === 'error'
                ? 'bg-rose-950/80 border-rose-800 text-rose-300'
                : 'bg-blue-950/80 border-blue-800 text-blue-300'
            }`}
          >
            <div className="flex items-center gap-3">
              {authMessage.type === 'success' ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              ) : authMessage.type === 'error' ? (
                <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-blue-400 shrink-0" />
              )}
              <span>{authMessage.text}</span>
            </div>
            <button
              onClick={() => setAuthMessage(null)}
              className="text-xs px-2 py-1 bg-black/20 hover:bg-black/40 rounded transition"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 overflow-x-auto">
          <button
            id="tab-auth"
            onClick={() => setActiveTab('auth')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'auth'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4" />
              <span>Authentication & Sessions</span>
            </div>
          </button>
          <button
            id="tab-overview"
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4" />
              <span>Architecture Model</span>
            </div>
          </button>
          <button
            id="tab-schema"
            onClick={() => setActiveTab('schema')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'schema'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4" />
              <span>Database Schema (11 Tables)</span>
            </div>
          </button>
          <button
            id="tab-security"
            onClick={() => setActiveTab('security')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'security'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4" />
              <span>Security & Token Lifecycle</span>
            </div>
          </button>
          <button
            id="tab-prober"
            onClick={() => setActiveTab('prober')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition whitespace-nowrap ${
              activeTab === 'prober'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4" />
              <span>API Health & Prober</span>
            </div>
          </button>
        </div>

        {/* Tab 0: Authentication & Session Console */}
        {activeTab === 'auth' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* User Profile Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <UserCheck className="w-4 h-4 text-cyan-400" />
                    <span>Identity Status</span>
                  </h3>
                  <span
                    className={`px-2 py-0.5 text-xs rounded-full font-medium ${
                      currentUser
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {currentUser ? 'Authenticated' : 'Anonymous'}
                  </span>
                </div>

                {currentUser ? (
                  <div className="space-y-3 text-xs">
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Email:</span>
                        <span className="text-slate-200 font-semibold">{currentUser.email}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Assigned Role:</span>
                        <span className="text-cyan-400 uppercase font-semibold">{currentUser.role}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">User ID:</span>
                        <span className="text-slate-400 font-mono text-[11px] truncate max-w-[160px]">
                          {currentUser.id}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Data Retention:</span>
                        <span className="text-slate-200">{currentUser.dataRetentionDays} Days</span>
                      </div>
                    </div>

                    <div className="pt-2 flex flex-col gap-2">
                      <button
                        id="rotate-token-btn"
                        onClick={handleRotateRefreshToken}
                        disabled={authLoading}
                        className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-lg text-xs font-medium border border-slate-700 transition flex items-center justify-center gap-2"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${authLoading ? 'animate-spin' : ''}`} />
                        <span>Rotate Refresh Token (Token Family)</span>
                      </button>

                      <button
                        id="test-rbac-btn"
                        onClick={testAdminRbac}
                        className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-purple-400 rounded-lg text-xs font-medium border border-slate-700 transition flex items-center justify-center gap-2"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        <span>Probe Admin RBAC Boundary</span>
                      </button>
                    </div>

                    {rbacMessage && (
                      <div className="p-2.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-purple-300">
                        {rbacMessage}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-4 space-y-4">
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Authenticate with Google OIDC (PKCE S256). In iframe mode, login initiates securely via an isolated OAuth popup.
                    </p>
                    <button
                      id="google-login-main"
                      onClick={handleStartGoogleLogin}
                      disabled={authLoading}
                      className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white rounded-lg text-xs font-medium shadow-md shadow-blue-600/20 transition flex items-center justify-center gap-2 disabled:opacity-50"
                    >
                      <Globe className={`w-4 h-4 ${authLoading ? 'animate-spin' : ''}`} />
                      <span>Sign in with Google</span>
                    </button>
                  </div>
                )}
              </div>

              {/* Active Sessions List */}
              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                      <Laptop className="w-4 h-4 text-blue-400" />
                      <span>Active Sessions & Token Families</span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Real-time session monitoring with zero IP address storage (complete IP minimization).
                    </p>
                  </div>
                  <span className="px-2 py-0.5 text-xs bg-slate-800 text-slate-300 rounded font-mono">
                    {sessions.length} Active
                  </span>
                </div>

                {sessions.length > 0 ? (
                  <div className="space-y-2">
                    {sessions.map((sess) => (
                      <div
                        key={sess.id}
                        className={`p-3.5 rounded-lg border text-xs flex items-center justify-between ${
                          sess.isCurrent
                            ? 'bg-slate-950 border-cyan-800/80 shadow-sm shadow-cyan-950/20'
                            : 'bg-slate-950/60 border-slate-800'
                        }`}
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-slate-200">{sess.userAgent || 'Web Client'}</span>
                            {sess.isCurrent && (
                              <span className="px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-400 text-[10px] border border-cyan-800 font-medium">
                                Current Session
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono space-x-3">
                            <span>Family: {sess.familyId.substring(0, 8)}...</span>
                            <span>Last Used: {new Date(sess.lastUsedAt).toLocaleTimeString()}</span>
                          </div>
                        </div>

                        <div>
                          {!sess.isCurrent && (
                            <button
                              onClick={() => handleRevokeSession(sess.id)}
                              className="p-1.5 text-slate-400 hover:text-rose-400 transition rounded hover:bg-slate-900"
                              title="Revoke session"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-8 text-center bg-slate-950 rounded-lg border border-slate-800/60 text-xs text-slate-500">
                    No active sessions found. Sign in to inspect active token families.
                  </div>
                )}
              </div>
            </div>

            {/* WireGuard VPN Phase 3 MVP */}
            <VpnManager />

            {/* Development OAuth Debug Panel */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>OAuth 2.0 / OIDC Diagnostic Matrix</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    End-to-end security probe verifying PKCE, atomic Redis consumption, RS256 token verification, and cookie issuance.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 text-xs rounded bg-slate-800 text-slate-300 font-mono">
                    Zero Secret Exposure
                  </span>
                </div>
              </div>

              {/* 10-Step Visual Flow */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                {[
                  { step: 'OAUTH_START' as const, label: '1. OAuth Start' },
                  { step: 'REDIS_STATE' as const, label: '2. Redis State' },
                  { step: 'GOOGLE_AUTH_URL' as const, label: '3. Google Auth' },
                  { step: 'CALLBACK_RECEIVED' as const, label: '4. Callback' },
                  { step: 'TOKEN_EXCHANGE' as const, label: '5. Exchange' },
                  { step: 'OIDC_VERIFY' as const, label: '6. OIDC Verify' },
                  { step: 'DB_IDENTITY' as const, label: '7. DB Identity' },
                  { step: 'SESSION_CREATE' as const, label: '8. Session Create' },
                  { step: 'COOKIES_ISSUED' as const, label: '9. Cookies' },
                  { step: 'AUTH_ME' as const, label: '10. /auth/me' },
                ].map((item) => {
                  const status = getStepStatus(item.step);
                  return (
                    <div
                      key={item.step}
                      className={`p-3 rounded-lg border text-xs space-y-1.5 ${
                        status === 'PASS'
                          ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
                          : status === 'FAIL'
                          ? 'bg-rose-950/40 border-rose-800/80 text-rose-200'
                          : 'bg-slate-950 border-slate-800 text-slate-400'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-[11px]">{item.label}</span>
                        {status === 'PASS' ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : status === 'FAIL' ? (
                          <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                        ) : (
                          <span className="w-2 h-2 rounded-full bg-slate-600" />
                        )}
                      </div>
                      <div className="font-mono text-[10px] uppercase font-bold tracking-wider">
                        {status === 'PASS' ? 'PASS' : status === 'FAIL' ? 'FAIL' : 'IDLE / PENDING'}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Live Configuration & Google Cloud Console Registration Guide */}
              {diagnostics && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    <div className="font-semibold text-slate-200 flex items-center justify-between">
                      <span>Exact Runtime Callback URL:</span>
                      <button
                        onClick={() =>
                          copyToClipboard(
                            diagnostics.oauthConfiguration.resolvedRedirectUri,
                            'redirectUri'
                          )
                        }
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                      >
                        {copiedKey === 'redirectUri' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedKey === 'redirectUri' ? 'Copied' : 'Copy URI'}</span>
                      </button>
                    </div>
                    <div className="font-mono p-2 bg-slate-900 rounded border border-slate-800 text-cyan-300 break-all">
                      {diagnostics.oauthConfiguration.resolvedRedirectUri}
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Must match the <strong>Authorized redirect URIs</strong> in Google Cloud Console Credentials.
                    </p>
                  </div>

                  <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                    <div className="font-semibold text-slate-200 flex items-center justify-between">
                      <span>Authorized JavaScript Origin:</span>
                      <button
                        onClick={() =>
                          copyToClipboard(diagnostics.oauthConfiguration.currentOrigin, 'origin')
                        }
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
                      >
                        {copiedKey === 'origin' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedKey === 'origin' ? 'Copied' : 'Copy Origin'}</span>
                      </button>
                    </div>
                    <div className="font-mono p-2 bg-slate-900 rounded border border-slate-800 text-cyan-300 break-all">
                      {diagnostics.oauthConfiguration.currentOrigin}
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Must match the <strong>Authorized JavaScript origins</strong> in Google Cloud Console.
                    </p>
                  </div>
                </div>
              )}

              {/* Diagnostic Event Log */}
              {diagnostics?.history && diagnostics.history.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>Recent Diagnostic Events (Sanitized - No Secrets):</span>
                    <span>{diagnostics.history.length} Events Captured</span>
                  </div>
                  <div className="max-h-48 overflow-y-auto space-y-1.5 p-2 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono">
                    {diagnostics.history.slice(-8).reverse().map((evt, idx) => (
                      <div
                        key={idx}
                        className={`p-2 rounded flex items-start justify-between ${
                          evt.status === 'PASS'
                            ? 'bg-emerald-950/20 text-emerald-300 border border-emerald-900/40'
                            : 'bg-rose-950/20 text-rose-300 border border-rose-900/40'
                        }`}
                      >
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-bold">{evt.step}</span>
                            {evt.category && (
                              <span className="px-1 py-0.2 rounded bg-black/40 text-[10px] text-slate-300">
                                {evt.category}
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-slate-400">{evt.details}</div>
                        </div>
                        <span className="text-[10px] text-slate-500 whitespace-nowrap ml-4">
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 1: Architecture Model */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" />
                  <span>Data Plane vs. Control Plane Separation</span>
                </h3>
                <p className="text-sm text-slate-300 leading-relaxed">
                  Privacy Gateway isolates high-throughput WireGuard UDP network routing completely from the web and API control plane. The VPN data plane does not touch the database, eliminating browsing-history storage risks at the architectural level.
                </p>
                <div className="space-y-2 pt-2 text-xs">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-slate-200">Data Plane (WireGuard Kernel Node):</span>
                      <p className="text-slate-400 mt-0.5">Linux host kernel module (`wg0`), `nftables` NAT masquerading, and internal CoreDNS recursive resolver.</p>
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-slate-200">Control Plane (API & Admin Dashboard):</span>
                      <p className="text-slate-400 mt-0.5">Express.js API, PostgreSQL metadata, Redis session storage, and RS256 token authentication.</p>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  <span>System Runtime Specifications</span>
                </h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400">Control Plane</span>
                    <div className="text-slate-200 font-semibold mt-1">{systemInfo?.architecture?.controlPlane || 'Node.js / Express'}</div>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400">Database Engine</span>
                    <div className="text-slate-200 font-semibold mt-1">{systemInfo?.architecture?.database || 'PostgreSQL 16'}</div>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400">Heap Memory</span>
                    <div className="text-slate-200 font-semibold mt-1">{healthData?.memoryUsageMb.heapUsed || 0} MB / {healthData?.memoryUsageMb.heapTotal || 0} MB</div>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400">Process Uptime</span>
                    <div className="text-slate-200 font-semibold mt-1">{healthData?.uptimeSeconds || 0} seconds</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Database Schema */}
        {activeTab === 'schema' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <div>
                <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  <span>Relational Schema (11 Core Production Tables)</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Complete PostgreSQL relational topology designed for strict tenant isolation, token replay defense, and audit logging.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {[
                  { name: 'users', role: 'Core identity records, data retention limits, and active status flags', keys: 'PK: id (UUID), UK: email' },
                  { name: 'authentication_accounts', role: 'OIDC / Google OAuth linked accounts and provider subjects', keys: 'PK: id, FK: user_id, UK: (provider, provider_subject_id)' },
                  { name: 'user_sessions', role: 'CSPRNG refresh token hashes and token family IDs', keys: 'PK: id, FK: user_id, UK: refresh_token_hash, IDX: family_id' },
                  { name: 'session_token_history', role: 'Audit trail of rotated refresh token hashes to detect replay theft', keys: 'PK: id, FK: session_id, IDX: token_hash' },
                  { name: 'devices', role: 'Hardware devices, OS platforms, and client application versions', keys: 'PK: id, FK: user_id' },
                  { name: 'vpn_servers', role: 'WireGuard infrastructure nodes, CIDR pools, and health state', keys: 'PK: id, UK: public_endpoint' },
                  { name: 'wireguard_peers', role: 'Curve25519 public keys and allocated IPv4/IPv6 addresses', keys: 'PK: id, FK: user_id, FK: vpn_server_id, UK: public_key' },
                  { name: 'subscriptions', role: 'Plan tiers (Free/Premium/Business), limits, and billing status', keys: 'PK: id, FK: user_id' },
                  { name: 'privacy_scans', role: 'Deterministic 4-pillar privacy scores & diagnostic snapshots', keys: 'PK: id, FK: user_id' },
                  { name: 'privacy_events', role: 'Configurable retention stream for tracker & diagnostic alerts', keys: 'PK: id, FK: user_id' },
                  { name: 'audit_logs', role: 'Immutable security event log with actor and target records', keys: 'PK: id, FK: actor_user_id' },
                ].map((tbl) => (
                  <div key={tbl.name} className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-cyan-400">{tbl.name}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{tbl.keys}</span>
                    </div>
                    <p className="text-slate-400 leading-relaxed">{tbl.role}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Security & Token Lifecycle */}
        {activeTab === 'security' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Cryptographic & Token Family Specifications</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <span className="font-semibold text-slate-200">1. Asymmetric RS256 JWTs</span>
                  <p className="text-slate-400 leading-relaxed">
                    15-minute access tokens signed with RSA-2048 keys. Verified statelessly by all downstream gateway proxies without database lookups.
                  </p>
                </div>
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <span className="font-semibold text-slate-200">2. Token Family & Replay Detection</span>
                  <p className="text-slate-400 leading-relaxed">
                    Refresh tokens are single-use CSPRNG secrets hashed with SHA-256. If an already-rotated token is submitted, the entire token family is revoked instantly.
                  </p>
                </div>
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                  <span className="font-semibold text-slate-200">3. Double-Submit Cookie CSRF</span>
                  <p className="text-slate-400 leading-relaxed">
                    All state-mutating endpoints (`/refresh`, `/logout`, `/sessions/:id`) enforce constant-time `crypto.timingSafeEqual` comparison on `X-CSRF-Token`.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: API Health & Prober */}
        {activeTab === 'prober' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <h3 className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                <span>Interactive API Prober</span>
              </h3>
              <div className="flex flex-wrap gap-2">
                {[
                  '/health',
                  '/health/live',
                  '/health/ready',
                  '/api/v1/system/info',
                  '/api/v1/auth/diagnostics',
                  '/api/v1/auth/me',
                  '/api/v1/admin/users',
                ].map((ep) => (
                  <button
                    key={ep}
                    onClick={() => runProbe(ep)}
                    disabled={probing}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 active:bg-slate-900 text-xs text-slate-200 rounded border border-slate-700 font-mono transition"
                  >
                    GET {ep}
                  </button>
                ))}
              </div>

              {probeResult && (
                <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2 font-mono text-xs">
                  <div className="flex items-center justify-between text-slate-400 border-b border-slate-800 pb-2">
                    <span className="text-cyan-400">{probeResult.endpoint}</span>
                    <div className="flex items-center gap-3">
                      <span>Latency: {probeResult.latencyMs}ms</span>
                      <span
                        className={`px-2 py-0.5 rounded font-bold ${
                          probeResult.status < 400
                            ? 'bg-emerald-950 text-emerald-400'
                            : 'bg-rose-950 text-rose-400'
                        }`}
                      >
                        HTTP {probeResult.status}
                      </span>
                    </div>
                  </div>
                  <pre className="overflow-x-auto text-slate-300 max-h-64">
                    {JSON.stringify(probeResult.data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
