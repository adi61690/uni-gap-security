import { Alert } from '@/types';

const API_URL = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws/alerts';

function token() {
  if (typeof window === 'undefined') return '';
  return localStorage.getItem('uni_gap_access_token') || '';
}

async function request(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  const t = token();
  if (t) headers.set('Authorization', `Bearer ${t}`);
  const response = await fetch(`${API_URL}${path}`, { ...init, headers });
  if (!response.ok) throw new Error(await response.text().catch(() => 'Request failed'));
  return response.json();
}

export const AuthService = {
  async login(username: string, password: string, remember = true) {
    try {
      const data = await request('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password, remember }),
      });
      if (typeof window !== 'undefined') {
        const storage = remember ? localStorage : sessionStorage;
        storage.setItem('uni_gap_access_token', data.access_token);
        storage.setItem('uni_gap_user', JSON.stringify(data.user));
      }
      return {
        name: data.user.display_name,
        role: data.user.role,
        session: data.session_id,
        token: data.access_token,
        source: 'backend' as const,
      };
    } catch {
      // Local-development authentication fallback only; no telemetry is generated here.
      if (username === 'analyst' && password === 'analyst123') {
        const result = { name: 'Analyst', role: 'Security Analyst', session: `SES-DEMO-${Date.now()}`, source: 'demo' as const };
        if (typeof window !== 'undefined') localStorage.setItem('uni_gap_user', JSON.stringify(result));
        return result;
      }
      return null;
    }
  },
  async restore() {
    if (typeof window === 'undefined') return null;
    const cached = localStorage.getItem('uni_gap_user') || sessionStorage.getItem('uni_gap_user');
    if (!cached) return null;
    try {
      const user = await request('/api/v1/auth/me');
      return { name: user.display_name, role: user.role, session: cached ? JSON.parse(cached).session : '', source: 'backend' as const };
    } catch {
      try {
        return { ...JSON.parse(cached), source: 'demo' as const };
      } catch {
        return null;
      }
    }
  },
  async logout() {
    try { await request('/api/v1/auth/logout', { method: 'POST' }); } catch { /* backend may be offline */ }
    if (typeof window !== 'undefined') {
      localStorage.removeItem('uni_gap_access_token');
      localStorage.removeItem('uni_gap_user');
      sessionStorage.removeItem('uni_gap_access_token');
      sessionStorage.removeItem('uni_gap_user');
    }
  },
};

export class WebSocketService {
  ws: WebSocket | null = null;
  retryTimer: ReturnType<typeof setTimeout> | null = null;
  retries = 0;
  manualClose = false;

  connect(url: string = WS_URL, onMessage: (a: Alert) => void, onState: (s: string) => void) {
    this.manualClose = false;
    const open = () => {
      try {
        this.ws = new WebSocket(url);
        this.ws.onopen = () => { this.retries = 0; onState('LIVE'); };
        this.ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            const alert = payload?.alert || (payload?.type === 'alert' || payload?.threat_class ? payload : null);
            if (alert?.threat_class) onMessage(alert as Alert);
          } catch { /* ignore malformed event */ }
        };
        this.ws.onerror = () => onState('DISCONNECTED');
        this.ws.onclose = () => {
          onState('DISCONNECTED');
          if (!this.manualClose) this.reconnect(url, onMessage, onState);
        };
      } catch {
        onState('DISCONNECTED');
        this.reconnect(url, onMessage, onState);
      }
    };
    open();
  }

  private reconnect(url: string, onMessage: (a: Alert) => void, onState: (s: string) => void) {
    if (this.manualClose || this.retryTimer) return;
    this.retries += 1;
    if (this.retries > 8) return;
    onState('RECONNECTING');
    const delay = Math.min(1000 * 2 ** (this.retries - 1), 30000);
    this.retryTimer = setTimeout(() => { this.retryTimer = null; this.connect(url, onMessage, onState); }, delay);
  }

  close() {
    this.manualClose = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.ws?.close();
    this.ws = null;
  }
}

export const ApiService = {
  async testConnection() {
    const data = await request('/api/v1/health');
    return data.status === 'ok';
  },
  async testML() {
    const data = await request('/api/v1/health');
    return data.ml;
  },
  async ingestFlow(flow: Record<string, unknown>) {
    return request('/api/v1/ingest/flow', { method: 'POST', body: JSON.stringify(flow) });
  },
};

export function downloadText(name: string, text: string, type = 'text/plain') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function csv(rows: any[]) {
  if (!rows.length) return '';
  const keys = Object.keys(rows[0]);
  return [keys.join(','), ...rows.map(r => keys.map(k => JSON.stringify(r[k] ?? '')).join(','))].join('\n');
}
