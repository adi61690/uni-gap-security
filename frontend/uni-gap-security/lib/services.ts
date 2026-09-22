import { Alert, Severity, Telemetry, ThreatClass } from '@/types';

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

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let value = '';
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') {
      if (quoted && line[index + 1] === '"') { value += '"'; index += 1; } else quoted = !quoted;
    } else if (character === ',' && !quoted) { values.push(value); value = ''; } else value += character;
  }
  values.push(value);
  return values;
}

const numberValue = (value: string | undefined): number | undefined => {
  if (!value) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

const threatClassMap: Record<string, ThreatClass> = {
  BENIGN: 'Benign', SYN_FLOOD: 'DDoS', UDP_FLOOD: 'DDoS', SLOW_HTTP: 'Data Exfiltration',
  DNS_TUNNEL: 'DGA / DNS Tunneling', DGA: 'DGA / DNS Tunneling', C2_BEACON: 'Botnet C2',
};
const threatClass = (label: string): ThreatClass => threatClassMap[label] || 'Recon / Port Scan';

export async function loadLabFlowRows(basePath = ''): Promise<Record<string, string | number | undefined>[]> {
  const response = await fetch(`${basePath}/data/lab_generated_unidirectional_flows.csv`);
  if (!response.ok) throw new Error(`Lab dataset request failed: ${response.status}`);
  const lines = (await response.text()).trim().split(/\r?\n/);
  const headers = parseCsvLine(lines.shift() || '');
  return lines.filter(Boolean).map((line) => {
    const values = parseCsvLine(line);
    return Object.fromEntries(headers.map((header, index) => [header, values[index] ?? '']));
  });
}

export async function loadLabDataset(basePath = ''): Promise<{ alerts: Alert[]; telemetry: Telemetry[] }> {
  const rows = await loadLabFlowRows(basePath);
  const alerts: Alert[] = rows.map((row) => {
    const label = String(row.label || 'BENIGN');
    const confidence = numberValue(String(row.ground_truth_confidence ?? '')) ?? 0;
    const severity = (['Critical', 'High', 'Medium', 'Low'].includes(String(row.severity || 'Low')) ? String(row.severity || 'Low') : 'Low') as Severity;
    const evidence = {
      entropy: numberValue(String(row.source_ip_entropy ?? '')), packet_rate: numberValue(String(row.packet_rate ?? '')), flow_rate: numberValue(String(row.byte_rate ?? '')),
      iat_cv: numberValue(String(row.iat_std ?? '')), dominant_frequency_hz: numberValue(String(row.dominant_frequency_hz ?? '')), dns_entropy: numberValue(String(row.dns_entropy ?? '')),
      ja3: row.ja3 ? String(row.ja3) : undefined, ja4: row.ja4 ? String(row.ja4) : undefined, tls_metadata: row.tls_version ? String(row.tls_version) : undefined, quic_metadata: row.quic_version ? String(row.quic_version) : undefined,
      unique_destination_hosts: numberValue(String(row.unique_destination_hosts ?? '')), unique_destination_ports: numberValue(String(row.unique_destination_ports ?? '')),
      outbound_bytes: numberValue(String(row.outbound_bytes ?? '')), inbound_bytes: numberValue(String(row.inbound_bytes ?? '')), outbound_inbound_ratio: numberValue(String(row.outbound_inbound_ratio ?? '')),
    };
    return { timestamp: String(row.timestamp || ''), flow_id: String(row.flow_id || ''), threat_class: threatClass(label), threat_subtype: String(row.attack_type || label), severity, confidence, source_ip: String(row.src_ip || ''), destination_ip: String(row.dst_ip || ''), destination_port: numberValue(String(row.dst_port ?? '')) ?? 0, protocol: String(row.protocol || 'TCP'), evidence };
  });
  const telemetry: Telemetry[] = rows.map((row) => ({ time: String(row.timestamp || ''), mbps: (numberValue(String(row.byte_rate ?? '')) ?? 0) / 1000000 * 8, pps: numberValue(String(row.packet_rate ?? '')) ?? 0, fps: numberValue(String(row.flow_duration ?? '')) ? 1 / (numberValue(String(row.flow_duration ?? '')) as number) : 0, packetSize: numberValue(String(row.packet_size_mean ?? '')) ?? 0, duration: numberValue(String(row.flow_duration ?? '')) ?? 0 }));
  return { alerts, telemetry };
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
