export type LabFlowRow = Record<string, string | number | undefined>;

const severityRank: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const threatClassMap: Record<string, string> = {
  BENIGN: 'Benign',
  SYN_FLOOD: 'DDoS',
  UDP_FLOOD: 'DDoS',
  SLOW_HTTP: 'Data Exfiltration',
  DNS_TUNNEL: 'DGA / DNS Tunneling',
  DGA: 'DGA / DNS Tunneling',
  C2_BEACON: 'Botnet C2',
};

const toNumber = (value: string | number | undefined): number | undefined => {
  if (value === undefined || value === null || value === '') return undefined;
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

const threatClass = (label: string): any => threatClassMap[label] || 'Recon / Port Scan';

export const normalizeSeverity = (value?: string): any => {
  const level = (value || 'Low').toString();
  return severityRank[level] ? level : 'Low';
};

export function interleaveRows(rows: LabFlowRow[], windowSize = 220): LabFlowRow[] {
  const selected = rows.slice(0, Math.min(rows.length, windowSize));
  if (selected.length <= 1) return selected;

  const groups = new Map<string, LabFlowRow[]>();
  selected.forEach((row) => {
    const key = String(row.attack_type || row.label || 'BENIGN');
    const group = groups.get(key) || [];
    group.push(row);
    groups.set(key, group);
  });

  const ordered = [...groups.entries()].sort(([left], [right]) => left.localeCompare(right));
  const queue: LabFlowRow[] = [];
  const iterators = ordered.map(([, items]) => items[Symbol.iterator]());
  let active = true;

  while (active) {
    active = false;
    for (const iterator of iterators) {
      const next = iterator.next();
      if (!next.done) {
        queue.push(next.value);
        active = true;
      }
    }
    if (queue.length >= selected.length) break;
  }

  return queue.slice(0, selected.length);
}

export function buildLabReplayWindow(rows: LabFlowRow[], cursor = 0, windowSize = 220): LabFlowRow[] {
  if (!rows.length) return [];
  const safeCursor = ((cursor % rows.length) + rows.length) % rows.length;
  const end = Math.min(rows.length, safeCursor + windowSize);
  const segment = rows.slice(safeCursor, end);
  if (segment.length >= windowSize) return interleaveRows(segment, windowSize);

  const remainder = rows.slice(0, windowSize - segment.length);
  return interleaveRows([...segment, ...remainder], windowSize);
}

export function buildAlertsFromRows(rows: LabFlowRow[]) {
  return rows.map((row) => {
    const label = String(row.label || 'BENIGN');
    const confidence = toNumber(row.ground_truth_confidence) ?? 0;
    const severity = normalizeSeverity(String(row.severity || 'Low')) as any;
    const evidence = {
      entropy: toNumber(row.source_ip_entropy),
      packet_rate: toNumber(row.packet_rate),
      flow_rate: toNumber(row.byte_rate),
      iat_cv: toNumber(row.iat_std),
      dominant_frequency_hz: toNumber(row.dominant_frequency_hz),
      dns_entropy: toNumber(row.dns_entropy),
      ja3: row.ja3 ? String(row.ja3) : undefined,
      ja4: row.ja4 ? String(row.ja4) : undefined,
      tls_metadata: row.tls_version ? String(row.tls_version) : undefined,
      quic_metadata: row.quic_version ? String(row.quic_version) : undefined,
      unique_destination_hosts: toNumber(row.unique_destination_hosts),
      unique_destination_ports: toNumber(row.unique_destination_ports),
      outbound_bytes: toNumber(row.outbound_bytes),
      inbound_bytes: toNumber(row.inbound_bytes),
      outbound_inbound_ratio: toNumber(row.outbound_inbound_ratio),
      packet_size_statistics: row.packet_size_mean ? `${row.packet_size_mean}` : undefined,
      fanout: toNumber(row.fanout),
      scan_rate: toNumber(row.scan_rate),
      periodicity_score: toNumber(row.periodicity_score),
      destination_count: toNumber(row.unique_destination_hosts),
      beacon_interval: toNumber(row.inter_arrival_time),
    };

    return {
      timestamp: String(row.timestamp || new Date().toISOString()),
      flow_id: String(row.flow_id || `FLOW-${Math.random().toString(16).slice(2, 10)}`),
      threat_class: threatClass(label) as any,
      threat_subtype: String(row.attack_type || label),
      severity,
      confidence,
      source_ip: String(row.src_ip || '0.0.0.0'),
      destination_ip: String(row.dst_ip || '0.0.0.0'),
      destination_port: toNumber(row.dst_port) ?? 0,
      protocol: String(row.protocol || 'TCP'),
      evidence,
    };
  });
}

export function buildTelemetryFromRows(rows: LabFlowRow[]) {
  return rows.map((row) => ({
    time: String(row.timestamp || new Date().toISOString()),
    mbps: ((toNumber(row.byte_rate) ?? 0) / 1_000_000) * 8,
    pps: toNumber(row.packet_rate) ?? 0,
    fps: toNumber(row.flow_duration) ? 1 / (toNumber(row.flow_duration) as number) : 0,
    packetSize: toNumber(row.packet_size_mean) ?? 0,
    duration: toNumber(row.flow_duration) ?? 0,
  }));
}
