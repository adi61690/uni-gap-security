from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from urllib import request, parse

ROOT = Path(__file__).resolve().parents[1]


def http_json(url: str, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(url, data=data, headers=headers or {}, method='POST' if payload is not None else 'GET')
    with request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def flatten_feature(f: dict) -> dict:
    row = dict(f)
    row['packet_sizes'] = json.dumps(f.get('packet_sizes', []), separators=(',', ':'))
    row['inter_arrival_times'] = json.dumps(f.get('inter_arrival_times', []), separators=(',', ':'))
    row['tls_metadata'] = json.dumps(f.get('tls_metadata', {}), separators=(',', ':'))
    row['quic_metadata'] = json.dumps(f.get('quic_metadata', {}), separators=(',', ':'))
    row['passive_guardrails'] = json.dumps(f.get('passive_guardrails', {}), separators=(',', ':'))
    return row


def main():
    ap = argparse.ArgumentParser(description='Role 1 PCAP -> Role 2 -> Backend -> Role 3/4 -> alerts')
    ap.add_argument('--pcap', required=True)
    ap.add_argument('--role2', default='http://localhost:8100')
    ap.add_argument('--backend', default='http://localhost:8000')
    ap.add_argument('--username', default='analyst')
    ap.add_argument('--password', default='analyst123')
    args = ap.parse_args()

    pcap = Path(args.pcap).resolve()
    if not pcap.exists():
        raise SystemExit(f'PCAP not found: {pcap}')

    print(f'[1/4] Role 2 parsing {pcap}')
    result = http_json(args.role2.rstrip('/') + '/ingest/pcap', {'path': str(pcap)})
    features = result.get('features', [])
    print(f'      extracted flows: {len(features)}')

    processed = ROOT / 'data' / 'processed'
    processed.mkdir(parents=True, exist_ok=True)
    jsonl = processed / 'flow_features.jsonl'
    csv_path = processed / 'flow_features.csv'
    with jsonl.open('w', encoding='utf-8') as fh:
        for feature in features:
            fh.write(json.dumps(feature, separators=(',', ':')) + '\n')

    rows = [flatten_feature(f) for f in features]
    if rows:
        keys = list(rows[0].keys())
        with csv_path.open('w', newline='', encoding='utf-8') as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader(); w.writerows(rows)
    print(f'      saved {jsonl}')
    print(f'      saved {csv_path}')

    print('[2/4] Backend authentication')
    login = http_json(args.backend.rstrip('/') + '/api/v1/auth/login', {'username': args.username, 'password': args.password, 'remember': True})
    token = login['access_token']
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    detections = 0
    print('[3/4] Sending Role 2 flows to backend orchestration')
    for index, feature in enumerate(features, start=1):
        out = http_json(args.backend.rstrip('/') + '/api/v1/ingest/flow', feature, headers)
        if out.get('is_alert'):
            detections += 1
        if index <= 5 or index == len(features):
            print(f'      flow {index}/{len(features)} -> alert={out.get("is_alert", False)}')
    print(f'[4/4] Detections returned: {detections}')
    print('Open http://localhost:3000 to see alerts in the frontend WebSocket stream.')


if __name__ == '__main__':
    main()
