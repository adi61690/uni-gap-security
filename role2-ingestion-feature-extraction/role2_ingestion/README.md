# Role 2 — Ingestion & Feature Extraction Engineer

This is the **standalone Role 2 package** for Uni-Gap Security. It sits between the one-way capture/telemetry source and the separate Role 4 ML service.

## What this package does
- Passive PCAP/PCAPNG ingestion with Scapy
- Zeek JSON ingestion and fingerprint pass-through
- Normalized flow-record ingestion for NetFlow/IPFIX/sFlow collectors
- NetFlow v5 UDP decoding foundation
- Flow aggregation with forward/reverse directionality
- Source/destination IP entropy
- Byte/packet ratio
- Duration, packet rate, byte rate
- Directional symmetry
- Packet-size sequences
- Inter-arrival-time sequences and burstiness
- TLS ClientHello / ServerHello metadata inspection
- JA3 and JA3S derivation where the handshake is available
- JA4 pass-through from Zeek and other passive analyzers
- Metadata-only QUIC summary
- JSONL export
- Optional HTTP handoff to separate Role 4 ML
- FastAPI control API

## Strict passive boundary
Role 2 does **not**:
- send probes
- establish network sessions
- decrypt TLS or QUIC
- persist application payloads
- forward application payloads
- block, terminate, or mitigate traffic
- create a return path

For PCAP parsing, bounded handshake bytes may be inspected transiently to derive TLS handshake metadata. Those bytes are not stored or emitted.

## Architecture
```text
Read-only Traffic / PCAP / Zeek / Flow Exporter
                  |
                  v
              ROLE 2
      Ingestion + Flow Aggregation
                  |
          Metadata / Features only
                  |
                  v
              ROLE 4 ML
                  |
                  v
              BACKEND
                  |
                  v
              FRONTEND
```

## Install — Windows PowerShell
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH='.'
copy .env.example .env
```

## Run API
```powershell
python scripts\run_api.py
```
Open `http://localhost:8100/docs`.

## Test
```powershell
$env:PYTHONPATH='.'
pytest -q
```

## PCAP
```powershell
curl -X POST http://localhost:8100/ingest/pcap `
  -H "Content-Type: application/json" `
  -d '{"path":"C:/captures/sample.pcapng"}'
```

## Connect to Role 4
Set in `.env`:
```env
ROLE4_SERVICE_URL=http://localhost:8001
```
Then call:
```text
POST /role4/predict
```
with a `FlowFeatures` JSON object. Role 2 removes accidental payload-like keys before forwarding.

## NetFlow/IPFIX/sFlow
For production exporters, prefer a validated collector/decoder that understands version/template state and forward normalized records to `POST /ingest/flow-record` or directly into `IngestionEngine.ingest_flow_record()`.

Example normalized record:
```json
{
  "timestamp": 1789111200,
  "src_ip": "10.24.3.17",
  "dst_ip": "172.16.4.8",
  "src_port": 51542,
  "dst_port": 443,
  "protocol": "TCP",
  "bytes": 5480,
  "packets": 12
}
```

## Zeek
Generate `conn.log`, `ssl.log`, and `quic.log` in JSON mode, merge or normalize them upstream if necessary, and feed the resulting records to `/ingest/zeek`. Zeek-provided `ja3`, `ja3s`, and `ja4` values are preserved as metadata.

## Role 4 alignment
The output is designed for the separate `role4_ml_final` package. Role 4 can consume:
- `packet_sizes`
- `inter_arrival_times`
- `burstiness`
- `source_ip_entropy`
- `destination_ip_entropy`
- `byte_packet_ratio`
- `directional_symmetry`
- `tls_metadata`
- `quic_metadata`
- flow timing/volume fields

The frontend receives alerts from the backend, not directly from Role 2.
