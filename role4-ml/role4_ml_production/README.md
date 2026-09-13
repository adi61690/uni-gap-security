# Role 4 ML — Production-Ready Frontend Integration Package

**Role:** ML Engineer — Encrypted Traffic & Sequence/NLP Analysis
**Version:** 2.0.0-demo

This package extends the supplied Role 4 foundation into a complete integration layer for Uni-Gap Security. It is designed for **passive, read-only, one-way network observation**. It does not probe, establish return connections, perform inline mitigation, or decrypt payload contents.

## What is included

- DGA / DNS tunneling feature extraction
- Shannon entropy, query length, lexical ratios, numeric runs, n-gram summary features
- DNS record type and query-rate evidence
- Encrypted-session packet-size and timing features
- IAT coefficient of variation
- FFT / dominant frequency
- Autocorrelation and periodicity score
- JA3 / JA4 / TLS / QUIC metadata support
- Packet-size and timing evidence summaries
- CatBoost baseline models for DNS and encrypted-session detection
- PyTorch LSTM sequence model for encrypted traffic sequences
- Evidence and baseline-aware explanation layer
- Standardized Uni-Gap Security Alert schema
- FastAPI REST API
- WebSocket `/ws/alerts` integration
- `/ingest` event endpoint that broadcasts alerts to connected frontend clients
- Demo stream for testing the frontend without production traffic
- Synthetic training dataset generator
- Model manifest and metadata
- Unit tests
- Example DNS and encrypted-session events

## Important model note

The supplied source package did not contain a validated production-trained LSTM model or production dataset. This package therefore includes a **synthetic-data training pipeline and demonstration model artifacts**. These artifacts prove the software path works; they must not be presented as production validation or real-world accuracy. Replace the generated training data with your validated labeled telemetry/PCAP-derived dataset before making performance claims.

## 1. Windows setup in VS Code

Install Python 3.11 or newer.

Open the project folder in VS Code and run:

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 2. Train all demonstration models

```powershell
python scripts\train_all.py
```

This creates:

```text
models/
  dns_catboost.cbm
  dns_catboost_metadata.json
  encrypted_catboost.cbm
  encrypted_catboost_metadata.json
  role4_sequence_lstm.pt
  model_manifest.json
```

It also writes demonstration datasets under `data/`.

## 3. Start the ML API

```powershell
python -m uvicorn role4_ml.api:app --host 0.0.0.0 --port 8000
```

Or on Windows:

```powershell
run_api.bat
```

API:

```text
http://localhost:8000
```

Swagger:

```text
http://localhost:8000/docs
```

Health:

```text
GET http://localhost:8000/health
```

## 4. Connect the Uni-Gap frontend

Set the frontend environment variable:

```env
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws/alerts
NEXT_PUBLIC_API_URL=http://localhost:8000
```

The frontend can consume the WebSocket alert objects directly because the output is shaped around the standardized Uni-Gap alert contract.

## 5. WebSocket behavior

Connect:

```text
ws://localhost:8000/ws/alerts
```

The server first sends:

```json
{"type":"connected","service":"role4_ml","model_version":"role4-2.0.0-demo","demo_stream":true}
```

Send a DNS observation:

```json
{
  "type":"dns",
  "source_ip":"10.24.3.17",
  "destination_ip":"8.8.8.8",
  "destination_port":53,
  "protocol":"DNS",
  "domain":"x8f92kdl39qmx7z1p4k2.example.com",
  "dns_record_type":"A",
  "dns_query_rate":46.2
}
```

Send an encrypted session:

```json
{
  "type":"encrypted_session",
  "source_ip":"10.24.3.17",
  "destination_ip":"172.16.4.8",
  "destination_port":443,
  "protocol":"TCP",
  "ja3":"example-ja3",
  "ja4":"example-ja4",
  "tls_version":"TLS1.3",
  "packet_sizes":[120,130,125,900,850,870,110,105,900,850,870,110],
  "timestamps":[0,0.5,1,1.5,2,2.5,3,3.5,4,4.5,5,5.5]
}
```

## 6. REST prediction

```text
POST /predict
POST /ingest
```

Both accept the same observation contract.

`/ingest` is intended as the integration point for the upstream ingestion/feature-engine layer. When an alert is produced, it is broadcast to connected WebSocket clients.

## 7. Frontend Alert schema

A generated alert contains:

```json
{
  "timestamp":"...",
  "flow_id":"FLOW-XXXXXX",
  "threat_class":"DGA / DNS Tunneling",
  "threat_subtype":"DGA",
  "severity":"High",
  "confidence":0.947,
  "source_ip":"10.24.3.17",
  "destination_ip":"8.8.8.8",
  "destination_port":53,
  "protocol":"DNS",
  "evidence":{},
  "model":{},
  "evidence_summary":"...",
  "security_context":{
    "read_only_observation":true,
    "one_way_ingest":true,
    "no_active_probing":true,
    "no_return_path":true,
    "no_inline_mitigation":true,
    "payload_decrypted":false,
    "metadata_only":true
  }
}
```

## 8. What the frontend can display from Role 4

### DGA / DNS tunneling

- Shannon entropy
- query length
- n-gram anomaly score
- query rate
- DNS record type
- lexical anomaly score
- plain-English evidence explanation

### Encrypted malware / beaconing

- JA3 / JA4
- TLS version
- QUIC flag/metadata
- packet-size statistics
- timing statistics
- IAT CV
- dominant FFT frequency
- FFT magnitude
- autocorrelation peak
- periodicity score
- sequence-model confidence
- evidence explanation

The language is intentionally cautious: metadata indicates anomalous behavior relative to a learned baseline; it does not claim that a single feature proves malware.

## 9. Production integration architecture

```text
Observed traffic
      |
      v
Hardware Data Diode
      |
      v
Ingestion / Flow reconstruction
      |
      v
Feature Engine
      |
      v
Role 4 ML API (/ingest)
      |
      +--> DNS/DGA CatBoost
      +--> Encrypted-session CatBoost
      +--> Sequence LSTM
      +--> Evidence / baseline layer
      |
      v
Standardized Alert
      |
      v
WebSocket /ws/alerts
      |
      v
Uni-Gap Security Frontend
```

## 10. Passive-security constraints

This package never:

- sends probes
- performs active reconnaissance
- establishes return connections to observed destinations
- blocks or terminates traffic
- performs inline mitigation
- decrypts payload content

TLS and QUIC are treated as metadata/sequence observations only.

## 11. Tests

Install requirements, then run:

```powershell
pytest -q
```

## 12. Replace demo models with real validated training

1. Replace the generated `data/*_training_demo.csv` with a validated, labeled dataset.
2. Keep the feature-generation functions so training/inference stay aligned.
3. Run `python scripts/train_all.py` after adapting the dataset builder to your real fields.
4. Review precision, recall, F1, PR-AUC, calibration, false positives/hour and detection latency separately for DNS and encrypted traffic.
5. Version the resulting model files and manifest.

## 13. Troubleshooting

### `ModuleNotFoundError: role4_ml`

Run commands from the project root. The examples already use the package under `src/` when launched through the documented commands.

### API starts but reports models not loaded

Run:

```powershell
python scripts\train_all.py
```

then restart the API.

### Frontend shows disconnected

Verify:

```text
ws://localhost:8000/ws/alerts
```

and that port 8000 is not blocked by another application.

### Demo stream

The server emits demonstration alerts periodically only while at least one WebSocket client is connected. This is explicitly demo data and is not real network traffic.
