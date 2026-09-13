# Uni-Gap Security — Role 3 ML: Flow & Statistical Anomaly Detection

Role 3 is a **standalone ML service** for threats A, B, E and F: volumetric DDoS, behavioral/C2 beaconing, reconnaissance/port scanning, and data-exfiltration anomalies.

It consumes normalized **Role 2 `role2.v2` metadata only** and emits alerts compatible with the Uni-Gap backend/frontend. It does not contain the frontend, backend, Role 2, or Role 4 source.

## Detection coverage

- **DDoS / volumetric:** packet/byte rate, source/destination entropy, concentration/fan-out, amplification-like ratios, Isolation Forest anomaly scoring.
- **Botnet C2:** inter-arrival timing, IAT CV, FFT, autocorrelation, periodicity score, burstiness, learned classifier.
- **Recon / port scan:** unique destination hosts, fan-out, scan rate, destination entropy, learned anomaly/classifier.
- **Data exfiltration:** outbound/inbound bytes, ratio, volume asymmetry, sudden high outbound flow indicators.

## ML stack

- XGBoost when available, with a scikit-learn fallback for environments without XGBoost.
- Isolation Forest for unsupervised anomaly scoring.
- NumPy/Pandas-ready feature pipeline.
- PyTorch LSTM sequence model for C2 beacon scoring is included and trained when PyTorch is installed; FFT/autocorrelation remain as explainable fallback features. Role 4 remains responsible for encrypted/DNS sequence analysis.

## Setup

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH='src'
python scripts\train_all.py
python scripts\run_api.py
```

API: `http://localhost:8002/docs`

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src
python scripts/train_all.py
python scripts/run_api.py
```

### Docker

```bash
docker compose up --build
```

## Integration with Role 2

Set Role 2's optional downstream service URL to:

```text
http://localhost:8002/predict
```

Or post normalized flows directly:

```bash
curl -X POST http://localhost:8002/predict -H "Content-Type: application/json" --data @examples/sample_role2_flow.json
```

## Integration with backend

The backend should consume Role 3 alerts from `ws://localhost:8002/ws/detections` or call `/predict`/`/ingest` and then publish the standardized alert to the frontend's WebSocket.

## Model training

`python scripts/train_all.py` creates demonstration models under `models/`. These are **synthetic demo models**, not production validation. Replace the generated training data with labelled lab data from Role 1 -> Role 2 before reporting real-world accuracy.

## Outputs

Every alert contains threat class/subtype, severity, confidence, flow identifiers, source/destination metadata, evidence, model metadata, and read-only security context. No application payload is required.

## Tests

```bash
PYTHONPATH=src pytest -q
```


Use the repository-level scripts from the project root:

```powershell
```

