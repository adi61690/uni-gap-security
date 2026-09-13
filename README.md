# Uni-Gap Security — SIH 26145

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**


## Roles

1. `role1-network-traffic-simulation` — controlled lab traffic scenarios + dataset generation.
2. `role2-ingestion-feature-extraction/role2_ingestion` — passive flow normalization and one-way feature extraction.
3. `role3-flow-ml/role3_flow_ml` — DDoS, C2, recon and exfiltration models.
4. `role4-ml/role4_ml_production` — DGA/DNS/sequence/encrypted metadata models.
5. `backend/uni-gap-security-backend-only` — auth, storage, REST API, WebSocket, reports and audit.
6. `frontend/uni-gap-security` — 14-page analyst dashboard.

## Dataset included

`data/processed/lab_generated_unidirectional_flows.csv` is a reproducible **lab-generated synthetic flow dataset** created from the exact seven scenario families requested for the project: BENIGN, SYN_FLOOD, UDP_FLOOD, SLOW_HTTP, DNS_TUNNEL, DGA and C2_BEACON. It is provided so the full repository can be tested immediately. It is not a public benchmark and must not be described as production traffic.

For the final SIH lab, the same schema is consumed by Role 2 from actual authorized PCAP captures. Raw PCAPs are not committed.

## Run the full local stack

### 1. Generate/rebuild the dataset

```powershell
python scripts\build_lab_dataset.py
```

### 2. Train Role 3

```powershell
cd role3-flow-ml\role3_flow_ml
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\train_all.py ..\..\data\processed\lab_generated_unidirectional_flows.csv
python scripts\run_api.py
```

### 3. Train Role 4

In another terminal:

```powershell
cd role4-ml\role4_ml_production
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\train_all.py ..\..\data\processed\lab_generated_unidirectional_flows.csv
python -m uvicorn role4_ml.api:app --host 0.0.0.0 --port 8001
```

### 4. Start backend

```powershell
cd backend\uni-gap-security-backend-only
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 5. Start frontend

```powershell
cd frontend\uni-gap-security
npm install
copy .env.example .env.local
npm run dev
```

Open `http://localhost:3000`.

Demo/dev credentials are only for local authentication: `analyst` / `analyst123`. No database credential is stored in the browser.

## GitHub

GitHub stores source code and runs validation. The live dashboard is not a GitHub Pages app because it depends on the backend API and WebSocket. Use a VM, container host, or local machine for the runtime. Every push runs `.github/workflows/validate.yml`.

## References

See `docs/REFERENCES.md`. The project uses the official documentation/repositories for iperf3, Ostinato, TRex, hping3, Slowloris, dnscat2, iodine, Wireshark, Zeek and Scapy.

## Verify before pushing to GitHub

```powershell
python scripts\verify_repository.py
python scripts\build_lab_dataset.py
cd backend\uni-gap-security-backend-only
pytest -q
```

For the frontend CI gate, GitHub Actions runs `npm install` followed by `npm run build` using Node 22. The workflow deliberately does not use dependency caching, avoiding the missing-lockfile cache-path failure that can occur when a repository is uploaded without a generated `package-lock.json`.
