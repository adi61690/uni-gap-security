# Uni-Gap Security — Backend Only

A standalone FastAPI backend for the Uni-Gap Security frontend. **Role 4 ML is NOT embedded in this package.** The backend calls the separate Role 4 ML service over HTTP and exposes the normalized results to the frontend via REST and WebSocket.

## Responsibilities

- authentication and JWT sessions
- user/session audit records
- alert persistence, filtering and statistics
- REST APIs used by the Next.js frontend
- WebSocket live alert fan-out
- external Role 4 ML service adapter
- PCAP/PCAPNG upload and safe demo replay
- incidents and analyst notes
- threat-hunt search
- analytics and network summaries
- report generation and JSON/CSV/XLSX export
- settings persistence and connection tests
- passive one-way security status

The backend never sends commands to the observed production network. It does not probe, block, terminate, mitigate, decrypt payloads, or create a return path.

## 1. Final three-package architecture

```text
[1] FRONTEND
Next.js / React / TypeScript
        |
        | REST + WebSocket
        v
[2] BACKEND  :8000
FastAPI / DB / Auth / Alerts / Reports / Audit
        |
        | HTTP POST /predict
        | HTTP GET  /health
        v
[3] ROLE 4 ML  :8001
Feature Engineering / Models / Evidence / Inference
```

Use these as three separate folders/projects:

- `uni-gap-security-frontend.zip`
- `uni-gap-security-backend-only.zip`
- `role4_ml_final.zip`

## 2. Requirements

- Windows 10/11 or Linux
- Python 3.11+
- VS Code
- Node.js 20+ only for the separate frontend
- Backend does not require CatBoost, PyTorch, NumPy or pandas because ML is external

## 3. Windows setup

Open this backend folder in VS Code.

### Create a virtual environment

```powershell
python -m venv .venv
```

### Activate it

```powershell
.venv\Scripts\activate
```

### Install backend dependencies

```powershell
pip install -r requirements.txt
```

### Create environment file

```powershell
copy .env.example .env
```

## 4. Configure the backend

Open `.env` and verify:

```env
APP_NAME=Uni-Gap Security Backend
APP_ENV=development
SECRET_KEY=change-this-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=480
DATABASE_URL=sqlite:///./data/uni_gap.db
CORS_ORIGINS=http://localhost:3000
ML_SERVICE_URL=http://localhost:8001
ML_SERVICE_TIMEOUT_SECONDS=15
ML_SERVICE_ENABLED=true
DEMO_STREAM_ENABLED=true
DEMO_STREAM_INTERVAL_SECONDS=4
PCAP_MAX_MB=250
UPLOAD_DIR=./storage/pcaps
REPORT_DIR=./storage/reports
```

For PostgreSQL, replace `DATABASE_URL` with your SQLAlchemy PostgreSQL URL. The frontend must never receive database credentials.

## 5. Start Role 4 ML separately

Open the **separate** Role 4 ML project in another VS Code terminal/window. Follow its README and start its API on port `8001`. The backend expects:

```text
GET  http://localhost:8001/health
POST http://localhost:8001/predict
```

Do not copy the ML source into this backend project. Do not copy its model files here.

## 6. Start this backend

From the backend project:

```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Or on Windows:

```powershell
run_api.bat
```

Open:

- API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Health: `http://localhost:8000/api/v1/health`
- WebSocket: `ws://localhost:8000/ws/alerts`

## 7. Demo login

```text
Username: analyst
Password: analyst123
```

This is bootstrap/demo authentication only. Change the secret key and replace bootstrap credentials for any real deployment.

## 8. Connect the frontend

In the separate Next.js frontend create `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws/alerts
```

Then run the frontend in its own project:

```powershell
npm install
npm run dev
```

Open `http://localhost:3000`.

## 9. API groups

### Authentication

```text
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

### Alerts

```text
GET  /api/v1/alerts
GET  /api/v1/alerts/stats
POST /api/v1/alerts/predict
```

`POST /alerts/predict` forwards the observation to the separate ML service, persists an alert when the result is an alert, and broadcasts it over WebSocket.

### Analytics

```text
GET /api/v1/analytics?window=1h
GET /api/v1/analytics?window=6h
GET /api/v1/analytics?window=24h
GET /api/v1/analytics?window=7d
GET /api/v1/analytics?window=30d
```

### Threat Hunt

```text
POST /api/v1/hunt/search
```

### Incidents

```text
GET   /api/v1/incidents
PATCH /api/v1/incidents/{incident_id}
```

### PCAP

```text
POST /api/v1/pcap/upload
GET  /api/v1/pcap
GET  /api/v1/pcap/{job_id}
POST /api/v1/pcap/{job_id}/replay
POST /api/v1/pcap/{job_id}/reset
```

The replay implementation is observation-only. It does not transmit captured packets.

### Reports

```text
GET  /api/v1/reports
POST /api/v1/reports
GET  /api/v1/reports/{report_id}/download/{kind}
```

Kinds: `json`, `csv`, `xlsx`.

### Audit

```text
GET /api/v1/audit
GET /api/v1/audit/export.csv
```

### Settings

```text
GET  /api/v1/settings
PUT  /api/v1/settings
POST /api/v1/settings/test-connection
```

### Security / network state

```text
GET /api/v1/health
GET /api/v1/diode
GET /api/v1/network/summary
```

## 10. Frontend ↔ backend WebSocket

Connect: `ws://localhost:8000/ws/alerts`.

The backend sends:

```json
{"type":"connected","service":"uni-gap-backend","demo_stream":true}
```

Live detection:

```json
{
  "type":"alert",
  "timestamp":"2026-09-11T18:00:00Z",
  "flow_id":"FLOW-123",
  "threat_class":"DGA / DNS Tunneling",
  "threat_subtype":"DGA",
  "severity":"High",
  "confidence":0.947,
  "source_ip":"10.24.3.17",
  "destination_ip":"8.8.8.8",
  "destination_port":53,
  "protocol":"DNS",
  "evidence":{},
  "security_context":{
    "read_only_observation":true,
    "one_way_ingest":true,
    "metadata_only":true,
    "payload_decrypted":false
  }
}
```

The browser can send `ping`; the backend responds with `pong`.

## 11. Backend ↔ ML contract

The backend sends observation payloads such as:

```json
{
  "type":"dns",
  "domain":"x8f92kdl39qmx7z1.com",
  "source_ip":"10.24.3.17",
  "destination_ip":"8.8.8.8",
  "destination_port":53,
  "protocol":"DNS",
  "dns_record_type":"A",
  "dns_query_rate":42.0
}
```

or encrypted-session observations:

```json
{
  "type":"encrypted_session",
  "packet_sizes":[120,130,900,850,870,110,105,900],
  "timestamps":[0,0.5,1,1.5,2,2.5,3,3.5],
  "ja3":"...",
  "ja4":"...",
  "tls_version":"TLS1.3",
  "source_ip":"10.24.3.17",
  "destination_ip":"172.16.4.8",
  "destination_port":443,
  "protocol":"TCP"
}
```

The ML service is responsible for feature engineering and inference. The backend is responsible for authentication, persistence, auditing and distribution to the frontend.

## 12. Database

SQLite is the default and is created automatically under `data/uni_gap.db`.

For a team deployment, use PostgreSQL and point `DATABASE_URL` to it. Database credentials must stay on the backend/server side.

## 13. What the backend does not contain

This ZIP intentionally does **not** contain:

- `role4_ml/` source
- CatBoost model files
- PyTorch model files
- ML feature-engineering code
- frontend source
- database administration UI

This separation keeps the three project roles independent and makes it possible to update the ML service without modifying the frontend.

## 14. Recommended local startup order

1. Start Role 4 ML on `8001`.
2. Start this backend on `8000`.
3. Start the Next.js frontend on `3000`.
4. Log in as `analyst / analyst123`.
5. Confirm `/api/v1/health` reports ML `status: ok`.
6. Confirm the frontend WebSocket shows `LIVE`.
7. Send a test observation through `/api/v1/alerts/predict` or the frontend.

## 15. Run backend tests

```powershell
pytest -q
```

The tests mock the external ML service; they do not bundle or require ML model files.
