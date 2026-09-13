# Frontend Integration Contract

Base URL: `http://localhost:8000`

WebSocket: `ws://localhost:8000/ws/alerts`

The frontend should:

1. POST credentials to `/api/v1/auth/login`.
2. Store the access token in the frontend's prototype-safe session store.
3. Send the bearer token on protected REST endpoints.
4. Connect the live alert feed to `/ws/alerts`.
5. Use `type=alert` messages to prepend live alerts.
6. Use `/api/v1/alerts` for history/search/filtering.
7. Use `/api/v1/analytics` for historical charts.
8. Use `/api/v1/pcap/*` for replay controls.
9. Use `/api/v1/reports` for report creation and downloads.
10. Use `/api/v1/audit` for audit UI.
11. Use `/api/v1/settings` for persisted settings.
12. Use `/api/v1/diode` and `/api/v1/health` for passive security status.

The role4 ML package is embedded, so the backend is the single integration service. A separate Role 4 process is not required for the default deployment.


## Service boundaries

The backend and ML are separate deployables. The backend calls the ML service over HTTP:

- `GET {ML_SERVICE_URL}/health`
- `POST {ML_SERVICE_URL}/predict`

The ML service owns model loading, feature engineering and inference. The backend owns authentication, persistence, audit, frontend APIs, WebSocket fan-out, PCAP jobs and report generation.
