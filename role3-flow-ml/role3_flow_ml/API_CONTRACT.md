# Role 3 API Contract

Role 3 consumes Role 2 `role2.v2` normalized flow features and produces the same alert shape used by Uni-Gap Backend/Frontend.

## REST

`GET /health`

`POST /predict` — body is a `role2.v2` flow feature object.

`POST /ingest` — predicts and broadcasts an alert to connected WebSocket clients when a detection is emitted.

`POST /train` — trains demonstration models from synthetic labeled flow features.

## WebSocket

`ws://localhost:8002/ws/detections`

Send a serialized `role2.v2` feature object. The service returns either an Alert object or an observation/error envelope.

## Threat classes

- DDoS
- Botnet C2
- Recon / Port Scan
- Data Exfiltration

No packet payloads are accepted, stored, or required by Role 3.
