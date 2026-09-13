# Role 6 — Uni-Gap Security Frontend

Next.js analyst dashboard for the Uni-Gap passive monitoring platform.

## Run

```bash
npm install
npm run build
npm run dev
```

Open `http://localhost:3000`.

Environment:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws/alerts
```

The frontend does not fabricate network telemetry. Without the backend it shows empty/offline states. With Role 5 running, alerts arrive through the configured WebSocket.
