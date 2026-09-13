# Frontend runtime fix

The original frontend redirected unauthenticated users from `/` to `/login`, but the project had no `/login` route, causing a blank page.

This revision adds:
- `/login` route with working local development authentication (`analyst` / `analyst123`) and backend authentication when available.
- Explicit Next.js App Router pages for all dashboard routes.
- `dominant_frequency_hz` in the shared `Evidence` type.
- No frontend-generated live telemetry; empty/offline state is shown until backend observations arrive.

After extracting:

```powershell
cd frontend\uni-gap-security
npm install --legacy-peer-deps
npm run build
npm run dev
```

Open http://localhost:3000 and sign in with the local development credential when the backend is not available.
