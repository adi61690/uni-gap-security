# Frontend CI fix

The frontend build failed in GitHub Actions because Recharts imports `react-is` but it was not declared as a direct dependency.

This release declares `react-is` explicitly alongside React 19 and Recharts.

Run in `frontend/uni-gap-security`:

    npm install --legacy-peer-deps
    npm run build
