$Root = Split-Path -Parent $PSScriptRoot

Write-Host "Starting Role 4 ML..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$Root\role4-ml\role4_ml_production'; .\.venv\Scripts\Activate.ps1; python -m uvicorn role4_ml.api:app --host 0.0.0.0 --port 8001"

Write-Host "Starting Role 3 ML..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$Root\role3-flow-ml\role3_flow_ml'; .\.venv\Scripts\Activate.ps1; $env:PYTHONPATH='src'; python scripts\run_api.py"

Write-Host "Starting Backend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$Root\backend\uni-gap-security-backend-only'; .\.venv\Scripts\Activate.ps1; python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

Write-Host "Starting Role 2..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$Root\role2-ingestion-feature-extraction\role2_ingestion'; .\.venv\Scripts\Activate.ps1; python scripts\run_api.py"

Write-Host "Starting Frontend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$Root\frontend\uni-gap-security'; npm run dev"

Write-Host "Services are starting. Frontend: http://localhost:3000  Backend: http://localhost:8000/docs" -ForegroundColor Green
