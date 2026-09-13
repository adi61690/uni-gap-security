$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Write-Host "Setting up Uni-Gap Security dependencies..." -ForegroundColor Cyan

$pythonProjects = @(
  @{Name="Role1"; Path="$Root\role1-network-traffic-simulation"; Requirements="requirements.txt"},
  @{Name="Role2"; Path="$Root\role2-ingestion-feature-extraction\role2_ingestion"; Requirements="requirements.txt"},
  @{Name="Role3"; Path="$Root\role3-flow-ml\role3_flow_ml"; Requirements="requirements.txt"},
  @{Name="Role4"; Path="$Root\role4-ml\role4_ml_production"; Requirements="requirements.txt"},
  @{Name="Backend"; Path="$Root\backend\uni-gap-security-backend-only"; Requirements="requirements.txt"}
)

foreach ($p in $pythonProjects) {
  Write-Host "[$($p.Name)]" -ForegroundColor Yellow
  Push-Location $p.Path
  if (-not (Test-Path .venv)) { python -m venv .venv }
  & .\.venv\Scripts\python.exe -m pip install --upgrade pip
  & .\.venv\Scripts\python.exe -m pip install -r $p.Requirements
  Pop-Location
}

Write-Host "[Tools] Installing Hugging Face downloader..." -ForegroundColor Yellow
python -m pip install huggingface_hub

Write-Host "[Frontend]" -ForegroundColor Yellow
Push-Location "$Root\frontend\uni-gap-security"
npm install
Pop-Location

