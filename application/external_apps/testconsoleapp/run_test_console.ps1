# run_test_console.ps1
# Run the Simple Chat test console app

$ErrorActionPreference = "Stop"

$appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$requirements = Join-Path $appRoot "requirements.txt"
$envFile = Join-Path $appRoot ".env"

if (-not (Test-Path $envFile)) {
    Write-Error "Missing .env file at $envFile. Copy example.env to .env and fill values."
    exit 1
}

Write-Host "Installing dependencies..."
pip install -r $requirements

Write-Host "Running test console app..."
python (Join-Path $appRoot "main.py")
