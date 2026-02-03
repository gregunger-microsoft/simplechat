---
applyTo: '**'
---

# Run Simple Chat locally (single_app)

## What this does
This script runs the Simple Chat app from:
`C:\tempVA\simplechat_20260121\application\single_app`

## Prereqs
- The virtual environment exists at:
  `C:\tempVA\simplechat_20260121\application\single_app\.venv`
- The app settings file exists at:
  `C:\tempVA\simplechat_20260121\application\single_app\.env`

## Run
1) Open PowerShell.
2) Run the script:
   `C:\tempVA\simplechat_20260121\gunger\run_simplechat_local.ps1`

## App URL
- https://localhost:5000

## Notes
- The app runs with a self-signed HTTPS cert in debug mode.
- Ensure your `.env` values are valid for your Azure resources.
- Logs are written to `C:\tempVA\simplechat_20260121\application\single_app\logs\local_run`.
- If port 5000 is already in use, stop the other process or change the port.