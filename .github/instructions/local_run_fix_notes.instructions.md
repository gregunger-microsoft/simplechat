---
applyTo: '**'
---

# Local Run Fix Notes

## Summary
The app can fail to start or authenticate reliably when global environment variables override `.env` values. In particular, `AZURE_COSMOS_ENDPOINT` (and related Cosmos settings) and AAD variables (`CLIENT_ID`, `TENANT_ID`, `MICROSOFT_PROVIDER_AUTHENTICATION_SECRET`) may be set in the PowerShell session and override `.env` values.

## What was changed
- The local run script clears process-level Cosmos env vars before starting the app.
- The local run script clears process-level AAD env vars before starting the app.
- Output is logged to `application/single_app/logs/local_run` for troubleshooting.

## Script to use
- `C:\tempVA\simplechat_20260121\gunger\run_simplechat_local.ps1`

## How it works
1) Clears `AZURE_COSMOS_ENDPOINT`, `AZURE_COSMOS_KEY`, and `AZURE_COSMOS_AUTHENTICATION_TYPE` from the current PowerShell session.
2) Clears `CLIENT_ID`, `TENANT_ID`, and `MICROSOFT_PROVIDER_AUTHENTICATION_SECRET` from the current PowerShell session.
3) Starts the app from `application/single_app` so `.env` is loaded.
4) If port 5000 is already listening, it validates the existing app or exits with a clear error if another process owns the port.
5) Polls `https://localhost:5000` until it returns a response or times out.

## If it fails
- Re-check `.env` values under `application/single_app`.
- Ensure your Cosmos DB endpoint is reachable.
- Re-run the script; it will print startup errors if it cannot reach 200.