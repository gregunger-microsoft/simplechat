# Simple Chat - Test Console App

This console app simulates the MCP server login flow:
1) Opens a browser for Azure AD login.
2) Captures the auth code on a local callback.
3) Calls `/getATokenApi?create_session=true` to create a session and receive tokens + `session_id`.
4) Uses the session cookie to create a public workspace and fetch its details.

## Prereqs
- Simple Chat running at `BASE_URL` (default https://localhost:5000)
- Azure AD app registration allows redirect URI:
  `http://localhost:8400/callback`
- Public workspaces enabled and user has Create Public Workspace role.

## Setup
1) Create `.env` based on `example.env`.
2) Install dependencies:
   - `pip install -r requirements.txt`

## Run
- `python main.py`

## PowerShell Run Script
- `run_test_console.ps1`

## Notes
- If you use a self-signed cert locally, set `VERIFY_SSL=false` in `.env`.
- `SCOPES` must include the same scopes configured in `application/single_app/config.py`.
