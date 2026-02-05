# SimpleChat MCP Server (FastMCP)

This MCP server provides four tools for interacting with SimpleChat:

- **login_via_oauth**: Starts a device-code OAuth login flow and returns `user_code` + `verification_uri`.
- **oauth_login_status**: Returns the current authentication status (PRM bearer token and/or device-code flow).
- **show_user_profile**: Returns the authenticated user's profile, roles, and token claims from SimpleChat.
- **list_public_workspaces**: Returns the authenticated user's public workspaces from SimpleChat.

## Prerequisites

- SimpleChat running locally (default <https://localhost:5000>)
- Entra bearer token issued for the SimpleChat API (audience `api://<CLIENT_ID>`)
- The token includes the **ExternalApi** role (or equivalent scope)

## Setup

1. Create a `.env` file based on `example.env`.
2. Install dependencies:
   - `pip install -r requirements.txt`

## Run

- The MCP server always listens on: `http://localhost:8000/mcp`
- Run locally via script: `.\run_mcp_server.ps1`
- Run locally directly: `python server_minimal.py`

## Environment Variables

### Required — SimpleChat Connection
- `SIMPLECHAT_BASE_URL` — Base URL for SimpleChat (e.g. `https://localhost:5000`)
- `SIMPLECHAT_VERIFY_SSL` — Whether to verify SSL certificates (`true` or `false`)

### Required — MCP Server Configuration
- `MCP_REQUIRE_AUTH` — Enable PRM authentication (`true` or `false`)
- `MCP_PRM_METADATA_PATH` — Path to PRM metadata JSON file (e.g. `prm_metadata.json`)
- `MCP_SESSION_TOKEN_TTL_SECONDS` — TTL in seconds for cached MCP session tokens (e.g. `3600`)
- `FASTMCP_HOST` — Bind host (set by `run_mcp_server.ps1` to `0.0.0.0`)
- `FASTMCP_PORT` — Bind port (set by `run_mcp_server.ps1` to `8000`)
- `FASTMCP_SCHEME` — URL scheme for PRM metadata (`http` for local, `https` for production)

### Required — OAuth / Device-Code Flow
- `OAUTH_AUTHORIZATION_URL` — Entra authorization endpoint
- `OAUTH_TOKEN_URL` — Entra token endpoint
- `OAUTH_DEVICE_CODE_URL` — Entra device-code endpoint (auto-inferred from `OAUTH_TOKEN_URL` if omitted)
- `OAUTH_CLIENT_ID` — App registration client ID
- `OAUTH_CLIENT_SECRET` — App registration client secret (not sent in device-code flow for public clients)
- `OAUTH_SCOPES` — Space-separated scopes (e.g. `api://<CLIENT_ID>/ExternalApi User.Read offline_access openid profile`)
- `OAUTH_TIMEOUT_SECONDS` — Device-code polling timeout in seconds (e.g. `900`)

### Optional
- `OAUTH_REDIRECT_PORT` — Redirect port for auth-code flow (default: `53682`)
- `OAUTH_USE_DEVICE_CODE` — Enable device-code flow (`true` or `false`)
- `OAUTH_OPEN_BROWSER` — Auto-open browser during device-code flow (`false` by default)

## OAuth Login Notes

- `login_via_oauth` uses the device-code flow. The tool response includes `user_code` + `verification_uri`, and the server prints a message to stdout.
- Background polling exchanges the device code for an access token, then creates a SimpleChat session via `/external/login`.
- PRM authentication (bearer token from MCP client) is also supported and takes priority over device-code flow.

## PRM (Protected Resource Metadata)

The MCP server serves PRM metadata at:
`http://localhost:8000/.well-known/oauth-protected-resource`

Update `prm_metadata.json` with your Entra tenant, client, and scopes.

## Deployment

Use `deploy_mcp_containerapp.ps1` to build and deploy to Azure Container Apps.
The Dockerfile is included for container builds.
