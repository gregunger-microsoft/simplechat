---
applyTo: '**'
---

# MCP OAuth Login

## Overview and Purpose
The MCP server supports authentication via two methods:
1. **PRM (Protected Resource Metadata)** — The MCP client (e.g. VS Code) provides a bearer token automatically via the PRM handshake. This is the primary method.
2. **Device-Code OAuth Flow** — The `login_via_oauth` tool initiates a device-code flow for manual login. The user visits a URL and enters a code to authenticate.

After authentication, the MCP server creates a SimpleChat session via `/external/login` and caches it for subsequent tool calls.

## Dependencies
- MCP server running on http://localhost:8000/mcp
- SimpleChat running on https://localhost:5000
- OAuth authorization endpoint and token endpoint (Entra ID)
- Optional client secret if required by your OAuth provider

## Configuration Options
Set these environment variables (in `application/external_apps/mcp/.env`):
- `OAUTH_AUTHORIZATION_URL`
- `OAUTH_TOKEN_URL`
- `OAUTH_DEVICE_CODE_URL` (auto-inferred from `OAUTH_TOKEN_URL` if omitted)
- `OAUTH_CLIENT_ID`
- `OAUTH_CLIENT_SECRET` (not sent for device-code public client flow)
- `OAUTH_SCOPES`
- `OAUTH_TIMEOUT_SECONDS` (device-code polling timeout, e.g. `900`)
- `OAUTH_REDIRECT_PORT` (default: 53682)
- `OAUTH_USE_DEVICE_CODE` (`true` to enable device-code flow)
- `OAUTH_OPEN_BROWSER` (`false` by default; set `true` to auto-open browser)

## File Structure
- MCP server: application/external_apps/mcp/server_minimal.py
- MCP launcher: application/external_apps/mcp/run_mcp_server.ps1
- PRM metadata: application/external_apps/mcp/prm_metadata.json

## Usage Instructions
1. Configure OAuth env vars in `.env`.
2. Use MCP Inspector:
   - Transport: Streamable HTTP
   - URL: http://localhost:8000/mcp
3. Call `oauth_login_status` to check current auth state.
4. If not authenticated via PRM, call `login_via_oauth` and complete the device-code sign-in.
5. Call `show_user_profile` to verify identity.
6. Call `list_public_workspaces` (uses cached session).

## Known Limitations
- Device-code flow requires the Entra app registration to be configured as a public client.
- The MCP server needs outbound access to the OAuth endpoint.
- Session tokens are cached in-memory with a configurable TTL (`MCP_SESSION_TOKEN_TTL_SECONDS`).