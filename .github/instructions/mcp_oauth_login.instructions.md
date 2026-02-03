---
applyTo: '**'
---

# MCP OAuth Login

## Overview and Purpose
The MCP tool performs an OAuth authorization code flow with PKCE. The MCP server launches a browser, receives an authorization code, and then calls SimpleChat APIs on the user’s behalf.

## Dependencies
- MCP server running on http://localhost:8000/mcp
- OAuth authorization endpoint and token endpoint
- Optional client secret if required by your OAuth provider

## Configuration Options
Set these environment variables for defaults:
- `OAUTH_AUTHORIZATION_URL`
- `OAUTH_TOKEN_URL`
- `OAUTH_CLIENT_ID`
- `OAUTH_CLIENT_SECRET` (optional)
- `OAUTH_SCOPES`
- `OAUTH_REDIRECT_PORT` (default: 53682)

## File Structure
- MCP tool: application/external_apps/mcp/server.py
- MCP launcher: application/external_apps/mcp/run_mcp_server.ps1

## Usage Instructions
1. Configure OAuth env vars.
2. Use MCP Inspector:
   - Transport: Streamable HTTP
   - URL: http://localhost:8000/mcp
3. Call `login_via_oauth`.
4. Complete the browser sign-in.
5. Call `list_public_workspaces` (uses cached session).

## Known Limitations
- OAuth flow requires a local callback port to be available.
- The MCP server needs outbound access to the OAuth endpoint.