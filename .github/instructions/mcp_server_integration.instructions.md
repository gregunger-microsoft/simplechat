---
applyTo: '**'
---

# MCP Server Integration

## Overview and Purpose
Provides a FastMCP server that can authenticate into SimpleChat using an Entra bearer token (via PRM or device-code OAuth flow), then access user profile and public workspaces.

## Dependencies
- SimpleChat app running locally
- Entra bearer token issued for the SimpleChat API audience (`api://<CLIENT_ID>`)
- External API role in token (`ExternalApi`) or standard user roles (`User`, `Admin`)
- Python dependencies listed in `application/external_apps/mcp/requirements.txt`

## Technical Specifications
### Architecture Overview
- An MCP server (FastMCP) uses a bearer token to create a SimpleChat session via `/external/login`.
- The MCP server caches session cookies per token and calls SimpleChat APIs on behalf of the user.
- PRM metadata is served by the MCP server itself at `http://localhost:8000/.well-known/oauth-protected-resource`.
- A custom ASGI middleware (`_PrmAndAuthShim`) handles PRM metadata serving, bearer token extraction, and MCP session token caching.

### Tools Exposed
- `login_via_oauth` — Starts device-code OAuth login flow.
- `oauth_login_status` — Returns current authentication status (PRM and/or device-code).
- `show_user_profile` — Returns the authenticated user's profile, roles, and token claims.
- `list_public_workspaces` — Returns the authenticated user's public workspaces.

### API Endpoints (SimpleChat)
- `POST /external/login`
  - Validates bearer token and creates a server-side session.
- `GET /api/public_workspaces`
  - Returns paginated public workspaces for the authenticated user.

### Configuration Options
- `SIMPLECHAT_BASE_URL` (default `https://localhost:5000`)
- `SIMPLECHAT_VERIFY_SSL` (default `true`)
- `MCP_REQUIRE_AUTH` — Enable PRM authentication
- `MCP_PRM_METADATA_PATH` — Path to PRM metadata JSON file
- `MCP_SESSION_TOKEN_TTL_SECONDS` — TTL for cached MCP session tokens
- `FASTMCP_SCHEME` — URL scheme for PRM metadata (`http` for local)

### File Structure
- `application/external_apps/mcp/server_minimal.py`
- `application/external_apps/mcp/README.md`
- `application/external_apps/mcp/prm_metadata.json`
- `application/external_apps/mcp/run_mcp_server.ps1`
- `application/external_apps/mcp/deploy_mcp_containerapp.ps1`
- `application/single_app/route_external_prm.py`
- `application/single_app/route_external_authentication.py`

## Usage Instructions
1. Start SimpleChat locally.
2. Configure `application/external_apps/mcp/.env`.
3. Run the MCP server: `.\run_mcp_server.ps1` or `python server_minimal.py`.
4. Call `oauth_login_status` to check authentication.
5. Call `show_user_profile` to see the authenticated user's profile.
6. Call `list_public_workspaces` to fetch workspaces.

## Known Limitations
- The MCP server expects a bearer token that includes the `ExternalApi` role (or equivalent scope).
- PRM metadata is loaded from a local JSON file (`prm_metadata.json`).