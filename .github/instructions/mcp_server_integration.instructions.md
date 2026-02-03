---
applyTo: '**'
---

# MCP Server Integration

## Overview and Purpose
Provides a FastMCP server that can single sign-on (SSO) into SimpleChat using an Entra bearer token, then list a user's public workspaces.

## Dependencies
- SimpleChat app running locally
- Entra bearer token issued for the SimpleChat API audience (`api://<CLIENT_ID>`)
- External API role in token (`ExternalApi`) or standard user roles (`User`, `Admin`)
- Python dependencies listed in `application/external_apps/mcp/requirements.txt`

## Technical Specifications
### Architecture Overview
- An MCP server (FastMCP) uses a bearer token to create a SimpleChat session via `/external/login`.
- The MCP server caches session cookies per token and calls `/api/public_workspaces` on behalf of the user.
- PRM metadata is served by SimpleChat at `/.well-known/oauth-protected-resource`.

### API Endpoints
- `POST /external/login`
  - Validates bearer token and creates a server-side session.
- `GET /api/public_workspaces`
  - Returns paginated public workspaces for the authenticated user.

### Configuration Options
- `SIMPLECHAT_BASE_URL` (default `https://localhost:5000`)
- `SIMPLECHAT_VERIFY_SSL` (default `true`)

### File Structure
- `application/external_apps/mcp/server.py`
- `application/external_apps/mcp/README.md`
- `application/external_apps/mcp/prm_metadata.json`
- `application/single_app/route_external_prm.py`
- `application/single_app/route_external_authentication.py`

## Usage Instructions
1. Start SimpleChat locally.
2. Configure `application/external_apps/mcp/.env`.
3. Run the MCP server: `python server.py`.
4. Call the `login` tool with an Entra bearer token.
5. Call the `list_public_workspaces` tool to fetch workspaces.

## Known Limitations
- The MCP server expects a bearer token that includes the `ExternalApi` role (or equivalent scope).
- PRM metadata is provided as a static JSON file for HTTP hosting scenarios.