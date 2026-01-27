# SimpleChat MCP Server (FastMCP)

This MCP server provides two tools:
- **login**: Creates a SimpleChat session using an Entra bearer token.
- **list_public_workspaces**: Returns the authenticated user's public workspaces.

## Prerequisites
- SimpleChat running locally (default https://localhost:5000)
- Entra bearer token issued for the SimpleChat API (audience `api://<CLIENT_ID>`)
- The token includes the **ExternalApi** role

## Setup
1. Create a `.env` file based on `example.env`.
2. Install dependencies:
   - `pip install -r requirements.txt`

## Run
- `python server.py`

## Environment Variables
- `SIMPLECHAT_BASE_URL` (default: https://localhost:5000)
- `SIMPLECHAT_VERIFY_SSL` (default: true)

## PRM (Protected Resource Metadata)
SimpleChat serves PRM metadata at:
`/.well-known/oauth-protected-resource`

Update `prm_metadata.json` with your Entra tenant, client, and scopes.
