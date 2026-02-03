# MCP Port Lock + Device Code Login Visibility Fix

## Issue
Two related issues made the MCP developer experience confusing:

1) The MCP server port could be overridden via environment (`FASTMCP_PORT`), which conflicted with the required invariant that the MCP server must be reachable at:

- `http://localhost:8000/mcp`

2) When OAuth device-code flow was enabled, a browser window would open to the device login page, but the user code (needed to complete sign-in) was not made obvious.

## Root Cause
- The MCP server computed its bind port from `FASTMCP_PORT`, so any session/global env var could silently move it off 8000.
- The device-code flow opened the verification URL, but the returned `user_code` wasn’t emphasized in the tool message/console, making it easy to miss.

## Fix
- Port is now fixed at `8000` in the MCP server regardless of environment overrides.
- Device-code flow now returns (and prints) an explicit message containing:
  - `verification_uri`
  - `user_code`
- Added a lightweight MCP tool `oauth_login_status` to retrieve pending device-code details if the client UI doesn’t show tool output.
- MCP now loads `application/external_apps/mcp/.env` with override enabled to prevent empty/global env vars (especially `OAUTH_CLIENT_SECRET`) from silently breaking the token exchange.

## Files Modified
- application/external_apps/mcp/server.py
- application/external_apps/mcp/README.md

## Testing
- Run the functional test:
  - `python functional_tests/test_mcp_port_and_device_code_fix.py`

## Impact
- MCP endpoint is stable and predictable: `http://localhost:8000/mcp`.
- Device-code sign-in is self-explanatory (you always see the code + URL).
