# MCP OAuth Auth Code Flow Fix (Version 0.235.083)

## Fix Title
Non-blocking MCP OAuth auth-code flow with two-step completion.

## Issue Description
`login_via_oauth` timed out in MCP Inspector because the tool waited for the auth callback and blocked the response.

## Root Cause Analysis
The MCP tool used a synchronous callback listener and only returned after receiving the auth code, which exceeded Inspector timeouts.

## Version Implemented
Fixed/Implemented in version: **0.235.083**

## Technical Details
### Files Modified
- application/external_apps/mcp/server.py

### Code Changes Summary
- Added auth-code flow caching and callback URL parsing.
- `login_via_oauth` now returns the authorization URL immediately with `auth_code_flow_id`.
- The second call completes the session using `/getATokenApi` and the provided `auth_code`.

### Testing Approach
- Added functional test to validate auth-code flow cache and callback parsing.

## Validation
### Test Results
- Functional test: functional_tests/test_mcp_oauth_auth_code_flow.py

### User Experience Improvements
- OAuth login now completes reliably without MCP Inspector timeouts.

## Related Updates
- Uses the same auth-code exchange flow as the test console app.
