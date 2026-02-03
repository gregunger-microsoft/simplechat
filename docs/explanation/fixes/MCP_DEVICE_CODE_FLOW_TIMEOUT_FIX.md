# MCP Device Code Flow Timeout Fix (Version 0.235.083)

## Fix Title
Two-step MCP device code flow with cached flow ID.

## Issue Description
The MCP `login_via_oauth` tool timed out in the inspector because the device code flow waited for user completion before returning. The user never received the device code or verification URL in the tool response, so the flow stalled and timed out.

## Root Cause Analysis
The device code path synchronously polled the token endpoint and only returned after the login completed. This blocked the MCP response and caused inspector timeouts, while also hiding the user code needed to complete login.

## Version Implemented
Fixed/Implemented in version: **0.235.083**

## Technical Details
### Files Modified
- application/external_apps/mcp/server.py
- application/single_app/config.py

### Code Changes Summary
- Split device code login into two steps using a cached `device_code_flow_id`.
- First call returns the device code and verification URL immediately.
- Second call (with `device_code_flow_id`) completes polling and creates the session.
- Incremented the app version to 0.235.083.

### Testing Approach
- Added functional test to validate device code flow cache round-trip behavior.

## Validation
### Test Results
- Functional test: functional_tests/test_mcp_device_code_flow.py

### User Experience Improvements
- The inspector now shows a device code immediately and avoids request timeouts.

## Related Updates
- Version updated in config.py to **0.235.083**.
