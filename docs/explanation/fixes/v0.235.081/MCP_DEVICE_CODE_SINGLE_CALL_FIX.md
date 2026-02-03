# MCP_DEVICE_CODE_SINGLE_CALL_FIX

## Header Information
- **Fix Title:** MCP device code login completes in one call
- **Issue Description:** MCP device code login required a second call with a flow id, which was unacceptable for one-time login workflows.
- **Root Cause Analysis:** The MCP server returned a device code payload and exited before polling the token, forcing a second request.
- **Fixed/Implemented in version:** **0.235.081**

## Technical Details
- **Files Modified:**
  - `application/external_apps/mcp/server.py`
  - `application/single_app/config.py`
- **Code Changes Summary:**
  - Device code login now opens the verification URL and polls for the token in the same call.
  - Session creation happens immediately after token acquisition.
- **Testing Approach:**
  - Updated functional test to validate single-call completion.
- **Impact Analysis:**
  - Users can call `login_via_oauth` once and then access MCP tools without a second login call.

## Validation
- **Test Results:**
  - Functional test: `functional_tests/test_mcp_oauth_device_code_flow.py`
- **Before/After Comparison:**
  - **Before:** Required second call with `device_code_flow_id`.
  - **After:** Single call completes login and creates session.
- **User Experience Improvements:**
  - Simplified MCP login flow for device code authentication.
