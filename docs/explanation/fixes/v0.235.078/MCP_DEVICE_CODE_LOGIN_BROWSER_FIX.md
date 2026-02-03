# MCP_DEVICE_CODE_LOGIN_BROWSER_FIX

## Header Information
- **Fix Title:** MCP device code login returns verification URL
- **Issue Description:** The MCP `login_via_oauth` tool raised an error when device code login started, leaving clients without a usable response to open the verification URL.
- **Root Cause Analysis:** The device code flow raised `UrlElicitationRequiredError` instead of returning a structured payload, and the browser open attempt executed on the server host rather than the client.
- **Fixed/Implemented in version:** **0.235.078**

## Technical Details
- **Files Modified:**
  - `application/external_apps/mcp/server.py`
  - `application/single_app/config.py`
- **Code Changes Summary:**
  - Return a structured device code payload (verification URL, user code, flow ID) so MCP clients can open the login page directly.
  - Bumped application version to 0.235.078.
- **Testing Approach:**
  - Added functional test covering the device code payload response without raising an error.
- **Impact Analysis:**
  - Improves MCP client usability for device code login without changing token exchange behavior.

## Validation
- **Test Results:**
  - Functional test: `functional_tests/test_mcp_oauth_device_code_flow.py`
- **Before/After Comparison:**
  - **Before:** MCP returned an error with the user code message only.
  - **After:** MCP returns a structured response including verification URL and flow ID.
- **User Experience Improvements:**
  - Users can open the verification URL directly and complete sign-in without relying on server-side browser launch.
