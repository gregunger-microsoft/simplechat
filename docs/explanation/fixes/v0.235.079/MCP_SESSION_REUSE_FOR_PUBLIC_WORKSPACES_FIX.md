# MCP_SESSION_REUSE_FOR_PUBLIC_WORKSPACES_FIX

## Header Information
- **Fix Title:** MCP session reuse for public workspaces
- **Issue Description:** After OAuth login, MCP calls to list public workspaces still required re-authentication because cached sessions were not reused without an access token.
- **Root Cause Analysis:** The MCP server only looked up cached access tokens when `access_token` was missing and did not reuse the existing session cookie created by `/external/login`.
- **Fixed/Implemented in version:** **0.235.079**

## Technical Details
- **Files Modified:**
  - `application/external_apps/mcp/server.py`
  - `application/single_app/config.py`
- **Code Changes Summary:**
  - Added last-session cache per base URL and reused it when `access_token` is omitted.
  - Preserved existing access-token flow and updated version.
- **Testing Approach:**
  - Added functional test validating session reuse without access token.
- **Impact Analysis:**
  - One-time login is sufficient; subsequent MCP calls reuse the session cookie.

## Validation
- **Test Results:**
  - Functional test: `functional_tests/test_mcp_session_reuse_for_public_workspaces.py`
- **Before/After Comparison:**
  - **Before:** MCP required another login when `access_token` was omitted.
  - **After:** MCP reuses the cached session cookie for public workspace calls.
- **User Experience Improvements:**
  - Single OAuth login supports follow-on MCP API calls without re-auth.
