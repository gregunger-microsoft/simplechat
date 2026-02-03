# MCP_TOOL_SIGNATURES_MINIMAL_PARAMS_FIX

## Header Information
- **Fix Title:** MCP tool signatures use minimal parameters
- **Issue Description:** MCP tools exposed many optional parameters that should be driven by container environment variables, causing confusion and misuse.
- **Root Cause Analysis:** Tool signatures included configuration options that were intended to be read from environment variables at runtime.
- **Fixed/Implemented in version:** **0.235.080**

## Technical Details
- **Files Modified:**
  - `application/external_apps/mcp/server.py`
  - `application/single_app/config.py`
- **Code Changes Summary:**
  - Reduced MCP tool parameters to minimal inputs and switched to environment-driven configuration.
  - Updated application version to 0.235.080.
- **Testing Approach:**
  - Added functional test to validate minimal tool signatures.
- **Impact Analysis:**
  - Improves usability and reduces configuration errors for MCP clients.

## Validation
- **Test Results:**
  - Functional test: `functional_tests/test_mcp_tool_minimal_parameters.py`
- **Before/After Comparison:**
  - **Before:** MCP tools exposed multiple configuration parameters.
  - **After:** MCP tools only expose necessary parameters.
- **User Experience Improvements:**
  - Simpler MCP Inspector usage and clearer expected configuration.
