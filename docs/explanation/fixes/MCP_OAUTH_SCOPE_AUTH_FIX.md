# MCP OAuth Scope Authorization Fix (Version 0.235.082)

## Fix Title
MCP OAuth delegated scope authorization for external API access.

## Issue Description
After completing OAuth login via MCP, subsequent SimpleChat API calls failed with a 403 response because the access token carried delegated scopes (`scp`) instead of app roles (`roles`).

## Root Cause Analysis
The `accesstoken_required` guard only allowed app roles (`ExternalApi`, `User`, `Admin`). Delegated OAuth tokens issued to users include `scp` claims instead, so valid tokens were rejected.

## Version Implemented
Fixed/Implemented in version: **0.235.082**

## Technical Details
### Files Modified
- application/single_app/functions_authentication.py
- application/single_app/config.py

### Code Changes Summary
- Added delegated scope validation alongside existing role checks.
- Allowed `ExternalApi` scope values (including resource-scoped variants) to pass authorization.
- Incremented the app version to 0.235.082.

### Testing Approach
- Added functional test to validate role-based and scope-based authorization acceptance.

## Validation
### Test Results
- Functional test: functional_tests/test_external_api_scope_authorization.py

### User Experience Improvements
- OAuth sign-in via MCP now enables subsequent SimpleChat API calls without 403 errors.

## Related Updates
- Version updated in config.py to **0.235.082**.
