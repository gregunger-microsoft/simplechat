# API Session Option (Version 0.235.029)

## Overview and Purpose
Adds an optional `create_session` flag to the `/getATokenApi` route so a caller can request a server-side session and receive the session id for subsequent calls.

## Version Implemented
Implemented in version: **0.235.029**

## Dependencies
- Flask session backend (filesystem or Redis) configured in application/single_app/app.py
- Azure AD app registration configured for `/getATokenApi`

## Technical Specifications
- **Endpoint**: `/getATokenApi`
- **Method**: GET (Azure AD redirect)
- **Query Param**: `create_session` (optional)
  - Truthy values: `1`, `true`, `yes`, `y`, `on`
  - Falsy values: `0`, `false`, `no`, `n`, `off`

### Behavior
- If `create_session=false` (default): no session is created.
- If `create_session=true`: a session is created, the MSAL cache is stored, and the response includes `session_id`.
- The session itself is maintained via the standard Flask-Session cookie returned in the HTTP response.
- Optional `redirect_uri` query param is supported for localhost/127.0.0.1 only, enabling local console clients.

## Usage Instructions
### Example Redirect URL
`https://localhost:5000/getATokenApi?create_session=true&code=<AUTH_CODE>`

### Response Fields
- `session_created`: boolean
- `session_id`: present when `session_created=true`

## Testing and Validation
- Functional test: functional_tests/test_auth_api_optional_session.py
- Ensure `create_session=true` returns a `session_id` with valid token payload

## File Structure
- application/single_app/route_frontend_authentication.py
- functional_tests/test_auth_api_optional_session.py
- docs/explanation/features/API_SESSION_OPTION.md
