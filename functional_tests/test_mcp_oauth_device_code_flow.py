# test_mcp_oauth_device_code_flow.py
"""
Functional test for MCP OAuth device code flow single-call login.
Version: 0.235.081
Implemented in: 0.235.081

This test ensures login_via_oauth completes device code login in a single call
by polling for the token and creating a session.
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "application", "external_apps", "mcp"))

import server as mcp_server


def test_device_code_single_call_login():
    """Validate device code flow returns session payload after polling."""
    fake_payload = {
        "device_code": "device-code-123",
        "user_code": "ET5UJEY8J",
        "verification_uri": "https://microsoft.com/devicelogin",
        "verification_uri_complete": "https://microsoft.com/devicelogin?code=ET5UJEY8J",
        "interval": 5
    }
    fake_token = {"access_token": "token-123"}
    fake_session_payload = {"session_created": True, "session_id": "session-123", "user": {"userId": "user-1"}}

    original_request = mcp_server._request_device_code
    original_poll = mcp_server._poll_device_code_token
    original_create = mcp_server._create_session
    try:
        mcp_server._request_device_code = lambda *_args, **_kwargs: fake_payload
        mcp_server._poll_device_code_token = lambda **_kwargs: fake_token
        mcp_server._create_session = lambda *_args, **_kwargs: (object(), fake_session_payload)

        result = mcp_server.login_via_oauth(
            device_code_flow_id=None,
        )

        assert result == fake_session_payload

        print("✅ Device code login completed in a single call.")
        return True
    except Exception as exc:
        print(f"❌ Test failed: {exc}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        mcp_server._request_device_code = original_request
        mcp_server._poll_device_code_token = original_poll
        mcp_server._create_session = original_create


if __name__ == "__main__":
    success = test_device_code_single_call_login()
    sys.exit(0 if success else 1)
