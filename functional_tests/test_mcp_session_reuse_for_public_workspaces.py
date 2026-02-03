# test_mcp_session_reuse_for_public_workspaces.py
"""
Functional test for MCP session reuse when listing public workspaces.
Version: 0.235.079
Implemented in: 0.235.079

This test ensures that the MCP server can call list_public_workspaces after a
single OAuth login by reusing the cached session cookie when access_token is
omitted.
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "application", "external_apps", "mcp"))

import server as mcp_server


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.calls = []

    def get(self, url, params=None, verify=None, timeout=None):
        self.calls.append((url, params, verify, timeout))
        return FakeResponse({"workspaces": [], "page": 1, "page_size": 25, "total_count": 0})


def test_session_reuse_without_access_token():
    """Ensure list_public_workspaces uses cached session when access_token is missing."""
    base_url = "https://example.com"
    fake_session = FakeSession()

    with mcp_server._SESSION_LOCK:
        mcp_server._LAST_SESSION_BY_BASE_URL[base_url] = fake_session
        mcp_server._LAST_ACCESS_TOKEN_BY_BASE_URL.pop(base_url, None)

    result = mcp_server.list_public_workspaces(
        access_token=None,
        base_url=base_url,
        page=1,
        page_size=25,
        search=None,
        verify_ssl=True
    )

    assert result["total_count"] == 0
    assert len(fake_session.calls) == 1
    assert fake_session.calls[0][0] == f"{base_url}/api/public_workspaces"

    with mcp_server._SESSION_LOCK:
        mcp_server._LAST_SESSION_BY_BASE_URL.pop(base_url, None)

    print("✅ Cached session reused without access token.")
    return True


if __name__ == "__main__":
    success = test_session_reuse_without_access_token()
    sys.exit(0 if success else 1)
