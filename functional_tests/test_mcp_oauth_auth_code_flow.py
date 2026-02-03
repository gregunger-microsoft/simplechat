# test_mcp_oauth_auth_code_flow.py
#!/usr/bin/env python3
"""
Functional test for MCP OAuth auth-code flow handling.
Version: 0.235.083
Implemented in: 0.235.083

This test ensures the MCP server can cache auth-code flow state and
parse callback URLs for the second-step completion.
"""

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mcp_root = os.path.join(repo_root, "application", "external_apps", "mcp")
sys.path.append(mcp_root)

import server


def test_auth_code_flow_cache_and_parse():
    """Validate auth code flow caching and callback URL parsing."""
    print("🧪 Testing MCP OAuth auth code flow cache and parser")

    flow_id = "flow-id"
    payload = {"redirect_uri": "http://localhost:53682/callback", "state": "state"}

    server._cache_auth_code_flow(flow_id, payload)
    cached = server._pop_auth_code_flow(flow_id)

    assert cached is not None, "Expected cached flow"
    assert cached["redirect_uri"] == payload["redirect_uri"], "Redirect URI should match"

    parsed = server._parse_auth_code("http://localhost:53682/callback?code=abc123&state=state")
    assert parsed == "abc123", "Should parse auth code from callback URL"

    print("✅ MCP OAuth auth code flow cache test passed")
    return True


if __name__ == "__main__":
    success = test_auth_code_flow_cache_and_parse()
    sys.exit(0 if success else 1)
