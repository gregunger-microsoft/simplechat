# test_mcp_device_code_flow.py
#!/usr/bin/env python3
"""
Functional test for MCP device code flow caching.
Version: 0.235.083
Implemented in: 0.235.083

This test ensures the MCP server returns a device_code_flow_id and caches
payload metadata so the second call can complete the flow.
"""

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mcp_root = os.path.join(repo_root, "application", "external_apps", "mcp")
sys.path.append(mcp_root)

import server


def test_device_code_flow_cache_roundtrip():
    """Validate cache storage and pop semantics for device code flow."""
    print("🧪 Testing MCP device code flow cache roundtrip")

    flow_id = "test-flow-id"
    payload = {
        "device_code": "device-code",
        "user_code": "user-code",
        "verification_uri": "https://example.test",
        "interval": 5
    }
    metadata = {
        "token_url": "https://token.test",
        "client_id": "client-id",
        "client_secret": "secret",
        "timeout_seconds": 90,
        "interval": 5
    }

    server._cache_device_code_flow(flow_id, payload, metadata)
    cached = server._pop_device_code_flow(flow_id)

    assert cached is not None, "Expected cached flow to be returned"
    assert cached["payload"]["device_code"] == "device-code", "Payload should match"
    assert cached["metadata"]["token_url"] == "https://token.test", "Metadata should match"

    missing = server._pop_device_code_flow(flow_id)
    assert missing is None, "Flow should be removed after pop"

    print("✅ Device code flow cache test passed")
    return True


if __name__ == "__main__":
    success = test_device_code_flow_cache_roundtrip()
    sys.exit(0 if success else 1)
