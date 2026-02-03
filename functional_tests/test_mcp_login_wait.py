# test_mcp_login_wait.py
#!/usr/bin/env python3
"""
Functional test for MCP login wait tracking.

This test ensures that login wait state is created, finished, and readable.
"""

import os
import sys
import threading

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mcp_root = os.path.join(repo_root, "application", "external_apps", "mcp")
sys.path.append(mcp_root)

import server


def test_login_wait_tracking():
    """Validate login wait state lifecycle for a base URL."""
    print("🧪 Testing MCP login wait tracking")

    base_url = "https://localhost:5000"
    event = server._start_login_wait(base_url)
    assert isinstance(event, threading.Event), "Expected login wait event"

    server._finish_login_wait(base_url, None)
    status = server._get_login_status(base_url)

    assert status is not None, "Expected login status"
    assert status.get("error") is None, "Expected no error"
    assert status.get("event").is_set() is True, "Expected event to be set"

    print("✅ MCP login wait tracking test passed")
    return True


if __name__ == "__main__":
    success = test_login_wait_tracking()
    sys.exit(0 if success else 1)
