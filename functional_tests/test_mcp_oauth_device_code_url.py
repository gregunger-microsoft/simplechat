# test_mcp_oauth_device_code_url.py
"""
Functional test for MCP OAuth device code URL resolution.
Version: 0.235.076
Implemented in: 0.235.077

This test ensures the device code URL is derived correctly from common token URLs.
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.append(repo_root)

from application.external_apps.mcp.server import _resolve_device_code_url


def test_device_code_url_resolution() -> bool:
    """Validate device code URL resolution from common OAuth token URLs."""
    print("🔍 Testing device code URL resolution...")

    v2_token = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
    v2_device = _resolve_device_code_url(v2_token, "")
    assert v2_device.endswith("/oauth2/v2.0/devicecode"), "v2.0 device code URL mismatch"

    v1_token = "https://login.microsoftonline.com/tenant/oauth2/token"
    v1_device = _resolve_device_code_url(v1_token, "")
    assert v1_device.endswith("/oauth2/devicecode"), "v1 device code URL mismatch"

    explicit = _resolve_device_code_url("", "https://example.com/devicecode")
    assert explicit == "https://example.com/devicecode", "explicit device code URL should win"

    print("✅ Device code URL resolution passed!")
    return True


if __name__ == "__main__":
    success = test_device_code_url_resolution()
    sys.exit(0 if success else 1)
