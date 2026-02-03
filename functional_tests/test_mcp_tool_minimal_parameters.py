# test_mcp_tool_minimal_parameters.py
"""
Functional test for MCP tool minimal parameters.
Version: 0.235.080
Implemented in: 0.235.080

This test ensures MCP tools expose only the minimal parameters required and rely
on environment variables for configuration.
"""

import os
import sys
import inspect

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "application", "external_apps", "mcp"))

import server as mcp_server


def test_mcp_tool_signatures():
    """Validate MCP tool parameter lists are minimal."""
    login_params = list(inspect.signature(mcp_server.login).parameters.keys())
    oauth_params = list(inspect.signature(mcp_server.login_via_oauth).parameters.keys())
    list_params = list(inspect.signature(mcp_server.list_public_workspaces).parameters.keys())

    assert login_params == ["access_token"], f"Unexpected login params: {login_params}"
    assert oauth_params == ["device_code_flow_id"], f"Unexpected login_via_oauth params: {oauth_params}"
    assert list_params == ["page", "page_size", "search"], f"Unexpected list_public_workspaces params: {list_params}"

    print("✅ MCP tool signatures are minimal.")
    return True


if __name__ == "__main__":
    success = test_mcp_tool_signatures()
    sys.exit(0 if success else 1)
