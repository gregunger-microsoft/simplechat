#!/usr/bin/env python3
"""Functional test for MCP port lock + device-code UX.

This test ensures:
- The MCP server port is fixed at 8000 (not configurable via FASTMCP_PORT).
- The device-code OAuth flow provides a clear message including the user code.
- A status tool exists to retrieve pending login details.

Note: No version comment included because no version bump was requested.
"""

# test_mcp_port_and_device_code_fix.py

from __future__ import annotations

import ast
from pathlib import Path


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_port_is_fixed_and_device_code_is_visible() -> bool:
    repo_root = Path(__file__).resolve().parents[1]
    server_path = repo_root / "application" / "external_apps" / "mcp" / "server_minimal.py"

    if not server_path.exists():
        raise FileNotFoundError(f"Expected MCP server at: {server_path}")

    source = _read_text(server_path)
    tree = ast.parse(source)

    # 1) Port must be fixed at 8000
    default_port_assignments: list[ast.Assign] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEFAULT_MCP_PORT":
                    default_port_assignments.append(node)

    if not default_port_assignments:
        raise AssertionError("DEFAULT_MCP_PORT assignment not found.")

    last_assignment = default_port_assignments[-1]
    if not isinstance(last_assignment.value, ast.Constant) or last_assignment.value.value != 8000:
        raise AssertionError("DEFAULT_MCP_PORT must be the constant 8000.")

    # 2) Device-code flow must include the user code in a human-readable message
    if "enter this code: {user_code}" not in source:
        raise AssertionError("Device-code message does not include 'enter this code: {user_code}'.")

    # 2b) .env must be loaded from the MCP folder (avoid CWD surprises)
    if "load_dotenv(dotenv_path=_DOTENV_PATH" not in source:
        raise AssertionError("Expected load_dotenv(dotenv_path=_DOTENV_PATH, override=True) in the MCP server.")

    # 3) Status tool should exist (helps when the client doesn't surface tool return payload)
    if '@_mcp.tool(name="oauth_login_status")' not in source:
        raise AssertionError("Expected oauth_login_status tool decorator not found.")

    # 4) show_user_profile tool should exist
    if '@_mcp.tool(name="show_user_profile")' not in source:
        raise AssertionError("Expected show_user_profile tool decorator not found.")

    print("✅ MCP port lock + device-code UX checks passed")
    return True


if __name__ == "__main__":
    ok = False
    try:
        ok = test_port_is_fixed_and_device_code_is_visible()
    except Exception as exc:
        print(f"❌ Test failed: {exc}")
        raise

    raise SystemExit(0 if ok else 1)
