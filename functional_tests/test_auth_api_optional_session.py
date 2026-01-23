#!/usr/bin/env python3
"""
Functional test for optional API session creation.
Version: 0.235.029
Implemented in: 0.235.029

This test ensures the create_session flag parsing works consistently for /getATokenApi.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from application.single_app.route_frontend_authentication import _parse_bool


def test_parse_bool_truthy():
    """Validate truthy values parse to True."""
    values = ["1", "true", "TRUE", "yes", "y", "on", True]
    for value in values:
        result = _parse_bool(value, default=False)
        if result is not True:
            raise AssertionError(f"Expected True for {value}, got {result}")


def test_parse_bool_falsy():
    """Validate falsy values parse to False."""
    values = ["0", "false", "FALSE", "no", "n", "off", False]
    for value in values:
        result = _parse_bool(value, default=True)
        if result is not False:
            raise AssertionError(f"Expected False for {value}, got {result}")


def test_parse_bool_default():
    """Validate default is used for None or unknown values."""
    if _parse_bool(None, default=True) is not True:
        raise AssertionError("Expected default True for None")
    if _parse_bool("maybe", default=False) is not False:
        raise AssertionError("Expected default False for unknown value")


if __name__ == "__main__":
    tests = [test_parse_bool_truthy, test_parse_bool_falsy, test_parse_bool_default]
    results = []

    for test in tests:
        print(f"\n🧪 Running {test.__name__}...")
        try:
            test()
            print("✅ Test passed!")
            results.append(True)
        except Exception as exc:
            print(f"❌ Test failed: {exc}")
            import traceback
            traceback.print_exc()
            results.append(False)

    success = all(results)
    print(f"\n📊 Results: {sum(results)}/{len(results)} tests passed")
    sys.exit(0 if success else 1)
