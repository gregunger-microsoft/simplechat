# test_external_api_scope_authorization.py
#!/usr/bin/env python3
"""
Functional test for external API OAuth scope authorization.
Version: 0.235.082
Implemented in: 0.235.082

This test ensures that external API authorization accepts delegated scopes
(e.g., ExternalApi) in addition to app roles.
"""

import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
single_app_root = os.path.join(repo_root, "application", "single_app")
sys.path.append(single_app_root)

from functions_authentication import is_external_api_authorized


def test_external_api_scope_authorization():
    """Validate roles and delegated scopes for external API access."""
    print("🧪 Testing External API OAuth Scope Authorization")

    role_claims = {"roles": ["ExternalApi"]}
    scope_claims = {"scp": "ExternalApi openid profile"}
    resource_scope_claims = {"scp": "api://client-id/ExternalApi"}
    invalid_claims = {"scp": "openid profile"}

    assert is_external_api_authorized(role_claims) is True, "Role-based access should be allowed"
    assert is_external_api_authorized(scope_claims) is True, "Scope-based access should be allowed"
    assert is_external_api_authorized(resource_scope_claims) is True, "Resource scope should be allowed"
    assert is_external_api_authorized(invalid_claims) is False, "Unrelated scopes should be rejected"

    print("✅ External API authorization checks passed")
    return True


if __name__ == "__main__":
    success = test_external_api_scope_authorization()
    sys.exit(0 if success else 1)
