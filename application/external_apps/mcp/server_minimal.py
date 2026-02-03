# server_minimal.py
"""Minimal MCP server: device-code OAuth login + SimpleChat integration.

Goals:
- Only what we need: login via device code and access SimpleChat.
- Read config exclusively from application/external_apps/mcp/.env.
- Verbose, safe logs (never print secrets).

Tools exposed:
- login_via_oauth
- oauth_login_status
- show_user_profile
- list_public_workspaces
"""

from __future__ import annotations

import os
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP


_DOTENV_PATH = Path(__file__).resolve().parent / ".env"
if _DOTENV_PATH.exists():
    load_dotenv(dotenv_path=_DOTENV_PATH, override=True)
else:
    load_dotenv(override=True)

DEFAULT_MCP_HOST = "localhost"
DEFAULT_MCP_PORT = 8000

_env_port = os.getenv("FASTMCP_PORT", "").strip()
if _env_port and _env_port != str(DEFAULT_MCP_PORT):
    print(f"[MCP] Ignoring FASTMCP_PORT={_env_port}; port is fixed at {DEFAULT_MCP_PORT}.")


_mcp = FastMCP("simplechat-mcp-minimal")

_STATE_LOCK = threading.Lock()
_STATE: Dict[str, Any] = {
    "event": None,
    "pending": False,
    "error": None,
    "auth_flow": None,
    "user_code": None,
    "verification_uri": None,
    "verification_uri_complete": None,
    "expires_in": None,
    "interval": None,
    "access_token": None,
    "simplechat_session": None,
    "user_profile": None,
    "token_claims": None,
}


def _env(name: str, required: bool = True) -> str:
    value = os.getenv(name, "").strip()
    if required and not value:
        raise ValueError(f"Missing required setting {name} in {_DOTENV_PATH}")
    return value


def _resolve_device_code_url(token_url: str) -> str:
    if token_url.endswith("/oauth2/v2.0/token"):
        return token_url.replace("/oauth2/v2.0/token", "/oauth2/v2.0/devicecode")
    if token_url.endswith("/oauth2/token"):
        return token_url.replace("/oauth2/token", "/oauth2/devicecode")
    raise ValueError("Cannot infer device-code URL from OAUTH_TOKEN_URL; set OAUTH_DEVICE_CODE_URL.")


def _request_device_code(device_code_url: str, client_id: str, scope: str) -> Dict[str, Any]:
    print(f"[MCP] Requesting device code from {device_code_url}")
    response = requests.post(
        device_code_url,
        data={"client_id": client_id, "scope": scope},
        timeout=30,
    )
    if response.status_code != 200:
        try:
            payload = response.json()
        except Exception:
            payload = {"raw": response.text}
        raise RuntimeError(f"Device code request failed ({response.status_code}): {payload}")
    return response.json()


def _poll_device_code_token(
    token_url: str,
    client_id: str,
    client_secret: str,
    device_code: str,
    timeout_seconds: int,
    poll_interval: int,
) -> Dict[str, Any]:
    start = time.time()
    interval = max(1, poll_interval)

    secret_present = bool(client_secret)
    print(
        "[MCP] Starting token polling (PUBLIC CLIENT mode - no secret sent). "
        f"token_url={token_url} client_secret_in_env={secret_present} (not used for device code flow)"
    )

    attempt = 0
    while time.time() - start < timeout_seconds:
        attempt += 1
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code,
        }
        # NOTE: Device code flow for PUBLIC CLIENTS (like this app) does NOT include client_secret.
        # Only confidential clients use client_secret with device code flow.
        # The AADSTS7000218 error means the app registration is NOT configured as confidential,
        # so we must omit client_secret entirely.

        # Debug: show what we're sending
        has_secret_key = "client_secret" in data
        print(f"[MCP] Token poll attempt #{attempt}: POST data keys={list(data.keys())} has_client_secret_key={has_secret_key} (public client mode)")

        response = requests.post(token_url, data=data, timeout=30)
        print(f"[MCP] Token poll attempt #{attempt}: response status={response.status_code}")

        if response.status_code == 200:
            try:
                return response.json()
            except Exception as exc:
                raise RuntimeError(f"Token response was not JSON: {exc}")

        payload: Dict[str, Any]
        try:
            payload = response.json()
        except Exception:
            payload = {"raw": response.text}

        error = str(payload.get("error", "")).lower()
        if error == "authorization_pending":
            time.sleep(interval)
            continue
        if error == "slow_down":
            interval += 5
            time.sleep(interval)
            continue
        if error == "expired_token":
            raise TimeoutError("Device code expired before login completed.")

        raise RuntimeError(f"Device-code token exchange failed ({response.status_code}): {payload}")

    raise TimeoutError("Device code login did not complete within timeout.")


def _start_background_poll() -> None:
    token_url = _env("OAUTH_TOKEN_URL")
    client_id = _env("OAUTH_CLIENT_ID")
    client_secret = _env("OAUTH_CLIENT_SECRET", required=False)
    timeout_seconds = int(os.getenv("OAUTH_TIMEOUT_SECONDS", "900").strip() or "900")

    with _STATE_LOCK:
        device_code = _STATE.get("device_code")
        interval = int(_STATE.get("interval") or 5)
        event = _STATE.get("event")

    if not device_code or not isinstance(event, threading.Event):
        return

    def _worker() -> None:
        try:
            token_payload = _poll_device_code_token(
                token_url=token_url,
                client_id=client_id,
                client_secret=client_secret,
                device_code=device_code,
                timeout_seconds=timeout_seconds,
                poll_interval=interval,
            )
            access_token = token_payload.get("access_token")
            if not access_token:
                raise RuntimeError(f"Token payload missing access_token: {token_payload}")

            # Create SimpleChat session
            simplechat_base_url = _env("SIMPLECHAT_BASE_URL", required=False) or "https://localhost:5000"
            simplechat_verify_ssl = os.getenv("SIMPLECHAT_VERIFY_SSL", "true").strip().lower() in ["1", "true", "yes", "y", "on"]
            
            session = requests.Session()
            session.headers.update({"Authorization": f"Bearer {access_token}"})
            
            print(f"[MCP] Creating SimpleChat session at {simplechat_base_url}/external/login")
            print(f"[MCP] Token length: {len(access_token)} chars, first 20: {access_token[:20]}...")
            external_login_response = session.post(
                f"{simplechat_base_url}/external/login",
                verify=simplechat_verify_ssl,
                timeout=30
            )
            
            if external_login_response.status_code != 200:
                print(f"[MCP] SimpleChat /external/login failed: {external_login_response.status_code}")
                print(f"[MCP] Response body: {external_login_response.text}")
                external_login_response.raise_for_status()
            
            external_login_payload = external_login_response.json()
            print(f"[MCP] SimpleChat session created: {external_login_payload.get('session_created')}")

            user_info = external_login_payload.get("user", {})
            all_claims = external_login_payload.get("claims", {})

            with _STATE_LOCK:
                _STATE["access_token"] = access_token
                _STATE["simplechat_session"] = session
                _STATE["user_profile"] = user_info
                _STATE["token_claims"] = all_claims
                _STATE["pending"] = False
                _STATE["error"] = None
            print("[MCP] Device-code token exchange succeeded.")
        except Exception as exc:
            error_msg = str(exc)
            with _STATE_LOCK:
                _STATE["pending"] = False
                _STATE["error"] = error_msg
                # Clear stale auth fields so status returns "none" instead of leaving device_code around
                _STATE["auth_flow"] = None
                _STATE["user_code"] = None
                _STATE["verification_uri"] = None
                _STATE["device_code"] = None
            print(f"[MCP] Device-code login failed: {error_msg}")
        finally:
            event.set()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


@_mcp.tool(name="login_via_oauth")
def login_via_oauth() -> Dict[str, Any]:
    """Start device-code OAuth login.

    Returns device-code instructions (user_code, verification_uri).
    """
    token_url = _env("OAUTH_TOKEN_URL")
    client_id = _env("OAUTH_CLIENT_ID")
    scope = _env("OAUTH_SCOPES")

    device_code_url = os.getenv("OAUTH_DEVICE_CODE_URL", "").strip() or _resolve_device_code_url(token_url)

    device_payload = _request_device_code(device_code_url, client_id, scope)

    device_code = device_payload.get("device_code")
    user_code = device_payload.get("user_code")
    verification_uri = device_payload.get("verification_uri")
    verification_uri_complete = device_payload.get("verification_uri_complete")
    expires_in = device_payload.get("expires_in")
    interval = int(device_payload.get("interval", 5))

    if not device_code or not user_code or not verification_uri:
        raise RuntimeError(f"Device code response missing required fields: {device_payload}")

    # Open browser for convenience.
    try:
        webbrowser.open(verification_uri_complete or verification_uri)
    except Exception as exc:
        print(f"[MCP] webbrowser.open failed: {exc}")

    with _STATE_LOCK:
        event = threading.Event()
        _STATE.update(
            {
                "event": event,
                "pending": True,
                "error": None,
                "auth_flow": "device_code",
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": verification_uri_complete,
                "expires_in": expires_in,
                "interval": interval,
                "access_token": None,
            }
        )

    _start_background_poll()

    message = (
        f"Go to {verification_uri} and enter this code: {user_code}. "
        "Session will be created automatically after you finish sign-in."
    )
    print(f"[MCP] {message}")

    return {
        "auth_flow": "device_code",
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": expires_in,
        "interval": interval,
        "message": message,
    }


@_mcp.tool(name="oauth_login_status")
def oauth_login_status() -> Dict[str, Any]:
    """Return current login status and safe diagnostics."""
    client_secret_value = os.getenv("OAUTH_CLIENT_SECRET", "")
    client_secret_present = bool(client_secret_value.strip())

    with _STATE_LOCK:
        event = _STATE.get("event")
        pending = bool(_STATE.get("pending"))
        error = _STATE.get("error")
        status = "pending" if pending else ("complete" if _STATE.get("access_token") else "none")
        result: Dict[str, Any] = {
            "status": status,
            "pending": pending,
            "error": error,
            "auth_flow": _STATE.get("auth_flow"),
            "user_code": _STATE.get("user_code"),
            "verification_uri": _STATE.get("verification_uri"),
            "verification_uri_complete": _STATE.get("verification_uri_complete"),
            "expires_in": _STATE.get("expires_in"),
            "interval": _STATE.get("interval"),
            "dotenv_path": str(_DOTENV_PATH),
            "dotenv_found": _DOTENV_PATH.exists(),
            "oauth_client_secret_present": client_secret_present,
            "oauth_client_secret_length": len(client_secret_value.strip()) if client_secret_present else 0,
        }

    if isinstance(event, threading.Event) and pending:
        # Don’t block too long; status is meant to be polled.
        pass

    return result


@_mcp.tool(name="show_user_profile")
def show_user_profile() -> Dict[str, Any]:
    """Return SimpleChat user profile from the bearer token claims.

    If not logged in yet, starts login and returns the device-code payload.
    """
    with _STATE_LOCK:
        user_profile = _STATE.get("user_profile")
        token_claims = _STATE.get("token_claims")
        session = _STATE.get("simplechat_session")
        pending = bool(_STATE.get("pending"))
        error = _STATE.get("error")
        event = _STATE.get("event")

    print(f"[MCP] show_user_profile called: has_profile={bool(user_profile)} has_session={bool(session)} pending={pending}")

    if not user_profile:
        # If there's a login in progress, wait for it briefly
        if pending and isinstance(event, threading.Event):
            print("[MCP] Login in progress, waiting up to 15s for profile...")
            event.wait(timeout=15)
            with _STATE_LOCK:
                user_profile = _STATE.get("user_profile")
                token_claims = _STATE.get("token_claims")
                error = _STATE.get("error")
            print(f"[MCP] After wait: has_profile={bool(user_profile)} error={error}")

        if not user_profile:
            if error:
                return {
                    "success": False,
                    "login_required": True,
                    "message": f"Previous login failed: {error}",
                    "error": error,
                    "hint": "Call login_via_oauth to start a fresh login.",
                }
            else:
                # Start a fresh login if none is in progress.
                print("[MCP] No profile and no pending login, starting fresh login...")
                payload = login_via_oauth()
                payload["success"] = False
                payload["login_required"] = True
                return payload

    return {
        "userId": user_profile.get("userId"),
        "displayName": user_profile.get("displayName"),
        "email": user_profile.get("email"),
        "all_token_claims": token_claims or {},
    }


@_mcp.tool(name="list_public_workspaces")
def list_public_workspaces(
    page: int = 1,
    page_size: int = 25,
    search: Optional[str] = None
) -> Dict[str, Any]:
    """Return the authenticated user's public workspaces from SimpleChat.
    
    If not logged in yet, starts login and returns the device-code payload.
    """
    with _STATE_LOCK:
        session = _STATE.get("simplechat_session")
        token = _STATE.get("access_token")
        pending = bool(_STATE.get("pending"))
        error = _STATE.get("error")
        event = _STATE.get("event")

    print(f"[MCP] list_public_workspaces called: has_session={bool(session)} has_token={bool(token)} pending={pending}")

    if not session:
        # If there's a login in progress, wait for it briefly
        if pending and isinstance(event, threading.Event):
            print("[MCP] Login in progress, waiting up to 15s for session...")
            event.wait(timeout=15)
            with _STATE_LOCK:
                session = _STATE.get("simplechat_session")
                error = _STATE.get("error")
            print(f"[MCP] After wait: has_session={bool(session)} error={error}")

        if not session:
            if error:
                return {
                    "success": False,
                    "login_required": True,
                    "message": f"Previous login failed: {error}",
                    "error": error,
                    "hint": "Call login_via_oauth to start a fresh login.",
                }
            else:
                # Start a fresh login if none is in progress.
                print("[MCP] No session and no pending login, starting fresh login...")
                payload = login_via_oauth()
                payload["success"] = False
                payload["login_required"] = True
                return payload

    simplechat_base_url = _env("SIMPLECHAT_BASE_URL", required=False) or "https://localhost:5000"
    simplechat_verify_ssl = os.getenv("SIMPLECHAT_VERIFY_SSL", "true").strip().lower() in ["1", "true", "yes", "y", "on"]

    params: Dict[str, Any] = {
        "page": page,
        "page_size": page_size
    }
    if search:
        params["search"] = search

    url = f"{simplechat_base_url}/api/public_workspaces"
    print(f"[MCP] Calling SimpleChat GET {url}")
    response = session.get(
        url,
        params=params,
        verify=simplechat_verify_ssl,
        timeout=30
    )
    
    if response.status_code != 200:
        try:
            details = response.json()
        except Exception:
            details = {"raw": response.text}
        return {
            "error": "simplechat_request_failed",
            "status_code": response.status_code,
            "details": details,
            "hint": "If this is 401/403, ensure you have completed login_via_oauth.",
        }

    return response.json()


if __name__ == "__main__":
    os.environ["FASTMCP_HOST"] = DEFAULT_MCP_HOST
    os.environ["FASTMCP_PORT"] = str(DEFAULT_MCP_PORT)

    # Streamable HTTP transport is required for MCP Inspector.
    _mcp.run(transport="streamable-http")
