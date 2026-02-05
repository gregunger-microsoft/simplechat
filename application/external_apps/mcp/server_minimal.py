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

import json
import os
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional, cast

import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import Context, FastMCP


_DOTENV_PATH = Path(__file__).resolve().parent / ".env"
if _DOTENV_PATH.exists():
    load_dotenv(dotenv_path=_DOTENV_PATH, override=True)
else:
    load_dotenv(override=True)

DEFAULT_MCP_HOST = "localhost"
DEFAULT_MCP_PORT = 8000
DEFAULT_REQUIRE_MCP_AUTH = os.getenv("MCP_REQUIRE_AUTH", "false").strip().lower() in ["1", "true", "yes", "y", "on"]
DEFAULT_PRM_METADATA_PATH = os.getenv("MCP_PRM_METADATA_PATH", "prm_metadata.json").strip() or "prm_metadata.json"

_env_port = os.getenv("FASTMCP_PORT", "").strip()
if _env_port and _env_port != str(DEFAULT_MCP_PORT):
    print(f"[MCP] Ignoring FASTMCP_PORT={_env_port}; port is fixed at {DEFAULT_MCP_PORT}.")


_mcp = FastMCP("simplechat-mcp-minimal")

# Session cache: bearer_token -> requests.Session
_SESSION_CACHE: Dict[str, requests.Session] = {}
_SESSION_LOCK = threading.Lock()

# Cache the /external/login payload (contains user + claims) per bearer token.
_LOGIN_PAYLOAD_CACHE: Dict[str, Dict[str, Any]] = {}

# Cache bearer token per MCP streamable-http session id. This lets the server reuse
# the PRM-provided bearer token across tool calls even if the client doesn't resend it.
_MCP_SESSION_TOKEN_CACHE: Dict[str, Dict[str, Any]] = {}
_MCP_SESSION_TOKEN_TTL_SECONDS = int(os.getenv("MCP_SESSION_TOKEN_TTL_SECONDS", "3600").strip() or "3600")

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


def _extract_bearer_token(auth_header: str) -> Optional[str]:
    """Extract bearer token from Authorization header."""
    if not auth_header:
        return None
    token = auth_header.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token or None


def _get_bearer_token_from_context(ctx: Optional[Context[Any, Any, Any]]) -> Optional[str]:
    """Extract bearer token from the current request Context.

    This is the canonical way tools should access PRM-provided auth.
    """
    if ctx is None:
        return None

    request_context = getattr(ctx, "request_context", None)
    request = getattr(request_context, "request", None) if request_context else None
    headers = getattr(request, "headers", None) if request else None
    if not headers:
        return None

    auth_header = headers.get("authorization")
    return _extract_bearer_token(auth_header or "")


def _get_or_create_simplechat_session(bearer_token: str) -> requests.Session:
    """Get cached session or create new one via SimpleChat /external/login."""
    with _SESSION_LOCK:
        if bearer_token in _SESSION_CACHE:
            print("[MCP] Using cached SimpleChat session for token")
            return _SESSION_CACHE[bearer_token]
    
    # Create new session
    simplechat_base_url = _env("SIMPLECHAT_BASE_URL", required=False) or "https://localhost:5000"
    simplechat_verify_ssl = os.getenv("SIMPLECHAT_VERIFY_SSL", "true").strip().lower() in ["1", "true", "yes", "y", "on"]
    
    print("[MCP] Creating new SimpleChat session via /external/login")
    
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {bearer_token}"})
    
    # Call SimpleChat /external/login to establish session
    login_url = f"{simplechat_base_url}/external/login"
    try:
        response = session.post(login_url, json={}, verify=simplechat_verify_ssl, timeout=30)
        
        if response.status_code != 200:
            try:
                error_details = response.json()
            except Exception:
                error_details = {"raw": response.text}
            raise RuntimeError(f"SimpleChat login failed ({response.status_code}): {error_details}")
        
        print("[MCP] SimpleChat session created successfully")

        try:
            login_payload: Dict[str, Any] = response.json()
        except Exception:
            login_payload = {}
        
        # Cache the session
        with _SESSION_LOCK:
            _SESSION_CACHE[bearer_token] = session
            if login_payload:
                _LOGIN_PAYLOAD_CACHE[bearer_token] = login_payload
        
        return session
        
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to connect to SimpleChat: {e}")


def _get_cached_login_payload(bearer_token: str) -> Optional[Dict[str, Any]]:
    with _SESSION_LOCK:
        payload = _LOGIN_PAYLOAD_CACHE.get(bearer_token)
    return payload if isinstance(payload, dict) else None


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
def show_user_profile(ctx: Context[Any, Any, Any]) -> Dict[str, Any]:
    """Return SimpleChat user profile from the PRM bearer token.

    This tool must never initiate its own auth flow. It relies exclusively on
    PRM/MCP client authentication and reuses that bearer token.
    """
    bearer_token = _get_bearer_token_from_context(ctx)
    if not bearer_token:
        return {
            "success": False,
            "error": "no_bearer_token",
            "message": "No bearer token available. PRM authentication is required.",
        }

    try:
        _get_or_create_simplechat_session(bearer_token)
    except Exception as e:
        return {
            "success": False,
            "error": "session_creation_failed",
            "message": str(e),
        }

    payload = _get_cached_login_payload(bearer_token) or {}
    user = payload.get("user")
    claims = payload.get("claims")

    if not isinstance(user, dict):
        user = {}
    user = cast(Dict[str, Any], user)
    if not isinstance(claims, dict):
        claims = {}
    claims = cast(Dict[str, Any], claims)

    return {
        "userId": user.get("userId"),
        "displayName": user.get("displayName"),
        "email": user.get("email"),
        "all_token_claims": claims,
    }


@_mcp.tool(name="list_public_workspaces")
def list_public_workspaces(
    ctx: Context[Any, Any, Any],
    page: int = 1,
    page_size: int = 25,
    search: Optional[str] = None
) -> Dict[str, Any]:
    """Return the authenticated user's public workspaces from SimpleChat.
    
    Uses the bearer token from PRM authentication to create a SimpleChat session.
    """
    bearer_token = _get_bearer_token_from_context(ctx)
    
    if not bearer_token:
        return {
            "success": False,
            "error": "no_bearer_token",
            "message": "No bearer token available. Authentication via PRM is required.",
            "hint": "Reconnect to the MCP server and complete PRM auth in the client.",
        }
    
    print("[MCP] Using bearer token from PRM authentication")
    try:
        session = _get_or_create_simplechat_session(bearer_token)
    except Exception as e:
        return {
            "success": False,
            "error": "session_creation_failed",
            "message": str(e),
            "hint": "Ensure your bearer token is valid and SimpleChat is accessible.",
        }

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
            "hint": "If this is 401/403, ensure your PRM bearer token has SimpleChat API access.",
        }

    return response.json()


class _PrmAndAuthShim:
    """ASGI middleware that serves PRM metadata and enforces authentication."""
    
    def __init__(self, app: Any, streamable_path: str, require_auth: bool, prm_metadata_path: str) -> None:
        self._app = app
        self._streamable_path = streamable_path
        self._require_auth = require_auth
        self._prm_metadata_path = prm_metadata_path
    
    def _load_prm_metadata(self) -> Dict[str, Any]:
        candidate_path = Path(self._prm_metadata_path)
        if not candidate_path.is_absolute():
            candidate_path = Path(__file__).resolve().parent / candidate_path
        
        if not candidate_path.exists():
            return {
                "resource": f"http://localhost:{DEFAULT_MCP_PORT}",
                "resource_name": "SimpleChat MCP",
                "authorization_servers": [],
                "scopes_supported": [],
                "bearer_methods_supported": ["header"],
            }
        
        with candidate_path.open("r", encoding="utf-8") as handle:
            data: Any = json.load(handle)

        if isinstance(data, dict):
            return cast(Dict[str, Any], data)
        return {
            "resource": f"http://localhost:{DEFAULT_MCP_PORT}",
            "resource_name": "SimpleChat MCP",
            "authorization_servers": [],
            "scopes_supported": [],
            "bearer_methods_supported": ["header"],
        }
    
    @staticmethod
    def _get_request_origin(scope: Dict[str, Any]) -> str:
        scheme = (scope.get("scheme") or "http").strip() or "http"
        headers_list = list(scope.get("headers", []))
        host_values = [value for (key, value) in headers_list if (key or b"").lower() == b"host"]
        host = b"".join(host_values).decode("utf-8", errors="ignore").strip()
        if not host:
            host = f"localhost:{DEFAULT_MCP_PORT}"
        return f"{scheme}://{host}"
    
    async def _send_json(self, send: Any, status: int, payload: Dict[str, Any], headers: Optional[list[tuple[bytes, bytes]]] = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        response_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        if headers:
            response_headers.extend(headers)
        
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": response_headers,
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
    
    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        
        path = scope.get("path") or ""
        method = scope.get("method") or ""
        
        origin = self._get_request_origin(scope)
        prm_url = f"{origin}/.well-known/oauth-protected-resource"
        streamable_path = (self._streamable_path or "").rstrip("/")
        normalized_path = path.rstrip("/")
        
        # Serve PRM metadata
        if method == "GET" and path == "/.well-known/oauth-protected-resource":
            prm = self._load_prm_metadata()
            prm["resource"] = f"{origin}{streamable_path}"
            await self._send_json(send, 200, prm)
            return

        # Enforce authentication for MCP endpoints (this is what triggers PRM handshake).
        is_mcp_path = normalized_path == streamable_path or path.startswith(streamable_path + "/")
        if self._require_auth and is_mcp_path:
            headers_list = list(scope.get("headers", []))

            # 1) Try Authorization header
            auth_values = [value for (key, value) in headers_list if (key or b"").lower() == b"authorization"]
            auth_header_bytes = b"".join(auth_values).strip()
            auth_header = auth_header_bytes.decode("utf-8", errors="ignore") if auth_header_bytes else ""
            bearer_token = _extract_bearer_token(auth_header)

            # 2) If missing, try cached token via MCP session id header
            session_id_values = [value for (key, value) in headers_list if (key or b"").lower() == b"mcp-session-id"]
            mcp_session_id = b"".join(session_id_values).decode("utf-8", errors="ignore").strip() if session_id_values else ""

            if not bearer_token and mcp_session_id:
                with _SESSION_LOCK:
                    cached = _MCP_SESSION_TOKEN_CACHE.get(mcp_session_id)
                if isinstance(cached, dict):
                    cached_token = cached.get("bearer_token")
                    expires_at = cached.get("expires_at")
                    if isinstance(expires_at, (int, float)) and expires_at < time.time():
                        with _SESSION_LOCK:
                            _MCP_SESSION_TOKEN_CACHE.pop(mcp_session_id, None)
                    elif isinstance(cached_token, str) and cached_token.strip():
                        bearer_token = cached_token.strip()
                        # Inject Authorization header into scope so tools can read it via Context
                        scope_headers = list(scope.get("headers", []))
                        scope_headers.append((b"authorization", f"Bearer {bearer_token}".encode("utf-8")))
                        scope["headers"] = scope_headers

            has_token = bool(bearer_token)
            print(
                f"[MCP PRM] {method} {path} - has_bearer_token={has_token} has_mcp_session_id={bool(mcp_session_id)}"
            )

            if not has_token:
                link_target = f'<{prm_url}>; rel="oauth-protected-resource"'.encode("utf-8")
                # Keep this header minimal and PRM-focused so clients can discover metadata and reuse auth silently.
                scope_hint = ""
                try:
                    prm = self._load_prm_metadata()
                    scopes = prm.get("scopes_supported")
                    if isinstance(scopes, list) and scopes and isinstance(scopes[0], str) and scopes[0].strip():
                        scope_hint = scopes[0].strip()
                except Exception:
                    scope_hint = ""

                if scope_hint:
                    www_auth = f'Bearer resource_metadata="{prm_url}", scope="{scope_hint}"'.encode("utf-8")
                else:
                    www_auth = f'Bearer resource_metadata="{prm_url}"'.encode("utf-8")
                await self._send_json(
                    send,
                    401,
                    {
                        "error": "unauthorized",
                        "message": "Authorization required to use this MCP server.",
                        "hint": "Complete PRM auth in the client; the server will cache the token after the first authenticated request.",
                    },
                    headers=[
                        (b"www-authenticate", www_auth),
                        (b"link", link_target),
                    ],
                )
                return

            # If we have a bearer token, capture the MCP session id from either the request
            # (mcp-session-id header) or the response (base transport may assign it).
            if bearer_token:
                if mcp_session_id:
                    with _SESSION_LOCK:
                        _MCP_SESSION_TOKEN_CACHE[mcp_session_id] = {
                            "bearer_token": bearer_token,
                            "expires_at": time.time() + _MCP_SESSION_TOKEN_TTL_SECONDS,
                        }

                async def send_capture_session_id(message: Dict[str, Any]) -> None:
                    if message.get("type") == "http.response.start":
                        resp_headers = list(message.get("headers", []))
                        resp_session_values = [
                            value
                            for (key, value) in resp_headers
                            if (key or b"").lower() == b"mcp-session-id"
                        ]
                        resp_session_id = (
                            b"".join(resp_session_values).decode("utf-8", errors="ignore").strip()
                            if resp_session_values
                            else ""
                        )
                        if resp_session_id:
                            with _SESSION_LOCK:
                                _MCP_SESSION_TOKEN_CACHE[resp_session_id] = {
                                    "bearer_token": bearer_token,
                                    "expires_at": time.time() + _MCP_SESSION_TOKEN_TTL_SECONDS,
                                }
                    await send(message)

                await self._app(scope, receive, send_capture_session_id)
                return
        
        await self._app(scope, receive, send)


if __name__ == "__main__":
    os.environ["FASTMCP_HOST"] = DEFAULT_MCP_HOST
    os.environ["FASTMCP_PORT"] = str(DEFAULT_MCP_PORT)

    print(f"[MCP] Starting server with MCP_REQUIRE_AUTH={DEFAULT_REQUIRE_MCP_AUTH}")
    print(f"[MCP] PRM metadata path: {DEFAULT_PRM_METADATA_PATH}")

    # Streamable HTTP transport is required for MCP Inspector.
    if DEFAULT_REQUIRE_MCP_AUTH:
        import uvicorn
        
        base_app = _mcp.streamable_http_app()
        wrapped_app = _PrmAndAuthShim(
            app=base_app,
            streamable_path="/mcp",
            require_auth=DEFAULT_REQUIRE_MCP_AUTH,
            prm_metadata_path=DEFAULT_PRM_METADATA_PATH,
        )
        
        print(f"[MCP] Server starting on http://{DEFAULT_MCP_HOST}:{DEFAULT_MCP_PORT}/mcp (with PRM authentication)")
        uvicorn.run(wrapped_app, host=DEFAULT_MCP_HOST, port=DEFAULT_MCP_PORT, log_level="info")
    else:
        print(f"[MCP] Server starting on http://{DEFAULT_MCP_HOST}:{DEFAULT_MCP_PORT}/mcp (no authentication)")
        _mcp.run(transport="streamable-http")
