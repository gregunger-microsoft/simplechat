# server.py
"""SimpleChat MCP server using FastMCP with PRM-style bearer authorization."""

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from dotenv import load_dotenv
from mcp import UrlElicitationRequiredError
from mcp.server.fastmcp import FastMCP
from mcp.types import ElicitRequestURLParams

# Force .env values to override any inherited process env vars.
# Load the .env that sits next to this server file to avoid relying on CWD.
_dotenv_path = Path(__file__).resolve().parent / ".env"
if _dotenv_path.exists():
    load_dotenv(dotenv_path=_dotenv_path, override=True)
else:
    load_dotenv(override=True)

DEFAULT_BASE_URL = os.getenv("SIMPLECHAT_BASE_URL", "https://localhost:5000").rstrip("/")
DEFAULT_VERIFY_SSL = os.getenv("SIMPLECHAT_VERIFY_SSL", "true").strip().lower() in ["1", "true", "yes", "y", "on"]
DEFAULT_MCP_HOST = os.getenv("FASTMCP_HOST", "0.0.0.0").strip() or "0.0.0.0"
DEFAULT_MCP_PORT = 8000
DEFAULT_OAUTH_USE_DEVICE_CODE = os.getenv("OAUTH_USE_DEVICE_CODE", "false").strip().lower() in ["1", "true", "yes", "y", "on"]
DEFAULT_OAUTH_REDIRECT_PORT = int(os.getenv("OAUTH_REDIRECT_PORT", "53682"))
DEFAULT_OAUTH_TIMEOUT_SECONDS = int(os.getenv("OAUTH_TIMEOUT_SECONDS", "180"))
DEFAULT_REQUIRE_MCP_AUTH = os.getenv("MCP_REQUIRE_AUTH", "false").strip().lower() in ["1", "true", "yes", "y", "on"]
DEFAULT_PRM_METADATA_PATH = os.getenv("MCP_PRM_METADATA_PATH", "prm_metadata.json").strip() or "prm_metadata.json"

_env_port = os.getenv("FASTMCP_PORT", "").strip()
if _env_port and _env_port != str(DEFAULT_MCP_PORT):
    print(f"[SimpleChat MCP] Ignoring FASTMCP_PORT={_env_port}; port is fixed at {DEFAULT_MCP_PORT}.")

_SESSION_CACHE: Dict[str, requests.Session] = {}
_SESSION_LOCK = threading.Lock()
_LAST_ACCESS_TOKEN_BY_BASE_URL: Dict[str, str] = {}
_LAST_SESSION_BY_BASE_URL: Dict[str, requests.Session] = {}
_DEVICE_CODE_LOCK = threading.Lock()
_LOGIN_STATUS_BY_BASE_URL: Dict[str, Dict[str, Any]] = {}
_LOGIN_STATUS_LOCK = threading.Lock()


def _try_extract_tenant_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    match = re.search(r"login\.microsoftonline\.com/([^/]+)/", url)
    if match:
        tenant = match.group(1).strip()
        return tenant or None
    return None


def _try_get_graph_token_via_obo(user_access_token: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    try:
        import msal
    except Exception as exc:
        return None, {"error": "msal_not_available", "message": str(exc)}

    authorization_url = os.getenv("OAUTH_AUTHORIZATION_URL", "").strip()
    token_url = os.getenv("OAUTH_TOKEN_URL", "").strip()
    client_id = os.getenv("OAUTH_CLIENT_ID", "").strip()
    client_secret = os.getenv("OAUTH_CLIENT_SECRET", "").strip()
    tenant_id = os.getenv("OAUTH_TENANT_ID", "").strip()

    if not tenant_id:
        tenant_id = _try_extract_tenant_from_url(token_url) or _try_extract_tenant_from_url(authorization_url) or ""

    if not tenant_id or not client_id or not client_secret:
        return None, {
            "error": "obo_not_configured",
            "message": "OBO requires OAUTH_TENANT_ID (or a tenant in OAUTH_TOKEN_URL/OAUTH_AUTHORIZATION_URL), OAUTH_CLIENT_ID, and OAUTH_CLIENT_SECRET."
        }

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scopes_raw = os.getenv("GRAPH_OBO_SCOPES", "https://graph.microsoft.com/User.Read").strip()
    scopes = [scope for scope in scopes_raw.split() if scope.strip()]
    if not scopes:
        scopes = ["https://graph.microsoft.com/User.Read"]

    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=authority,
    )

    result = app.acquire_token_on_behalf_of(user_assertion=user_access_token, scopes=scopes)
    access_token = result.get("access_token")
    if not access_token:
        return None, result
    return access_token, None


def _extract_bearer_token(access_token: Optional[str]) -> Optional[str]:
    if not access_token:
        return None
    token = access_token.strip()
    if not token:
        return None
    if token.lower().startswith("bearer "):
        token = token[len("bearer "):].strip()
    return token or None


def _try_extract_claims_challenge(www_authenticate: str) -> Optional[str]:
    if not www_authenticate:
        return None
    match = re.search(r'claims="([^"]+)"', www_authenticate)
    if match:
        return match.group(1)
    return None


def _start_login_wait(base_url: str) -> threading.Event:
    event = threading.Event()
    with _LOGIN_STATUS_LOCK:
        _LOGIN_STATUS_BY_BASE_URL[base_url] = {"event": event, "error": None}
    return event


def _finish_login_wait(base_url: str, error: Optional[str]) -> None:
    with _LOGIN_STATUS_LOCK:
        entry = _LOGIN_STATUS_BY_BASE_URL.get(base_url)
        if entry:
            entry["error"] = error
            event = entry.get("event")
            if isinstance(event, threading.Event):
                event.set()


def _get_login_status(base_url: str) -> Optional[Dict[str, Any]]:
    with _LOGIN_STATUS_LOCK:
        return _LOGIN_STATUS_BY_BASE_URL.get(base_url)


def _update_login_status(base_url: str, updates: Dict[str, Any]) -> None:
    if not updates:
        return
    with _LOGIN_STATUS_LOCK:
        entry = _LOGIN_STATUS_BY_BASE_URL.get(base_url)
        if entry is not None:
            entry.update(updates)


def _start_device_code_background_poll(
    base_url: str,
    verify_ssl: bool,
    token_url: str,
    client_id: str,
    device_code: str,
    client_secret: str,
    timeout_seconds: int,
    poll_interval: int
) -> None:
    def _worker() -> None:
        try:
            token_payload = _poll_device_code_token(
                token_url=token_url,
                client_id=client_id,
                device_code=device_code,
                timeout_seconds=timeout_seconds,
                poll_interval=poll_interval,
                client_secret=client_secret or ""
            )
            access_token = token_payload.get("access_token")
            if not access_token:
                _finish_login_wait(base_url, "Token response missing access_token.")
                return
            session, _ = _create_session(access_token, base_url, verify_ssl)
            cache_key = _session_cache_key(access_token, base_url)
            with _SESSION_LOCK:
                _SESSION_CACHE[cache_key] = session
            _store_last_token(base_url, access_token)
            _store_last_session(base_url, session)
            _finish_login_wait(base_url, None)
        except Exception as exc:
            error_text = str(exc)
            print(f"[SimpleChat MCP] Device code login failed: {error_text}")
            _finish_login_wait(base_url, error_text)
            return

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()



mcp = FastMCP("SimpleChat MCP", host=DEFAULT_MCP_HOST, port=DEFAULT_MCP_PORT)


class _AcceptHeaderShim:
    def __init__(self, app: Any, streamable_path: str) -> None:
        self._app = app
        self._streamable_path = streamable_path

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") == "http" and scope.get("method") == "GET" and scope.get("path") == self._streamable_path:
            headers = list(scope.get("headers", []))
            accept_values = [value for (key, value) in headers if key == b"accept"]
            accept_header = b",".join(accept_values)
            if b"text/event-stream" not in accept_header:
                headers.append((b"accept", b"text/event-stream"))
                scope = dict(scope)
                scope["headers"] = headers

        await self._app(scope, receive, send)


class _PrmAndAuthShim:
    def __init__(
        self,
        app: Any,
        streamable_path: str,
        require_auth: bool,
        prm_metadata_path: str,
    ) -> None:
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
            data = json.load(handle)

        if isinstance(data, dict):
            return data
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

        if method == "GET" and path == "/.well-known/oauth-protected-resource":
            prm = self._load_prm_metadata()
            if isinstance(prm, dict):
                prm["resource"] = f"{origin}{streamable_path}"
            await self._send_json(send, 200, prm)
            return

        if self._require_auth and normalized_path == streamable_path:
            headers_list = list(scope.get("headers", []))
            auth_values = [value for (key, value) in headers_list if (key or b"").lower() == b"authorization"]
            auth_header = b"".join(auth_values).strip()
            if not auth_header:
                link_target = f"<{prm_url}>; rel=\"oauth-protected-resource\"".encode("utf-8")
                www_auth = f"Bearer realm=\"SimpleChat MCP\", resource_metadata=\"{prm_url}\"".encode("utf-8")
                await self._send_json(
                    send,
                    401,
                    {
                        "error": "unauthorized",
                        "message": "Authorization required to use this MCP server.",
                        "hint": "If your client supports MCP Authorization + PRM, it should prompt you to sign in.",
                    },
                    headers=[
                        (b"www-authenticate", www_auth),
                        (b"link", link_target),
                    ],
                )
                return

        await self._app(scope, receive, send)


def _session_cache_key(access_token: str, base_url: str) -> str:
    token_hash = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    return f"{base_url}:{token_hash}"


def _create_session(access_token: str, base_url: str, verify_ssl: bool) -> Tuple[requests.Session, Dict[str, Any]]:
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {access_token}"})

    response = session.post(
        f"{base_url}/external/login",
        verify=verify_ssl,
        timeout=30
    )
    response.raise_for_status()
    return session, response.json()


def _create_session_from_auth_code(
    base_url: str,
    verify_ssl: bool,
    code: str,
    redirect_uri: str
) -> Tuple[requests.Session, Dict[str, Any]]:
    session = requests.Session()
    response = session.get(
        f"{base_url}/getATokenApi",
        params={
            "code": code,
            "create_session": "true",
            "redirect_uri": redirect_uri
        },
        verify=verify_ssl,
        timeout=30
    )
    response.raise_for_status()
    return session, response.json()


def _store_last_token(base_url: str, access_token: str) -> None:
    with _SESSION_LOCK:
        _LAST_ACCESS_TOKEN_BY_BASE_URL[base_url] = access_token


def _store_last_session(base_url: str, session: requests.Session) -> None:
    with _SESSION_LOCK:
        _LAST_SESSION_BY_BASE_URL[base_url] = session


def _build_pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _build_pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def _build_oauth_authorization_url(
    authorization_url: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: str,
    state: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{authorization_url}?{urllib.parse.urlencode(params)}"


def _resolve_device_code_url(token_url: str, device_code_url: str) -> str:
    if device_code_url:
        return device_code_url
    if not token_url:
        return ""
    if token_url.endswith("/oauth2/v2.0/token"):
        return token_url.replace("/oauth2/v2.0/token", "/oauth2/v2.0/devicecode")
    if token_url.endswith("/oauth2/token"):
        return token_url.replace("/oauth2/token", "/oauth2/devicecode")
    return ""


def _request_device_code(device_code_url: str, client_id: str, scope: str) -> Dict[str, Any]:
    response = requests.post(
        device_code_url,
        data={
            "client_id": client_id,
            "scope": scope
        },
        timeout=30
    )
    response.raise_for_status()
    return response.json()


def _poll_device_code_token(
    token_url: str,
    client_id: str,
    device_code: str,
    timeout_seconds: int,
    poll_interval: int,
    client_secret: str = ""
) -> Dict[str, Any]:
    start_time = time.time()
    interval = max(1, poll_interval)

    resolved_secret = (client_secret or os.getenv("OAUTH_CLIENT_SECRET", "")).strip()
    logged_secret_usage = False
    logged_request_shape = False

    while time.time() - start_time < timeout_seconds:
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code
        }

        auth = None
        client_auth_method = "none"
        if resolved_secret:
            # Prefer client_secret_basic to avoid environments where client_secret_post isn't recognized.
            auth = (client_id, resolved_secret)
            client_auth_method = "basic"

        if not logged_secret_usage:
            print(
                "[SimpleChat MCP] Device code token polling started. "
                f"client_auth_method={client_auth_method} "
                f"client_secret_length={len(resolved_secret) if resolved_secret else 0}"
            )
            logged_secret_usage = True

        if not logged_request_shape:
            try:
                prepared = requests.Request("POST", token_url, data=data).prepare()
                body_text = prepared.body.decode("utf-8", errors="ignore") if isinstance(prepared.body, (bytes, bytearray)) else str(prepared.body or "")
                has_client_secret_in_body = "client_secret=" in body_text
            except Exception:
                has_client_secret_in_body = False

            _update_login_status(
                base_url=os.getenv("SIMPLECHAT_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
                updates={
                    "token_request_has_client_secret_key": "client_secret" in data,
                    "token_request_client_secret_length": len(resolved_secret) if resolved_secret else 0,
                    "token_request_body_has_client_secret": has_client_secret_in_body,
                    "token_request_client_auth_method": client_auth_method,
                },
            )
            logged_request_shape = True

        response = requests.post(token_url, data=data, auth=auth, timeout=30)
        if response.status_code == 200:
            return response.json()

        payload: Dict[str, Any] = {}
        try:
            payload = response.json()
        except ValueError:
            response.raise_for_status()

        error = payload.get("error", "").lower()
        if error == "authorization_pending":
            time.sleep(interval)
            continue
        if error == "slow_down":
            interval += 5
            time.sleep(interval)
            continue
        if error == "expired_token":
            raise TimeoutError("OAuth device code expired before login completed.")

        error_description = payload.get("error_description") or payload.get("message") or ""
        hint = ""
        if response.status_code == 401 and "AADSTS7000218" in error_description:
            hint = " Hint: your app registration requires a client secret; verify OAUTH_CLIENT_SECRET is set in application/external_apps/mcp/.env and not overridden by an empty env var."

        raise RuntimeError(
            (
                f"OAuth device code token exchange failed ({response.status_code}): "
                f"{payload.get('error') or 'unknown_error'} {error_description}".strip()
                + hint
            )
        )

    raise TimeoutError("OAuth device code login did not complete within the allowed time.")




def _wait_for_oauth_code(redirect_port: int, expected_state: str, timeout_seconds: int) -> str:
    code_result: Dict[str, str] = {}
    done = threading.Event()

    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                return

            params = urllib.parse.parse_qs(parsed.query)
            code = params.get("code", [""])[0]
            state = params.get("state", [""])[0]
            error = params.get("error", [""])[0]

            if error:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f"OAuth error: {error}".encode("utf-8"))
                done.set()
                return

            if not code or state != expected_state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid authorization response")
                done.set()
                return

            code_result["code"] = code
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Login complete. You can close this window.")
            done.set()

    server = HTTPServer(("localhost", redirect_port), CallbackHandler)

    def _serve() -> None:
        server.handle_request()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        if done.is_set():
            break
        time.sleep(0.1)

    server.server_close()

    if not done.is_set() or "code" not in code_result:
        raise TimeoutError("OAuth login did not complete within the allowed time.")

    return code_result["code"]


def _get_session(access_token: str, base_url: str, verify_ssl: bool) -> requests.Session:
    cache_key = _session_cache_key(access_token, base_url)
    with _SESSION_LOCK:
        cached = _SESSION_CACHE.get(cache_key)
        if cached:
            return cached

        session, _ = _create_session(access_token, base_url, verify_ssl)
        _SESSION_CACHE[cache_key] = session
        return session


@mcp.tool(name="login")
def login(access_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a SimpleChat session using an Entra bearer token.
    """
    resolved_base_url = DEFAULT_BASE_URL.rstrip("/")
    resolved_verify_ssl = DEFAULT_VERIFY_SSL

    if not access_token or not access_token.strip():
        login_url = f"{resolved_base_url}/login"
        raise UrlElicitationRequiredError(
            [
                ElicitRequestURLParams(
                    mode="url",
                    message="Sign in to SimpleChat to obtain a bearer token, then retry with access_token.",
                    url=login_url,
                    elicitationId="simplechat-login",
                )
            ],
            message=f"Authentication required. Open {login_url} to sign in.",
        )

    session, payload = _create_session(access_token, resolved_base_url, resolved_verify_ssl)
    cache_key = _session_cache_key(access_token, resolved_base_url)
    with _SESSION_LOCK:
        _SESSION_CACHE[cache_key] = session
    _store_last_token(resolved_base_url, access_token)
    _store_last_session(resolved_base_url, session)
    return payload


@mcp.tool(name="login_via_oauth")
def login_via_oauth() -> Dict[str, Any]:
    """
    Interactive OAuth login with PKCE.
    Opens a browser to authorize and exchanges the code for an access token.
    """
    resolved_base_url = DEFAULT_BASE_URL.rstrip("/")
    resolved_verify_ssl = DEFAULT_VERIFY_SSL

    resolved_authorization_url = os.getenv("OAUTH_AUTHORIZATION_URL", "").strip()
    resolved_token_url = os.getenv("OAUTH_TOKEN_URL", "").strip()
    resolved_client_id = os.getenv("OAUTH_CLIENT_ID", "").strip()
    resolved_client_secret = os.getenv("OAUTH_CLIENT_SECRET", "").strip()
    resolved_scope = os.getenv("OAUTH_SCOPES", "").strip()
    resolved_redirect_port = DEFAULT_OAUTH_REDIRECT_PORT
    resolved_use_device_code = DEFAULT_OAUTH_USE_DEVICE_CODE
    resolved_device_code_url = _resolve_device_code_url(
        resolved_token_url,
        os.getenv("OAUTH_DEVICE_CODE_URL", "").strip()
    )

    if not resolved_authorization_url or not resolved_token_url or not resolved_client_id or not resolved_scope:
        raise ValueError("OAuth configuration missing. Set OAUTH_AUTHORIZATION_URL, OAUTH_TOKEN_URL, OAUTH_CLIENT_ID, and OAUTH_SCOPES.")

    if resolved_use_device_code:
        if not resolved_device_code_url:
            raise ValueError("Device code flow enabled but device code URL could not be resolved. Set OAUTH_DEVICE_CODE_URL.")

        device_payload = _request_device_code(resolved_device_code_url, resolved_client_id, resolved_scope)
        device_code = device_payload.get("device_code")
        user_code = device_payload.get("user_code")
        verification_uri = device_payload.get("verification_uri")
        verification_uri_complete = device_payload.get("verification_uri_complete")
        interval = int(device_payload.get("interval", 5))

        if not device_code or not user_code or not verification_uri:
            raise ValueError("OAuth device code response missing device_code, user_code, or verification_uri.")

        if verification_uri_complete:
            webbrowser.open(verification_uri_complete)
        else:
            webbrowser.open(verification_uri)

        _start_login_wait(resolved_base_url)
        _update_login_status(
            resolved_base_url,
            {
                "auth_flow": "device_code",
                "user_code": user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": verification_uri_complete,
                "expires_in": device_payload.get("expires_in"),
                "interval": interval,
            },
        )
        _start_device_code_background_poll(
            base_url=resolved_base_url,
            verify_ssl=resolved_verify_ssl,
            token_url=resolved_token_url,
            client_id=resolved_client_id,
            device_code=device_code,
            client_secret=resolved_client_secret,
            timeout_seconds=DEFAULT_OAUTH_TIMEOUT_SECONDS,
            poll_interval=interval,
        )

        device_message = (
            f"Go to {verification_uri} and enter this code: {user_code}. "
            "Session will be created automatically after you finish sign-in."
        )
        print(f"[SimpleChat MCP] Device code login started. {device_message}")

        return {
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": device_payload.get("expires_in"),
            "interval": interval,
            "message": device_message,
        }

    redirect_uri = f"http://localhost:{resolved_redirect_port}/callback"
    verifier = _build_pkce_verifier()
    challenge = _build_pkce_challenge(verifier)
    state = secrets.token_urlsafe(16)

    auth_url = _build_oauth_authorization_url(
        resolved_authorization_url,
        resolved_client_id,
        redirect_uri,
        resolved_scope,
        challenge,
        state,
    )

    webbrowser.open(auth_url)
    code = _wait_for_oauth_code(resolved_redirect_port, state, DEFAULT_OAUTH_TIMEOUT_SECONDS)
    session, payload = _create_session_from_auth_code(
        resolved_base_url,
        resolved_verify_ssl,
        code,
        redirect_uri
    )

    access_token = _extract_bearer_token(payload.get("access_token"))
    if access_token:
        try:
            sso_session, sso_payload = _create_session(access_token, resolved_base_url, resolved_verify_ssl)
        except Exception as exc:
            raise RuntimeError(
                "OAuth token exchange succeeded, but SimpleChat session creation via /external/login failed. "
                "Ensure your OAuth scopes/token audience match the SimpleChat API and include required roles."
            ) from exc

        cache_key = _session_cache_key(access_token, resolved_base_url)
        with _SESSION_LOCK:
            _SESSION_CACHE[cache_key] = sso_session

        _store_last_token(resolved_base_url, access_token)
        _store_last_session(resolved_base_url, sso_session)
        payload["simplechat_session_created"] = True
        payload["simplechat_session"] = sso_payload
        return payload

    _store_last_session(resolved_base_url, session)
    return payload


def _ensure_device_code_login_started(base_url: str, verify_ssl: bool) -> Dict[str, Any]:
    resolved_authorization_url = os.getenv("OAUTH_AUTHORIZATION_URL", "").strip()
    resolved_token_url = os.getenv("OAUTH_TOKEN_URL", "").strip()
    resolved_client_id = os.getenv("OAUTH_CLIENT_ID", "").strip()
    resolved_client_secret = os.getenv("OAUTH_CLIENT_SECRET", "").strip()
    resolved_scope = os.getenv("OAUTH_SCOPES", "").strip()
    resolved_device_code_url = _resolve_device_code_url(
        resolved_token_url,
        os.getenv("OAUTH_DEVICE_CODE_URL", "").strip(),
    )

    if not resolved_authorization_url or not resolved_token_url or not resolved_client_id or not resolved_scope:
        raise ValueError(
            "OAuth configuration missing. Set OAUTH_AUTHORIZATION_URL, OAUTH_TOKEN_URL, OAUTH_CLIENT_ID, and OAUTH_SCOPES."
        )
    if not resolved_device_code_url:
        raise ValueError("Device code flow enabled but device code URL could not be resolved. Set OAUTH_DEVICE_CODE_URL.")

    with _DEVICE_CODE_LOCK:
        existing = _get_login_status(base_url) or {}
        event = existing.get("event")
        if isinstance(event, threading.Event) and not event.is_set():
            user_code = existing.get("user_code")
            verification_uri = existing.get("verification_uri")
            verification_uri_complete = existing.get("verification_uri_complete")
            if user_code and verification_uri:
                return {
                    "login_required": True,
                    "auth_flow": "device_code",
                    "user_code": user_code,
                    "verification_uri": verification_uri,
                    "verification_uri_complete": verification_uri_complete,
                    "expires_in": existing.get("expires_in"),
                    "interval": existing.get("interval"),
                    "message": f"Go to {verification_uri} and enter this code: {user_code}.",
                }

        device_payload = _request_device_code(resolved_device_code_url, resolved_client_id, resolved_scope)
        device_code = device_payload.get("device_code")
        user_code = device_payload.get("user_code")
        verification_uri = device_payload.get("verification_uri")
        verification_uri_complete = device_payload.get("verification_uri_complete")
        interval = int(device_payload.get("interval", 5))

        if not device_code or not user_code or not verification_uri:
            raise ValueError("OAuth device code response missing device_code, user_code, or verification_uri.")

        if verification_uri_complete:
            webbrowser.open(verification_uri_complete)
        else:
            webbrowser.open(verification_uri)

        _start_login_wait(base_url)
        _update_login_status(
            base_url,
            {
                "auth_flow": "device_code",
                "user_code": user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": verification_uri_complete,
                "expires_in": device_payload.get("expires_in"),
                "interval": interval,
            },
        )
        _start_device_code_background_poll(
            base_url=base_url,
            verify_ssl=verify_ssl,
            token_url=resolved_token_url,
            client_id=resolved_client_id,
            device_code=device_code,
            client_secret=resolved_client_secret,
            timeout_seconds=DEFAULT_OAUTH_TIMEOUT_SECONDS,
            poll_interval=interval,
        )

        device_message = (
            f"Go to {verification_uri} and enter this code: {user_code}. "
            "Session will be created automatically after you finish sign-in."
        )
        print(f"[SimpleChat MCP] Device code login started. {device_message}")

        return {
            "login_required": True,
            "auth_flow": "device_code",
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": device_payload.get("expires_in"),
            "interval": interval,
            "message": device_message,
        }


@mcp.tool(name="list_public_workspaces")
def list_public_workspaces(
    page: int = 1,
    page_size: int = 25,
    search: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return the authenticated user's public workspaces from SimpleChat.
    """
    resolved_base_url = DEFAULT_BASE_URL.rstrip("/")
    resolved_verify_ssl = DEFAULT_VERIFY_SSL

    resolved_access_token = None
    with _SESSION_LOCK:
        resolved_access_token = _LAST_ACCESS_TOKEN_BY_BASE_URL.get(resolved_base_url)

    if not resolved_access_token:
        login_status = _get_login_status(resolved_base_url)
        if login_status:
            event = login_status.get("event")
            if isinstance(event, threading.Event) and not event.is_set():
                event.wait(timeout=15)
            with _SESSION_LOCK:
                resolved_access_token = _LAST_ACCESS_TOKEN_BY_BASE_URL.get(resolved_base_url)
            if not resolved_access_token and login_status.get("error"):
                return {
                    "success": False,
                    "error": "oauth_login_failed",
                    "message": str(login_status.get("error")),
                }
            if not resolved_access_token and isinstance(event, threading.Event) and not event.is_set():
                user_code = login_status.get("user_code")
                verification_uri = login_status.get("verification_uri")
                if user_code and verification_uri:
                    return {
                        "success": False,
                        "login_required": True,
                        "auth_flow": "device_code",
                        "user_code": user_code,
                        "verification_uri": verification_uri,
                        "verification_uri_complete": login_status.get("verification_uri_complete"),
                        "expires_in": login_status.get("expires_in"),
                        "interval": login_status.get("interval"),
                        "message": f"Go to {verification_uri} and enter this code: {user_code}.",
                    }

    if resolved_access_token:
        session = _get_session(resolved_access_token, resolved_base_url, resolved_verify_ssl)
        _store_last_session(resolved_base_url, session)
    else:
        with _SESSION_LOCK:
            cached_session = _LAST_SESSION_BY_BASE_URL.get(resolved_base_url)
        if cached_session:
            session = cached_session
        else:
            if DEFAULT_OAUTH_USE_DEVICE_CODE:
                payload = _ensure_device_code_login_started(resolved_base_url, resolved_verify_ssl)
                payload["success"] = False
                return payload

            login_url = f"{resolved_base_url}/login"
            raise UrlElicitationRequiredError(
                [
                    ElicitRequestURLParams(
                        mode="url",
                        message="Authentication required. Run login_via_oauth and complete sign-in, then retry.",
                        url=login_url,
                        elicitationId="simplechat-login",
                    )
                ],
                message=f"Authentication required. Open {login_url} or run login_via_oauth, then retry.",
            )


    params: Dict[str, Any] = {
        "page": page,
        "page_size": page_size
    }
    if search:
        params["search"] = search

    response = session.get(
        f"{resolved_base_url}/api/public_workspaces",
        params=params,
        verify=resolved_verify_ssl,
        timeout=30
    )
    response.raise_for_status()
    return response.json()


@mcp.tool(name="oauth_login_status")
def oauth_login_status() -> Dict[str, Any]:
    """Returns current OAuth login status (including device-code details if applicable)."""
    resolved_base_url = DEFAULT_BASE_URL.rstrip("/")

    client_secret_value = os.getenv("OAUTH_CLIENT_SECRET", "")
    client_secret_present = bool(client_secret_value and client_secret_value.strip())

    login_status = _get_login_status(resolved_base_url)
    if not login_status:
        return {
            "status": "none",
            "pending": False,
            "error": None,
            "oauth_client_secret_present": client_secret_present,
            "oauth_client_secret_length": len(client_secret_value.strip()) if client_secret_present else 0,
            "dotenv_path": str(_dotenv_path),
            "dotenv_found": _dotenv_path.exists(),
        }

    event = login_status.get("event")
    pending = isinstance(event, threading.Event) and not event.is_set()

    return {
        "status": "pending" if pending else "complete",
        "pending": pending,
        "error": login_status.get("error"),
        "auth_flow": login_status.get("auth_flow"),
        "user_code": login_status.get("user_code"),
        "verification_uri": login_status.get("verification_uri"),
        "verification_uri_complete": login_status.get("verification_uri_complete"),
        "expires_in": login_status.get("expires_in"),
        "interval": login_status.get("interval"),
        "oauth_client_secret_present": client_secret_present,
        "oauth_client_secret_length": len(client_secret_value.strip()) if client_secret_present else 0,
        "dotenv_path": str(_dotenv_path),
        "dotenv_found": _dotenv_path.exists(),
    }


@mcp.tool(name="show_user_profile")
def show_user_profile(
    access_token: Optional[str] = None,
    use_last_token: bool = True,
    graph_base_url: Optional[str] = None
) -> Dict[str, Any]:
    """Retrieves the current user's profile information from Microsoft Graph.

    Notes:
    - Pass a Microsoft Graph access token (scope like User.Read) via `access_token`.
    - If `use_last_token` is true and `access_token` is not provided, this will try
      the most recent token cached by the `login` tool.
    """
    resolved_base_url = DEFAULT_BASE_URL.rstrip("/")
    resolved_token = _extract_bearer_token(access_token)

    if not resolved_token and use_last_token:
        with _SESSION_LOCK:
            resolved_token = _LAST_ACCESS_TOKEN_BY_BASE_URL.get(resolved_base_url)
        if not resolved_token:
            login_status = _get_login_status(resolved_base_url)
            if login_status:
                event = login_status.get("event")
                if isinstance(event, threading.Event) and not event.is_set():
                    event.wait(timeout=15)
                with _SESSION_LOCK:
                    resolved_token = _LAST_ACCESS_TOKEN_BY_BASE_URL.get(resolved_base_url)
                if not resolved_token and login_status.get("error"):
                    return {
                        "error": "OAuth login failed",
                        "message": str(login_status.get("error")),
                    }

    if not resolved_token:
        return {
            "error": "Missing access token",
            "message": "Run login_via_oauth first (or provide a Microsoft Graph bearer token via access_token)."
        }

    resolved_graph_base_url = (graph_base_url or os.getenv("GRAPH_BASE_URL", "https://graph.microsoft.com")).strip()
    if not resolved_graph_base_url:
        resolved_graph_base_url = "https://graph.microsoft.com"
    resolved_graph_base_url = resolved_graph_base_url.rstrip("/")

    url = f"{resolved_graph_base_url}/v1.0/me"

    def _call_graph(graph_token: str) -> requests.Response:
        headers = {
            "Authorization": f"Bearer {graph_token}",
            "Accept": "application/json",
        }
        return requests.get(url, headers=headers, timeout=30)

    try:
        response = _call_graph(resolved_token)

        if response.status_code in (401, 403):
            graph_token, obo_error = _try_get_graph_token_via_obo(resolved_token)
            if graph_token:
                response = _call_graph(graph_token)
            else:
                return {
                    "error": "Authentication failed",
                    "status_code": response.status_code,
                    "message": "Microsoft Graph rejected the token, and OBO token exchange failed.",
                    "obo": obo_error,
                }

        if response.status_code == 200:
            payload = response.json()
            email = payload.get("mail") or payload.get("userPrincipalName") or ""
            return {
                "displayName": payload.get("displayName"),
                "email": email,
                "id": payload.get("id"),
                "userPrincipalName": payload.get("userPrincipalName"),
                "givenName": payload.get("givenName"),
                "surname": payload.get("surname"),
                "jobTitle": payload.get("jobTitle"),
                "department": payload.get("department"),
                "officeLocation": payload.get("officeLocation"),
            }

        www_authenticate = response.headers.get("WWW-Authenticate", "")
        claims_challenge = _try_extract_claims_challenge(www_authenticate)

        error_payload: Dict[str, Any] = {}
        try:
            error_payload = response.json()
        except ValueError:
            error_payload = {"raw": response.text}

        if response.status_code in (401, 403):
            result: Dict[str, Any] = {
                "error": "Authentication failed",
                "status_code": response.status_code,
                "message": "Microsoft Graph rejected the token. Ensure it includes appropriate scopes (e.g., User.Read).",
                "wwwAuthenticate": www_authenticate,
                "details": error_payload
            }
            if claims_challenge:
                result["claimsChallenge"] = claims_challenge
                result["hint"] = "A claims challenge was returned; you may need to re-authenticate with additional claims/consent."
            return result

        return {
            "error": "Microsoft Graph request failed",
            "status_code": response.status_code,
            "details": error_payload
        }

    except requests.RequestException as exc:
        return {
            "error": "Request exception",
            "message": str(exc)
        }


if __name__ == "__main__":
    transport = os.getenv("FASTMCP_TRANSPORT", "streamable-http").strip() or "streamable-http"
    if transport == "streamable-http":
        import uvicorn

        base_app = mcp.streamable_http_app()
        base_app = _PrmAndAuthShim(
            base_app,
            streamable_path=mcp.settings.streamable_http_path,
            require_auth=DEFAULT_REQUIRE_MCP_AUTH,
            prm_metadata_path=DEFAULT_PRM_METADATA_PATH,
        )
        app = _AcceptHeaderShim(base_app, mcp.settings.streamable_http_path)
        log_level = os.getenv("FASTMCP_LOG_LEVEL", "info").strip().lower()
        uvicorn.run(app, host=DEFAULT_MCP_HOST, port=DEFAULT_MCP_PORT, log_level=log_level)
    else:
        mcp.run(transport=transport)
