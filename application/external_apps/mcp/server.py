# server.py
"""SimpleChat MCP server using FastMCP with PRM-style bearer authorization."""

import base64
import hashlib
import os
import secrets
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple

import requests
from dotenv import load_dotenv
from mcp import UrlElicitationRequiredError
from mcp.server.fastmcp import FastMCP
from mcp.types import ElicitRequestURLParams

load_dotenv()

DEFAULT_BASE_URL = os.getenv("SIMPLECHAT_BASE_URL", "https://localhost:5000").rstrip("/")
DEFAULT_VERIFY_SSL = os.getenv("SIMPLECHAT_VERIFY_SSL", "true").strip().lower() in ["1", "true", "yes", "y", "on"]
DEFAULT_MCP_HOST = os.getenv("FASTMCP_HOST", "0.0.0.0").strip() or "0.0.0.0"
DEFAULT_MCP_PORT = int(os.getenv("FASTMCP_PORT", "8000").strip() or "8000")

_SESSION_CACHE: Dict[str, requests.Session] = {}
_SESSION_LOCK = threading.Lock()
_LAST_ACCESS_TOKEN_BY_BASE_URL: Dict[str, str] = {}

mcp = FastMCP("SimpleChat MCP", host=DEFAULT_MCP_HOST, port=DEFAULT_MCP_PORT)


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


def _store_last_token(base_url: str, access_token: str) -> None:
    with _SESSION_LOCK:
        _LAST_ACCESS_TOKEN_BY_BASE_URL[base_url] = access_token


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
def login(access_token: Optional[str] = None, base_url: Optional[str] = None, verify_ssl: Optional[bool] = None) -> Dict[str, Any]:
    """
    Create a SimpleChat session using an Entra bearer token.
    """
    resolved_base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
    resolved_verify_ssl = DEFAULT_VERIFY_SSL if verify_ssl is None else bool(verify_ssl)

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
    return payload


@mcp.tool(name="login_via_oauth")
def login_via_oauth(
    base_url: Optional[str] = None,
    verify_ssl: Optional[bool] = None,
    authorization_url: Optional[str] = None,
    token_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    scope: Optional[str] = None,
    redirect_port: Optional[int] = None,
    open_browser: bool = True,
    timeout_seconds: int = 180,
) -> Dict[str, Any]:
    """
    Interactive OAuth login with PKCE.
    Opens a browser to authorize and exchanges the code for an access token.
    """
    resolved_base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
    resolved_verify_ssl = DEFAULT_VERIFY_SSL if verify_ssl is None else bool(verify_ssl)

    resolved_authorization_url = authorization_url or os.getenv("OAUTH_AUTHORIZATION_URL", "").strip()
    resolved_token_url = token_url or os.getenv("OAUTH_TOKEN_URL", "").strip()
    resolved_client_id = client_id or os.getenv("OAUTH_CLIENT_ID", "").strip()
    resolved_client_secret = client_secret or os.getenv("OAUTH_CLIENT_SECRET", "").strip()
    resolved_scope = scope or os.getenv("OAUTH_SCOPES", "").strip()
    resolved_redirect_port = redirect_port or int(os.getenv("OAUTH_REDIRECT_PORT", "53682"))

    if not resolved_authorization_url or not resolved_token_url or not resolved_client_id or not resolved_scope:
        raise ValueError("OAuth configuration missing. Set OAUTH_AUTHORIZATION_URL, OAUTH_TOKEN_URL, OAUTH_CLIENT_ID, and OAUTH_SCOPES.")

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

    if open_browser:
        webbrowser.open(auth_url)

    code = _wait_for_oauth_code(resolved_redirect_port, state, timeout_seconds)

    data = {
        "grant_type": "authorization_code",
        "client_id": resolved_client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    if resolved_scope:
        data["scope"] = resolved_scope
    if resolved_client_secret:
        data["client_secret"] = resolved_client_secret

    response = requests.post(resolved_token_url, data=data, timeout=30)
    response.raise_for_status()
    token_payload = response.json()
    access_token = token_payload.get("access_token")
    if not access_token:
        raise ValueError("OAuth token response missing access_token.")

    session, payload = _create_session(access_token, resolved_base_url, resolved_verify_ssl)
    cache_key = _session_cache_key(access_token, resolved_base_url)
    with _SESSION_LOCK:
        _SESSION_CACHE[cache_key] = session
    _store_last_token(resolved_base_url, access_token)
    return payload


@mcp.tool(name="list_public_workspaces")
def list_public_workspaces(
    access_token: Optional[str] = None,
    base_url: Optional[str] = None,
    page: int = 1,
    page_size: int = 25,
    search: Optional[str] = None,
    verify_ssl: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Return the authenticated user's public workspaces from SimpleChat.
    """
    resolved_base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
    resolved_verify_ssl = DEFAULT_VERIFY_SSL if verify_ssl is None else bool(verify_ssl)

    resolved_access_token = access_token
    if not resolved_access_token or not resolved_access_token.strip():
        with _SESSION_LOCK:
            resolved_access_token = _LAST_ACCESS_TOKEN_BY_BASE_URL.get(resolved_base_url)

    if not resolved_access_token:
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

    session = _get_session(resolved_access_token, resolved_base_url, resolved_verify_ssl)

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


if __name__ == "__main__":
    transport = os.getenv("FASTMCP_TRANSPORT", "streamable-http").strip() or "streamable-http"
    mcp.run(transport=transport)
