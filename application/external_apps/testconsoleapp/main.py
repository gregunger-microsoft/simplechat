# main.py
"""Console test client for Simple Chat authentication and API usage."""

import json
import os
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Sequence, Tuple, Type, cast

import requests
import dotenv

def load_dotenv(*args: Any, **kwargs: Any) -> bool:
    dotenv_module = cast(Any, dotenv)
    return bool(dotenv_module.load_dotenv(*args, **kwargs))


def create_auth_handler(auth_state: Dict[str, Any], expected_path: str) -> Type[BaseHTTPRequestHandler]:
    class AuthCodeHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != expected_path:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
                return

            query = urllib.parse.parse_qs(parsed.query)
            auth_state["code"] = query.get("code", [None])[0]
            auth_state["error"] = query.get("error", [None])[0]
            auth_state["event"].set()
            print("Auth callback received.", flush=True)

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            body = (
                "<html><body><h2>Login complete.</h2>"
                "<p>You can close this window and return to the console.</p>"
                "</body></html>"
            )
            self.wfile.write(body.encode("utf-8"))

        def log_message(self, format: str, *args: object) -> None:
            return

    return AuthCodeHandler


def build_authorize_url(tenant_id: str, client_id: str, redirect_uri: str, scopes: Sequence[str]) -> str:
    base = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": " ".join(scopes),
        "prompt": "select_account"
    }
    return f"{base}?{urllib.parse.urlencode(params)}"


def wait_for_auth_code(auth_state: Dict[str, Any], timeout_seconds: int = 180) -> Tuple[Optional[str], Optional[str]]:
    started = time.time()
    last_log = 0.0
    while time.time() - started < timeout_seconds:
        auth_event = cast(threading.Event, auth_state["event"])
        if auth_event.is_set():
            code = cast(Optional[str], auth_state.get("code"))
            error = cast(Optional[str], auth_state.get("error"))
            if not code and error:
                return None, error
            return code, error
        elapsed = time.time() - started
        if elapsed - last_log >= 5:
            log(f"Waiting for auth code... {int(elapsed)}s")
            last_log = elapsed
        time.sleep(0.2)
    return None, "timeout"


def parse_auth_code_from_input(raw_input: str) -> Optional[str]:
    text = raw_input.strip()
    if not text:
        return None
    if text.startswith("http"):
        parsed = urllib.parse.urlparse(text)
        query = urllib.parse.parse_qs(parsed.query)
        return query.get("code", [None])[0]
    return text


def log(message: str) -> None:
    print(message, flush=True)


def main():
    load_dotenv()

    base_url = os.getenv("BASE_URL", "https://localhost:5000").rstrip("/")
    tenant_id = os.getenv("TENANT_ID")
    client_id = os.getenv("CLIENT_ID")
    scopes = os.getenv(
        "SCOPES",
        "openid profile offline_access User.Read User.ReadBasic.All People.Read.All Group.Read.All"
    ).split()

    redirect_host = os.getenv("REDIRECT_HOST", "localhost")
    redirect_port = int(os.getenv("REDIRECT_PORT", "8400"))
    redirect_path = os.getenv("REDIRECT_PATH", "/callback")
    redirect_uri = f"http://{redirect_host}:{redirect_port}{redirect_path}"

    create_session = os.getenv("CREATE_SESSION", "true").strip().lower() in ["1", "true", "yes", "y", "on"]
    verify_ssl = os.getenv("VERIFY_SSL", "true").strip().lower() in ["1", "true", "yes", "y", "on"]

    if not tenant_id or not client_id:
        raise SystemExit("TENANT_ID and CLIENT_ID must be set in .env")

    auth_state: Dict[str, Any] = {
        "event": threading.Event(),
        "code": None,
        "error": None
    }
    handler = create_auth_handler(auth_state, redirect_path)

    httpd = HTTPServer((redirect_host, redirect_port), handler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    auth_url = build_authorize_url(tenant_id, client_id, redirect_uri, scopes)
    log("Opening browser for login...")
    webbrowser.open(auth_url)

    log("Waiting for auth code...")
    auth_code, auth_error = wait_for_auth_code(auth_state, timeout_seconds=240)
    log("Auth wait complete. Shutting down local callback server...")
    shutdown_thread = threading.Thread(target=httpd.shutdown, daemon=True)
    shutdown_thread.start()
    shutdown_thread.join(timeout=5)
    httpd.server_close()
    log("Callback server stopped.")

    if auth_error == "timeout" or not auth_code:
        log("Auth code not received. Paste the full callback URL or code:")
        manual_input = input("callback> ")
        auth_code = parse_auth_code_from_input(manual_input)
        if not auth_code:
            raise SystemExit(f"Authentication failed: {auth_error}")
    elif auth_error:
        raise SystemExit(f"Authentication failed: {auth_error}")

    log("Auth code received. Exchanging for tokens...")

    session = requests.Session()
    token_url = f"{base_url}/getATokenApi"
    token_params = {
        "code": auth_code,
        "create_session": "true" if create_session else "false",
        "redirect_uri": redirect_uri
    }

    try:
        token_response = session.get(token_url, params=token_params, verify=verify_ssl, timeout=30)
        log(f"Token response status: {token_response.status_code}")
        if token_response.status_code >= 400:
            log(f"Token response body: {token_response.text}")
        token_response.raise_for_status()
        token_payload = token_response.json()
    except requests.RequestException as exc:
        raise SystemExit(f"Token request failed: {exc}")

    session_id = token_payload.get("session_id")
    log(f"Session created: {token_payload.get('session_created')} | session_id: {session_id}")

    if not create_session:
        log("Session not requested. Exiting.")
        return

    workspace_name = os.getenv("WORKSPACE_NAME", "Test Public Workspace")
    workspace_description = os.getenv("WORKSPACE_DESCRIPTION", "Created by test console app")

    create_url = f"{base_url}/api/public_workspaces"
    create_payload = {
        "name": workspace_name,
        "description": workspace_description
    }

    log("Creating public workspace...")
    try:
        create_response = session.post(create_url, json=create_payload, verify=verify_ssl, timeout=30)
        log(f"Create workspace status: {create_response.status_code}")
        create_response.raise_for_status()
        created = create_response.json()
    except requests.RequestException as exc:
        raise SystemExit(f"Create workspace failed: {exc}")

    workspace_id = created.get("id")
    log(f"Created public workspace: {workspace_id} - {created.get('name')}")

    if not workspace_id:
        raise SystemExit("Workspace creation did not return an id.")

    get_url = f"{base_url}/api/public_workspaces/{workspace_id}"
    log("Fetching public workspace details...")
    try:
        get_response = session.get(get_url, verify=verify_ssl, timeout=30)
        log(f"Get workspace status: {get_response.status_code}")
        get_response.raise_for_status()
    except requests.RequestException as exc:
        raise SystemExit(f"Get workspace failed: {exc}")

    log("Workspace details:")
    log(json.dumps(get_response.json(), indent=2))


if __name__ == "__main__":
    main()
