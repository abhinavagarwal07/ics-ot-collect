"""Loopback-only, dependency-free viewer for preserved capture evidence.

The HTTP boundary accepts registered adapter IDs, never filesystem paths, keys,
shell commands, or user-provided Git revisions. Decryption/loading is an explicit
same-origin POST; all other routes are read-only.
"""

from __future__ import annotations

import argparse
import hmac
import json
import re
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_ASSETS = {"/": ("viewer.html", "text/html; charset=utf-8"),
           "/viewer.js": ("viewer.js", "text/javascript; charset=utf-8"),
           "/viewer.css": ("viewer.css", "text/css; charset=utf-8")}


class ViewerHTTPServer(ThreadingHTTPServer):
    # Closing the viewer waits for active bounded operations to release their
    # staging files/temporary Git volume instead of abandoning daemon threads.
    daemon_threads = False
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], adapter: Any):
        if address[0] not in ("127.0.0.1", "::1"):
            raise ValueError("The viewer must bind to 127.0.0.1 or ::1 loopback")
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        self.adapter = adapter
        self.adapter_lock = threading.RLock()
        self.csrf_token = secrets.token_urlsafe(32)
        super().__init__(address, ViewerHandler)
        port = self.server_address[1]
        host = f"[{address[0]}]" if ":" in address[0] else address[0]
        self.allowed_hosts = {f"{host}:{port}", f"localhost:{port}"}


class ViewerHandler(BaseHTTPRequestHandler):
    server: ViewerHTTPServer
    server_version = "LocalCaptureViewer"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        # Bound incomplete request bodies and clients that stop reading an
        # excerpt. Long adapter work is unaffected by an idle socket timeout.
        self.connection.settimeout(15)

    def log_message(self, _format: str, *args: Any) -> None:
        # Paths and query strings can contain capture identifiers; keep them out
        # of logs, including the standard library's malformed-request logging.
        return

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
        if len(body) > MAX_RESPONSE_BYTES:
            self._error(409, "response_limit", "This result exceeds the viewer limit. Choose a smaller capture or page.")
            return
        self._respond(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message}})

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self._error(code, "http_error", "The request could not be processed.")

    def _guard(self, *, mutation: bool = False, public_static: bool = False) -> bool:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0] not in self.server.allowed_hosts:
            self._error(403, "host_rejected", "Only the viewer's loopback host is allowed.")
            return False
        # Browser extensions and browser-created tabs can initiate a top-level
        # navigation with Sec-Fetch-Site: cross-site. These fixed assets contain
        # no capture data or token. Their public bootstrap must not weaken the
        # origin checks on /api/session, evidence reads, or explicit operations.
        if public_static and not mutation and self.command in ("GET", "HEAD"):
            return True
        origins = self.headers.get_all("Origin", [])
        expected = "http://" + hosts[0]
        if len(origins) > 1 or (origins and origins[0] != expected):
            self._error(403, "origin_rejected", "Only same-origin viewer requests are allowed.")
            return False
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site is not None and fetch_site not in ("same-origin", "none"):
            self._error(403, "origin_rejected", "Only same-origin viewer requests are allowed.")
            return False
        if mutation:
            token = self.headers.get("X-Viewer-Token", "")
            if not origins or not hmac.compare_digest(token.encode("utf-8"), self.server.csrf_token.encode("ascii")):
                self._error(403, "token_required", "Refresh the viewer before loading a capture.")
                return False
        return True

    @staticmethod
    def _one(query: dict[str, list[str]], name: str, default: str | None = None) -> str:
        values = query.get(name, [])
        if not values and default is not None:
            return default
        if len(values) != 1 or not values[0] or len(values[0]) > 512:
            raise ValueError("Invalid query")
        return values[0]

    def _adapter(self, method: str, *args: Any, **kwargs: Any) -> Any:
        if method in ("load", "git_diff"):
            # The adapter owns an exclusive load lock and publishes bounded
            # progress metadata. Keep metadata routes responsive during a load.
            return getattr(self.server.adapter, method)(*args, **kwargs)
        with self.server.adapter_lock:
            return getattr(self.server.adapter, method)(*args, **kwargs)

    def _handle_failure(self, exc: Exception) -> None:
        if "budget" in type(exc).__name__.lower():
            self._error(409, "budget_limit", "The selected capture cannot fit within the local disk budget. Free viewer-managed space or choose a smaller capture.")
        elif isinstance(exc, (ValueError, KeyError, TypeError)):
            self._error(400, "invalid_selection", "The capture or entity selection is invalid or unavailable. Refresh the repository list.")
        elif isinstance(exc, FileNotFoundError):
            self._error(404, "not_loaded", "The selected evidence is not available locally.")
        else:
            # Never send exception text: filesystem paths, private-key locations,
            # remote command diagnostics and decrypted content can occur there.
            self._error(409, "unavailable", "This evidence could not be read. Check the local configuration and capture availability.")

    def do_GET(self) -> None:
        if not self._guard(public_static=self.path.partition("?")[0] in _ASSETS):
            return
        if len(self.path) > MAX_REQUEST_BYTES or self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            self.close_connection = True
            self._error(400, "invalid_request", "The request is not supported.")
            return
        try:
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc:
                raise ValueError("Absolute request target")
            path = parsed.path
            if path in _ASSETS:
                name, content_type = _ASSETS[path]
                body = files("icsot_observer").joinpath("web", name).read_bytes()
                self._respond(200, body, content_type)
                return
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=12)
            if path == "/api/session":
                result = {"token": self.server.csrf_token, "mode": "local", "read_only": True}
            elif path == "/api/overview":
                if "refresh" in query:
                    if query["refresh"] != ["1"]:
                        raise ValueError("Invalid metadata refresh")
                    result = self._adapter("overview", refresh=True)
                else:
                    result = self._adapter("overview")
            elif path == "/api/budget":
                result = self._adapter("budget_status")
            elif path.startswith("/api/repos/"):
                key = unquote(path[len("/api/repos/"):])
                if not key or "/" in key or len(key) > 512:
                    raise ValueError("Invalid repository")
                result = self._adapter("repo", key)
            elif path == "/api/compare":
                category = self._one(query, "category", "issues")
                if category not in {"issues", "pulls", "comments", "releases", "tags", "events", "git", "coverage"}:
                    raise ValueError("Invalid category")
                offset = int(self._one(query, "offset", "0"))
                limit = int(self._one(query, "limit", "100"))
                if offset < 0 or offset > 1000000 or limit < 1 or limit > 100:
                    raise ValueError("Invalid page")
                result = self._adapter("compare", self._one(query, "repo"), self._one(query, "left"), self._one(query, "right"), category=category, offset=offset, limit=limit)
            elif path == "/api/entity":
                result = self._adapter("entity_detail", self._one(query, "repo"), self._one(query, "capture"), self._one(query, "kind"), self._one(query, "id"))
            elif path == "/api/raw":
                result = self._adapter("raw_record", self._one(query, "repo"), self._one(query, "capture"), self._one(query, "ref"))
            else:
                self._error(404, "not_found", "This viewer route does not exist.")
                return
            self._json(200, result)
        except Exception as exc:
            self._handle_failure(exc)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        if not self._guard(mutation=True):
            return
        try:
            if self.path not in ("/api/load", "/api/git-diff"):
                self._error(404, "not_found", "This viewer route does not exist.")
                return
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise ValueError("Invalid body")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_REQUEST_BYTES or self.headers.get_content_type() != "application/json":
                raise ValueError("Invalid body")
            value = json.loads(self.rfile.read(length))
            if self.path == "/api/git-diff":
                required = {"repo", "capture", "base", "head"}
                if not isinstance(value, dict) or not required <= set(value) or set(value) - required - {"path"}:
                    raise ValueError("Invalid Git selection")
                if any(not isinstance(v, str) or not v or len(v) > 1024 for v in value.values()):
                    raise ValueError("Invalid Git selection")
                if any(not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value[name]) for name in ("base", "head")):
                    raise ValueError("Invalid Git object identifier")
                result = self._adapter("git_diff", value["repo"], value["capture"], value["base"], value["head"], path=value.get("path"))
                if isinstance(result, dict) and result.get("status") in ("available", "complete", "loaded", "ok"):
                    self._json(200, result)
                else:
                    self._error(409, "git_unavailable", "File diffs are unavailable for this selection. Choose two captured refs from a loaded full Git bundle that fits the local disk budget.")
                return
            if not isinstance(value, dict) or set(value) != {"repo", "capture"} or any(not isinstance(v, str) or not v or len(v) > 512 for v in value.values()):
                raise ValueError("Invalid selection")
            result = self._adapter("load", value["repo"], value["capture"])
            status = result.get("status") if isinstance(result, dict) else None
            if status == "loaded":
                self._json(200, result)
            elif status == "key_required":
                self._error(409, "key_required", "Start the local server with --private-key pointing to the local decryption key, then load the capture again.")
            elif status == "busy":
                self._error(409, "capture_busy", "Another selected capture is loading. Wait for it to finish before requesting a load.")
            elif status and "budget" in status:
                self._error(409, "budget_limit", "This capture cannot be loaded within the configured local disk budget. Check available capacity or choose a smaller capture.")
            else:
                self._error(409, "load_unavailable", "The selected evidence could not be authenticated or loaded. Check its capture coverage and the local server configuration.")
        except Exception as exc:
            self.close_connection = True
            self._handle_failure(exc)

    def do_OPTIONS(self) -> None:
        if self._guard():
            self._error(405, "method_not_allowed", "This method is not supported.")


def create_server(adapter: Any, *, bind: str = "127.0.0.1", port: int = 0) -> ViewerHTTPServer:
    """Create a loopback server. Port zero is useful for tests and local launches."""
    return ViewerHTTPServer((bind, port), adapter)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Browse captured repository differences locally.")
    parser.add_argument("--bind", default="127.0.0.1", help="Numeric loopback address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--root", type=Path, action="append", help="Existing local capture root; repeat to add another")
    parser.add_argument("--private-key", type=Path, help="Local decryption key path; stays on the server")
    parser.add_argument("--offline", action="store_true", help="Use only existing local metadata and evidence")
    args = parser.parse_args(argv)
    from .viewer_data import ViewerData
    try:
        adapter = ViewerData(args.workspace.resolve(), roots=args.root, private_key_path=args.private_key, offline=args.offline)
        server = create_server(adapter, bind=args.bind, port=args.port)
    except (ValueError, OSError):
        parser.error("Unable to start the viewer: check the loopback address, port, and local configuration.")
    host = f"[{args.bind}]" if ":" in args.bind else args.bind
    print(f"Local capture viewer: http://{host}:{server.server_address[1]}", flush=True)
    print("Press Ctrl-C to stop. Capture loads require an explicit selection in the viewer.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
