"""Threaded HTTPS API for the local Portal PWA."""

from __future__ import annotations

import ipaddress
import json
import mimetypes
import os
import signal
import ssl
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .backend import BackendError
from .core import MAX_FILE, PortalCore, PortalError


class PortalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, core: PortalCore, web_root: Path):
        super().__init__(address, handler)
        self.core = core
        self.web_root = web_root
        self.allowed_origins: set[str] = set()


class Handler(BaseHTTPRequestHandler):
    server_version = "Portal/0.9"

    def log_message(self, fmt, *args):
        # Only method, normalized path and status. Query strings and bodies can hold secrets.
        path = urllib.parse.urlsplit(self.path).path
        sys.stderr.write(
            f"portal-http {self.command} {path} {args[1] if len(args) > 1 else '-'}\n"
        )

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin", "")
        return not origin or origin in self.server.allowed_origins

    def _headers(
        self,
        status: int,
        content_type: str = "application/json",
        length: int | None = None,
    ):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy", "camera=(self), microphone=(), geolocation=()"
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def json(self, status: int, value):
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        self._headers(status, "application/json; charset=utf-8", len(raw))
        self.wfile.write(raw)

    def error(self, exc: Exception):
        if isinstance(exc, PortalError):
            self.json(exc.status, {"error": exc.code, "message": str(exc)})
        elif isinstance(exc, BackendError):
            self.json(409, {"error": "desktop_unavailable", "message": str(exc)})
        else:
            # Never reflect exception details from unexpected failures.
            self.json(
                500,
                {
                    "error": "internal_error",
                    "message": "Portal could not complete the request",
                },
            )

    def body_json(self, limit: int = 1024 * 1024) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise PortalError("invalid content length") from exc
        if length < 0 or length > limit:
            raise PortalError("request body too large", 413)
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise PortalError("malformed JSON") from exc
        if not isinstance(value, dict):
            raise PortalError("JSON body must be an object")
        return value

    def auth(self, capability: str | None = None):
        header = self.headers.get("Authorization", "")
        raw = header[7:] if header.startswith("Bearer ") else ""
        return self.server.core.authenticate(raw, capability)

    def schedule_clipboard_clear(self, text: str, result: dict) -> None:
        if not result.get("clear_at"):
            return
        delay = max(0, result["clear_at"] - self.server.core.now())

        def clear_if_unchanged():
            try:
                if self.server.core.backend.clipboard_get() == text:
                    self.server.core.backend.clipboard_set("")
            except BackendError:
                pass

        timer = threading.Timer(delay, clear_if_unchanged)
        timer.daemon = True
        timer.start()

    def parsed(self):
        return urllib.parse.urlsplit(self.path)

    def do_OPTIONS(self):
        self.json(405, {"error": "method_not_allowed"})

    def do_GET(self):
        try:
            if not self._origin_ok():
                raise PortalError("origin rejected", 403, "origin_rejected")
            parsed = self.parsed()
            path = parsed.path
            if path == "/api/health":
                return self.json(200, {"status": "ready", "version": "0.9.2"})
            if path.startswith("/api/pair/"):
                request_id = path.rsplit("/", 1)[-1]
                claim = self.headers.get("X-Portal-Claim", "")
                return self.json(200, self.server.core.poll_pair(request_id, claim))
            if path == "/api/state":
                session = self.auth()
                caps = session["capability_set"]
                value = {
                    "device": {
                        "id": session["device_id"],
                        "name": session["name"],
                        "capabilities": sorted(caps),
                    },
                    "inbox": self.server.core.inbox() if "send_receive" in caps else [],
                    "windows": self.server.core.windows_state()
                    if "window_control" in caps
                    else {"windows": [], "workspaces": [], "monitors": []},
                    "media": self.server.core.backend.media()
                    if "media" in caps
                    else [],
                    "audio": self.server.core.backend.audio_outputs()
                    if "audio" in caps
                    else [],
                    "actions": [
                        a
                        for a in self.server.core.action_registry()
                        if a["capability"] in caps
                    ],
                    "vision": self.server.core.store.setting(
                        "vision", {"active": False}
                    ),
                    "xray": "xray" in caps
                    and self.server.core.backend.xray_available(),
                }
                return self.json(200, value)
            if path == "/api/inbox":
                self.auth("send_receive")
                return self.json(200, {"items": self.server.core.inbox()})
            if path.startswith("/api/inbox/") and path.endswith("/content"):
                self.auth("send_receive")
                item_id = path.split("/")[3]
                row = self.server.core.inbox_content(item_id)
                if row["content_path"]:
                    source = Path(row["content_path"])
                    size = source.stat().st_size
                    self._headers(200, row["mime"] or "application/octet-stream", size)
                    with source.open("rb") as stream:
                        while chunk := stream.read(1024 * 1024):
                            self.wfile.write(chunk)
                    return
                raw = (row["text_value"] or "").encode()
                self._headers(200, "text/plain; charset=utf-8", len(raw))
                self.wfile.write(raw)
                return
            if path == "/api/clipboard":
                self.auth("clipboard")
                return self.json(200, self.server.core.clipboard_get())
            if path == "/api/windows":
                self.auth("window_control")
                return self.json(200, self.server.core.windows_state())
            if path.startswith("/api/windows/"):
                self.auth("window_control")
                return self.json(
                    200,
                    self.server.core.window_detail(
                        urllib.parse.unquote(path.rsplit("/", 1)[-1])
                    ),
                )
            if path == "/api/media":
                self.auth("media")
                return self.json(200, {"players": self.server.core.backend.media()})
            if path == "/api/audio":
                self.auth("audio")
                return self.json(
                    200, {"outputs": self.server.core.backend.audio_outputs()}
                )
            if path == "/api/actions":
                session = self.auth()
                return self.json(
                    200,
                    {
                        "actions": [
                            a
                            for a in self.server.core.action_registry()
                            if a["capability"] in session["capability_set"]
                        ]
                    },
                )
            return self.static(path)
        except Exception as exc:  # noqa: BLE001 - HTTP boundary sanitizes unexpected failures
            self.error(exc)

    def do_POST(self):
        try:
            if not self._origin_ok():
                raise PortalError("origin rejected", 403, "origin_rejected")
            path = self.parsed().path
            body = self.body_json()
            if path == "/api/pair/request":
                value = self.server.core.request_pair(
                    str(body.get("secret", "")),
                    str(body.get("device_name", "Phone")),
                    str(body.get("public_id", "")),
                    list(body.get("capabilities", [])),
                )
                return self.json(202, value)
            if path == "/api/session":
                return self.json(
                    201,
                    self.server.core.resume(
                        str(body.get("device_id", "")),
                        str(body.get("device_token", "")),
                    ),
                )
            if path == "/api/inbox":
                self.auth("send_receive")
                return self.json(
                    201,
                    self.server.core.add_text(
                        str(body.get("kind", "text")),
                        str(body.get("text", "")),
                        name=str(body.get("name", "")),
                        secure=bool(body.get("secure", False)),
                    ),
                )
            if path == "/api/continue":
                session = self.auth("send_receive")
                kind, text = str(body.get("kind", "text")), str(body.get("text", ""))
                secure = bool(body.get("secure", False))
                if kind != "url" and "clipboard" not in session["capability_set"]:
                    raise PortalError(
                        "capability denied: clipboard", 403, "permission_denied"
                    )
                item = self.server.core.add_text(
                    kind, text, name="Continue on PC", secure=secure
                )
                if kind == "url":
                    self.server.core.backend.open_target(text)
                    item["continued"] = "opened"
                else:
                    result = self.server.core.clipboard_set(
                        text, secure, int(body.get("clear_after", 60 if secure else 0))
                    )
                    self.schedule_clipboard_clear(text, result)
                    item["continued"] = "clipboard"
                    item["clear_at"] = result.get("clear_at")
                return self.json(201, item)
            if path.startswith("/api/inbox/") and path.endswith("/action"):
                self.auth("send_receive")
                return self.json(
                    200,
                    self.server.core.inbox_action(
                        path.split("/")[3], str(body.get("action", ""))
                    ),
                )
            if path == "/api/clipboard":
                self.auth("clipboard")
                text = str(body.get("text", ""))
                result = self.server.core.clipboard_set(
                    text,
                    bool(body.get("secure", False)),
                    int(body.get("clear_after", 0)),
                )
                self.schedule_clipboard_clear(text, result)
                return self.json(200, result)
            if path.startswith("/api/windows/") and path.endswith("/action"):
                self.auth("window_control")
                address = urllib.parse.unquote(path.split("/")[3])
                action = str(body.get("action", ""))
                if action == "close" and not bool(body.get("confirmed", False)):
                    raise PortalError(
                        "close requires confirmation", 409, "confirmation_required"
                    )
                if action == "take":
                    self.server.core.backend.window_action(address, "focus")
                    return self.json(
                        200, self.server.core.take_this(session_id=self.auth()["id"])
                    )
                self.server.core.backend.window_action(
                    address, action, str(body.get("value", ""))
                )
                return self.json(200, {"status": "ok"})
            if path == "/api/control":
                action = str(body.get("action", ""))
                capability = "keyboard" if action in {"type", "key"} else "pointer"
                self.auth(capability)
                self.server.core.backend.control(action, body)
                return self.json(200, {"status": "ok"})
            if path == "/api/vision":
                session = self.auth("window_control")
                return self.json(
                    200,
                    self.server.core.set_vision(
                        bool(body.get("active", True)), session["id"]
                    ),
                )
            if path == "/api/vision/select":
                session = self.auth("window_control")
                return self.json(
                    200,
                    self.server.core.resolve_vision(
                        str(body.get("token", "")), session
                    ),
                )
            if path == "/api/media":
                self.auth("media")
                self.server.core.backend.media_action(
                    str(body.get("player", "")),
                    str(body.get("action", "")),
                    str(body.get("value", "")),
                )
                return self.json(200, {"status": "ok"})
            if path == "/api/audio":
                self.auth("audio")
                if body.get("action") == "volume":
                    self.server.core.backend.set_volume(float(body.get("delta", 0)))
                else:
                    self.server.core.backend.set_audio_output(str(body.get("id", "")))
                return self.json(200, {"status": "ok"})
            if path == "/api/actions/run":
                session = self.auth()
                return self.json(
                    200,
                    self.server.core.run_action(
                        str(body.get("id", "")), str(body.get("value", "")), session
                    ),
                )
            raise PortalError("endpoint not found", 404, "not_found")
        except Exception as exc:  # noqa: BLE001 - HTTP boundary sanitizes unexpected failures
            self.error(exc)

    def do_PUT(self):
        try:
            if not self._origin_ok():
                raise PortalError("origin rejected", 403, "origin_rejected")
            parsed = self.parsed()
            if parsed.path != "/api/files":
                raise PortalError("endpoint not found", 404, "not_found")
            self.auth("files")
            query = urllib.parse.parse_qs(parsed.query)
            try:
                size = int(self.headers.get("Content-Length", "-1"))
            except ValueError as exc:
                raise PortalError("invalid content length") from exc
            if size > MAX_FILE:
                raise PortalError("file too large", 413)
            result = self.server.core.add_file(
                query.get("name", ["file"])[0],
                self.rfile,
                size,
                self.headers.get("Content-Type", ""),
                secure=query.get("secure", ["0"])[0] == "1",
            )
            return self.json(201, result)
        except Exception as exc:  # noqa: BLE001 - HTTP boundary sanitizes unexpected failures
            self.error(exc)

    def static(self, path: str):
        mapping = {
            "/": "index.html",
            "/index.html": "index.html",
            "/app.js": "app.js",
            "/style.css": "style.css",
            "/manifest.webmanifest": "manifest.webmanifest",
            "/sw.js": "sw.js",
            "/icon.svg": "icon.svg",
        }
        name = mapping.get(path)
        if not name:
            raise PortalError("not found", 404, "not_found")
        file_path = self.server.web_root / name
        raw = file_path.read_bytes()
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        cache = (
            "no-cache" if name in {"index.html", "sw.js"} else "public, max-age=3600"
        )
        self.send_response(200)
        self.send_header(
            "Content-Type",
            mime
            + (
                "; charset=utf-8"
                if mime.startswith("text/")
                or mime in {"application/javascript", "application/manifest+json"}
                else ""
            ),
        )
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(raw)


RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _ipv4(address: object) -> ipaddress.IPv4Address | None:
    try:
        parsed = ipaddress.ip_address(str(address))
    except ValueError:
        return None
    return parsed if isinstance(parsed, ipaddress.IPv4Address) else None


def advertised_address_allowed(address: str) -> bool:
    parsed = _ipv4(address)
    return bool(
        parsed
        and (parsed.is_loopback or any(parsed in network for network in RFC1918_NETWORKS))
    )


def listen_address_allowed(address: str) -> bool:
    return address == "0.0.0.0" or advertised_address_allowed(address)


def loopback_address(address: str) -> bool:
    parsed = _ipv4(address)
    return bool(parsed and parsed.is_loopback)


def private_bind(address: str) -> bool:
    """Compatibility name for callers checking Portal's permitted listen policy."""

    return listen_address_allowed(address)


def select_default_route_address(routes: list[dict], interfaces: list[dict]) -> str:
    """Choose an active RFC1918 source on a main-table IPv4 default route."""

    assigned: dict[str, list[tuple[ipaddress.IPv4Address, int]]] = {}
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        ifname = interface.get("ifname")
        if not isinstance(ifname, str):
            continue
        candidates = []
        for info in interface.get("addr_info") or []:
            if not isinstance(info, dict):
                continue
            if info.get("family") != "inet" or info.get("scope") != "global":
                continue
            if info.get("tentative") or info.get("dadfailed"):
                continue
            if info.get("valid_life_time") == 0 or info.get("preferred_life_time") == 0:
                continue
            parsed = _ipv4(info.get("local"))
            if not parsed or not advertised_address_allowed(str(parsed)):
                continue
            try:
                prefix = int(info.get("prefixlen", 32))
            except (TypeError, ValueError):
                prefix = 32
            candidates.append((parsed, prefix))
        if candidates:
            assigned[ifname] = candidates

    def route_priority(item: tuple[int, dict]) -> tuple[bool, int, int]:
        index, route = item
        if not isinstance(route, dict):
            return (True, 2**31, index)
        try:
            metric = int(route.get("metric", 0))
        except (TypeError, ValueError):
            metric = 0
        # A gateway-backed LAN route is preferred to a point-to-point tunnel;
        # metrics retain the kernel's preference among routes of the same kind.
        return (not bool(route.get("gateway")), metric, index)

    for _, route in sorted(enumerate(routes), key=route_priority):
        if not isinstance(route, dict):
            continue
        if route.get("dst") not in (None, "default", "0.0.0.0/0"):
            continue
        if "linkdown" in (route.get("flags") or []):
            continue
        candidates = assigned.get(route.get("dev"), [])
        if not candidates:
            continue
        preferred = _ipv4(route.get("prefsrc") or route.get("src"))
        if preferred and any(preferred == local for local, _ in candidates):
            return str(preferred)
        gateway = _ipv4(route.get("gateway"))
        if gateway:
            for local, prefix in candidates:
                try:
                    if gateway in ipaddress.ip_network(f"{local}/{prefix}", strict=False):
                        return str(local)
                except ValueError:
                    continue
        return str(candidates[0][0])
    return "127.0.0.1"


def _ip_json(command: list[str]) -> list[dict]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            return []
        value = json.loads(result.stdout)
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def lan_ip() -> str:
    override = os.environ.get("PORTAL_ADVERTISE_ADDRESS", "")
    if override:
        return override if advertised_address_allowed(override) else "127.0.0.1"
    routes = _ip_json(["ip", "-j", "-4", "route", "show", "table", "main", "default"])
    interfaces = _ip_json(["ip", "-j", "-4", "address", "show", "up", "scope", "global"])
    return select_default_route_address(routes, interfaces)


def ensure_certificate(state_dir: Path, address: str) -> tuple[Path, Path]:
    cert, key = state_dir / "tls.crt", state_dir / "tls.key"
    if cert.exists() and key.exists():
        ip_ok = (
            subprocess.run(
                ["openssl", "x509", "-in", str(cert), "-noout", "-checkip", address],
                capture_output=True,
                check=False,
            ).returncode
            == 0
        )
        fresh = (
            subprocess.run(
                ["openssl", "x509", "-in", str(cert), "-noout", "-checkend", "172800"],
                capture_output=True,
                check=False,
            ).returncode
            == 0
        )
        if ip_ok and fresh:
            return cert, key
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    next_cert, next_key = state_dir / "tls.crt.new", state_dir / "tls.key.new"
    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ed25519",
        "-nodes",
        "-days",
        "30",
        "-subj",
        "/CN=Portal Local",
        "-addext",
        f"subjectAltName=IP:{address},IP:127.0.0.1",
        "-keyout",
        str(next_key),
        "-out",
        str(next_cert),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError("could not create Portal TLS certificate")
    os.chmod(next_key, 0o600)
    os.chmod(next_cert, 0o600)
    next_key.replace(key)
    next_cert.replace(cert)
    return cert, key


def serve(
    state_dir: Path,
    web_root: Path,
    listen_address: str | None = None,
    port: int = 59443,
    tls: bool = True,
    advertise_address: str | None = None,
    monitor_network: bool = False,
):
    if advertise_address is None:
        advertise_address = (
            listen_address
            if listen_address not in (None, "0.0.0.0")
            else lan_ip()
        )
    if listen_address is None:
        listen_address = (
            "127.0.0.1" if loopback_address(advertise_address) else "0.0.0.0"
        )
    if not listen_address_allowed(listen_address):
        raise RuntimeError("Portal refuses to bind a public or non-IPv4 address")
    if not advertised_address_allowed(advertise_address):
        raise RuntimeError("Portal refuses to advertise a public or non-IPv4 address")
    scheme = "https" if tls else "http"
    core = PortalCore(state_dir, base_url=f"{scheme}://{advertise_address}:{port}")
    server = PortalHTTPServer((listen_address, port), Handler, core, web_root)
    server.allowed_origins = {
        f"{scheme}://{advertise_address}:{port}",
        f"{scheme}://127.0.0.1:{port}",
    }
    if tls:
        cert, key = ensure_certificate(state_dir, advertise_address)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    stop = threading.Event()

    def shutdown(_signum=None, _frame=None):
        if not stop.is_set():
            stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    network_thread = None
    if monitor_network:

        def watch_network():
            previous_mismatch = None
            while not stop.wait(3):
                current = lan_ip()
                if current == advertise_address:
                    previous_mismatch = None
                elif current == previous_mismatch:
                    shutdown()
                    return
                else:
                    previous_mismatch = current

        network_thread = threading.Thread(target=watch_network, daemon=True)
        network_thread.start()
    print(
        json.dumps(
            {
                "status": "ready",
                "url": core.base_url,
                "listen_address": listen_address,
                "advertise_address": advertise_address,
                "port": server.server_address[1],
                "pid": os.getpid(),
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stop.set()
        server.server_close()
        if network_thread:
            network_thread.join(1)
