"""Portal command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .backend import BackendError
from .core import ALL_CAPABILITIES, PortalCore, PortalError
from .doctor import report as doctor_report
from .qr import matrix
from .service import (
    advertised_address_allowed,
    ensure_certificate,
    lan_ip,
    listen_address_allowed,
    loopback_address,
    serve,
)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def state_dir() -> Path:
    return Path(os.environ.get("PORTAL_STATE_DIR", Path.home() / ".local/state/portal"))


def active_runtime() -> dict:
    try:
        runtime = json.loads((state_dir() / "runtime.json").read_text())
        pid = int(runtime["pid"])
        os.kill(pid, 0)
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
        if b"portal.cli" not in cmdline and b"/bin/portal" not in cmdline:
            raise OSError("runtime PID does not belong to Portal")
        return runtime
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {}


def base_url() -> str:
    override = os.environ.get("PORTAL_BASE_URL")
    if override:
        return override
    runtime = active_runtime()
    if runtime.get("url"):
        return str(runtime["url"])
    return f"https://{lan_ip()}:{os.environ.get('PORTAL_PORT', '59443')}"


def core() -> PortalCore:
    return PortalCore(state_dir(), base_url=base_url())


def output(value, as_json=False):
    if as_json:
        print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    elif isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2))


def runtime_status(c: PortalCore) -> dict:
    runtime = active_runtime()
    running = bool(runtime)
    pending = c.pending_pairs()
    devices = c.devices()
    try:
        monitors = c.backend.monitors()
    except BackendError:
        monitors = []
    return {
        "version": __version__,
        "running": running,
        "url": runtime.get("url", c.base_url),
        "listen_address": runtime.get("listen_address"),
        "advertise_address": runtime.get("advertise_address"),
        "port": runtime.get("port"),
        "pid": runtime.get("pid"),
        "pending": pending,
        "devices": devices,
        "vision": c.store.setting("vision", {"active": False}),
        "monitors": monitors,
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="portal", description="Your PC, in your pocket.")
    p.add_argument("--version", action="version", version=f"Portal {__version__}")
    sub = p.add_subparsers(dest="command")
    for name in ("status", "pair", "devices", "doctor", "panel-state"):
        q = sub.add_parser(name)
        q.add_argument("--json", action="store_true")
    q = sub.add_parser("serve")
    q.add_argument("--bind", default=os.environ.get("PORTAL_BIND_ADDRESS"))
    q.add_argument("--advertise", default=os.environ.get("PORTAL_ADVERTISE_ADDRESS"))
    q.add_argument(
        "--port", type=int, default=int(os.environ.get("PORTAL_PORT", "59443"))
    )
    q.add_argument(
        "--no-tls",
        action="store_true",
        help="Only permitted with loopback or PORTAL_ALLOW_INSECURE=1",
    )
    q = sub.add_parser("approve")
    q.add_argument("request_id")
    q.add_argument("--deny", action="store_true")
    q.add_argument("--capability", action="append", choices=sorted(ALL_CAPABILITIES))
    q.add_argument("--json", action="store_true")
    q = sub.add_parser("device")
    q.add_argument("action", choices=("disconnect", "revoke", "permissions"))
    q.add_argument("device_id")
    q.add_argument("capabilities", nargs="*")
    q = sub.add_parser("vision")
    q.add_argument(
        "action", nargs="?", choices=("on", "off", "toggle", "status"), default="toggle"
    )
    q.add_argument("--json", action="store_true")
    q = sub.add_parser("take")
    q.add_argument("--json", action="store_true")
    q = sub.add_parser("send")
    q.add_argument("target")
    q.add_argument("--json", action="store_true")
    q = sub.add_parser("discard")
    q.add_argument("item_id")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    c = core()
    try:
        if not args.command:
            result = subprocess.run(
                ["omarchy-shell", "shell", "summon", "io.github.3eye3y3.portal", "{}"],
                check=False,
            )
            return result.returncode
        if args.command in {"status", "panel-state"}:
            value = runtime_status(c)
            if (
                args.command == "panel-state"
                and not value["pending"]
                and not value["devices"]
            ):
                pair = c.start_pairing()
                pair["qr"] = matrix(pair["url"])
                pair.pop("secret", None)
                value["pairing"] = pair
            output(value, args.json)
        elif args.command == "pair":
            value = c.start_pairing()
            value["qr"] = matrix(value["url"])
            value.pop("secret", None)
            certificate_address = urlsplit(c.base_url).hostname or lan_ip()
            cert, _ = ensure_certificate(state_dir(), certificate_address)
            value["certificate_sha256"] = hashlib.sha256(cert.read_bytes()).hexdigest()
            output(value, args.json)
        elif args.command == "approve":
            output(
                c.decide_pair(args.request_id, not args.deny, args.capability),
                args.json,
            )
        elif args.command == "devices":
            output({"devices": c.devices()}, args.json)
        elif args.command == "device":
            if args.action == "disconnect":
                c.disconnect(args.device_id)
            elif args.action == "revoke":
                c.revoke(args.device_id)
            else:
                c.edit_device(args.device_id, args.capabilities)
            output({"status": "ok"}, True)
        elif args.command == "vision":
            old = bool(c.store.setting("vision", {}).get("active", False))
            if args.action == "status":
                value = c.vision_status()
                for marker in value.get("markers", []):
                    marker["qr"] = matrix(marker["url"])
                    marker.pop("token", None)
            else:
                active = args.action == "on" or (args.action == "toggle" and not old)
                value = c.set_vision(active)
            output(value, args.json)
        elif args.command == "take":
            output(c.take_this(), args.json)
        elif args.command == "send":
            target = Path(args.target).expanduser().resolve()
            output(c.add_local_file(target), args.json)
        elif args.command == "discard":
            output(c.inbox_action(args.item_id, "discard"), True)
        elif args.command == "doctor":
            data = doctor_report(PLUGIN_ROOT, state_dir())
            if args.json:
                output(data, True)
            else:
                print("PORTAL DOCTOR\n")
                for label, ok in data["checks"].items():
                    print(f"{'✓' if ok else '○'} {label}")
                print()
                for label, ok in data["features"].items():
                    if label == "X-Ray integration":
                        status = "AVAILABLE" if ok else "NOT INSTALLED"
                    else:
                        status = "READY" if ok else "UNAVAILABLE"
                    print(f"{label:<24} {status}")
        elif args.command == "serve":
            monitor_network = args.advertise is None and args.bind is None
            listen_address = args.bind
            advertise_address = args.advertise
            if advertise_address is None:
                advertise_address = (
                    listen_address
                    if listen_address not in (None, "0.0.0.0")
                    else lan_ip()
                )
            if not advertised_address_allowed(advertise_address):
                raise PortalError("Portal refuses public or non-IPv4 advertised addresses")
            if listen_address is None:
                listen_address = (
                    "127.0.0.1"
                    if loopback_address(advertise_address)
                    else "0.0.0.0"
                )
            if not listen_address_allowed(listen_address):
                raise PortalError("Portal refuses public or non-IPv4 bind addresses")
            if (
                args.no_tls
                and not loopback_address(listen_address)
                and os.environ.get("PORTAL_ALLOW_INSECURE") != "1"
            ):
                raise PortalError(
                    "plain HTTP is restricted to loopback; use TLS for LAN"
                )
            runtime = state_dir() / "runtime.json"
            runtime.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            scheme = "http" if args.no_tls else "https"
            runtime.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "url": f"{scheme}://{advertise_address}:{args.port}",
                        "listen_address": listen_address,
                        "advertise_address": advertise_address,
                        "port": args.port,
                        "started": time.time(),
                    }
                )
            )
            os.chmod(runtime, 0o600)
            try:
                serve(
                    state_dir(),
                    PLUGIN_ROOT / "web",
                    listen_address,
                    args.port,
                    not args.no_tls,
                    advertise_address,
                    monitor_network,
                )
            finally:
                try:
                    if json.loads(runtime.read_text()).get("pid") == os.getpid():
                        runtime.unlink()
                except (OSError, json.JSONDecodeError):
                    pass
        return 0
    except PortalError as exc:
        print(f"portal: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
