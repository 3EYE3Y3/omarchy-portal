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

from . import __version__
from .backend import BackendError
from .core import ALL_CAPABILITIES, PortalCore, PortalError
from .doctor import report as doctor_report
from .qr import matrix
from .service import ensure_certificate, lan_ip, private_bind, serve

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def state_dir() -> Path:
    return Path(os.environ.get("PORTAL_STATE_DIR", Path.home() / ".local/state/portal"))


def base_url() -> str:
    return os.environ.get(
        "PORTAL_BASE_URL",
        f"https://{lan_ip()}:{os.environ.get('PORTAL_PORT', '59443')}",
    )


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
    runtime_path = state_dir() / "runtime.json"
    running, runtime = False, {}
    try:
        runtime = json.loads(runtime_path.read_text())
        os.kill(int(runtime["pid"]), 0)
        running = True
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        pass
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
    q.add_argument("--bind", default=None)
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
                value["pairing"] = pair
            output(value, args.json)
        elif args.command == "pair":
            value = c.start_pairing()
            value["qr"] = matrix(value["url"])
            cert, _ = ensure_certificate(state_dir(), lan_ip())
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
            address = args.bind or lan_ip()
            if not private_bind(address):
                raise PortalError("Portal refuses public or non-IPv4 bind addresses")
            if (
                args.no_tls
                and address not in {"127.0.0.1", "localhost", "::1"}
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
                        "url": f"{scheme}://{address}:{args.port}",
                        "started": time.time(),
                    }
                )
            )
            os.chmod(runtime, 0o600)
            try:
                serve(
                    state_dir(),
                    PLUGIN_ROOT / "web",
                    address,
                    args.port,
                    not args.no_tls,
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
