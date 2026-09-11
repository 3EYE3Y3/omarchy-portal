"""Capability probes for `portal doctor`."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path


def command_ok(args: list[str]) -> bool:
    try:
        return (
            subprocess.run(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def report(plugin_root: Path, state_dir: Path) -> dict:
    manifest_ok = command_ok(["omarchy", "plugin", "validate", str(plugin_root)])
    hypr = command_ok(["hyprctl", "-j", "version"])
    lua_dispatch = (
        command_ok(["hyprctl", "eval", "return type(hl.dsp.cursor.move)"])
        if hypr
        else False
    )
    checks = {
        "Omarchy detected": shutil.which("omarchy") is not None,
        "plugin API compatible": manifest_ok,
        "Hyprland detected": hypr,
        "Quickshell detected": shutil.which("quickshell") is not None,
        "LAN available": any(name != "lo" for _, name in socket.if_nameindex()),
        "QR support": shutil.which("qrencode") is not None,
        "clipboard support": bool(shutil.which("wl-copy") and shutil.which("wl-paste")),
        "media support": bool(shutil.which("playerctl") or shutil.which("busctl")),
        "PipeWire available": shutil.which("wpctl") is not None,
        "window control available": hypr and lua_dispatch,
        "screenshot support": shutil.which("grim") is not None,
        "pointer movement": hypr and lua_dispatch,
        "pointer click/scroll": hypr and lua_dispatch,
        "keyboard input": shutil.which("wtype") is not None,
        "TLS support": shutil.which("openssl") is not None,
    }
    runtime = state_dir / "runtime.json"
    ready = False
    if runtime.exists():
        try:
            pid = int(json.loads(runtime.read_text()).get("pid", 0))
            os.kill(pid, 0)
            ready = True
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    features = {
        "Portal service": ready,
        "Phone UI": (plugin_root / "web/index.html").is_file(),
        "Pairing": True,
        "Universal Send": True,
        "Take This": True,
        "Control": checks["pointer movement"] and checks["keyboard input"],
        "Window management": hypr,
        "Portal Vision": checks["QR support"] and hypr,
        "X-Ray integration": shutil.which("xray") is not None,
    }
    return {"checks": checks, "features": features}
