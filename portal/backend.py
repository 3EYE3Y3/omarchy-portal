"""Desktop integration adapters. Every action uses an unprivileged desktop API."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class BackendError(RuntimeError):
    pass


class DesktopBackend:
    def run(
        self, args: list[str], *, input_text: str | None = None, timeout: float = 4
    ) -> str:
        try:
            result = subprocess.run(
                args,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendError(str(exc)) from exc
        if result.returncode:
            raise BackendError(
                (result.stderr or result.stdout or "command failed").strip()
            )
        return result.stdout

    def json_command(self, args: list[str]) -> Any:
        try:
            return json.loads(self.run(args))
        except json.JSONDecodeError as exc:
            raise BackendError("desktop API returned malformed JSON") from exc

    def windows(self) -> list[dict]:
        clients = self.json_command(["hyprctl", "-j", "clients"])
        result = []
        for item in clients:
            if not item.get("mapped", True) or item.get("hidden", False):
                continue
            result.append(
                {
                    "address": item.get("address", ""),
                    "stable_id": item.get("stableId", ""),
                    "class": item.get("class", "Unknown"),
                    "title": item.get("title", "Untitled"),
                    "pid": int(item.get("pid", 0)),
                    "workspace": item.get("workspace", {}),
                    "monitor": int(item.get("monitor", 0)),
                    "at": item.get("at", [0, 0]),
                    "size": item.get("size", [0, 0]),
                    "fullscreen": bool(item.get("fullscreen", False)),
                    "floating": bool(item.get("floating", False)),
                    "visible": bool(item.get("visible", True)),
                }
            )
        return result

    def monitors(self) -> list[dict]:
        return self.json_command(["hyprctl", "-j", "monitors"])

    def workspaces(self) -> list[dict]:
        return self.json_command(["hyprctl", "-j", "workspaces"])

    def active_window(self) -> dict:
        window = self.json_command(["hyprctl", "-j", "activewindow"])
        if not window or not window.get("address"):
            raise BackendError("no active window")
        return window

    def find_window(self, address: str) -> dict | None:
        return next((w for w in self.windows() if w["address"] == address), None)

    def eval_lua(self, expression: str) -> str:
        # Omarchy 4 / Hyprland 0.56 exposes typed Lua dispatcher objects.
        # Every caller below validates identifiers and JSON-quotes strings
        # before constructing an expression.
        return self.run(["hyprctl", "eval", expression])

    @staticmethod
    def lua_string(value: str) -> str:
        return json.dumps(value, ensure_ascii=True)

    @staticmethod
    def lua_window(address: str) -> str:
        if not re.fullmatch(r"0x[0-9a-fA-F]+", address):
            raise BackendError("invalid window address")
        return f'tonumber("{address}")'

    def window_action(self, address: str, action: str, value: str = "") -> None:
        if not re.fullmatch(r"0x[0-9a-fA-F]+", address):
            raise BackendError("invalid window address")
        if not self.find_window(address):
            raise BackendError("window disappeared")
        target = self.lua_window(address)
        if action == "focus":
            self.eval_lua(f"hl.dispatch(hl.dsp.focus({{ window = {target} }}))")
        elif action == "workspace":
            if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,64}", value):
                raise BackendError("invalid workspace")
            self.eval_lua(
                f"hl.dispatch(hl.dsp.window.move({{ workspace = {self.lua_string(value)}, follow = false, window = {target} }}))"
            )
        elif action == "monitor":
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
                raise BackendError("invalid monitor")
            monitor = next(
                (m for m in self.monitors() if str(m.get("name")) == value), None
            )
            if not monitor:
                raise BackendError("monitor not found")
            workspace = str((monitor.get("activeWorkspace") or {}).get("name", ""))
            if not workspace:
                raise BackendError("monitor has no active workspace")
            self.eval_lua(
                f"hl.dispatch(hl.dsp.window.move({{ workspace = {self.lua_string(workspace)}, follow = false, window = {target} }}))"
            )
        elif action == "fullscreen":
            self.eval_lua(
                f'hl.dispatch(hl.dsp.window.fullscreen({{ mode = "fullscreen", window = {target} }}))'
            )
        elif action == "close":
            self.eval_lua(f"hl.dispatch(hl.dsp.window.close({{ window = {target} }}))")
        else:
            raise BackendError("unknown window action")

    def control(self, action: str, payload: dict) -> None:
        if action == "move":
            cursor = self.json_command(["hyprctl", "cursorpos", "-j"])
            dx = max(-500, min(500, int(payload.get("dx", 0))))
            dy = max(-500, min(500, int(payload.get("dy", 0))))
            x, y = int(cursor["x"]) + dx, int(cursor["y"]) + dy
            self.eval_lua(f"hl.dispatch(hl.dsp.cursor.move({{ x = {x}, y = {y} }}))")
        elif action in {"left", "right"}:
            button = "mouse:272" if action == "left" else "mouse:273"
            self.eval_lua(
                f'hl.dispatch(hl.dsp.send_shortcut({{ mods = "", key = "{button}" }}))'
            )
        elif action == "scroll":
            direction = "mouse_up" if float(payload.get("dy", 0)) < 0 else "mouse_down"
            key = "mouse:274" if direction == "mouse_up" else "mouse:275"
            self.eval_lua(
                f'hl.dispatch(hl.dsp.send_shortcut({{ mods = "", key = "{key}" }}))'
            )
        elif action == "type":
            text = str(payload.get("text", ""))
            if len(text.encode()) > 65536:
                raise BackendError("keyboard input too large")
            self.run(["wtype", "--", text], timeout=10)
        elif action == "key":
            key = str(payload.get("key", ""))
            allowed = {
                "Return",
                "Escape",
                "Tab",
                "BackSpace",
                "Delete",
                "Left",
                "Right",
                "Up",
                "Down",
                "space",
            }
            if key not in allowed:
                raise BackendError("key not allowed")
            self.run(["wtype", "-k", key])
        else:
            raise BackendError("unknown control action")

    def clipboard_get(self) -> str:
        return self.run(["wl-paste", "--no-newline"], timeout=2)

    def clipboard_set(self, text: str) -> None:
        self.run(["wl-copy", "--", text], timeout=2)

    def open_target(self, target: str) -> None:
        self.run(["xdg-open", target], timeout=2)

    def terminal_cwd(self, pid: int) -> str | None:
        seen = set()
        current = pid
        for _ in range(12):
            if current <= 1 or current in seen:
                break
            seen.add(current)
            try:
                cwd = os.readlink(f"/proc/{current}/cwd")
                comm = Path(f"/proc/{current}/comm").read_text().strip().lower()
                if comm in {"bash", "zsh", "fish", "nu", "tmux", "nvim", "vim"}:
                    return cwd
                stat = Path(f"/proc/{current}/stat").read_text()
                current = int(stat.split(") ", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                break
        return None

    def current_context(self) -> dict:
        try:
            window = self.active_window()
        except BackendError:
            window = {}
        klass = str(window.get("class", ""))
        title = str(window.get("title", ""))
        pid = int(window.get("pid", 0))
        if any(
            term in klass.lower()
            for term in ("terminal", "ghostty", "kitty", "alacritty", "foot")
        ):
            cwd = self.terminal_cwd(pid)
            if cwd:
                return {
                    "kind": "directory",
                    "value": cwd,
                    "application": klass,
                    "title": title,
                }
        try:
            clip = self.clipboard_get()
            if clip:
                kind = (
                    "url"
                    if re.match(r"^https?://", clip.strip(), re.IGNORECASE)
                    else "text"
                )
                return {
                    "kind": kind,
                    "value": clip,
                    "application": klass,
                    "title": title,
                    "fallback": True,
                }
        except BackendError:
            pass
        return {
            "kind": "application",
            "value": klass or title or "Desktop",
            "application": klass,
            "title": title,
        }

    def media(self) -> list[dict]:
        if not shutil.which("playerctl"):
            return self._media_busctl()
        try:
            names = [n for n in self.run(["playerctl", "-l"]).splitlines() if n]
        except BackendError:
            return []
        players = []
        for name in names:
            try:
                raw = self.run(
                    [
                        "playerctl",
                        "-p",
                        name,
                        "metadata",
                        "--format",
                        "{{artist}}\t{{title}}\t{{mpris:length}}",
                    ]
                )
                artist, title, length = (raw.rstrip("\n").split("\t") + ["", "", ""])[
                    :3
                ]
                status = self.run(["playerctl", "-p", name, "status"]).strip()
                players.append(
                    {
                        "id": name,
                        "status": status,
                        "artist": artist,
                        "title": title,
                        "length": int(length or 0),
                    }
                )
            except (BackendError, ValueError):
                continue
        return players

    def _mpris_names(self) -> list[str]:
        if not shutil.which("busctl"):
            return []
        try:
            text = self.run(["busctl", "--user", "--no-pager", "--no-legend", "list"])
        except BackendError:
            return []
        return [
            line.split()[0]
            for line in text.splitlines()
            if line.startswith("org.mpris.MediaPlayer2.")
        ]

    def _bus_property(self, service: str, prop: str):
        raw = self.run(
            [
                "busctl",
                "--user",
                "--json=short",
                "get-property",
                service,
                "/org/mpris/MediaPlayer2",
                "org.mpris.MediaPlayer2.Player",
                prop,
            ]
        )
        return json.loads(raw).get("data")

    @staticmethod
    def _metadata_value(metadata: dict, key: str, default=""):
        value = metadata.get(key, {}).get("data", default)
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        return value

    def _media_busctl(self) -> list[dict]:
        players = []
        for service in self._mpris_names():
            try:
                status = str(self._bus_property(service, "PlaybackStatus") or "")
                metadata = self._bus_property(service, "Metadata") or {}

                artist = str(self._metadata_value(metadata, "xesam:artist"))
                title = str(self._metadata_value(metadata, "xesam:title"))
                if status not in {"Playing", "Paused"} or not (artist or title):
                    continue
                players.append(
                    {
                        "id": service,
                        "status": status,
                        "artist": artist,
                        "title": title,
                        "length": int(
                            self._metadata_value(metadata, "mpris:length", 0) or 0
                        ),
                    }
                )
            except (BackendError, json.JSONDecodeError, TypeError, ValueError):
                continue
        return players

    def media_action(self, player: str, action: str, value: str = "") -> None:
        if action not in {"play-pause", "previous", "next", "pause", "play"}:
            raise BackendError("media action not allowed")
        if shutil.which("playerctl"):
            self.run(["playerctl", "-p", player, action])
            return
        if player not in self._mpris_names():
            raise BackendError("media player disappeared")
        method = {
            "play-pause": "PlayPause",
            "previous": "Previous",
            "next": "Next",
            "pause": "Pause",
            "play": "Play",
        }[action]
        self.run(
            [
                "busctl",
                "--user",
                "call",
                player,
                "/org/mpris/MediaPlayer2",
                "org.mpris.MediaPlayer2.Player",
                method,
            ]
        )

    def audio_outputs(self) -> list[dict]:
        if not shutil.which("wpctl"):
            return []
        text = self.run(["wpctl", "status", "-n"])
        outputs, in_sinks = [], False
        for line in text.splitlines():
            if "Sinks:" in line:
                in_sinks = True
                continue
            if in_sinks and ("Sources:" in line or "Filters:" in line):
                break
            if not in_sinks:
                continue
            match = re.search(r"(\*)?\s*(\d+)\.\s+(.+?)(?:\s+\[vol:|$)", line)
            if match:
                outputs.append(
                    {
                        "id": match.group(2),
                        "name": match.group(3).strip(),
                        "default": match.group(1) == "*",
                    }
                )
        return outputs

    def set_audio_output(self, node_id: str) -> None:
        if not node_id.isdigit():
            raise BackendError("invalid audio output")
        self.run(["wpctl", "set-default", node_id])

    def set_volume(self, delta: float) -> None:
        delta = max(-0.1, min(0.1, float(delta)))
        percent = max(1, round(abs(delta) * 100))
        suffix = "+" if delta >= 0 else "-"
        self.run(
            [
                "wpctl",
                "set-volume",
                "-l",
                "1.25",
                "@DEFAULT_AUDIO_SINK@",
                f"{percent}%{suffix}",
            ]
        )

    def screenshot(self, active: bool = False) -> Path:
        fd, name = tempfile.mkstemp(prefix="portal-shot-", suffix=".png")
        os.close(fd)
        target = Path(name)
        args = ["grim"]
        if active:
            w = self.active_window()
            x, y = w["at"]
            width, height = w["size"]
            args += ["-g", f"{x},{y} {width}x{height}"]
        args.append(str(target))
        self.run(args, timeout=10)
        return target

    def xray(self, target: str) -> dict | None:
        if not shutil.which("xray"):
            return None
        try:
            data = json.loads(self.run(["xray", "--json", target], timeout=2))
            return data if isinstance(data, dict) else None
        except (BackendError, json.JSONDecodeError):
            return None

    def xray_available(self) -> bool:
        return shutil.which("xray") is not None


class FakeBackend(DesktopBackend):
    """Deterministic adapter used by the acceptance tests."""

    def __init__(self):
        self._windows: list[dict] = []
        self.clipboard = ""
        self.calls: list[tuple] = []
        self._media: list[dict] = []
        self._audio: list[dict] = []
        self.xray_value = None

    def windows(self):
        return [dict(w) for w in self._windows]

    def monitors(self):
        return [
            {
                "id": 0,
                "name": "eDP-1",
                "x": 0,
                "y": 0,
                "width": 1920,
                "height": 1080,
                "scale": 1,
            }
        ]

    def workspaces(self):
        return [{"id": 1, "name": "1", "monitor": "eDP-1"}]

    def active_window(self):
        if not self._windows:
            raise BackendError("no active window")
        return self._windows[0]

    def clipboard_get(self):
        return self.clipboard

    def clipboard_set(self, text):
        self.clipboard = text
        self.calls.append(("clipboard", text))

    def open_target(self, target):
        self.calls.append(("open", target))

    def window_action(self, address, action, value=""):
        if not self.find_window(address):
            raise BackendError("window disappeared")
        self.calls.append(("window", address, action, value))

    def control(self, action, payload):
        self.calls.append(("control", action, payload))

    def eval_lua(self, expression):
        self.calls.append(("lua", expression))
        return "ok"

    def media(self):
        return list(self._media)

    def media_action(self, player, action, value=""):
        self.calls.append(("media", player, action, value))

    def audio_outputs(self):
        return list(self._audio)

    def set_audio_output(self, node_id):
        self.calls.append(("audio", node_id))

    def set_volume(self, delta):
        self.calls.append(("volume", delta))

    def xray(self, target):
        return self.xray_value

    def xray_available(self):
        return self.xray_value is not None
