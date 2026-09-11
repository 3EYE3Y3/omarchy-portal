"""Portal domain layer: pairing, authorization, transfers, context and Vision."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import time
import unicodedata
import uuid
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote

from .backend import DesktopBackend
from .security import (
    derive,
    digest,
    load_or_create_key,
    looks_sensitive,
    secure_compare,
    token,
)
from .store import Store

PAIR_TTL = 300
REQUEST_TTL = 300
SESSION_TTL = 24 * 3600
INBOX_TTL = 24 * 3600
SECRET_TTL = 300
VISION_TTL = 20
MAX_TEXT = 1_000_000
MAX_FILE = 512 * 1024 * 1024
DEFAULT_CAPABILITIES = {
    "send_receive",
    "clipboard",
    "media",
    "window_control",
    "files",
    "command_palette",
}
ALL_CAPABILITIES = DEFAULT_CAPABILITIES | {
    "pointer",
    "keyboard",
    "screenshots",
    "audio",
    "terminal",
    "xray",
}


class PortalError(RuntimeError):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.status = status
        self.code = code


def clean_name(value: str, fallback: str = "item") -> str:
    value = unicodedata.normalize("NFC", str(value or "")).replace("\x00", "")
    value = value.replace("/", "_").replace("\\", "_").strip().strip(".")
    value = re.sub(r"[\r\n\t]", " ", value)
    value = "".join(ch for ch in value if unicodedata.category(ch)[0] != "C")
    if not value:
        value = fallback
    encoded = value.encode("utf-8")
    if len(encoded) > 220:
        stem, suffix = os.path.splitext(value)
        suffix = suffix[:20]
        budget = 220 - len(suffix.encode())
        while len(stem.encode()) > budget:
            stem = stem[:-1]
        value = stem + suffix
    return value


class PortalCore:
    def __init__(
        self,
        state_dir: Path,
        backend: DesktopBackend | None = None,
        clock: Callable[[], float] = time.time,
        base_url: str = "https://127.0.0.1:59443",
    ):
        self.store = Store(state_dir)
        self.backend = backend or DesktopBackend()
        self.clock = clock
        self.base_url = base_url.rstrip("/")
        self.key = load_or_create_key(state_dir / "server.key")

    def now(self) -> float:
        return float(self.clock())

    def start_pairing(self) -> dict:
        raw = token()
        expires = self.now() + PAIR_TTL
        self.store.execute(
            "INSERT INTO pairing_tokens(digest,expires) VALUES(?,?)",
            (digest(raw), expires),
        )
        # Fragment prevents the bearer-like pairing secret from reaching HTTP logs.
        return {
            "url": f"{self.base_url}/#pair={quote(raw)}",
            "secret": raw,
            "expires": expires,
        }

    def request_pair(
        self, secret: str, name: str, public_id: str, requested: list[str]
    ) -> dict:
        now = self.now()
        token_digest = digest(secret)
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM pairing_tokens WHERE digest=?", (token_digest,)
            ).fetchone()
            if not row or row["consumed"] is not None:
                raise PortalError(
                    "pairing token is invalid or already used",
                    401,
                    "invalid_pairing_token",
                )
            if row["expires"] < now:
                raise PortalError("pairing token expired", 401, "expired_pairing_token")
            db.execute(
                "UPDATE pairing_tokens SET consumed=? WHERE digest=?",
                (now, token_digest),
            )
            request_id = uuid.uuid4().hex
            claim = token()
            allowed = sorted(set(requested) & ALL_CAPABILITIES)
            if not allowed:
                allowed = sorted(DEFAULT_CAPABILITIES)
            db.execute(
                "INSERT INTO pair_requests VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    digest(claim),
                    clean_name(name, "Phone")[:80],
                    clean_name(public_id, uuid.uuid4().hex)[:128],
                    json.dumps(allowed),
                    "pending",
                    now,
                    now + REQUEST_TTL,
                    None,
                    None,
                ),
            )
        return {
            "request_id": request_id,
            "claim_token": claim,
            "status": "pending",
            "expires": now + REQUEST_TTL,
        }

    def pending_pairs(self) -> list[dict]:
        rows = self.store.all(
            "SELECT id,device_name,requested,created,expires FROM pair_requests WHERE status='pending' AND expires>=? ORDER BY created",
            (self.now(),),
        )
        return [dict(r) | {"requested": json.loads(r["requested"])} for r in rows]

    def decide_pair(
        self, request_id: str, allow: bool, capabilities: list[str] | None = None
    ) -> dict:
        now = self.now()
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM pair_requests WHERE id=?", (request_id,)
            ).fetchone()
            if not row or row["status"] != "pending" or row["expires"] < now:
                raise PortalError(
                    "pair request is no longer pending", 404, "pair_request_missing"
                )
            if not allow:
                db.execute(
                    "UPDATE pair_requests SET status='denied' WHERE id=?", (request_id,)
                )
                return {"status": "denied"}
            requested = set(json.loads(row["requested"]))
            granted = sorted(
                (set(capabilities) if capabilities is not None else requested)
                & requested
                & ALL_CAPABILITIES
            )
            device_id = uuid.uuid4().hex
            credential = derive(self.key, "device", request_id, row["claim_digest"])
            existing = db.execute(
                "SELECT id FROM devices WHERE public_id=?", (row["public_id"],)
            ).fetchone()
            if existing:
                device_id = existing["id"]
                db.execute(
                    "UPDATE devices SET name=?,credential_digest=?,capabilities=?,last_seen=?,revoked=NULL WHERE id=?",
                    (
                        row["device_name"],
                        digest(credential),
                        json.dumps(granted),
                        now,
                        device_id,
                    ),
                )
            else:
                db.execute(
                    "INSERT INTO devices VALUES(?,?,?,?,?,?,?,NULL)",
                    (
                        device_id,
                        row["public_id"],
                        row["device_name"],
                        digest(credential),
                        json.dumps(granted),
                        now,
                        now,
                    ),
                )
            session_token = derive(self.key, "session", request_id, row["claim_digest"])
            session_id = uuid.uuid4().hex
            db.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?,?,NULL)",
                (
                    session_id,
                    digest(session_token),
                    device_id,
                    now,
                    now + SESSION_TTL,
                    now,
                ),
            )
            db.execute(
                "UPDATE pair_requests SET status='approved',device_id=?,granted=? WHERE id=?",
                (device_id, json.dumps(granted), request_id),
            )
        return {"status": "approved", "device_id": device_id, "capabilities": granted}

    def poll_pair(self, request_id: str, claim: str) -> dict:
        row = self.store.one("SELECT * FROM pair_requests WHERE id=?", (request_id,))
        if not row or not secure_compare(digest(claim), row["claim_digest"]):
            raise PortalError("pair request not found", 404, "pair_request_missing")
        if row["expires"] < self.now():
            raise PortalError("pair request expired", 401, "expired_pair_request")
        if row["status"] != "approved":
            return {"status": row["status"]}
        session_token = derive(self.key, "session", request_id, row["claim_digest"])
        credential = derive(self.key, "device", request_id, row["claim_digest"])
        return {
            "status": "approved",
            "device_id": row["device_id"],
            "session_token": session_token,
            "device_token": credential,
            "capabilities": json.loads(row["granted"] or "[]"),
        }

    def resume(self, device_id: str, device_token: str) -> dict:
        now = self.now()
        row = self.store.one("SELECT * FROM devices WHERE id=?", (device_id,))
        if (
            not row
            or row["revoked"] is not None
            or not secure_compare(digest(device_token), row["credential_digest"])
        ):
            raise PortalError("device credential rejected", 401, "invalid_device")
        raw = token()
        sid = uuid.uuid4().hex
        self.store.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?,NULL)",
            (sid, digest(raw), device_id, now, now + SESSION_TTL, now),
        )
        self.store.execute(
            "UPDATE devices SET last_seen=? WHERE id=?", (now, device_id)
        )
        return {
            "session_token": raw,
            "expires": now + SESSION_TTL,
            "capabilities": json.loads(row["capabilities"]),
        }

    def authenticate(self, raw: str, capability: str | None = None) -> dict:
        if not raw:
            raise PortalError("authentication required", 401, "missing_auth")
        now = self.now()
        row = self.store.one(
            "SELECT s.*,d.name,d.capabilities,d.revoked AS device_revoked FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.token_digest=?",
            (digest(raw),),
        )
        if not row:
            raise PortalError("invalid session", 401, "invalid_auth")
        if row["expires"] < now or row["revoked"] is not None:
            raise PortalError("session expired or revoked", 401, "expired_session")
        if row["device_revoked"] is not None:
            raise PortalError("device revoked", 401, "revoked_device")
        caps = set(json.loads(row["capabilities"]))
        if capability and capability not in caps:
            raise PortalError(
                f"capability denied: {capability}", 403, "permission_denied"
            )
        self.store.execute(
            "UPDATE sessions SET last_seen=? WHERE id=?", (now, row["id"])
        )
        self.store.execute(
            "UPDATE devices SET last_seen=? WHERE id=?", (now, row["device_id"])
        )
        return dict(row) | {"capability_set": caps}

    def devices(self) -> list[dict]:
        rows = self.store.all(
            "SELECT id,name,capabilities,created,last_seen,revoked FROM devices ORDER BY last_seen DESC"
        )
        now = self.now()
        result = []
        for r in rows:
            online = self.store.one(
                "SELECT 1 FROM sessions WHERE device_id=? AND revoked IS NULL AND expires>? AND last_seen>?",
                (r["id"], now, now - 90),
            )
            result.append(
                dict(r)
                | {
                    "capabilities": json.loads(r["capabilities"]),
                    "connected": bool(online),
                }
            )
        return result

    def edit_device(self, device_id: str, capabilities: list[str]) -> None:
        caps = sorted(set(capabilities) & ALL_CAPABILITIES)
        if not self.store.one("SELECT 1 FROM devices WHERE id=?", (device_id,)):
            raise PortalError("unknown device", 404)
        self.store.execute(
            "UPDATE devices SET capabilities=? WHERE id=?",
            (json.dumps(caps), device_id),
        )

    def disconnect(self, device_id: str) -> None:
        self.store.execute(
            "UPDATE sessions SET revoked=? WHERE device_id=? AND revoked IS NULL",
            (self.now(), device_id),
        )

    def revoke(self, device_id: str) -> None:
        now = self.now()
        with self.store.connect() as db:
            db.execute("UPDATE devices SET revoked=? WHERE id=?", (now, device_id))
            db.execute(
                "UPDATE sessions SET revoked=? WHERE device_id=? AND revoked IS NULL",
                (now, device_id),
            )

    def _destination(self, requested: str) -> Path:
        safe = clean_name(requested)
        path = self.store.inbox_dir / safe
        if path.parent != self.store.inbox_dir:
            raise PortalError("unsafe filename")
        if not path.exists():
            return path
        stem, suffix = path.stem, path.suffix
        for index in range(1, 10000):
            candidate = path.with_name(f"{stem}-{index}{suffix}")
            if not candidate.exists():
                return candidate
        raise PortalError("could not allocate destination", 500)

    def add_text(
        self,
        kind: str,
        text: str,
        *,
        name: str = "",
        secure: bool = False,
        direction: str = "to_pc",
    ) -> dict:
        if kind not in {"text", "url", "clipboard"}:
            raise PortalError("unsupported item kind")
        if len(text.encode()) > MAX_TEXT:
            raise PortalError("text too large", 413)
        if kind == "url" and not re.match(r"^https?://", text.strip(), re.IGNORECASE):
            raise PortalError("only http(s) URLs are accepted")
        secure = bool(secure or looks_sensitive(text))
        now = self.now()
        item_id = uuid.uuid4().hex
        expires = now + (SECRET_TTL if secure else INBOX_TTL)
        self.store.execute(
            "INSERT INTO inbox VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                item_id,
                kind,
                clean_name(name, "Secure text" if secure else kind.title()),
                "text/plain",
                len(text.encode()),
                None,
                text,
                direction,
                int(secure),
                now,
                expires,
            ),
        )
        return self.inbox_item(item_id, include_text=True)

    def add_file(
        self,
        name: str,
        source,
        size: int,
        mime: str = "",
        *,
        secure: bool = False,
        direction: str = "to_pc",
    ) -> dict:
        if size < 0 or size > MAX_FILE:
            raise PortalError("file size is outside allowed range", 413)
        destination = self._destination(name)
        temp = destination.with_name(f".{destination.name}.{secrets.token_hex(6)}.part")
        written = 0
        try:
            with temp.open("xb") as out:
                while written < size:
                    chunk = source.read(min(1024 * 1024, size - written))
                    if not chunk:
                        raise PortalError(
                            "transfer interrupted", 400, "interrupted_transfer"
                        )
                    out.write(chunk)
                    written += len(chunk)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temp, 0o600)
            temp.replace(destination)
        except Exception:
            temp.unlink(missing_ok=True)
            raise
        now = self.now()
        item_id = uuid.uuid4().hex
        kind = (
            "image"
            if (mime or mimetypes.guess_type(destination.name)[0] or "").startswith(
                "image/"
            )
            else "file"
        )
        self.store.execute(
            "INSERT INTO inbox VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                item_id,
                kind,
                destination.name,
                mime
                or mimetypes.guess_type(destination.name)[0]
                or "application/octet-stream",
                size,
                str(destination),
                None,
                direction,
                int(secure),
                now,
                now + (SECRET_TTL if secure else INBOX_TTL),
            ),
        )
        return self.inbox_item(item_id)

    def add_local_file(self, source: Path, direction: str = "to_phone") -> dict:
        if not source.is_file():
            raise PortalError("file not found", 404)
        with source.open("rb") as stream:
            return self.add_file(
                source.name,
                stream,
                source.stat().st_size,
                mimetypes.guess_type(source.name)[0] or "",
                direction=direction,
            )

    def inbox_item(self, item_id: str, include_text: bool = False) -> dict:
        row = self.store.one("SELECT * FROM inbox WHERE id=?", (item_id,))
        if not row:
            raise PortalError("inbox item not found", 404)
        item = dict(row)
        item.pop("content_path", None)
        if not include_text and item.get("secure"):
            item["text_value"] = None
        return item

    def inbox(self) -> list[dict]:
        self.store.cleanup(self.now())
        rows = self.store.all(
            "SELECT * FROM inbox WHERE expires>=? ORDER BY created DESC", (self.now(),)
        )
        result = []
        for row in rows:
            item = dict(row)
            item.pop("content_path", None)
            if item["secure"]:
                item["text_value"] = None
            result.append(item)
        return result

    def inbox_content(self, item_id: str):
        row = self.store.one(
            "SELECT * FROM inbox WHERE id=? AND expires>=?", (item_id, self.now())
        )
        if not row:
            raise PortalError("inbox item expired or missing", 404)
        return row

    def inbox_action(self, item_id: str, action: str) -> dict:
        row = self.inbox_content(item_id)
        if action == "discard":
            if row["content_path"]:
                Path(row["content_path"]).unlink(missing_ok=True)
            self.store.execute("DELETE FROM inbox WHERE id=?", (item_id,))
            return {"status": "discarded"}
        target = row["content_path"] or row["text_value"] or ""
        if action == "copy":
            if row["content_path"]:
                target = row["content_path"]
            self.backend.clipboard_set(target)
            return {"status": "copied"}
        if action == "open":
            if row["kind"] == "text":
                self.backend.clipboard_set(target)
                return {"status": "copied"}
            self.backend.open_target(target)
            return {"status": "opened"}
        raise PortalError("unknown inbox action")

    def clipboard_set(
        self, text: str, secure: bool = False, clear_after: int = 0
    ) -> dict:
        if len(text.encode()) > MAX_TEXT:
            raise PortalError("clipboard too large", 413)
        secure = secure or looks_sensitive(text)
        self.backend.clipboard_set(text)
        if not secure and text:
            now = self.now()
            self.store.execute(
                "INSERT INTO clipboard_history VALUES(?,?,?,?)",
                (uuid.uuid4().hex, text[:160], now, now + 3600),
            )
            with self.store.connect() as db:
                db.execute(
                    "DELETE FROM clipboard_history WHERE id NOT IN (SELECT id FROM clipboard_history ORDER BY created DESC LIMIT 10)"
                )
        # Service schedules clearing without retaining content; the caller receives deadline.
        return {
            "secure": secure,
            "clear_at": self.now() + clear_after
            if secure and clear_after > 0
            else None,
        }

    def clipboard_get(self) -> dict:
        text = self.backend.clipboard_get()
        return {"text": text, "sensitive_guess": looks_sensitive(text)}

    def take_this(self, session_id: str | None = None) -> dict:
        context = self.backend.current_context()
        kind = context.get("kind", "application")
        value = str(context.get("value", ""))
        if kind == "directory":
            # Directories are context, never recursively transferred implicitly.
            return self.add_text(
                "text", value, name="Terminal directory", direction="to_phone"
            ) | {"context": context}
        if kind in {"url", "text"}:
            return self.add_text(
                kind,
                value,
                name=context.get("title", "Current context"),
                direction="to_phone",
            ) | {"context": context}
        return self.add_text(
            "text", value, name="Active application", direction="to_phone"
        ) | {"context": context}

    def windows_state(self) -> dict:
        windows = self.backend.windows()
        return {
            "windows": windows,
            "workspaces": self.backend.workspaces(),
            "monitors": self.backend.monitors(),
        }

    def window_detail(self, address: str) -> dict:
        window = self.backend.find_window(address)
        if not window:
            raise PortalError("window disappeared", 404, "window_missing")
        klass = window["class"].lower()
        category = "generic"
        if any(x in klass for x in ("firefox", "chrom", "browser")):
            category = "browser"
        elif any(
            x in klass for x in ("terminal", "ghostty", "kitty", "alacritty", "foot")
        ):
            category = "terminal"
        elif any(x in klass for x in ("spotify", "vlc", "mpv")):
            category = "media"
        elif any(x in klass for x in ("nautilus", "thunar", "dolphin", "nemo")):
            category = "files"
        xray = self.backend.xray(address)
        return window | {"category": category, "xray": xray}

    def set_vision(self, active: bool, session_id: str | None = None) -> dict:
        self.store.set_setting(
            "vision",
            {"active": bool(active), "session_id": session_id, "changed": self.now()},
        )
        if not active:
            self.store.execute("DELETE FROM vision_markers")
        return {"active": bool(active)}

    def vision_status(self) -> dict:
        setting = self.store.setting("vision", {"active": False})
        if not setting.get("active"):
            return {"active": False, "markers": []}
        session_id = setting.get("session_id")
        if not session_id:
            row = self.store.one(
                "SELECT id FROM sessions WHERE revoked IS NULL AND expires>? ORDER BY last_seen DESC LIMIT 1",
                (self.now(),),
            )
            session_id = row["id"] if row else None
        if not session_id:
            return {"active": True, "markers": [], "reason": "no authenticated session"}
        now = self.now()
        markers = []
        for window in self.backend.windows():
            if not window.get("visible", True):
                continue
            raw = token()
            self.store.execute(
                "INSERT INTO vision_markers VALUES(?,?,?,?,?,NULL)",
                (
                    digest(raw),
                    session_id,
                    window["address"],
                    window.get("stable_id", ""),
                    now + VISION_TTL,
                ),
            )
            url = f"{self.base_url}/#vision={quote(raw)}"
            markers.append(
                {
                    "token": raw,
                    "url": url,
                    "window": window,
                    "expires": now + VISION_TTL,
                }
            )
        return {"active": True, "markers": markers, "expires": now + VISION_TTL}

    def resolve_vision(self, raw: str, session: dict) -> dict:
        now = self.now()
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM vision_markers WHERE digest=?", (digest(raw),)
            ).fetchone()
            if not row or row["used"] is not None:
                raise PortalError(
                    "Vision marker is invalid or already used", 401, "invalid_marker"
                )
            if row["expires"] < now:
                raise PortalError("Vision marker expired", 401, "expired_marker")
            if row["session_id"] != session["id"]:
                raise PortalError(
                    "Vision marker belongs to another session", 403, "wrong_session"
                )
            window = self.backend.find_window(row["window_address"])
            if not window or (
                row["stable_id"] and window.get("stable_id") != row["stable_id"]
            ):
                raise PortalError(
                    "target window no longer exists", 404, "window_missing"
                )
            db.execute(
                "UPDATE vision_markers SET used=? WHERE digest=?", (now, digest(raw))
            )
        return self.window_detail(row["window_address"])

    def action_registry(self) -> list[dict]:
        return [
            {"id": "lock", "title": "Lock PC", "capability": "command_palette"},
            {"id": "mute", "title": "Mute or unmute", "capability": "audio"},
            {
                "id": "terminal",
                "title": "Launch terminal",
                "capability": "command_palette",
            },
            {
                "id": "browser",
                "title": "Launch browser",
                "capability": "command_palette",
            },
            {
                "id": "workspace",
                "title": "Change workspace",
                "capability": "window_control",
            },
            {
                "id": "screenshot",
                "title": "Take screenshot",
                "capability": "screenshots",
            },
            {
                "id": "vision",
                "title": "Toggle Portal Vision",
                "capability": "window_control",
            },
        ]

    def run_action(self, action: str, value: str, session: dict) -> dict:
        caps = session["capability_set"]
        required = next(
            (a["capability"] for a in self.action_registry() if a["id"] == action), None
        )
        if not required:
            raise PortalError("unknown action", 404)
        if required not in caps:
            raise PortalError(
                f"capability denied: {required}", 403, "permission_denied"
            )
        if action == "lock":
            self.backend.run(["omarchy", "system", "lock"])
        elif action == "mute":
            self.backend.run(["wpctl", "set-mute", "@DEFAULT_AUDIO_SINK@", "toggle"])
        elif action == "terminal":
            self.backend.run(["omarchy", "launch", "terminal"])
        elif action == "browser":
            self.backend.run(["omarchy", "launch", "browser"])
        elif action == "workspace":
            if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,64}", value):
                raise PortalError("invalid workspace")
            self.backend.eval_lua(
                f"hl.dispatch(hl.dsp.focus({{ workspace = {self.backend.lua_string(value)} }}))"
            )
        elif action == "vision":
            self.set_vision(
                not self.store.setting("vision", {}).get("active", False), session["id"]
            )
        elif action == "screenshot":
            shot = self.backend.screenshot(value == "active")
            item = self.add_local_file(shot, "to_phone")
            shot.unlink(missing_ok=True)
            return item
        return {"status": "ok"}
