"""Persistent Portal state. Content and credentials are deliberately separated."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS pairing_tokens (
  digest TEXT PRIMARY KEY, expires REAL NOT NULL, consumed REAL
);
CREATE TABLE IF NOT EXISTS pair_requests (
  id TEXT PRIMARY KEY, claim_digest TEXT NOT NULL, device_name TEXT NOT NULL,
  public_id TEXT NOT NULL, requested TEXT NOT NULL, status TEXT NOT NULL,
  created REAL NOT NULL, expires REAL NOT NULL, device_id TEXT, granted TEXT
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, public_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  credential_digest TEXT NOT NULL, capabilities TEXT NOT NULL,
  created REAL NOT NULL, last_seen REAL NOT NULL, revoked REAL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, token_digest TEXT UNIQUE NOT NULL, device_id TEXT NOT NULL,
  created REAL NOT NULL, expires REAL NOT NULL, last_seen REAL NOT NULL,
  revoked REAL, FOREIGN KEY(device_id) REFERENCES devices(id)
);
CREATE TABLE IF NOT EXISTS inbox (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, mime TEXT,
  size INTEGER NOT NULL, content_path TEXT, text_value TEXT, direction TEXT NOT NULL,
  secure INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS clipboard_history (
  id TEXT PRIMARY KEY, preview TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS vision_markers (
  digest TEXT PRIMARY KEY, session_id TEXT NOT NULL, window_address TEXT NOT NULL,
  stable_id TEXT, expires REAL NOT NULL, used REAL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Store:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.inbox_dir = state_dir / "inbox"
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.inbox_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path = state_dir / "portal.db"
        with self.connect() as db:
            db.executescript(SCHEMA)
        os.chmod(self.db_path, 0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.db_path, timeout=8)
        if self.db_path.exists():
            os.chmod(self.db_path, 0o600)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.db_path) + suffix)
            if sidecar.exists():
                os.chmod(sidecar, 0o600)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def execute(self, sql: str, args: tuple = ()) -> None:
        with self.connect() as db:
            db.execute(sql, args)

    def one(self, sql: str, args: tuple = ()):
        with self.connect() as db:
            return db.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()):
        with self.connect() as db:
            return db.execute(sql, args).fetchall()

    def setting(self, key: str, default=None):
        row = self.one("SELECT value FROM settings WHERE key=?", (key,))
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def set_setting(self, key: str, value) -> None:
        self.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value, separators=(",", ":"))),
        )

    def cleanup(self, now: float | None = None) -> None:
        now = now or time.time()
        expired_files = self.all(
            "SELECT content_path FROM inbox WHERE expires < ? AND content_path IS NOT NULL",
            (now,),
        )
        for row in expired_files:
            try:
                Path(row["content_path"]).unlink(missing_ok=True)
            except OSError:
                pass
        with self.connect() as db:
            db.execute("DELETE FROM inbox WHERE expires < ?", (now,))
            db.execute("DELETE FROM clipboard_history WHERE expires < ?", (now,))
            db.execute(
                "DELETE FROM sessions WHERE expires < ? OR revoked IS NOT NULL", (now,)
            )
            db.execute(
                "DELETE FROM pairing_tokens WHERE expires < ? OR consumed IS NOT NULL",
                (now - 3600,),
            )
            db.execute("DELETE FROM pair_requests WHERE expires < ?", (now - 3600,))
            db.execute(
                "DELETE FROM vision_markers WHERE expires < ? OR used IS NOT NULL",
                (now - 300,),
            )
