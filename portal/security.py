"""Small, auditable security primitives built on Python's standard library."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

TOKEN_BYTES = 32
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[opsu]_|sk-[A-Za-z0-9_-]{10})[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\b(?:api[_-]?key|token|password|passwd|secret)\s*[:=]", re.IGNORECASE),
    re.compile(r"\b(?:[A-Z0-9]{4}[- ]){3,}[A-Z0-9]{4}\b", re.IGNORECASE),
)


def token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def derive(key: bytes, purpose: str, *parts: str) -> str:
    message = "\0".join((purpose, *parts)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def secure_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def looks_sensitive(text: str) -> bool:
    if not text:
        return False
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        data = path.read_bytes()
        if len(data) == 32:
            return data
    except FileNotFoundError:
        pass
    data = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return data
