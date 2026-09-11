from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from portal.core import PortalError
from tests.helpers import paired


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core, self.backend, *_ = paired(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def add(self, name, data):
        return self.core.add_file(name, io.BytesIO(data), len(data))

    def test_normal_transfer(self):
        item = self.add("notes.txt", b"hello")
        row = self.core.inbox_content(item["id"])
        self.assertEqual(Path(row["content_path"]).read_bytes(), b"hello")

    def test_zero_byte_file(self):
        self.assertEqual(self.add("empty", b"")["size"], 0)

    def test_large_filename_is_bounded(self):
        self.assertLessEqual(
            len(self.add("a" * 500 + ".txt", b"x")["name"].encode()), 220
        )

    def test_unicode_filename(self):
        self.assertIn("東京", self.add("東京 📷.png", b"x")["name"])

    def test_path_traversal_is_neutralized(self):
        item = self.add("../../.ssh/authorized_keys", b"no")
        row = self.core.inbox_content(item["id"])
        self.assertEqual(Path(row["content_path"]).parent, self.core.store.inbox_dir)
        self.assertNotIn("/", item["name"])

    def test_overwrite_protection(self):
        self.assertNotEqual(
            self.add("same.txt", b"a")["name"], self.add("same.txt", b"b")["name"]
        )

    def test_interrupted_transfer(self):
        with self.assertRaisesRegex(PortalError, "interrupted"):
            self.core.add_file("partial", io.BytesIO(b"x"), 10)
        self.assertFalse(list(self.core.store.inbox_dir.glob("*.part")))

    def test_discard_removes_payload(self):
        item = self.add("gone", b"x")
        path = Path(self.core.inbox_content(item["id"])["content_path"])
        self.core.inbox_action(item["id"], "discard")
        self.assertFalse(path.exists())


class ClipboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core, self.backend, *_ = paired(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_normal_text(self):
        self.core.clipboard_set("hello")
        self.assertEqual(self.core.clipboard_get()["text"], "hello")
        self.assertEqual(len(self.core.store.all("SELECT * FROM clipboard_history")), 1)

    def test_large_text(self):
        self.core.clipboard_set("x" * 900_000)
        self.assertEqual(len(self.backend.clipboard), 900_000)

    def test_too_large_text(self):
        with self.assertRaises(PortalError):
            self.core.clipboard_set("x" * 1_000_001)

    def test_secret_mode_skips_history(self):
        self.assertTrue(self.core.clipboard_set("password=hunter2", True, 30)["secure"])
        self.assertFalse(self.core.store.all("SELECT * FROM clipboard_history"))

    def test_empty_clipboard(self):
        self.core.clipboard_set("")
        self.assertEqual(self.core.clipboard_get()["text"], "")
