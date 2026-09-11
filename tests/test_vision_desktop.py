from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from portal.core import PortalError
from tests.helpers import paired, window


class VisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core, self.backend, self.clock, self.done, self.session = paired(
            Path(self.temp.name)
        )
        self.backend._windows = [window()]
        self.core.set_vision(True, self.session["id"])

    def tearDown(self):
        self.temp.cleanup()

    def marker(self):
        return self.core.vision_status()["markers"][0]

    def test_valid_marker(self):
        self.assertEqual(
            self.core.resolve_vision(self.marker()["token"], self.session)["address"],
            "0xabc",
        )

    def test_expired_marker(self):
        marker = self.marker()
        self.clock.advance(21)
        with self.assertRaisesRegex(PortalError, "expired"):
            self.core.resolve_vision(marker["token"], self.session)

    def test_wrong_session(self):
        marker = self.marker()
        other = dict(self.session)
        other["id"] = "other"
        with self.assertRaisesRegex(PortalError, "another session"):
            self.core.resolve_vision(marker["token"], other)

    def test_destroyed_window(self):
        marker = self.marker()
        self.backend._windows = []
        with self.assertRaisesRegex(PortalError, "no longer exists"):
            self.core.resolve_vision(marker["token"], self.session)

    def test_moved_window_is_resolved_live(self):
        marker = self.marker()
        self.backend._windows[0]["at"] = [500, 600]
        self.assertEqual(
            self.core.resolve_vision(marker["token"], self.session)["at"], [500, 600]
        )

    def test_reused_marker(self):
        marker = self.marker()
        self.core.resolve_vision(marker["token"], self.session)
        with self.assertRaisesRegex(PortalError, "already used"):
            self.core.resolve_vision(marker["token"], self.session)

    def test_unknown_window_identity(self):
        marker = self.marker()
        self.backend._windows[0]["stable_id"] = "replacement"
        with self.assertRaises(PortalError):
            self.core.resolve_vision(marker["token"], self.session)


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core, self.backend, *_ = paired(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_no_windows(self):
        self.assertEqual(self.core.windows_state()["windows"], [])

    def test_window_disappears_during_action(self):
        with self.assertRaisesRegex(Exception, "disappeared"):
            self.backend.window_action("0xabc", "focus")

    def test_workspace_change(self):
        self.backend._windows = [window()]
        self.backend.window_action("0xabc", "workspace", "2")
        self.assertEqual(self.backend.calls[-1][-1], "2")

    def test_monitor_change(self):
        self.backend._windows = [window()]
        self.backend.window_action("0xabc", "monitor", "HDMI-A-1")
        self.assertEqual(self.backend.calls[-1][-1], "HDMI-A-1")

    def test_context_falls_back_to_clipboard(self):
        self.backend._windows = [window()]
        self.backend.clipboard = "https://example.test"
        self.assertEqual(self.core.take_this()["context"]["kind"], "url")
