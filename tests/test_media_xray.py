from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from portal.backend import BackendError, DesktopBackend
from tests.helpers import paired, window


class MediaXrayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core, self.backend, *_ = paired(Path(self.temp.name))
        self.backend._windows = [window()]

    def tearDown(self):
        self.temp.cleanup()

    def test_no_player(self):
        self.assertEqual(self.backend.media(), [])

    def test_one_player(self):
        self.backend._media = [{"id": "one", "status": "Playing"}]
        self.assertEqual(len(self.backend.media()), 1)

    def test_multiple_players(self):
        self.backend._media = [{"id": "one"}, {"id": "two"}]
        self.assertEqual(len(self.backend.media()), 2)

    def test_volume_is_bounded_and_routed(self):
        self.backend.set_volume(0.05)
        self.assertEqual(self.backend.calls[-1], ("volume", 0.05))

    def test_xray_unavailable(self):
        self.assertIsNone(self.core.window_detail("0xabc")["xray"])

    def test_xray_available(self):
        self.backend.xray_value = {"cpu": 12, "ram": 1024}
        self.assertEqual(self.core.window_detail("0xabc")["xray"]["cpu"], 12)

    def test_xray_invalid_response_degrades(self):
        self.backend.xray_value = None
        self.assertIsNone(self.core.window_detail("0xabc")["xray"])

    def test_xray_timeout_degrades(self):
        backend = DesktopBackend()
        with (
            mock.patch("portal.backend.shutil.which", return_value="/usr/bin/xray"),
            mock.patch.object(backend, "run", side_effect=BackendError("timeout")),
        ):
            self.assertIsNone(backend.xray("0xabc"))
