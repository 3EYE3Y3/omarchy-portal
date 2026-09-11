from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from portal.backend import FakeBackend
from portal.core import PortalCore, PortalError
from tests.helpers import Clock, paired


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.clock = Clock()
        self.core = PortalCore(self.root, FakeBackend(), self.clock)

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_pair(self):
        pair = self.core.start_pairing()
        req = self.core.request_pair(
            pair["secret"], "Phone", "device-public", ["clipboard"]
        )
        self.core.decide_pair(req["request_id"], True)
        done = self.core.poll_pair(req["request_id"], req["claim_token"])
        self.assertEqual(done["status"], "approved")
        self.assertEqual(
            self.core.authenticate(done["session_token"], "clipboard")["name"], "Phone"
        )

    def test_expired_token(self):
        pair = self.core.start_pairing()
        self.clock.advance(301)
        with self.assertRaisesRegex(PortalError, "expired"):
            self.core.request_pair(pair["secret"], "Phone", "p", [])

    def test_reused_token(self):
        pair = self.core.start_pairing()
        self.core.request_pair(pair["secret"], "Phone", "p", [])
        with self.assertRaisesRegex(PortalError, "already used"):
            self.core.request_pair(pair["secret"], "Phone2", "p2", [])

    def test_malformed_pairing_data(self):
        with self.assertRaises(PortalError):
            self.core.request_pair("not-a-token", "Phone", "p", [])

    def test_denied_pair(self):
        pair = self.core.start_pairing()
        req = self.core.request_pair(pair["secret"], "Phone", "p", [])
        self.core.decide_pair(req["request_id"], False)
        self.assertEqual(
            self.core.poll_pair(req["request_id"], req["claim_token"])["status"],
            "denied",
        )

    def test_wrong_claim_is_hidden(self):
        pair = self.core.start_pairing()
        req = self.core.request_pair(pair["secret"], "Phone", "p", [])
        with self.assertRaises(PortalError):
            self.core.poll_pair(req["request_id"], "wrong")


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core, self.backend, self.clock, self.done, self.session = paired(
            Path(self.temp.name)
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_missing_auth(self):
        with self.assertRaisesRegex(PortalError, "required"):
            self.core.authenticate("")

    def test_invalid_auth(self):
        with self.assertRaisesRegex(PortalError, "invalid"):
            self.core.authenticate("wrong")

    def test_expired_session(self):
        self.clock.advance(24 * 3600 + 1)
        with self.assertRaisesRegex(PortalError, "expired"):
            self.core.authenticate(self.done["session_token"])

    def test_permission_denied(self):
        self.core.edit_device(self.done["device_id"], ["clipboard"])
        with self.assertRaisesRegex(PortalError, "denied"):
            self.core.authenticate(self.done["session_token"], "pointer")

    def test_revoked_device(self):
        self.core.revoke(self.done["device_id"])
        with self.assertRaisesRegex(PortalError, "revoked"):
            self.core.authenticate(self.done["session_token"])

    def test_disconnect_and_reconnect(self):
        self.core.disconnect(self.done["device_id"])
        with self.assertRaises(PortalError):
            self.core.authenticate(self.done["session_token"])
        resumed = self.core.resume(self.done["device_id"], self.done["device_token"])
        self.assertTrue(self.core.authenticate(resumed["session_token"])["id"])
