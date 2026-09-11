from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from portal.backend import FakeBackend
from portal.core import PortalCore
from portal.service import Handler, PortalHTTPServer, private_bind
from tests.helpers import Clock


class HTTPNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.backend = FakeBackend()
        self.core = PortalCore(
            Path(self.temp.name), self.backend, self.clock, "http://127.0.0.1"
        )
        web = Path(__file__).resolve().parents[1] / "web"
        self.server = PortalHTTPServer(("127.0.0.1", 0), Handler, self.core, web)
        port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{port}"
        self.server.allowed_origins = {self.base}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        pair = self.core.start_pairing()
        req = self.core.request_pair(
            pair["secret"],
            "Phone",
            "http-phone",
            ["send_receive", "files", "clipboard"],
        )
        self.core.decide_pair(req["request_id"], True)
        self.done = self.core.poll_pair(req["request_id"], req["claim_token"])

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.temp.cleanup()

    def request(
        self,
        path,
        *,
        method="GET",
        body=None,
        token=True,
        origin=None,
        content_type="application/json",
    ):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {self.done['session_token']}"
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            headers["Content-Type"] = content_type
        return urllib.request.urlopen(
            urllib.request.Request(
                self.base + path, data=body, headers=headers, method=method
            ),
            timeout=3,
        )

    def test_health_survives_phone_disappearance(self):
        self.assertEqual(
            json.load(self.request("/api/health", token=False))["status"], "ready"
        )
        self.clock.advance(100)
        self.assertFalse(self.core.devices()[0]["connected"])

    def test_missing_auth_http(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request("/api/inbox", token=False)
        self.assertEqual(ctx.exception.code, 401)
        ctx.exception.close()

    def test_malformed_message(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request("/api/inbox", method="POST", body=b"{broken")
        self.assertEqual(ctx.exception.code, 400)
        self.assertEqual(json.load(ctx.exception)["error"], "bad_request")
        ctx.exception.close()

    def test_origin_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request("/api/inbox", origin="https://attacker.invalid")
        self.assertEqual(ctx.exception.code, 403)
        ctx.exception.close()

    def test_file_upload_round_trip(self):
        payload = b"portal-transfer"
        response = self.request(
            "/api/files?name=hello.bin",
            method="PUT",
            body=payload,
            content_type="application/octet-stream",
        )
        item = json.load(response)
        self.assertEqual(
            self.request(f"/api/inbox/{item['id']}/content").read(), payload
        )

    def test_permission_denied_http(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.request("/api/control", method="POST", body={"action": "left"})
        self.assertEqual(ctx.exception.code, 403)
        ctx.exception.close()

    def test_continue_text_reaches_pc_clipboard(self):
        item = json.load(
            self.request(
                "/api/continue",
                method="POST",
                body={"kind": "text", "text": "continue here"},
            )
        )
        self.assertEqual(item["continued"], "clipboard")
        self.assertEqual(self.backend.clipboard, "continue here")

    def test_bind_policy_rejects_public_addresses(self):
        self.assertFalse(private_bind("8.8.8.8"))
        self.assertTrue(private_bind("10.26.80.6"))


if __name__ == "__main__":
    unittest.main()
