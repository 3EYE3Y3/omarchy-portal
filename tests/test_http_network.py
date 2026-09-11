from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from portal.backend import FakeBackend
from portal.core import PortalCore
from portal.service import (
    Handler,
    PortalHTTPServer,
    advertised_address_allowed,
    lan_ip,
    listen_address_allowed,
    select_default_route_address,
    serve,
)
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
        self.assertFalse(listen_address_allowed("8.8.8.8"))
        self.assertTrue(listen_address_allowed("0.0.0.0"))
        self.assertTrue(listen_address_allowed("10.26.80.6"))
        self.assertFalse(advertised_address_allowed("0.0.0.0"))


class DefaultRouteAddressTests(unittest.TestCase):
    @staticmethod
    def interface(name, address, prefix=24, **overrides):
        info = {
            "family": "inet",
            "local": address,
            "prefixlen": prefix,
            "scope": "global",
            "valid_life_time": 3600,
            "preferred_life_time": 3600,
        }
        info.update(overrides)
        return {"ifname": name, "addr_info": [info]}

    def choose(self, routes, interfaces):
        return select_default_route_address(routes, interfaces)

    def test_normal_wifi_default_route_uses_its_preferred_source(self):
        routes = [
            {
                "dst": "default",
                "gateway": "192.168.4.1",
                "dev": "wifi-device",
                "prefsrc": "192.168.4.33",
                "metric": 600,
            }
        ]
        interfaces = [self.interface("wifi-device", "192.168.4.33", 22)]
        self.assertEqual(self.choose(routes, interfaces), "192.168.4.33")

    def test_ethernet_wins_by_default_route_metric(self):
        routes = [
            {
                "dst": "default",
                "gateway": "192.168.4.1",
                "dev": "wifi-device",
                "prefsrc": "192.168.4.33",
                "metric": 600,
            },
            {
                "dst": "default",
                "gateway": "172.20.0.1",
                "dev": "wired-device",
                "prefsrc": "172.20.0.25",
                "metric": 100,
            },
        ]
        interfaces = [
            self.interface("wifi-device", "192.168.4.33", 22),
            self.interface("wired-device", "172.20.0.25"),
        ]
        self.assertEqual(self.choose(routes, interfaces), "172.20.0.25")

    def test_vpn_address_is_ignored_when_not_on_main_default_route(self):
        routes = [
            {
                "dst": "default",
                "gateway": "192.168.4.1",
                "dev": "wifi-device",
                "prefsrc": "192.168.4.33",
            }
        ]
        interfaces = [
            self.interface("tunnel-device", "10.26.80.6"),
            self.interface("wifi-device", "192.168.4.33", 22),
        ]
        self.assertEqual(self.choose(routes, interfaces), "192.168.4.33")

    def test_gateway_route_is_preferred_to_point_to_point_tunnel_default(self):
        routes = [
            {
                "dst": "default",
                "dev": "tunnel-device",
                "prefsrc": "10.26.80.6",
                "metric": 10,
            },
            {
                "dst": "default",
                "gateway": "192.168.4.1",
                "dev": "wifi-device",
                "prefsrc": "192.168.4.33",
                "metric": 600,
            },
        ]
        interfaces = [
            self.interface("tunnel-device", "10.26.80.6"),
            self.interface("wifi-device", "192.168.4.33", 22),
        ]
        self.assertEqual(self.choose(routes, interfaces), "192.168.4.33")

    def test_container_bridge_is_not_an_arbitrary_fallback(self):
        routes = [
            {
                "dst": "default",
                "gateway": "192.168.4.1",
                "dev": "wifi-device",
            }
        ]
        interfaces = [
            self.interface("container-bridge", "172.17.0.1", 16),
            self.interface("wifi-device", "192.168.4.33", 22),
        ]
        self.assertEqual(self.choose(routes, interfaces), "192.168.4.33")

    def test_stale_preferred_source_uses_active_address_on_route_interface(self):
        routes = [
            {
                "dst": "default",
                "gateway": "192.168.4.1",
                "dev": "wifi-device",
                "prefsrc": "192.168.4.99",
            }
        ]
        interfaces = [self.interface("wifi-device", "192.168.4.33", 22)]
        self.assertEqual(self.choose(routes, interfaces), "192.168.4.33")

    def test_unavailable_or_deprecated_addresses_are_not_advertised(self):
        routes = [
            {
                "dst": "default",
                "gateway": "10.0.0.1",
                "dev": "missing-device",
                "prefsrc": "10.0.0.9",
            },
            {
                "dst": "default",
                "gateway": "192.168.4.1",
                "dev": "stale-device",
                "prefsrc": "192.168.4.33",
            },
        ]
        interfaces = [
            self.interface("stale-device", "192.168.4.33", preferred_life_time=0)
        ]
        self.assertEqual(self.choose(routes, interfaces), "127.0.0.1")

    def test_loopback_only_and_no_default_route_fall_back_to_loopback(self):
        loopback = {
            "ifname": "loopback-device",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "127.0.0.1",
                    "prefixlen": 8,
                    "scope": "host",
                }
            ],
        }
        self.assertEqual(self.choose([], [loopback]), "127.0.0.1")

    def test_lan_ip_queries_main_routes_and_active_global_addresses(self):
        route = {
            "dst": "default",
            "gateway": "192.168.4.1",
            "dev": "wifi-device",
            "prefsrc": "192.168.4.33",
        }
        interface = self.interface("wifi-device", "192.168.4.33", 22)
        with mock.patch("portal.service._ip_json", side_effect=[[route], [interface]]) as query:
            self.assertEqual(lan_ip(), "192.168.4.33")
        self.assertEqual(
            query.call_args_list[0].args[0],
            ["ip", "-j", "-4", "route", "show", "table", "main", "default"],
        )
        self.assertEqual(
            query.call_args_list[1].args[0],
            ["ip", "-j", "-4", "address", "show", "up", "scope", "global"],
        )

    def test_server_listens_wildcard_but_advertises_route_address(self):
        fake_server = mock.Mock()
        fake_server.server_address = ("0.0.0.0", 59443)
        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch("portal.service.PortalHTTPServer", return_value=fake_server) as cls,
            mock.patch("portal.service.signal.signal"),
            redirect_stdout(io.StringIO()) as stdout,
        ):
            serve(
                Path(temp),
                Path(__file__).resolve().parents[1] / "web",
                listen_address="0.0.0.0",
                port=59443,
                tls=False,
                advertise_address="192.168.4.33",
            )
            core = cls.call_args.args[2]
            pairing_url = core.start_pairing()["url"]
        cls.assert_called_once()
        self.assertEqual(cls.call_args.args[0], ("0.0.0.0", 59443))
        self.assertEqual(core.base_url, "http://192.168.4.33:59443")
        self.assertTrue(pairing_url.startswith(core.base_url + "/#pair="))
        self.assertEqual(
            fake_server.allowed_origins,
            {"http://192.168.4.33:59443", "http://127.0.0.1:59443"},
        )
        ready = json.loads(stdout.getvalue())
        self.assertEqual(ready["listen_address"], "0.0.0.0")
        self.assertEqual(ready["advertise_address"], "192.168.4.33")

    def test_no_usable_route_defaults_to_loopback_only(self):
        fake_server = mock.Mock()
        fake_server.server_address = ("127.0.0.1", 59443)
        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch("portal.service.PortalHTTPServer", return_value=fake_server) as cls,
            mock.patch("portal.service.signal.signal"),
            mock.patch("portal.service.lan_ip", return_value="127.0.0.1"),
            redirect_stdout(io.StringIO()),
        ):
            serve(
                Path(temp),
                Path(__file__).resolve().parents[1] / "web",
                port=59443,
                tls=False,
            )
        self.assertEqual(cls.call_args.args[0], ("127.0.0.1", 59443))


if __name__ == "__main__":
    unittest.main()
