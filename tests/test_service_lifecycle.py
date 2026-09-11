from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ServiceLifecycleTests(unittest.TestCase):
    def test_manifest_declares_the_omarchy_service_entry_point(self):
        manifest = json.loads((ROOT / "manifest.json").read_text())
        self.assertIn("service", manifest["kinds"])
        self.assertEqual(manifest["entryPoints"]["service"], "Service.qml")

    def test_service_startup_does_not_depend_on_private_manifest_metadata(self):
        source = (ROOT / "Service.qml").read_text()
        self.assertNotIn("manifest.__sourceDir", source)
        self.assertIn('Qt.resolvedUrl("bin/portal")', source)
        self.assertIn("Component.onCompleted: daemon.running = true", source)

    def test_displayed_pairing_url_comes_from_the_advertised_pairing_url(self):
        source = (ROOT / "Panel.qml").read_text()
        self.assertIn("root.pairing?.url", source)

    def test_unexpected_exit_keeps_the_three_second_restart_contract(self):
        source = (ROOT / "Service.qml").read_text()
        self.assertIn("interval: 3000", source)
        self.assertIn("restartTimer.start()", source)
        self.assertIn("onTriggered: if (!daemon.running)", source)

    def test_sanitized_tls_failures_reach_the_local_shell_log(self):
        source = (ROOT / "Service.qml").read_text()
        self.assertIn('indexOf("portal-tls ") === 0', source)
        self.assertIn("console.warn(String(line))", source)


if __name__ == "__main__":
    unittest.main()
