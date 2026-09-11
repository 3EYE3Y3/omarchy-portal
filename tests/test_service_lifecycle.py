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

    def test_unexpected_exit_keeps_the_three_second_restart_contract(self):
        source = (ROOT / "Service.qml").read_text()
        self.assertIn("interval: 3000", source)
        self.assertIn("restartTimer.start()", source)
        self.assertIn("onTriggered: if (!daemon.running)", source)


if __name__ == "__main__":
    unittest.main()
