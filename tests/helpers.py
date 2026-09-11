from __future__ import annotations

from pathlib import Path

from portal.backend import FakeBackend
from portal.core import PortalCore


class Clock:
    def __init__(self, value=1_800_000_000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def window(address="0xabc", stable="stable-a", workspace="1", monitor=0):
    return {
        "address": address,
        "stable_id": stable,
        "class": "firefox",
        "title": "Example",
        "pid": 123,
        "workspace": {
            "id": int(workspace) if workspace.isdigit() else 1,
            "name": workspace,
        },
        "monitor": monitor,
        "at": [10, 20],
        "size": [800, 600],
        "fullscreen": False,
        "floating": False,
        "visible": True,
    }


def paired(tmp: Path, capabilities=None):
    clock = Clock()
    backend = FakeBackend()
    core = PortalCore(
        tmp, backend=backend, clock=clock, base_url="https://10.0.0.2:59443"
    )
    pair = core.start_pairing()
    req = core.request_pair(
        pair["secret"],
        "Test phone",
        "public-one",
        capabilities
        or [
            "send_receive",
            "clipboard",
            "media",
            "window_control",
            "pointer",
            "keyboard",
            "files",
            "command_palette",
            "xray",
        ],
    )
    core.decide_pair(req["request_id"], True)
    done = core.poll_pair(req["request_id"], req["claim_token"])
    session = core.authenticate(done["session_token"])
    return core, backend, clock, done, session
