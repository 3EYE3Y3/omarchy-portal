"""QR matrix helper using Omarchy's installed qrencode utility."""

from __future__ import annotations

import subprocess


def matrix(value: str) -> list[str]:
    result = subprocess.run(
        ["qrencode", "-t", "ASCII", "-m", "2", "-o", "-", value],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return []
    # qrencode ASCII uses two horizontal chars per module. Sampling pairs yields a QML-friendly grid.
    rows = []
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        rows.append(
            "".join(
                "1" if line[i : i + 2].strip() else "0" for i in range(0, len(line), 2)
            )
        )
    width = max((len(r) for r in rows), default=0)
    return [r.ljust(width, "0") for r in rows]
