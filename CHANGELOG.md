# Changelog

## [0.9.2] - 2026-09-11

- Select the advertised IPv4 address from the active source address on the preferred main-table default route instead of a public UDP routing probe.
- Cross-check route sources against active interface addresses, ignore unrelated VPN/container addresses, and fall back to loopback when no usable private default route exists.
- Listen independently on `0.0.0.0` while keeping QR codes, displayed URLs, TLS certificates, runtime status, and exact-origin checks tied to the advertised LAN address.

## [0.9.1] - 2026-09-11

- Fix automatic backend startup after login, reboot, plugin rescan, and `omarchy restart shell` by resolving the bundled launcher relative to `Service.qml` instead of relying on private manifest metadata that Omarchy removes from third-party manifests.
- Preserve one shell-owned unprivileged daemon and its three-second restart after unexpected exit.

## [0.9.0] - 2026-09-11

Local Acceptance Candidate.

- Native Omarchy service/bar panel and adaptive phone PWA.
- Explicit secure LAN pairing, trusted devices, sessions and per-feature grants.
- Universal Send, Portal Inbox, clipboard/secret transfer, Take This and Continue on PC.
- Wayland control, Hyprland window/workspace actions, media, audio, screenshots and safe command palette.
- Session/window-bound, expiring, single-use Portal Vision markers.
- Optional structured X-Ray integration.
- Doctor CLI, automated security/edge tests, architecture/privacy/security/compatibility documentation.
