# Changelog

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
