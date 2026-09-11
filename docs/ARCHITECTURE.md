# Architecture

## Components

`manifest.json` declares one Omarchy `service` and one `bar-widget`. `Service.qml` is instantiated once by the shell, starts the unprivileged HTTPS process and owns click-through Vision overlays. `BarWidget.qml` supplies the precision `◉` bar control and loads `Panel.qml`, which uses Omarchy's `Panel`, `KeyboardPanel`, `PanelKeyCatcher`, `Color` and `Style` APIs.

The Python package has four boundaries:

1. `portal.service` — conservative HTTPS/static PWA adapter and endpoint capability checks.
2. `portal.core` — pairing, sessions, Inbox, clipboard retention, context, Vision and safe action registry.
3. `portal.store` — SQLite WAL persistence and expiry cleanup.
4. `portal.backend` — replaceable unprivileged Omarchy/Hyprland/Wayland/MPRIS/PipeWire adapters.

The PWA is `web/index.html`, `style.css`, and `app.js`. It uses polling on deliberate refreshes rather than an always-open socket. This makes reconnect behavior simple and leaves no WebSocket authentication surface in v0.9.

## Pairing protocol

1. PC generates random `P`, stores `SHA256(P)` plus five-minute expiry, and encodes `https://LAN-IP:59443/#pair=P`.
2. Because fragments never reach HTTP, the phone PWA explicitly posts `P`, its random persistent public ID, a human label and requested capabilities.
3. In one SQLite transaction the server validates expiry/unused status, consumes `P`, creates random claim `C`, and stores only `SHA256(C)`.
4. PC reads the pending request locally and approves/denies it.
5. On approval the server creates/updates a trusted device and a 24-hour session. Device/session values are deterministically derived with HMAC-SHA-256 from the server key, request ID and claim digest so an interrupted approval poll can safely retry without storing plaintext tokens.
6. Phone polls with `C`, receives device/session values, and stores them in origin-scoped browser storage.
7. A trusted, non-revoked device can exchange its device credential for a new random session.

## Session protocol

Authenticated endpoints require a non-cookie Bearer token. The store compares its digest, expiry, session revocation, device revocation and requested capability. Same-origin validation applies to browser-originated requests. Responses disable caching and apply CSP, frame, referrer, MIME and permissions headers.

## Context and action routing

Take This reads the active Hyprland window. For terminals it walks a bounded `/proc` parent chain and returns a working directory only when a recognized shell/editor process is found. Otherwise it uses clipboard text/URL as a clearly marked fallback, then active application identity. Portal does not scrape browser databases, fake current URLs or claim unsupported file-manager selections.

Continue on PC routes `http(s)` URLs to `xdg-open`, file/image payloads to the Inbox and text to `wl-copy`. The fixed action registry maps IDs to one backend method and one required capability. Inputs are validated before forming command argument arrays or Lua expressions; subprocesses never use a shell.

## Hyprland model

Windows, monitors and workspaces are read from JSON IPC. Omarchy 4.0.2's Hyprland 0.56.2 uses typed Lua dispatchers, so Portal calls `hyprctl eval` with installed `hl.dsp.focus`, `hl.dsp.window.move`, `hl.dsp.window.fullscreen`, `hl.dsp.window.close`, `hl.dsp.cursor.move`, and `hl.dsp.send_shortcut`. Window addresses accept only `0x[0-9a-fA-F]+`; names are JSON/Lua quoted and length/character bounded.

Moving a window to a monitor resolves that monitor's current workspace, then performs a window-to-workspace move. This matches Hyprland's workspace-centric model.

## Portal Vision

Vision activation records an authenticated session. The PC service reads visible windows and generates a random 20-second marker for each `{session, address, stableId}`. QML renders the QR matrix above the compositor-provided window geometry on passive layer-shell surfaces with empty input masks. The phone camera decodes the fragment token, authenticates normally, and posts it once. Core verifies session, expiry, reuse, live address and stable identity, then returns fresh window detail/actions.

Marker transport can be replaced later without changing this mapping. Generic computer vision is unnecessary because the compositor already knows identity and geometry.

## Transfers and retention

Binary requests are streamed in 1 MiB chunks to an exclusive random partial file, bounded by declared `Content-Length`, `fsync`ed and atomically renamed. Interrupted transfers delete the partial. Inbox records have explicit direction and expiry. Cleanup removes expired payloads. Archives remain opaque files.

Text is stored only as needed for Inbox semantics. Secure items receive short expiry and do not enter clipboard preview history. A future release can replace local transport/store interfaces without coupling them to QML or the PWA.

## Optional X-Ray

Availability is `PATH` capability detection. Window detail invokes only the documented external shape `xray --json <address>` with a two-second deadline. It accepts only a JSON object. Absence, timeout, non-zero exit and malformed data all become `null`, hiding Inspect without changing Portal behavior.

