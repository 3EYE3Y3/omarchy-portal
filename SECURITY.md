# Security policy

## Scope and threat model

Portal v0.9 is for a trusted local network. With a usable LAN route it listens on the host's IPv4 interfaces so a transient VPN address cannot strand the service, but advertises only an active RFC1918 source associated with the preferred main-table default route. With no usable private route, both listen and advertised addresses fall back to loopback. It has no relay, discovery beacon, UPnP, router automation or WAN mode. A host firewall remains recommended on hostile networks.

Portal protects against passive LAN interception with TLS 1.2+ and a local 30-day self-signed Ed25519 certificate. Because public WebPKI cannot issue certificates for private IP addresses, first use requires a browser certificate exception. On an untrusted LAN, verify the SHA-256 certificate fingerprint shown by:

```bash
openssl x509 -in ~/.local/state/portal/tls.crt -noout -fingerprint -sha256
```

This pairing is not a PAKE and does not make a user-approved incorrect certificate safe against an active man-in-the-middle. Do not accept a certificate whose fingerprint you have not verified on an untrusted network.

## Pairing and sessions

- Pairing and claim values use 32 bytes from the OS CSPRNG.
- Pairing values expire in five minutes, are single-purpose, and become consumed on the first valid request.
- Pairing/marker values use URL fragments, avoiding request lines, referrers and routine server logs.
- A local PC decision is required before credentials are issued.
- Device and session credentials are stored only as SHA-256 digests; plaintext session values exist only at endpoints.
- Sessions expire after 24 hours and are invalidated by disconnect/revoke.
- Device identity includes a random browser-generated public identifier and a 256-bit device credential; user-agent text is display metadata only.
- No authentication cookies are used. API requests require an `Authorization: Bearer` header, avoiding ambient-cookie CSRF.
- Browser origins are checked against the exact advertised Portal and loopback origins; wildcard listen addresses are never accepted as browser origins. WebSocket is not used in v0.9, so there is no unauthenticated WebSocket surface.

## Capability model

`send_receive`, `clipboard`, `media`, `window_control`, `files`, `command_palette`, `pointer`, `keyboard`, `screenshots`, `audio`, `terminal`, and `xray` are distinct grants. Pairing requests a useful low-risk baseline; pointer/keyboard/screenshots/audio must be added explicitly. Every protected API handler enforces its required grant.

The command palette is an allowlisted registry. Raw shell and terminal execution are not exposed. Transferred files are not executed or extracted.

## Files and sensitive text

Upload length is bounded to 512 MiB. Filenames are NFC-normalized, control characters and separators are removed, UTF-8 length is capped, writes use an exclusive random `.part` path, data is flushed before atomic rename, and collisions receive generated suffixes. Payloads use mode `0600` in a mode `0700` state tree.

Clipboard and secret contents are never logged. The recent clipboard history stores at most ten short previews for one hour. Explicit or heuristically detected secret transfers skip history and expire after five minutes. Optional clipboard clearing only clears if the clipboard still equals the transferred value. Heuristic secret detection is not guaranteed; users should select Secure Transfer explicitly.

## Portal Vision

Markers contain random selectors, not durable authentication credentials. Each server record is tied to a current authenticated session, Hyprland address, stable window identity and 20-second expiry. It is single-use and revalidated against current compositor state. Destroyed or replaced windows are rejected; moved windows resolve at their current geometry. Stopping Vision deletes live markers.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not include real clipboard content, tokens, certificates, Inbox files, URLs or database files. Include Portal/Omarchy/Hyprland versions and a minimal reproduction. Security fixes take priority over feature work.

Supported security release: `0.9.x` until local acceptance determines `1.0.0`.
