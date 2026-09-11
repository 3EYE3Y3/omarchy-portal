# Privacy

Portal has no analytics, telemetry, advertising ID, tracking pixel, crash upload, cloud backend, account system or external service dependency. It does not contact GitHub or any registry while running.

Phone/PC requests and transfers stay on the selected local interface. The HTTPS service logs only method, normalized path and result code. It never logs query strings, request bodies, clipboard/secret content, authorization values, pairing values, marker values, filenames or URLs.

Local state is under `~/.local/state/portal`:

- `portal.db`: hashed credentials, grants, timestamps and Inbox metadata;
- `inbox/`: received/offered payloads, mode `0600`;
- `server.key`: 32-byte HMAC key, mode `0600`;
- `tls.key` and `tls.crt`: local transport identity;
- `runtime.json`: PID and local URL only.

Normal Inbox items expire after 24 hours. Secure items expire after five minutes. Clipboard previews keep at most ten entries for one hour; secure values skip them. Users can discard items immediately, revoke trusted devices, disconnect sessions, or remove the state directory after disabling Portal.

Portal reads only desktop state needed for a requested feature: Hyprland window metadata, a deliberate clipboard get/set, MPRIS metadata, PipeWire output labels, a requested screenshot, or a bounded terminal process ancestry for Take This. It does not capture screen video, microphone, camera (the phone camera stays inside the phone browser), keystroke history, browser history or full shell history.

