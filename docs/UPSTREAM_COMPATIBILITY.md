# Upstream compatibility

Reconnaissance performed on 2026-09-11 (Australia/Perth). The installed machine is authoritative for this candidate.

| Component | Installed | Portal use |
|---|---:|---|
| Omarchy | `4.0.2-1` | `omarchy plugin` schema/installation, shell theming and lifecycle |
| Hyprland | `0.56.2`, commit `efb5099…` | JSON state IPC and typed Lua dispatcher API |
| Quickshell | `0.3.1` | native service/bar panel, Process and layer-shell Vision markers |
| Qt declarative | `6.11.2` | QML runtime/lint tooling |

## Plugin contract

The installed validator accepts schema number `1`, a non-reserved ID matching `[A-Za-z0-9][A-Za-z0-9._-]*`, non-empty `kinds`, and safe relative `entryPoints`. Supported kinds discovered in `PluginRegistry.qml` and first-party manifests are `bar`, `bar-widget`, `menu`, `overlay`, `panel`, and `service`. Portal declares `service` plus `bar-widget`, with `Service.qml` and `BarWidget.qml`.

User plugins install at `~/.config/omarchy/plugins/<id>`. Third-party enablement records the plugin in `~/.config/omarchy/shell.json`; source files are never written under `/usr/share/omarchy`. Plugin filesystem changes hot-reload. `omarchy-shell shell rescanPlugins` rescans discovery, and `omarchy restart shell` is the safe explicit restart command. Services mount at startup; bar widgets receive the shell/bar/settings properties and use the shared panel lifecycle. Omarchy removes private registry metadata such as `manifest.__sourceDir` before injecting third-party manifests, so Portal resolves its bundled launcher from `Qt.resolvedUrl("bin/portal")` in `Service.qml`.

The panel follows current first-party APIs: `qs.Commons.Color`, `qs.Commons.Style`, `qs.Ui.BarWidget`, `BarIconButton`, `Panel`, `KeyboardPanel`, and `PanelKeyCatcher`. Vision uses Quickshell `Variants`, `PanelWindow`, `Region` input masks and `WlrLayershell` overlay surfaces.

## IPC and desktop APIs

- Shell IPC: `omarchy-shell shell summon|hide|toggle <plugin-id> <payload>` and plugin `IpcHandler` methods.
- Hyprland read IPC: `hyprctl -j clients|monitors|workspaces|activewindow|cursorpos`.
- Hyprland mutation IPC: Omarchy 4/Hyprland 0.56 rejects legacy string dispatcher syntax; Portal uses `hyprctl eval 'hl.dispatch(hl.dsp.…)'` with typed tables.
- Clipboard: `wl-copy`, `wl-paste`.
- Keyboard: `wtype` (native Wayland).
- Pointer: `hl.dsp.cursor.move` and `hl.dsp.send_shortcut` mouse keys; no X11/`xdotool`, `ydotool`, uinput daemon or privilege.
- Media: MPRIS via `playerctl` when present, otherwise direct user D-Bus calls through `busctl`.
- Audio: PipeWire/WirePlumber via `wpctl`.
- Screenshots: `grim`, matching Omarchy's Wayland capture stack.
- QR: installed `qrencode` matrix output.

`playerctl`, `shellcheck`, and PATH-level `qmllint` were not installed during initial reconnaissance; Portal uses direct MPRIS D-Bus as the media fallback, and Qt's `/usr/lib/qt6/bin/qmllint` is used with an import shim. All optional capabilities degrade without breaking pairing/transfers.

## Keybinding compatibility

`SUPER + SHIFT + P` is occupied by the stock Google Photos web app. Portal uses `SUPER + CTRL + SHIFT + P`. Its installer checks live keybindings, backs up the user file, appends one labeled override, calls `hyprctl reload`, then requires an empty `hyprctl configerrors` result.

## Installation boundary

The supported install mechanism is `omarchy plugin add <git-url> --enable --yes`; it clones into the user plugin directory, validates before enabling and rescans the shell. Portal does not edit upstream Omarchy source. During this build a separate Codex process was actively developing/testing `~/Projects/omarchy-xray`, so live install/reload is intentionally deferred to avoid plugin lifecycle conflicts.
