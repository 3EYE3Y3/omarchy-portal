pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons

// Long-lived plugin service: owns the unprivileged local HTTPS daemon and the
// click-through, short-lived Portal Vision marker surfaces.
Item {
    id: service

    property var shell: null
    property var manifest: null
    // Third-party manifests are deliberately sanitized before the shell injects
    // them, so private registry metadata such as __sourceDir is unavailable here.
    // Resolve the executable from this component instead; that is stable across
    // login, shell restart, plugin rescan, and non-ASCII/space-containing paths.
    readonly property string portalBin: decodeURIComponent(
        Qt.resolvedUrl("bin/portal").toString().replace(/^file:\/\//, ""))
    readonly property string pluginDir: portalBin.replace(/\/bin\/portal$/, "")
    property bool ready: false
    property string url: ""
    property string error: ""
    property var status: ({})
    property bool visionActive: false
    property var visionMarkers: []

    function runPortal(args) {
        var command = ["bash", portalBin];
        for (var i = 0; i < args.length; i++)
            command.push(args[i]);
        return command;
    }

    function refresh() {
        if (!statusProc.running) {
            statusProc.command = runPortal(["status", "--json"]);
            statusProc.running = true;
        }
    }

    function refreshVision() {
        if (!visionProc.running) {
            visionProc.command = runPortal(["vision", "status", "--json"]);
            visionProc.running = true;
        }
    }

    Process {
        id: daemon
        command: service.runPortal(["serve"])
        stdout: SplitParser {
            onRead: function (line) {
                try {
                    var data = JSON.parse(line);
                    if (data.status === "ready") {
                        service.ready = true;
                        service.url = String(data.url || "");
                        service.error = "";
                    }
                } catch (e) {}
            }
        }
        stderr: SplitParser {
            onRead: function (line) {
                // The HTTP access log deliberately carries no queries, body or tokens.
                if (String(line).indexOf("Address already in use") !== -1)
                    service.error = "Portal port is already in use";
                if (String(line).indexOf("portal-tls ") === 0)
                    console.warn(String(line));
            }
        }
        onExited: function (code) {
            service.ready = false;
            if (code !== 0 && service.error === "")
                service.error = "Portal service stopped";
            restartTimer.start();
        }
    }

    Timer {
        id: restartTimer
        interval: 3000
        onTriggered: if (!daemon.running)
            daemon.running = true
    }

    Process {
        id: statusProc
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                try {
                    service.status = JSON.parse(text || "{}");
                    service.ready = service.status.running === true;
                    service.url = String(service.status.url || service.url);
                    var active = service.status.vision && service.status.vision.active === true;
                    service.visionActive = active;
                    if (!active)
                        service.visionMarkers = [];
                } catch (e) {}
            }
        }
    }

    Process {
        id: visionProc
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                try {
                    var data = JSON.parse(text || "{}");
                    service.visionActive = data.active === true;
                    service.visionMarkers = Array.isArray(data.markers) ? data.markers : [];
                } catch (e) {
                    service.visionMarkers = [];
                }
            }
        }
    }

    Timer {
        interval: service.visionActive ? 750 : 2500
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: service.refresh()
    }
    Timer {
        interval: 5000
        running: service.visionActive || (service.status.vision !== undefined && service.status.vision.active === true)
        repeat: true
        triggeredOnStart: true
        onTriggered: service.refreshVision()
    }

    // Each screen gets a passive overlay. A completely empty input mask makes
    // every marker click-through; phone camera selection is the only interaction.
    property var markerWindows: Variants {
        model: Quickshell.screens

        PanelWindow {
            id: markerWindow
            required property var modelData
            screen: modelData
            visible: service.visionActive && localMarkers.length > 0
            anchors {
                top: true
                bottom: true
                left: true
                right: true
            }
            color: "transparent"
            exclusionMode: ExclusionMode.Ignore
            WlrLayershell.namespace: "portal-vision"
            WlrLayershell.layer: WlrLayer.Overlay
            WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
            mask: Region {}

            readonly property var localMarkers: service.visionMarkers.filter(function (marker) {
                var win = marker.window || {};
                var monitors = service.status.monitors || [];
                // Hyprland monitor id matches the index on normal configurations. If
                // status lacks monitor metadata, show on the focused screen fallback.
                for (var i = 0; i < monitors.length; i++)
                    if (Number(monitors[i].id) === Number(win.monitor))
                        return String(monitors[i].name) === String(modelData.name);
                return Number(win.monitor || 0) === 0;
            })

            Repeater {
                model: markerWindow.localMarkers

                delegate: Rectangle {
                    id: markerCard
                    required property var modelData
                    readonly property var win: markerCard.modelData.window || {}
                    readonly property var origin: win.at || [0, 0]
                    readonly property var extent: win.size || [200, 200]
                    width: 110
                    height: 132
                    x: Math.max(8, Math.min(markerWindow.width - width - 8, Number(origin[0]) + Number(extent[0]) / 2 - width / 2))
                    y: Math.max(8, Math.min(markerWindow.height - height - 8, Number(origin[1]) + 34))
                    radius: 12
                    color: "#f7f8ef"
                    border.width: 2
                    border.color: "#151611"

                    Column {
                        anchors.centerIn: parent
                        spacing: 5

                        Grid {
                            id: qrGrid
                            width: 92
                            height: 92
                            columns: count
                            rows: count
                            readonly property var matrixRows: markerCard.modelData.qr || []
                            readonly property int count: matrixRows.length
                            Repeater {
                                model: parent.count * parent.count
                                Rectangle {
                                    required property int index
                                    width: 92 / Math.max(1, qrGrid.count)
                                    height: width
                                    color: qrGrid.matrixRows[Math.floor(index / qrGrid.count)].charAt(index % qrGrid.count) === "1" ? "#10110e" : "#f7f8ef"
                                }
                            }
                        }

                        Text {
                            width: 96
                            text: String(markerCard.win.class || "WINDOW").toUpperCase()
                            elide: Text.ElideRight
                            horizontalAlignment: Text.AlignHCenter
                            color: "#151611"
                            font.family: Style.font.family
                            font.pixelSize: 10
                            font.bold: true
                        }
                    }
                }
            }
        }
    }

    Component.onCompleted: daemon.running = true
}
