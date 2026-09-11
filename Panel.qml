pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
    id: root
    moduleName: "io.github.3eye3y3.portal"
    ipcTarget: moduleName
    manageIpc: false

    property var anchorItem: null
    property var hostWidget: null
    property var portal: null
    property var panelState: ({})
    property var pairing: null
    property string message: ""
    readonly property var devices: Array.isArray(panelState.devices) ? panelState.devices : []
    readonly property var pending: Array.isArray(panelState.pending) ? panelState.pending : []
    readonly property bool connected: devices.some(function (device) {
        return device.connected === true;
    })
    readonly property string pluginDir: portal ? portal.pluginDir : ""

    function command(args) {
        var result = ["bash", pluginDir + "/bin/portal"];
        for (var i = 0; i < args.length; i++)
            result.push(args[i]);
        return result;
    }
    function refresh() {
        if (!refreshProc.running && pluginDir !== "") {
            refreshProc.command = command(["panel-state", "--json"]);
            refreshProc.running = true;
        }
    }
    function newPair() {
        if (!pairProc.running) {
            pairProc.command = command(["pair", "--json"]);
            pairProc.running = true;
        }
    }
    function decide(id, allow) {
        if (!actionProc.running) {
            message = allow ? "Approving…" : "Denying…";
            actionProc.command = allow ? command(["approve", id, "--json"]) : command(["approve", id, "--deny", "--json"]);
            actionProc.running = true;
        }
    }
    function takeThis() {
        if (!actionProc.running) {
            message = "Taking current context…";
            actionProc.command = command(["take", "--json"]);
            actionProc.running = true;
        }
    }
    function toggleVision() {
        if (!actionProc.running) {
            message = "Toggling Portal Vision…";
            actionProc.command = command(["vision", "toggle", "--json"]);
            actionProc.running = true;
        }
    }
    function manageDevice(action, id) {
        if (!actionProc.running) {
            message = action === "revoke" ? "Revoking device…" : "Disconnecting…";
            actionProc.command = command(["device", action, id]);
            actionProc.running = true;
        }
    }
    function open() {
        root.controller.show();
        refresh();
        Qt.callLater(function () {
            keyCatcher.forceActiveFocus();
        });
    }

    Process {
        id: refreshProc
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                try {
                    root.panelState = JSON.parse(text || "{}");
                    if (root.panelState.pairing)
                        root.pairing = root.panelState.pairing;
                } catch (e) {
                    root.message = "Could not read Portal status";
                }
            }
        }
    }
    Process {
        id: pairProc
        stdout: StdioCollector {
            waitForEnd: true
            onStreamFinished: {
                try {
                    root.pairing = JSON.parse(text || "{}");
                } catch (e) {
                    root.message = "Could not create pairing code";
                }
            }
        }
    }
    Process {
        id: actionProc
        stdout: StdioCollector {
            waitForEnd: true
        }
        onExited: function (code) {
            root.message = code === 0 ? "Done" : "Action failed";
            root.refresh();
            if (root.portal)
                root.portal.refreshVision();
        }
    }
    Timer {
        interval: 1200
        running: root.opened
        repeat: true
        onTriggered: root.refresh()
    }

    KeyboardPanel {
        id: popup
        anchorItem: root.anchorItem
        owner: root.hostWidget || root
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        contentWidth: fittedContentWidth(Style.space(340))
        contentHeight: fittedContentHeight(content.implicitHeight)

        PanelKeyCatcher {
            id: keyCatcher
            anchors.fill: parent
            Keys.onEscapePressed: root.close()

            ColumnLayout {
                id: content
                anchors.fill: parent
                spacing: Style.space(12)

                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        text: "◉  PORTAL"
                        color: Color.foreground
                        font.family: Style.font.family
                        font.pixelSize: Style.font.title
                        font.bold: true
                        Layout.fillWidth: true
                    }
                    Text {
                        text: root.connected ? "● CONNECTED" : (root.portal && root.portal.ready ? "● READY" : "○ OFFLINE")
                        color: root.connected ? Color.accent : Color.foreground
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                    }
                }
                Text {
                    text: "Your PC, in your pocket"
                    color: Color.foreground
                    opacity: .62
                    font.family: Style.font.family
                    font.pixelSize: Style.font.body
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 1
                    color: Color.foreground
                    opacity: .12
                }

                ColumnLayout {
                    visible: root.pending.length > 0
                    Layout.fillWidth: true
                    spacing: Style.space(8)
                    Text {
                        text: String(root.pending[0]?.device_name || "Phone") + " wants to connect"
                        color: Color.foreground
                        font.family: Style.font.family
                        font.pixelSize: Style.font.body
                        font.bold: true
                    }
                    Text {
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: "Requested: " + (root.pending[0]?.requested || []).join(", ").replace(/_/g, " ")
                        color: Color.foreground
                        opacity: .65
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        PortalButton {
                            text: "DENY"
                            Layout.fillWidth: true
                            onClicked: root.decide(String(root.pending[0].id), false)
                        }
                        PortalButton {
                            text: "ALLOW"
                            accent: true
                            Layout.fillWidth: true
                            onClicked: root.decide(String(root.pending[0].id), true)
                        }
                    }
                }

                ColumnLayout {
                    visible: root.pending.length === 0 && root.pairing !== null
                    Layout.alignment: Qt.AlignHCenter
                    spacing: Style.space(8)
                    Text {
                        Layout.alignment: Qt.AlignHCenter
                        text: "SCAN WITH YOUR PHONE"
                        color: Color.foreground
                        opacity: .62
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: true
                    }
                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredWidth: Style.space(196)
                        Layout.preferredHeight: Style.space(196)
                        radius: Math.max(8, Style.cornerRadius)
                        color: "#f8f9f0"
                        property var rows: root.pairing?.qr || []
                        property int count: rows.length
                        Grid {
                            id: pairGrid
                            anchors.fill: parent
                            columns: parent.count
                            rows: parent.count
                            property var matrixRows: parent.rows
                            property int count: parent.count
                            Repeater {
                                model: parent.count * parent.count
                                Rectangle {
                                    required property int index
                                    width: pairGrid.width / Math.max(1, pairGrid.count)
                                    height: width
                                    color: pairGrid.matrixRows[Math.floor(index / pairGrid.count)].charAt(index % pairGrid.count) === "1" ? "#11120f" : "#f8f9f0"
                                }
                            }
                        }
                    }
                    Text {
                        Layout.alignment: Qt.AlignHCenter
                        text: "Local network only · expires quickly"
                        color: Color.foreground
                        opacity: .52
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                    }
                }

                ColumnLayout {
                    visible: root.pending.length === 0 && root.pairing === null
                    Layout.fillWidth: true
                    spacing: Style.space(6)
                    Text {
                        text: "CONNECTED"
                        color: Color.foreground
                        opacity: .55
                        font.family: Style.font.family
                        font.pixelSize: Style.font.caption
                        font.bold: true
                    }
                    Repeater {
                        model: root.devices.slice(0, 3)
                        RowLayout {
                            id: deviceRow
                            required property var modelData
                            Layout.fillWidth: true
                            Text {
                                text: String(modelData.name || "Phone")
                                color: Color.foreground
                                font.family: Style.font.family
                                font.pixelSize: Style.font.body
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                            }
                            Text {
                                text: modelData.connected ? "●" : "○"
                                color: modelData.connected ? Color.accent : Color.foreground
                                opacity: modelData.connected ? 1 : .45
                                font.pixelSize: Style.font.body
                            }
                            PortalButton {
                                visible: deviceRow.modelData.connected
                                text: "OFF"
                                implicitWidth: Style.space(48)
                                onClicked: root.manageDevice("disconnect", String(deviceRow.modelData.id))
                            }
                            PortalButton {
                                text: "REVOKE"
                                implicitWidth: Style.space(68)
                                onClicked: root.manageDevice("revoke", String(deviceRow.modelData.id))
                            }
                        }
                    }
                }

                RowLayout {
                    visible: root.pending.length === 0
                    Layout.fillWidth: true
                    PortalButton {
                        text: "PAIR"
                        Layout.fillWidth: true
                        onClicked: root.newPair()
                    }
                    PortalButton {
                        text: "TAKE THIS"
                        accent: true
                        enabled: root.devices.length > 0
                        Layout.fillWidth: true
                        onClicked: root.takeThis()
                    }
                }
                PortalButton {
                    visible: root.devices.length > 0
                    text: (root.panelState.vision?.active ? "STOP PORTAL VISION" : "PORTAL VISION")
                    Layout.fillWidth: true
                    onClicked: root.toggleVision()
                }
                Text {
                    visible: root.message !== ""
                    text: root.message
                    color: Color.foreground
                    opacity: .62
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                }
            }
        }
    }

    component PortalButton: Rectangle {
        id: button
        property string text: ""
        property bool accent: false
        signal clicked
        implicitHeight: Style.space(42)
        radius: Math.max(6, Style.cornerRadius)
        color: accent ? Color.accent : Color.foreground
        opacity: enabled ? (accent ? 1 : .10) : .28
        Text {
            anchors.centerIn: parent
            text: button.text
            color: button.accent ? Color.background : Color.foreground
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            font.bold: true
            font.letterSpacing: 1
        }
        MouseArea {
            anchors.fill: parent
            enabled: button.enabled
            cursorShape: Qt.PointingHandCursor
            onClicked: button.clicked()
        }
    }
}
