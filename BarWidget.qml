import QtQuick
import Quickshell.Io
import qs.Commons
import qs.Ui

BarWidget {
    id: root
    moduleName: "io.github.3eye3y3.portal"

    readonly property var portal: bar && bar.shell ? bar.shell.serviceFor(moduleName) : null
    readonly property bool connected: portal && portal.status && Array.isArray(portal.status.devices) ? portal.status.devices.some(function (device) {
        return device.connected === true;
    }) : false
    readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

    function injectPanel() {
        var panel = panelLoader.item;
        if (!panel)
            return;
        panel.bar = root.bar;
        panel.anchorItem = button;
        panel.hostWidget = root;
        panel.portal = root.portal;
    }
    function open() {
        if (panelLoader.item)
            panelLoader.item.open();
    }
    function close() {
        if (panelLoader.item)
            panelLoader.item.close();
    }
    function toggle() {
        if (panelLoader.item)
            panelLoader.item.toggle();
    }
    function closeForPopoutSwitch() {
        if (panelLoader.item)
            panelLoader.item.closeForPopoutSwitch();
    }
    readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

    implicitWidth: button.implicitWidth
    implicitHeight: button.implicitHeight
    onBarChanged: injectPanel()
    onPortalChanged: injectPanel()

    Loader {
        id: panelLoader
        active: true
        source: Qt.resolvedUrl("Panel.qml")
        visible: false
        onLoaded: {
            root.injectPanel();
            Qt.callLater(root.injectPanel);
        }
    }

    IpcHandler {
        target: root.moduleName
        function open(): void {
            root.open();
        }
        function close(): void {
            root.close();
        }
        function show(): void {
            root.open();
        }
        function hide(): void {
            root.close();
        }
        function toggle(): void {
            root.toggle();
        }
    }

    BarIconButton {
        id: button
        anchors.fill: parent
        bar: root.bar
        text: "◉"
        foreground: root.connected ? Color.accent : (root.bar ? root.bar.barForeground : Color.foreground)
        tooltipText: root.connected ? "Portal · phone connected" : "Portal · ready to pair"
        onPressed: root.toggle()
    }
}
