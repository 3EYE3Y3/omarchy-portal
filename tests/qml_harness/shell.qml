import QtQuick
import Quickshell

ShellRoot {
    Loader {
        id: loader
        // Stage the plugin tree beside this harness. The service must resolve
        // its executable from its own component URL without private manifest
        // metadata, exactly as a third-party Omarchy service does.
        source: "Service.qml"
        onStatusChanged: if (status === Loader.Error)
            console.error("Portal service harness load failed", source, loader.item)
        onLoaded: item.manifest = {
            "schemaVersion": 1,
            "id": "io.github.3eye3y3.portal"
        }
    }
}
