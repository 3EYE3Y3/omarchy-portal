import QtQuick
import Quickshell

ShellRoot {
    Loader {
        id: loader
        source: "Panel.qml"
        onStatusChanged: if (status === Loader.Error)
            console.error("Portal panel harness load failed", source, loader.item)
    }
}
