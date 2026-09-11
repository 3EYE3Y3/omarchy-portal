import QtQuick
import Quickshell

ShellRoot {
    Loader {
        id: loader
        // The smoke script stages Service.qml beside this harness because
        // Quickshell intentionally blackholes Loader URLs outside config root.
        source: "Service.qml"
        onStatusChanged: if (status === Loader.Error)
            console.error("Portal service harness load failed", source, loader.item)
        onLoaded: {
            item.manifest = {
                "__sourceDir": Quickshell.env("PORTAL_PLUGIN_ROOT")
            };
        }
    }
}
