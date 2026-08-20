package com.extera.plugins.exitfy;

final class CoreProcessState {
    private CoreProcessState() {
    }

    static boolean requiresRestart(CoreFamily loaded, CoreFamily required) {
        return loaded != null && required != null && loaded != required;
    }
}

