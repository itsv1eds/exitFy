package com.extera.plugins.exitfy;

final class NativeBridge {
    private NativeBridge() {
    }

    static native String nativeOpen(int fileDescriptor, String path,
                                    String identity, int coreApi);

    static native String nativeLoadedIdentity();

    static native int nativeLoadedCoreApi();

    static native String nativeStart(String configJson);

    static native String nativeStop();
}
