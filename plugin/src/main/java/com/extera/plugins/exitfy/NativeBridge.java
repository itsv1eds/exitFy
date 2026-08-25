package com.extera.plugins.exitfy;

final class NativeBridge {
    private NativeBridge() {
    }

    static native String nativeOpen(int fileDescriptor, String path,
                                    String identity, int coreApi);

    /** Every loaded identity, comma separated; empty when nothing is mapped. */
    static native String nativeLoadedIdentity();

    static native int nativeLoadedCoreApi(String identity);

    static native String nativeStart(String identity, String configJson);

    static native String nativeStop(String identity);
}
