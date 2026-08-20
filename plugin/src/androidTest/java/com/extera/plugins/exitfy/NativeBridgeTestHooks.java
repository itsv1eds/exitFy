package com.extera.plugins.exitfy;

final class NativeBridgeTestHooks {
    private NativeBridgeTestHooks() {
    }

    static native void nativeSetMetadataPause(boolean enabled);

    static native boolean nativeMetadataPauseEntered();

    static native String nativeExerciseApiOne(String path);

    static native void nativeResetBridgeForTests();
}
