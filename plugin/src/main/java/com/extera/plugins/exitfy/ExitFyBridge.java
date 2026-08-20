package com.extera.plugins.exitfy;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.Process;

import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.ui.ActionBar.BaseFragment;

import java.lang.ref.WeakReference;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@SuppressLint({"ObsoleteSdkInt", "UnsafeDynamicallyLoadedCode"})
public final class ExitFyBridge {
    static final String DEX_KEEPER_PREFIX = "exitfy-dex-keeper:exitFy_v2:";
    static final String DEX_KEEPER_NAME = DEX_KEEPER_PREFIX + "4.0.0-beta.25";
    private static final String PROCESS_OWNER_KEY =
            "com.extera.plugins.exitfy.dex_owner";
    private static final String PROCESS_OWNER_TOKEN = UUID.randomUUID().toString();
    private static final Object DEX_KEEPER_MONITOR = new Object();
    private static final CopyOnWriteArrayList<WeakReference<Runnable>> UI_LISTENERS =
            new CopyOnWriteArrayList<>();
    private static final Runnable UI_NOTIFIER = new UiNotifier();

    private static volatile RuntimeCoordinator coordinator;
    private static boolean bridgeLoaded;
    private static String bridgePath = "";
    private static boolean dexKeeperStarted;

    private ExitFyBridge() {
    }

    public static synchronized void configure(String bootstrapJson) {
        try {
            if (Build.VERSION.SDK_INT < 29) {
                throw new IllegalStateException("Android API 29+ required");
            }
            if (!Process.is64Bit()) {
                throw new IllegalStateException("64-bit arm64-v8a process required");
            }
            String[] abis = Build.SUPPORTED_ABIS;
            if (abis == null || abis.length == 0 || !"arm64-v8a".equals(abis[0])) {
                throw new IllegalStateException("arm64-v8a primary process ABI required");
            }
            BootstrapConfig bootstrap = BootstrapConfig.parse(bootstrapJson);
            if (!bridgeLoaded) {
                loadNativeBridge(bootstrap.nativeBridgePath);
                bridgeLoaded = true;
                bridgePath = bootstrap.nativeBridgePath;
            } else if (!bridgePath.equals(bootstrap.nativeBridgePath)) {
                throw new IllegalStateException("native bridge cannot be replaced in this process");
            }
            if (coordinator != null) coordinator.unload();
            coordinator = RuntimeCoordinator.create(bootstrap);
            notifyUiListeners();
        } catch (RuntimeException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException(error.getMessage(), error);
        }
    }

    public static synchronized void load() {
        requireCoordinator().load();
        notifyUiListeners();
    }

    public static synchronized void unload() {
        if (coordinator != null) coordinator.unload();
        notifyUiListeners();
    }

    public static void updateSettings(String settingsJson) {
        requireCoordinator().updateSettings(settingsJson);
    }

    public static String execute(String commandJson) {
        return requireCoordinator().execute(commandJson);
    }

    public static String getUiState() {
        RuntimeCoordinator value = coordinator;
        if (value != null) return value.getUiState();
        try {
            return new JSONObject()
                    .put("runtimeAvailable", false)
                    .put("state", "STOPPED")
                    .toString();
        } catch (Throwable ignored) {
            return "{\"runtimeAvailable\":false,\"state\":\"STOPPED\"}";
        }
    }

    public static void onAppResume() {
        RuntimeCoordinator value = coordinator;
        if (value != null) value.onAppResume();
    }

    /** Reflected only by the Python menu entry; it is intentionally not public bridge ABI. */
    static BaseFragment createDashboardFragment() {
        return new ExitFyDashboardFragment();
    }

    static void addUiListener(Runnable listener) {
        if (listener == null) return;
        removeUiListener(listener);
        UI_LISTENERS.add(new WeakReference<>(listener));
    }

    static void removeUiListener(Runnable listener) {
        for (WeakReference<Runnable> reference : UI_LISTENERS) {
            Runnable value = reference.get();
            if (value == null || value == listener) UI_LISTENERS.remove(reference);
        }
    }

    static void notifyUiListeners() {
        try {
            AndroidUtilities.runOnUIThread(UI_NOTIFIER);
        } catch (Throwable ignored) {
        }
    }

    private static void dispatchUiListeners() {
        for (WeakReference<Runnable> reference : UI_LISTENERS) {
            Runnable listener = reference.get();
            if (listener == null) {
                UI_LISTENERS.remove(reference);
                continue;
            }
            try {
                listener.run();
            } catch (Throwable ignored) {
            }
        }
    }

    private static synchronized RuntimeCoordinator requireCoordinator() {
        if (coordinator == null) throw new IllegalStateException("exitFy is not configured");
        return coordinator;
    }

    private static void loadNativeBridge(String path) {
        loadNativeBridge(path, PROCESS_OWNER_KEY, PROCESS_OWNER_TOKEN, System::load);
    }

    /** Package-private overload makes failure ordering testable without dlopen. */
    static void loadNativeBridge(String path, String ownerKey, String ownerToken,
                                 NativeLibraryLoader loader) {
        if (!claimProcessOwner(ownerKey, ownerToken)) {
            throw new IllegalStateException(
                    "exitFy DEX/native bridge is already owned by another class loader; "
                            + "restart exteraGram");
        }
        try {
            // Retain only the winning class loader before native mapping. If
            // keeper creation fails, no native code has been loaded and the
            // process claim can safely be released for another attempt.
            ensureDexKeeper();
        } catch (RuntimeException | Error failure) {
            releaseProcessOwner(ownerKey, ownerToken);
            throw failure;
        }
        // A failed/partial System.load must keep the winning class loader and
        // owner token. The same retained DEX can then retry; another loader
        // must not race a potentially mapped native library.
        loader.load(path);
    }

    /** Package-private so unit tests can verify process-lifetime idempotence. */
    static synchronized void ensureDexKeeper() {
        if (dexKeeperStarted) return;
        Thread keeper = new Thread(new DexKeeper(), DEX_KEEPER_NAME);
        keeper.setDaemon(true);
        keeper.setContextClassLoader(ExitFyBridge.class.getClassLoader());
        keeper.start();
        dexKeeperStarted = true;
    }

    @FunctionalInterface
    interface NativeLibraryLoader {
        void load(String path);
    }

    /** Package-private seams keep the process-wide class-loader guard testable. */
    static boolean claimProcessOwner(String key, String token) {
        Properties properties = System.getProperties();
        synchronized (properties) {
            String current = properties.getProperty(key);
            if (current != null && !current.equals(token)) return false;
            if (current == null) properties.setProperty(key, token);
            return true;
        }
    }

    static void releaseProcessOwner(String key, String token) {
        Properties properties = System.getProperties();
        synchronized (properties) {
            if (token.equals(properties.getProperty(key))) properties.remove(key);
        }
    }

    /**
     * Python plugin modules are removed from sys.modules during a host engine
     * reload. This intentional process-lifetime daemon keeps both its target
     * class and context ClassLoader strongly reachable without hooking or
     * mutating the plugin engine. It must never be stopped in-process.
     */
    private static final class DexKeeper implements Runnable {
        @Override
        public void run() {
            while (true) {
                synchronized (DEX_KEEPER_MONITOR) {
                    try {
                        DEX_KEEPER_MONITOR.wait();
                    } catch (InterruptedException ignored) {
                        // An interrupt must not release anonymous DEX metadata.
                    }
                }
            }
        }
    }

    private static final class UiNotifier implements Runnable {
        @Override
        public void run() {
            dispatchUiListeners();
        }
    }
}
