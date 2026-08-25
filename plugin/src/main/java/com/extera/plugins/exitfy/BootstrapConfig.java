package com.extera.plugins.exitfy;

import org.json.JSONObject;

import java.io.File;

final class BootstrapConfig {
    private static final String PLUGIN_VERSION = "4.0.0-beta.28";
    private static final int SETTINGS_SCHEMA = 6;

    final String pluginId;
    final String pluginVersion;
    final File dataDir;
    final String nativeBridgePath;
    final String nativeAbi;
    /**
     * Device identifier carried over from the 3.x plugin. Sources bind a
     * subscription to it, so generating a fresh one silently loses access to
     * every subscription the previous install had registered.
     */
    final String migratedHwid;

    private BootstrapConfig(String pluginId, String pluginVersion, File dataDir, String nativeBridgePath,
                            String nativeAbi, String migratedHwid) {
        this.pluginId = pluginId;
        this.pluginVersion = pluginVersion;
        this.dataDir = dataDir;
        this.nativeBridgePath = nativeBridgePath;
        this.nativeAbi = nativeAbi;
        this.migratedHwid = migratedHwid;
    }

    static BootstrapConfig parse(String json) throws Exception {
        JSONObject value = JsonGuard.object(json == null ? "{}" : json);
        String pluginId = value.optString("pluginId", "exitFy_v2");
        String pluginVersion = value.optString("pluginVersion", "");
        int settingsSchema = value.optInt("settingsSchema", 0);
        File dataDir = new File(value.optString("dataDir", ""));
        File bridgeFile = new File(value.optString("nativeBridgePath", ""));
        String abi = value.optString("nativeAbi", "");
        if (!"exitFy_v2".equals(pluginId)) throw new IllegalArgumentException("invalid plugin id");
        if (!PLUGIN_VERSION.equals(pluginVersion)) {
            throw new IllegalArgumentException("plugin version mismatch");
        }
        if (settingsSchema != SETTINGS_SCHEMA) {
            throw new IllegalArgumentException("settings schema mismatch");
        }
        if (!dataDir.isDirectory()) throw new IllegalArgumentException("invalid private data directory");
        if (!bridgeFile.isFile()) throw new IllegalArgumentException("native bridge is missing");
        File canonicalBridge = bridgeFile.getCanonicalFile();
        String privateRoot = dataDir.getCanonicalPath() + File.separator;
        if (!canonicalBridge.getPath().startsWith(privateRoot)) {
            throw new IllegalArgumentException("native bridge escapes private data directory");
        }
        if (!abi.equals("arm64-v8a")) {
            throw new IllegalArgumentException("unsupported native ABI");
        }
        File expectedBridge = new File(new File(new File(dataDir, "bridge"), abi),
                "libexitfy_bridge.so").getCanonicalFile();
        if (!canonicalBridge.equals(expectedBridge)) {
            throw new IllegalArgumentException("native bridge path is not stable");
        }
        String migratedHwid = value.optString("migratedHwid", "").trim();
        if (!migratedHwid.matches("[0-9a-f]{16}")) migratedHwid = "";
        return new BootstrapConfig(pluginId, pluginVersion, dataDir,
                canonicalBridge.getPath(), abi, migratedHwid);
    }
}
