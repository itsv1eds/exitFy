package com.extera.plugins.exitfy;

import org.json.JSONObject;

import java.util.Objects;

final class SettingsModel {
    static final int CUSTOM_PROVIDER_ID = 3;
    private static final int MAX_HWID_INPUT_CODE_POINTS = 4_096;
    private static final int MAX_HWID_CODE_POINTS = 256;
    private static final int MAX_HWID_UTF8_BYTES = 1_024;
    static final String PING_PROXY_GET = "proxy_get";
    static final String PING_TCP = "tcp";

    final boolean enabled;
    final int providerId;
    final String customHwid;
    final int schemaVersion;
    final String pingType;
    final boolean dualCore;
    final boolean failover;
    final boolean refreshOnOpen;
    /** Minutes between automatic latency checks; 0 keeps them off. */
    final int autoCheckMinutes;
    final boolean callsViaProxy;

    SettingsModel(boolean enabled, int providerId, String customHwid,
                  int schemaVersion, String pingType) {
        this(enabled, providerId, customHwid, schemaVersion, pingType, false, false);
    }

    SettingsModel(boolean enabled, int providerId, String customHwid,
                  int schemaVersion, String pingType, boolean dualCore,
                  boolean failover) {
        this(enabled, providerId, customHwid, schemaVersion, pingType, dualCore,
                failover, false, 0);
    }

    SettingsModel(boolean enabled, int providerId, String customHwid,
                  int schemaVersion, String pingType, boolean dualCore,
                  boolean failover, boolean refreshOnOpen, int autoCheckMinutes) {
        this(enabled, providerId, customHwid, schemaVersion, pingType, dualCore,
                failover, refreshOnOpen, autoCheckMinutes, false);
    }

    SettingsModel(boolean enabled, int providerId, String customHwid,
                  int schemaVersion, String pingType, boolean dualCore,
                  boolean failover, boolean refreshOnOpen, int autoCheckMinutes,
                  boolean callsViaProxy) {
        this.enabled = enabled;
        this.providerId = Math.max(0, Math.min(providerId, CUSTOM_PROVIDER_ID));
        this.customHwid = normalizeCustomHwid(customHwid);
        this.schemaVersion = schemaVersion;
        this.pingType = normalizePingType(pingType);
        this.dualCore = dualCore;
        this.failover = failover;
        this.refreshOnOpen = refreshOnOpen;
        this.autoCheckMinutes = normalizeAutoCheckMinutes(autoCheckMinutes);
        this.callsViaProxy = callsViaProxy;
    }

    static SettingsModel defaults() {
        return new SettingsModel(false, 0, "", 6, PING_TCP);
    }

    static SettingsModel fromJson(String json) {
        try {
            JSONObject object = JsonGuard.object(json == null ? "{}" : json);
            return new SettingsModel(
                    object.optBoolean("enabled", false),
                    boundedInt(object, "provider_id", 0, CUSTOM_PROVIDER_ID),
                    object.optString("custom_hwid", ""),
                    object.optInt("schema_version", 6),
                    object.optString("ping_type", PING_TCP),
                    object.optBoolean("dual_core", false),
                    object.optBoolean("failover", false),
                    object.optBoolean("refresh_on_open", false),
                    object.optInt("auto_check_minutes", 0),
                    object.optBoolean("calls_via_proxy", false)
            );
        } catch (Exception ignored) {
            return defaults();
        }
    }

    JSONObject toJson() {
        JSONObject object = new JSONObject();
        try {
            object.put("enabled", enabled);
            object.put("provider_id", providerId);
            object.put("custom_hwid", customHwid);
            object.put("schema_version", schemaVersion);
            object.put("ping_type", pingType);
            object.put("dual_core", dualCore);
            object.put("failover", failover);
            object.put("refresh_on_open", refreshOnOpen);
            object.put("auto_check_minutes", autoCheckMinutes);
            object.put("calls_via_proxy", callsViaProxy);
        } catch (Exception ignored) {
        }
        return object;
    }

    SettingsModel withSetting(String key, Object value) {
        if (key == null) throw new IllegalArgumentException("missing setting key");
        switch (key) {
            case "enabled":
                if (!(value instanceof Boolean)) {
                    throw new IllegalArgumentException("enabled must be boolean");
                }
                return new SettingsModel((Boolean) value, providerId, customHwid,
                        schemaVersion, pingType, dualCore, failover,
                        refreshOnOpen, autoCheckMinutes, callsViaProxy);
            case "provider_id":
                if (!(value instanceof Number)) {
                    throw new IllegalArgumentException("provider_id must be integer");
                }
                Number number = (Number) value;
                // The accepted range is only 0..2. Validate before narrowing so
                // arbitrary Number implementations cannot wrap via longValue().
                double providerValue = number.doubleValue();
                if (!Double.isFinite(providerValue)
                        || providerValue != Math.rint(providerValue)) {
                    throw new IllegalArgumentException("provider_id must be integer");
                }
                if (providerValue < 0d || providerValue > CUSTOM_PROVIDER_ID) {
                    throw new IllegalArgumentException("provider_id is out of range");
                }
                int provider = (int) providerValue;
                return new SettingsModel(enabled, provider, customHwid,
                        schemaVersion, pingType, dualCore, failover,
                        refreshOnOpen, autoCheckMinutes, callsViaProxy);
            case "ping_type":
                if (!(value instanceof String)
                        || !(PING_PROXY_GET.equals(value) || PING_TCP.equals(value))) {
                    throw new IllegalArgumentException("invalid ping_type");
                }
                return new SettingsModel(enabled, providerId, customHwid,
                        schemaVersion, (String) value, dualCore, failover,
                        refreshOnOpen, autoCheckMinutes, callsViaProxy);
            case "custom_hwid":
                if (!(value instanceof String)) {
                    throw new IllegalArgumentException("custom_hwid must be string");
                }
                return new SettingsModel(enabled, providerId, (String) value,
                        schemaVersion, pingType, dualCore, failover,
                        refreshOnOpen, autoCheckMinutes, callsViaProxy);
            case "dual_core":
                if (!(value instanceof Boolean)) {
                    throw new IllegalArgumentException("dual_core must be boolean");
                }
                return new SettingsModel(enabled, providerId, customHwid,
                        schemaVersion, pingType, (Boolean) value, failover);
            case "failover":
                if (!(value instanceof Boolean)) {
                    throw new IllegalArgumentException("failover must be boolean");
                }
                return new SettingsModel(enabled, providerId, customHwid,
                        schemaVersion, pingType, dualCore, (Boolean) value,
                        refreshOnOpen, autoCheckMinutes, callsViaProxy);
            case "refresh_on_open":
                if (!(value instanceof Boolean)) {
                    throw new IllegalArgumentException("refresh_on_open must be boolean");
                }
                return new SettingsModel(enabled, providerId, customHwid,
                        schemaVersion, pingType, dualCore, failover,
                        (Boolean) value, autoCheckMinutes);
            case "auto_check_minutes":
                if (!(value instanceof Number)) {
                    throw new IllegalArgumentException("auto_check_minutes must be integer");
                }
                double minutes = ((Number) value).doubleValue();
                if (!Double.isFinite(minutes) || minutes != Math.rint(minutes)
                        || normalizeAutoCheckMinutes((int) minutes) != (int) minutes) {
                    throw new IllegalArgumentException("auto_check_minutes is not allowed");
                }
                return new SettingsModel(enabled, providerId, customHwid,
                        schemaVersion, pingType, dualCore, failover,
                        refreshOnOpen, (int) minutes, callsViaProxy);
            case "calls_via_proxy":
                if (!(value instanceof Boolean)) {
                    throw new IllegalArgumentException("calls_via_proxy must be boolean");
                }
                return new SettingsModel(enabled, providerId, customHwid,
                        schemaVersion, pingType, dualCore, failover,
                        refreshOnOpen, autoCheckMinutes, (Boolean) value);
            default:
                throw new IllegalArgumentException("unsupported setting key");
        }
    }

    Object settingValue(String key) {
        switch (key) {
            case "enabled":
                return enabled;
            case "provider_id":
                return providerId;
            case "ping_type":
                return pingType;
            case "custom_hwid":
                return customHwid;
            case "dual_core":
                return dualCore;
            case "failover":
                return failover;
            case "refresh_on_open":
                return refreshOnOpen;
            case "auto_check_minutes":
                return autoCheckMinutes;
            case "calls_via_proxy":
                return callsViaProxy;
            default:
                throw new IllegalArgumentException("unsupported setting key");
        }
    }

    private static int boundedInt(JSONObject object, String key, int minimum, int maximum) {
        int value = object.optInt(key, minimum);
        return Math.max(minimum, Math.min(value, maximum));
    }

    // TCP is the default: it measures without taking Telegram's proxy away,
    // so it works while connected and when another app owns that setting.
    private static String normalizePingType(String value) {
        return PING_PROXY_GET.equals(value) ? PING_PROXY_GET : PING_TCP;
    }

    static String normalizeCustomHwid(String value) {
        String source = value == null ? "" : value;
        int rawEnd = 0;
        int rawCodePoints = 0;
        while (rawEnd < source.length() && rawCodePoints < MAX_HWID_INPUT_CODE_POINTS) {
            char first = source.charAt(rawEnd++);
            if (Character.isHighSurrogate(first) && rawEnd < source.length()
                    && Character.isLowSurrogate(source.charAt(rawEnd))) {
                rawEnd++;
            }
            rawCodePoints++;
        }
        if (rawEnd < source.length()) {
            source = source.substring(0, rawEnd);
        }
        String input = source.trim();
        StringBuilder output = new StringBuilder(Math.min(input.length(), MAX_HWID_CODE_POINTS));
        int codePoints = 0;
        int utf8Bytes = 0;
        for (int index = 0; index < input.length() && codePoints < MAX_HWID_CODE_POINTS; ) {
            char first = input.charAt(index);
            int codePoint;
            int consumed;
            if (Character.isHighSurrogate(first)) {
                if (index + 1 < input.length()
                        && Character.isLowSurrogate(input.charAt(index + 1))) {
                    codePoint = Character.toCodePoint(first, input.charAt(index + 1));
                    consumed = 2;
                } else {
                    codePoint = 0xfffd;
                    consumed = 1;
                }
            } else if (Character.isLowSurrogate(first)) {
                codePoint = 0xfffd;
                consumed = 1;
            } else {
                codePoint = first;
                consumed = 1;
            }
            index += consumed;
            // HTTP request headers must not accept CR/LF or other controls.
            if (Character.isISOControl(codePoint)) continue;
            int bytes = codePoint <= 0x7f ? 1
                    : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
            if (utf8Bytes + bytes > MAX_HWID_UTF8_BYTES) break;
            output.appendCodePoint(codePoint);
            utf8Bytes += bytes;
            codePoints++;
        }
        return output.toString();
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof SettingsModel)) return false;
        SettingsModel value = (SettingsModel) other;
        return enabled == value.enabled
                && providerId == value.providerId
                && schemaVersion == value.schemaVersion
                && Objects.equals(customHwid, value.customHwid)
                && Objects.equals(pingType, value.pingType)
                && dualCore == value.dualCore
                && failover == value.failover
                && refreshOnOpen == value.refreshOnOpen
                && autoCheckMinutes == value.autoCheckMinutes
                && callsViaProxy == value.callsViaProxy;
    }

    @Override
    public int hashCode() {
        return Objects.hash(enabled, providerId, customHwid, schemaVersion,
                pingType, dualCore, failover, refreshOnOpen, autoCheckMinutes,
                callsViaProxy);
    }

    static final int[] AUTO_CHECK_CHOICES = {0, 15, 60, 360};

    private static int normalizeAutoCheckMinutes(int value) {
        for (int choice : AUTO_CHECK_CHOICES) {
            if (choice == value) return choice;
        }
        return 0;
    }
}
