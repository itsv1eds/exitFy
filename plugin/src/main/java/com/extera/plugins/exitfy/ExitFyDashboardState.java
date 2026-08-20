package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Locale;

/**
 * Small immutable projection of the runtime JSON used by the dashboard.
 * Keeping parsing and display normalization outside Android Views makes late
 * background results cheap to discard and prevents unbounded provider text
 * from reaching a TextView.
 */
final class ExitFyDashboardState {
    static final int MAX_UI_STATE_UTF8_BYTES = 512 * 1024;
    static final ExitFyDashboardState EMPTY = parse("{}");

    final boolean runtimeAvailable;
    final String runtimeState;
    final boolean enabled;
    final int providerId;
    final boolean[] providerAvailability;
    final int serverCount;
    final int customUrlCount;
    // Retained as the existing restart handoff; this release adds no restart UI.
    final boolean restartRequired;
    final String pingType;
    final boolean customHwidSet;
    final String defaultHwid;
    final String connectionIssue;
    final boolean refreshRunning;
    final boolean importRunning;
    final boolean pingRunning;
    final int pingCompleted;
    final int pingTotal;
    final CoreInstallState coreInstall;
    final String activeKey;
    final String activeName;
    final String activeProtocol;
    final String activeTransport;
    final String activeSecurity;
    final long activeLatency;
    final String activePingStatus;

    private ExitFyDashboardState(JSONObject value) {
        runtimeAvailable = value.optBoolean("runtimeAvailable", false);
        runtimeState = safeToken(value.optString("state", "STOPPED"), "STOPPED");
        enabled = value.optBoolean("enabled", false);
        providerId = Math.max(0, Math.min(SettingsModel.CUSTOM_PROVIDER_ID,
                value.optInt("providerId", 0)));
        providerAvailability = parseProviderAvailability(
                value.optJSONArray("providerAvailability"));
        serverCount = Math.max(0, value.optInt("serverCount", 0));
        customUrlCount = Math.max(0, value.optInt("customUrlCount", 0));
        restartRequired = value.optBoolean("restartRequired", false);
        pingType = SettingsModel.PING_TCP.equals(safeToken(
                value.optString("pingType", SettingsModel.PING_PROXY_GET),
                SettingsModel.PING_PROXY_GET))
                ? SettingsModel.PING_TCP : SettingsModel.PING_PROXY_GET;
        customHwidSet = value.optBoolean("customHwidSet", false);
        defaultHwid = safeLabel(value.optString("defaultHwid", ""), 32, "");
        connectionIssue = safeLabel(value.optString("connectionIssue", ""), 180, "");

        JSONObject operations = value.optJSONObject("operations");
        refreshRunning = operations != null
                && "running".equals(operations.optString("subscriptionRefresh", ""));
        importRunning = operations != null
                && "running".equals(operations.optString("import", ""));
        JSONObject ping = value.optJSONObject("ping");
        pingRunning = ping != null && "running".equals(ping.optString("state", ""));
        pingCompleted = ping == null ? 0 : Math.max(0, ping.optInt("completed", 0));
        pingTotal = ping == null ? 0 : Math.max(0, ping.optInt("total", 0));
        coreInstall = CoreInstallState.parse(value.optJSONObject("coreInstall"));

        JSONObject active = value.optJSONObject("activeNodeInfo");
        activeKey = active == null ? "" : safeLabel(active.optString("key", ""), 192, "");
        activeName = active == null ? "" : safeLabel(active.optString("name", ""), 96, "");
        activeProtocol = active == null ? ""
                : safeToken(active.optString("protocol", ""), "");
        activeTransport = active == null ? ""
                : safeToken(active.optString("transport", ""), "");
        activeSecurity = active == null ? ""
                : safeToken(active.optString("security", ""), "");
        activeLatency = active == null ? -1L : Math.max(-1L, active.optLong("latency", -1L));
        activePingStatus = active == null ? "idle"
                : safeToken(active.optString("pingStatus", "idle"), "idle");

    }

    static ExitFyDashboardState parse(String json) {
        try {
            return new ExitFyDashboardState(JsonGuard.object(
                    json == null ? "{}" : json,
                    JsonGuard.MAX_STRING_BYTES,
                    MAX_UI_STATE_UTF8_BYTES));
        } catch (Throwable ignored) {
            return new ExitFyDashboardState(new JSONObject());
        }
    }

    String connectionTitle() {
        switch (runtimeState) {
            case "RUNNING":
                return I18n.t("Подключено", "Connected");
            case "STARTING":
                return I18n.t("Подключение…", "Connecting…");
            case "STOPPING":
                return I18n.t("Отключение…", "Disconnecting…");
            case "ERROR":
                return I18n.t("Ошибка подключения", "Connection error");
            default:
                return enabled
                        ? I18n.t("Ожидание подключения", "Waiting to connect")
                        : I18n.t("Отключено", "Disconnected");
        }
    }

    String providerName() {
        return providerName(providerId);
    }

    static String providerName(int id) {
        if (id == 0) return "Elix";
        if (id == 1) return "Shrimp";
        return I18n.t("Пользовательский", "Custom");
    }

    boolean providerAvailable(int id) {
        return id >= 0 && id < providerAvailability.length
                && providerAvailability[id];
    }

    String providerSummary() {
        String noun;
        if (I18n.isRussian()) {
            int mod100 = serverCount % 100;
            int mod10 = serverCount % 10;
            noun = mod100 >= 11 && mod100 <= 14 ? "серверов"
                    : mod10 == 1 ? "сервер"
                    : mod10 >= 2 && mod10 <= 4 ? "сервера" : "серверов";
        } else {
            noun = serverCount == 1 ? "server" : "servers";
        }
        return serverCount + " " + noun;
    }

    boolean hasActiveNode() {
        return !activeKey.isEmpty();
    }

    String activeTitle() {
        return activeName.isEmpty()
                ? I18n.t("Сервер не выбран", "No server selected") : activeName;
    }

    String activeProtocolSummary() {
        StringBuilder value = new StringBuilder();
        appendPart(value, activeProtocol.isEmpty() ? "" : activeProtocol.toUpperCase(Locale.ROOT));
        appendPart(value, activeTransport);
        appendPart(value, activeSecurity);
        return value.length() == 0 ? "—" : value.toString();
    }

    String activePingSummary() {
        if (activeLatency >= 0) return activeLatency + " " + I18n.t("мс", "ms");
        if ("pending".equals(activePingStatus) || pingRunning) {
            return I18n.t("Проверяется…", "Checking…");
        }
        if ("restart_required".equals(activePingStatus)) {
            return I18n.t("Недоступен", "Unavailable");
        }
        if ("tcp_failed_quic".equals(activePingStatus)) {
            return I18n.t(
                    "TCP-проверка неприменима",
                    "TCP check not applicable");
        }
        if ("cancelled".equals(activePingStatus)) {
            return I18n.t("Проверка отменена", "Check cancelled");
        }
        if (!"idle".equals(activePingStatus) && !"ok".equals(activePingStatus)) {
            return I18n.t("Нет ответа", "No response");
        }
        return I18n.t("Не проверен", "Not checked");
    }

    String pingProgress() {
        if (!pingRunning) return "";
        return Math.min(pingCompleted, pingTotal) + "/" + pingTotal;
    }

    boolean isTransitioning() {
        return "STARTING".equals(runtimeState) || "STOPPING".equals(runtimeState);
    }

    PrimaryAction primaryAction() {
        if (coreInstall.active()) return PrimaryAction.INSTALLING;
        if (coreInstall.required) return PrimaryAction.INSTALL_CORES;
        return enabled ? PrimaryAction.DISCONNECT : PrimaryAction.CONNECT;
    }

    enum PrimaryAction {
        INSTALLING,
        INSTALL_CORES,
        CONNECT,
        DISCONNECT;

        String label() {
            switch (this) {
                case INSTALLING:
                    return I18n.t("Установка…", "Installing…");
                case INSTALL_CORES:
                    return I18n.t("Установить ядра", "Install cores");
                case DISCONNECT:
                    return I18n.t("Отключить", "Disconnect");
                case CONNECT:
                default:
                    return I18n.t("Подключить", "Connect");
            }
        }
    }

    static final class CoreInstallState {
        private static final CoreInstallState EMPTY = new CoreInstallState(
                false, "idle", 0, "idle", 0L);

        final boolean required;
        final String state;
        final int progress;
        final String stage;
        final long generation;

        private CoreInstallState(boolean required, String state, int progress,
                                 String stage, long generation) {
            this.required = required;
            this.state = state;
            this.progress = progress;
            this.stage = stage;
            this.generation = generation;
        }

        boolean active() {
            return "queued".equals(state) || "running".equals(state);
        }

        boolean terminal() {
            return "success".equals(state) || "error".equals(state);
        }

        boolean successful() {
            return "success".equals(state);
        }

        boolean partial() {
            return "error".equals(state) && "partial".equals(stage);
        }

        String stageLabel() {
            switch (stage) {
                case "downloading":
                    return I18n.t("Загрузка файлов…", "Downloading files…");
                case "verifying":
                    return I18n.t("Проверка файлов…", "Verifying files…");
                case "done":
                    return I18n.t("Завершение установки…", "Finishing installation…");
                case "partial":
                    return I18n.t(
                            "Установлены не все компоненты",
                            "Not all components were installed");
                case "failed":
                    return I18n.t(
                            "Не удалось завершить установку",
                            "Could not finish installation");
                case "preparing":
                default:
                    return I18n.t(
                            "Подготовка к установке…",
                            "Preparing installation…");
            }
        }

        String terminalMessage() {
            if (successful()) {
                return I18n.t("Ядра установлены", "Cores installed");
            }
            if (partial()) {
                return I18n.t(
                        "Один компонент установлен. Оставшийся будет установлен автоматически",
                        "One component is installed. The remaining component will be installed automatically");
            }
            return I18n.t(
                    "Не удалось установить компоненты. Проверьте подключение к интернету и попробуйте снова",
                    "Could not install the components. Check your internet connection and try again");
        }

        private static CoreInstallState parse(JSONObject value) {
            if (value == null) return EMPTY;
            String state = knownState(safeToken(
                    value.optString("state", "idle"), "idle"));
            String stage = knownStage(safeToken(
                    value.optString("stage", "idle"), "idle"));
            int progress = Math.max(0, Math.min(100, value.optInt("progress", 0)));
            long generation = Math.max(0L, value.optLong("generation", 0L));
            return new CoreInstallState(
                    value.optBoolean("required", false),
                    state,
                    progress,
                    stage,
                    generation);
        }

        private static String knownState(String value) {
            switch (value) {
                case "queued":
                case "running":
                case "success":
                case "error":
                    return value;
                default:
                    return "idle";
            }
        }

        private static String knownStage(String value) {
            switch (value) {
                case "preparing":
                case "downloading":
                case "verifying":
                case "done":
                case "partial":
                case "failed":
                    return value;
                default:
                    return "idle";
            }
        }
    }

    private static boolean[] parseProviderAvailability(JSONArray value) {
        boolean[] result = new boolean[SettingsModel.CUSTOM_PROVIDER_ID + 1];
        for (int index = 0; index < result.length; index++) {
            result[index] = index == SettingsModel.CUSTOM_PROVIDER_ID
                    || value != null && value.optBoolean(index, false);
        }
        return result;
    }

    private static void appendPart(StringBuilder output, String part) {
        if (part == null || part.isEmpty() || "none".equals(part)) return;
        if (output.length() > 0) output.append(" · ");
        output.append(part);
    }

    private static String safeToken(String value, String fallback) {
        String normalized = safeLabel(value, 48, fallback).trim();
        if (normalized.isEmpty()) return fallback;
        for (int index = 0; index < normalized.length(); index++) {
            char item = normalized.charAt(index);
            if (!(item >= 'a' && item <= 'z') && !(item >= 'A' && item <= 'Z')
                    && !(item >= '0' && item <= '9') && item != '_' && item != '-') {
                return fallback;
            }
        }
        return normalized;
    }

    static String safeLabel(String value, int maximumCodePoints, String fallback) {
        if (value == null) return fallback;
        StringBuilder output = new StringBuilder(Math.min(value.length(), maximumCodePoints));
        int count = 0;
        for (int offset = 0; offset < value.length() && count < maximumCodePoints; ) {
            int point = value.codePointAt(offset);
            offset += Character.charCount(point);
            if (Character.isISOControl(point) || point == 0x2028 || point == 0x2029
                    || point == 0x061c || point == 0x200e || point == 0x200f
                    || (point >= 0x202a && point <= 0x202e)
                    || (point >= 0x2066 && point <= 0x2069)) {
                continue;
            }
            output.appendCodePoint(point);
            count++;
        }
        String result = output.toString().trim();
        String lower = result.toLowerCase(Locale.ROOT);
        if (containsUri(lower)) {
            return fallback;
        }
        return result.isEmpty() ? fallback : result;
    }

    private static boolean containsUri(String value) {
        return value.contains("http://") || value.contains("https://")
                || value.contains("vless://") || value.contains("vmess://")
                || value.contains("trojan://") || value.contains("ss://")
                || value.contains("socks://") || value.contains("socks5://")
                || value.contains("hysteria://") || value.contains("hysteria2://")
                || value.contains("hy2://") || value.contains("tuic://");
    }

}
