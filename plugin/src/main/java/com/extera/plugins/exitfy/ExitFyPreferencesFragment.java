package com.extera.plugins.exitfy;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.widget.LinearLayout;

import org.json.JSONObject;

import org.telegram.messenger.R;

/** Native Android View settings for options that used to live in plugin settings. */
final class ExitFyPreferencesFragment
        extends ExitFySubscreenFragment<ExitFyDashboardState> {
    private static final String[] PING_VALUES = {
            SettingsModel.PING_TCP,
            SettingsModel.PING_PROXY_GET,
    };

    private ExitFyDashboardState state = ExitFyDashboardState.EMPTY;
    private SettingRow pingTypeRow;
    private SettingRow customHwidRow;
    private SettingRow subscriptionUserAgentRow;
    private SettingRow dualCoreRow;
    private SettingRow coreVersionRow;
    private String coreVersions = "";
    private String callState = "";
    private SettingRow failoverRow;
    private SettingRow refreshOnOpenRow;
    private SettingRow autoCheckRow;
    private SettingRow callsRow;
    private SettingRow callStateRow;
    private SettingRow restartRow;
    private boolean commandBusy;

    @Override
    protected CharSequence screenTitle() {
        return I18n.t("Дополнительно", "Advanced");
    }

    @Override
    protected String workerThreadName() {
        return "exitfy-preferences";
    }

    @Override
    protected void buildContent(Context context, LinearLayout content) {
        pingTypeRow = settingRow(context, R.drawable.msg_speed,
                I18n.t("Тип пинга", "Ping type"), "");
        setSafeClick(pingTypeRow.view, this::showPingTypeDialog);
        content.addView(pingTypeRow.view, sectionParams());

        customHwidRow = settingRow(context, R.drawable.msg_edit,
                "HWID", "");
        setSafeClick(customHwidRow.view, this::showCustomHwidDialog);
        content.addView(customHwidRow.view, sectionParams());

        subscriptionUserAgentRow = settingRow(context, R.drawable.msg_edit,
                "User-Agent",
                I18n.t("С каким клиентом запрашиваются подписки",
                        "Which client identity is used to fetch subscriptions"));
        setSafeClick(subscriptionUserAgentRow.view, this::showSubscriptionUserAgentDialog);
        content.addView(subscriptionUserAgentRow.view, sectionParams());

        refreshOnOpenRow = settingRow(context, R.drawable.msg_download,
                I18n.t("Обновлять подписки при входе", "Refresh subscriptions on open"),
                I18n.t("При открытии клиента, если списки устарели",
                        "When the app opens and the lists are stale"));
        setSafeClick(refreshOnOpenRow.view, this::showRefreshOnOpenDialog);
        content.addView(refreshOnOpenRow.view, sectionParams());

        autoCheckRow = settingRow(context, R.drawable.msg_stats,
                I18n.t("Автопроверка задержки", "Automatic latency check"),
                I18n.t("Периодически и всегда по TCP, чтобы не прерывать подключение",
                        "On a schedule, always over TCP so the connection is not interrupted"));
        setSafeClick(autoCheckRow.view, this::showAutoCheckDialog);
        content.addView(autoCheckRow.view, sectionParams());

        callStateRow = settingRow(context, R.drawable.msg_stats,
                I18n.t("Состояние звонков", "Call routing state"),
                I18n.t("Врезки / запросы / сопоставлено / отправлено / получено",
                        "Hooks / requests / mapped / sent / received"));
        setSafeClick(callStateRow.view, this::loadCallState);
        content.addView(callStateRow.view, sectionParams());

        callsRow = settingRow(context, R.drawable.msg_secret,
                I18n.t("Звонки через exitFy (эксперимент)",
                        "Calls through exitFy (experimental)"),
                I18n.t("Медиа звонка идёт через ваш сервер, без сторонних релеев",
                        "Call media goes through your own server, with no third-party relay"));
        setSafeClick(callsRow.view, this::showCallsDialog);
        content.addView(callsRow.view, sectionParams());

        failoverRow = settingRow(context, R.drawable.msg_retry,
                I18n.t("Менять сервер при обрыве", "Switch server on failure"), "");
        setSafeClick(failoverRow.view, this::showFailoverDialog);
        content.addView(failoverRow.view, sectionParams());

        restartRow = settingRow(context, R.drawable.msg_reset,
                I18n.t("Перезапустить exteraGram", "Restart exteraGram"),
                I18n.t("Нужно после смены настроек, которые применяются при запуске",
                        "Needed after changing a setting that applies at startup"));
        setSafeClick(restartRow.view, this::confirmRestart);
        content.addView(restartRow.view, sectionParams());

        coreVersionRow = settingRow(context, R.drawable.msg_info,
                I18n.t("Версии компонентов", "Component versions"), "");
        content.addView(coreVersionRow.view, sectionParams());

        dualCoreRow = settingRow(context, R.drawable.msg_permissions,
                I18n.t("Два ядра сразу (эксперимент)", "Both cores at once (experimental)"), "");
        setSafeClick(dualCoreRow.view, this::showDualCoreDialog);
        content.addView(dualCoreRow.view, sectionParams());

        renderUiState(state);
        loadCoreVersions();
    }

    @Override
    protected ExitFyDashboardState parseUiState(String json) {
        return ExitFyDashboardState.parse(json);
    }

    @Override
    protected void renderUiState(ExitFyDashboardState next) {
        if (next == null) return;
        state = next;
        if (pingTypeRow == null || customHwidRow == null
                || subscriptionUserAgentRow == null
                || dualCoreRow == null || coreVersionRow == null
                || failoverRow == null || refreshOnOpenRow == null
                || autoCheckRow == null || callsRow == null) {
            return;
        }
        if (next.runtimeAvailable) {
            pingTypeRow.setValue(pingTypeLabel(next.pingType));
            customHwidRow.setValue(next.customHwidSet
                    ? I18n.t("Настроен", "Configured")
                    : (next.defaultHwid.isEmpty() ? "—" : next.defaultHwid));
            subscriptionUserAgentRow.setValue(next.subscriptionUserAgent.isEmpty()
                    ? SettingsModel.subscriptionUserAgentLabel("")
                    : next.subscriptionUserAgent);
            dualCoreRow.setValue(dualCoreLabel(next));
            coreVersionRow.setValue(coreVersions.isEmpty()
                    ? I18n.t("Загрузка…", "Loading…") : coreVersions);
            failoverRow.setValue(next.failover
                    ? I18n.t("Включено", "On") : I18n.t("Выключено", "Off"));
            refreshOnOpenRow.setValue(next.refreshOnOpen
                    ? I18n.t("Включено", "On") : I18n.t("Выключено", "Off"));
            autoCheckRow.setValue(autoCheckLabel(next.autoCheckMinutes));
            callsRow.setValue(next.callsViaProxy
                    ? I18n.t("Включено", "On") : I18n.t("Выключено", "Off"));
            if (callStateRow != null) {
                callStateRow.setValue(callState.isEmpty()
                        ? I18n.t("Нажмите, чтобы обновить", "Tap to refresh")
                        : callState);
            }
        } else {
            String unavailable = I18n.t("Runtime недоступен", "Runtime unavailable");
            pingTypeRow.setValue(unavailable);
            customHwidRow.setValue(unavailable);
            subscriptionUserAgentRow.setValue(unavailable);
            dualCoreRow.setValue(unavailable);
            coreVersionRow.setValue(unavailable);
            failoverRow.setValue(unavailable);
            refreshOnOpenRow.setValue(unavailable);
            autoCheckRow.setValue(unavailable);
            callsRow.setValue(unavailable);
            if (callStateRow != null) callStateRow.setValue(unavailable);
        }
        updateRowsEnabled();
    }

    @Override
    protected void onCommandBusyChanged(boolean busy) {
        commandBusy = busy;
        updateRowsEnabled();
    }

    private void updateRowsEnabled() {
        boolean enabled = state.runtimeAvailable && !commandBusy;
        if (pingTypeRow != null) pingTypeRow.setEnabled(enabled);
        if (customHwidRow != null) customHwidRow.setEnabled(enabled);
        if (subscriptionUserAgentRow != null) subscriptionUserAgentRow.setEnabled(enabled);
        if (dualCoreRow != null) dualCoreRow.setEnabled(enabled);
        if (failoverRow != null) failoverRow.setEnabled(enabled);
        if (refreshOnOpenRow != null) refreshOnOpenRow.setEnabled(enabled);
        if (autoCheckRow != null) autoCheckRow.setEnabled(enabled);
        if (callsRow != null) callsRow.setEnabled(enabled);
        if (callStateRow != null) callStateRow.setEnabled(enabled);
    }

    private void showPingTypeDialog() {
        CharSequence[] labels = {
                "TCP",
                "Proxy GET",
        };
        showChoiceDialog(I18n.t("Тип пинга", "Ping type"),
                labels, pingTypeIndex(state.pingType), index -> {
                    if (index < 0 || index >= PING_VALUES.length) return;
                    String value = PING_VALUES[index];
                    if (!value.equals(state.pingType)) {
                        setSetting("ping_type", value);
                    }
                });
    }

    private void showCustomHwidDialog() {
        showTextInputDialog(
                "HWID",
                null,
                null,
                I18n.t("Сохранить", "Save"),
                I18n.t("Сбросить", "Reset"),
                false,
                value -> setSetting("custom_hwid", value),
                () -> setSetting("custom_hwid", ""));
    }

    private void showSubscriptionUserAgentDialog() {
        String current = state.customSubscriptionUserAgentSet
                ? state.subscriptionUserAgent : "";
        showTextInputDialog(
                "User-Agent",
                I18n.t("Провайдер смотрит этот заголовок и решает, отдать JSON, base64 или Clash.",
                        "The provider uses this header to decide whether to send JSON, base64, or Clash."),
                SettingsModel.subscriptionUserAgentLabel(""),
                I18n.t("Сохранить", "Save"),
                I18n.t("Сбросить", "Reset"),
                false,
                current,
                value -> setSetting("subscription_user_agent", value),
                () -> setSetting("subscription_user_agent", ""));
    }

    /**
     * The second core is mapped for the life of the process and cannot be
     * unmapped, so the dialog states the cost before the choice rather than
     * after it.
     */
    private void showDualCoreDialog() {
        CharSequence[] labels = {
                I18n.t("Выключено", "Off"),
                I18n.t("Включено", "On"),
        };
        showChoiceDialog(
                I18n.t("Два ядра сразу (эксперимент)", "Both cores at once (experimental)"),
                labels, state.dualCore ? 1 : 0, index -> {
                    boolean value = index == 1;
                    if (value == state.dualCore) return;
                    if (!value) {
                        setSetting("dual_core", false);
                        showToast(I18n.t(
                                "Выключится после перезапуска exteraGram",
                                "Takes effect after exteraGram restarts"), true);
                        return;
                    }
                    setSetting("dual_core", true);
                    showToast(I18n.t(
                            "Серверы обоих типов теперь работают без перезапуска",
                            "Servers of both kinds now work without a restart"), true);
                });
    }

    private void loadCallState() {
        executeCommand(() -> new JSONObject().put("command", "call_relay_stats"),
                false, result -> {
                    if (result == null || !result.ok) return;
                    String label = describeCallState(result.data);
                    runUiAction(() -> {
                        callState = label;
                        if (callStateRow != null) {
                            callStateRow.setValue(label);
                        }
                    });
                });
    }

    private static String describeCallState(String data) {
        try {
            JSONObject value = JsonGuard.object(data == null ? "{}" : data);
            if (!value.optBoolean("enabled", false)) {
                return I18n.t("Выключено", "Off");
            }
            String counters = ExitFyDashboardState.safeLabel(
                    value.optString("counters", ""), 32, "");
            String prefix = value.optInt("hooks", 0) + "/" + value.optLong("requests", 0L);
            String line = counters.isEmpty()
                    ? prefix + I18n.t(" · нет подключения", " · not connected")
                    : prefix + "/" + counters;
            String refusal = ExitFyDashboardState.safeLabel(
                    value.optString("refusal", ""), 64, "");
            return refusal.isEmpty() ? line : line + " · " + refusal;
        } catch (Exception ignored) {
            return I18n.t("Недоступно", "Unavailable");
        }
    }

    private void confirmRestart() {
        confirm(
                I18n.t("Перезапустить exteraGram?", "Restart exteraGram?"),
                I18n.t("Приложение закроется и откроется снова. Переписки не затрагиваются.",
                        "The app closes and opens again. Your chats are not affected."),
                I18n.t("Перезапустить", "Restart"),
                this::restartApplication);
    }

    private void restartApplication() {
        Activity activity = getParentActivity();
        if (activity == null) return;
        try {
            Intent intent = activity.getPackageManager()
                    .getLaunchIntentForPackage(activity.getPackageName());
            if (intent == null) return;
            activity.finishAffinity();
            activity.startActivity(intent);
        } catch (Exception ignored) {
            return;
        }
        System.exit(0);
    }

    private void showCallsDialog() {
        CharSequence[] labels = {
                I18n.t("Выключено", "Off"),
                I18n.t("Включено", "On"),
        };
        showChoiceDialog(
                I18n.t("Звонки через exitFy (эксперимент)",
                        "Calls through exitFy (experimental)"),
                labels, state.callsViaProxy ? 1 : 0, index -> {
                    boolean value = index == 1;
                    if (value == state.callsViaProxy) return;
                    setSetting("calls_via_proxy", value);
                    showToast(value
                            ? I18n.t("Заработает после перезапуска exteraGram",
                            "Takes effect after exteraGram restarts")
                            : I18n.t("Выключится после перезапуска exteraGram",
                            "Turns off after exteraGram restarts"), true);
                });
    }

    private void showRefreshOnOpenDialog() {
        CharSequence[] labels = {
                I18n.t("Выключено", "Off"),
                I18n.t("Включено", "On"),
        };
        showChoiceDialog(
                I18n.t("Обновлять подписки при входе", "Refresh subscriptions on open"),
                labels, state.refreshOnOpen ? 1 : 0, index -> {
                    boolean value = index == 1;
                    if (value != state.refreshOnOpen) setSetting("refresh_on_open", value);
                });
    }

    private void showAutoCheckDialog() {
        int[] choices = SettingsModel.AUTO_CHECK_CHOICES;
        CharSequence[] labels = new CharSequence[choices.length];
        int selected = 0;
        for (int index = 0; index < choices.length; index++) {
            labels[index] = autoCheckLabel(choices[index]);
            if (choices[index] == state.autoCheckMinutes) selected = index;
        }
        showChoiceDialog(I18n.t("Автопроверка задержки", "Automatic latency check"),
                labels, selected, index -> {
                    if (index < 0 || index >= choices.length) return;
                    if (choices[index] == state.autoCheckMinutes) return;
                    setSetting("auto_check_minutes", choices[index]);
                });
    }

    private static String autoCheckLabel(int minutes) {
        if (minutes <= 0) return I18n.t("Выключено", "Off");
        if (minutes % 60 == 0) {
            return I18n.t("Каждые ", "Every ") + (minutes / 60)
                    + I18n.t(" ч", " h");
        }
        return I18n.t("Каждые ", "Every ") + minutes + I18n.t(" мин", " min");
    }

    private void showFailoverDialog() {
        CharSequence[] labels = {
                I18n.t("Выключено", "Off"),
                I18n.t("Включено", "On"),
        };
        showChoiceDialog(
                I18n.t("Менять сервер при обрыве", "Switch server on failure"),
                labels, state.failover ? 1 : 0, index -> {
                    boolean value = index == 1;
                    if (value == state.failover) return;
                    setSetting("failover", value);
                    if (value) {
                        showToast(I18n.t(
                                "Если сервер не отвечает, будет выбран следующий",
                                "A server that stops responding is replaced by the next one"),
                                true);
                    }
                });
    }

    /**
     * The versions are requested here rather than carried in the shared UI
     * state: the main screen deliberately never names an engine.
     */
    private void loadCoreVersions() {
        executeCommand(() -> new JSONObject().put("command", "core_versions"),
                false, result -> {
                    if (result == null || !result.ok) return;
                    String label = describeVersions(result.data);
                    runUiAction(() -> {
                        coreVersions = label;
                        if (coreVersionRow != null) coreVersionRow.setValue(label);
                    });
                });
    }

    private static String describeVersions(String data) {
        try {
            JSONObject value = JsonGuard.object(data == null ? "{}" : data);
            String xray = ExitFyDashboardState.safeLabel(
                    value.optString("xray", ""), 24, "");
            String singBox = ExitFyDashboardState.safeLabel(
                    value.optString("singBox", ""), 24, "");
            if (xray.isEmpty() && singBox.isEmpty()) {
                return I18n.t("Не установлены", "Not installed");
            }
            return "Xray " + (xray.isEmpty() ? "\u2014" : xray)
                    + " \u00b7 sing-box " + (singBox.isEmpty() ? "\u2014" : singBox);
        } catch (Exception ignored) {
            return I18n.t("Не установлены", "Not installed");
        }
    }

    private static String dualCoreLabel(ExitFyDashboardState state) {
        if (state.dualCoreActive) {
            return state.dualCore
                    ? I18n.t("Включено", "On")
                    : I18n.t("Включено до перезапуска", "On until restart");
        }
        return state.dualCore
                ? I18n.t("Включится при подключении", "On at next connection")
                : I18n.t("Выключено", "Off");
    }

    private static int pingTypeIndex(String value) {
        return SettingsModel.PING_PROXY_GET.equals(value) ? 1 : 0;
    }

    private static String pingTypeLabel(String value) {
        return SettingsModel.PING_PROXY_GET.equals(value)
                ? "Proxy GET"
                : "TCP";
    }
}
