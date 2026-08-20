package com.extera.plugins.exitfy;

import android.content.Context;
import android.widget.LinearLayout;

import org.telegram.messenger.R;

/** Native Android View settings for options that used to live in plugin settings. */
final class ExitFyPreferencesFragment
        extends ExitFySubscreenFragment<ExitFyDashboardState> {
    private static final String[] PING_VALUES = {
            SettingsModel.PING_PROXY_GET,
            SettingsModel.PING_TCP,
    };

    private ExitFyDashboardState state = ExitFyDashboardState.EMPTY;
    private SettingRow pingTypeRow;
    private SettingRow customHwidRow;
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

        renderUiState(state);
    }

    @Override
    protected ExitFyDashboardState parseUiState(String json) {
        return ExitFyDashboardState.parse(json);
    }

    @Override
    protected void renderUiState(ExitFyDashboardState next) {
        if (next == null) return;
        state = next;
        if (pingTypeRow == null || customHwidRow == null) return;
        if (next.runtimeAvailable) {
            pingTypeRow.setValue(pingTypeLabel(next.pingType));
            customHwidRow.setValue(next.customHwidSet
                    ? I18n.t("Настроен", "Configured")
                    : (next.defaultHwid.isEmpty() ? "—" : next.defaultHwid));
        } else {
            String unavailable = I18n.t("Runtime недоступен", "Runtime unavailable");
            pingTypeRow.setValue(unavailable);
            customHwidRow.setValue(unavailable);
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
    }

    private void showPingTypeDialog() {
        CharSequence[] labels = {
                "Proxy GET",
                "TCP",
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

    private static int pingTypeIndex(String value) {
        return SettingsModel.PING_TCP.equals(value) ? 1 : 0;
    }

    private static String pingTypeLabel(String value) {
        return SettingsModel.PING_TCP.equals(value)
                ? "TCP"
                : "Proxy GET";
    }
}
