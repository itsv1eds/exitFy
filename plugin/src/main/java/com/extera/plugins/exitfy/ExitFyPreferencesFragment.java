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
    private SettingRow dualCoreRow;
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

        dualCoreRow = settingRow(context, R.drawable.msg_settings,
                I18n.t("Два ядра сразу (эксперимент)", "Both cores at once (experimental)"), "");
        setSafeClick(dualCoreRow.view, this::showDualCoreDialog);
        content.addView(dualCoreRow.view, sectionParams());

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
        if (pingTypeRow == null || customHwidRow == null || dualCoreRow == null) return;
        if (next.runtimeAvailable) {
            pingTypeRow.setValue(pingTypeLabel(next.pingType));
            customHwidRow.setValue(next.customHwidSet
                    ? I18n.t("Настроен", "Configured")
                    : (next.defaultHwid.isEmpty() ? "—" : next.defaultHwid));
            dualCoreRow.setValue(dualCoreLabel(next));
        } else {
            String unavailable = I18n.t("Runtime недоступен", "Runtime unavailable");
            pingTypeRow.setValue(unavailable);
            customHwidRow.setValue(unavailable);
            dualCoreRow.setValue(unavailable);
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
        if (dualCoreRow != null) dualCoreRow.setEnabled(enabled);
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
        return SettingsModel.PING_TCP.equals(value) ? 1 : 0;
    }

    private static String pingTypeLabel(String value) {
        return SettingsModel.PING_TCP.equals(value)
                ? "TCP"
                : "Proxy GET";
    }
}
