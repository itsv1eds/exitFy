package com.extera.plugins.exitfy;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class VpnConnectionPolicyTest {
    @Test public void respectsManualDisableAndClientPolicyBeforeAutoResume() {
        assertFalse(VpnConnectionPolicy.shouldPause(false, true, true, true));
        assertFalse(VpnConnectionPolicy.shouldPause(true, false, true, false));
        assertTrue(VpnConnectionPolicy.shouldPause(true, true, true, false));
        assertTrue(VpnConnectionPolicy.shouldPause(true, false, false, true));
        assertFalse(VpnConnectionPolicy.shouldPause(true, true, false, false));
    }

    @Test public void preferenceSurvivesEverySiblingSettingAndJsonRestart() {
        SettingsModel initial = SettingsModel.defaults();
        assertFalse(initial.pauseOnVpn);
        SettingsModel settings = initial.withSetting("pause_on_vpn", true)
                .withSetting("enabled", true).withSetting("provider_id", 3)
                .withSetting("custom_hwid", "custom").withSetting("ping_type", "proxy_get")
                .withSetting("dual_core", false).withSetting("failover", true)
                .withSetting("refresh_on_open", true).withSetting("auto_check_minutes", 15)
                .withSetting("calls_via_proxy", true).withSetting("subscription_user_agent", "Happ/5.2.0")
                .withSetting("balance_mode", "sticky").withSetting("sort_by_ping", true)
                .withSetting("tutorial_step", 4);
        assertTrue(settings.pauseOnVpn);
        assertEquals(settings, SettingsModel.fromJson(settings.toJson().toString()));
        assertEquals(true, settings.settingValue("pause_on_vpn"));
        assertTrue(RuntimePolicy.connectionSettingsChanged(settings, settings.withSetting("pause_on_vpn", false)));
        assertFalse(settings.withSetting("pause_on_vpn", false).pauseOnVpn);
    }

    @Test public void dashboardExplainsPauseWithoutClaimingDisconnectionOrFailure() throws Exception {
        ExitFyDashboardState paused = ExitFyDashboardState.parse(new JSONObject()
                .put("runtimeAvailable", true).put("enabled", true).put("state", "RUNNING")
                .put("pauseOnVpn", true).put("vpnPaused", true)
                .put("coreInstall", new JSONObject().put("required", true)).toString());
        assertTrue(paused.enabled);
        assertTrue(paused.pauseOnVpn);
        assertTrue(paused.vpnPaused);
        assertEquals(ExitFyDashboardState.PrimaryAction.DISCONNECT, paused.primaryAction());
        assertEquals(I18n.t("Приостановлено: включён VPN", "Paused while VPN is active"), paused.connectionTitle());
        assertFalse(paused.nextStepHint().isEmpty());
        ExitFyDashboardState clientPaused = ExitFyDashboardState.parse(new JSONObject()
                .put("enabled", true).put("vpnPaused", true).put("vpnPauseReason", "client").toString());
        assertEquals(I18n.t("Приостановлено настройками клиента", "Paused by the client's network settings"),
                clientPaused.connectionTitle());
    }
}
