package com.extera.plugins.exitfy;

import org.json.JSONObject;
import org.json.JSONArray;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class ExitFyDashboardStateTest {
    @Test
    public void mapsRuntimeStateWithoutExposingSecretFields() throws Exception {
        JSONObject value = new JSONObject()
                .put("runtimeAvailable", true)
                .put("state", "RUNNING")
                .put("enabled", true)
                .put("providerId", 1)
                .put("providerAvailability", new JSONArray()
                        .put(true).put(true).put(true))
                .put("serverCount", 24)
                .put("customUrlCount", 3)
                .put("pingType", "proxy_get")
                .put("customHwidSet", true)
                .put("defaultHwid", "0123456789abcdef")
                .put("connectionIssue", "Connection refused")
                .put("activeNodeInfo", new JSONObject()
                        .put("key", "node-key")
                        .put("name", "Frankfurt 01")
                        .put("protocol", "vless")
                        .put("transport", "ws")
                        .put("security", "reality")
                        .put("latency", 84)
                        .put("pingStatus", "ok"))
                .put("operations", new JSONObject()
                        .put("subscriptionRefresh", "running")
                        .put("import", "idle"))
                .put("ping", new JSONObject().put("state", "idle"));

        ExitFyDashboardState state = ExitFyDashboardState.parse(value.toString());

        assertEquals("RUNNING", state.runtimeState);
        assertEquals("Shrimp", state.providerName());
        assertTrue(state.providerAvailable(0));
        assertTrue(state.providerAvailable(1));
        assertTrue(state.providerAvailable(2));
        assertEquals(3, state.customUrlCount);
        assertFalse(state.connectionTitle().isEmpty());
        assertEquals("Frankfurt 01", state.activeTitle());
        assertEquals("VLESS · ws · reality", state.activeProtocolSummary());
        assertEquals(84L, state.activeLatency);
        assertTrue(state.activePingSummary().startsWith("84 "));
        assertTrue(state.refreshRunning);
        assertTrue(state.runtimeAvailable);
        assertTrue(state.customHwidSet);
        assertEquals("0123456789abcdef", state.defaultHwid);
        assertEquals("Connection refused", state.connectionIssue);
    }

    @Test
    public void boundsConnectionIssueAndRejectsUriShapedDiagnostics()
            throws Exception {
        ExitFyDashboardState bounded = ExitFyDashboardState.parse(new JSONObject()
                .put("connectionIssue", "x".repeat(400))
                .toString());
        assertEquals(180, bounded.connectionIssue.length());

        ExitFyDashboardState redacted = ExitFyDashboardState.parse(new JSONObject()
                .put("connectionIssue",
                        "failed vless://uuid@secret.invalid:443")
                .toString());
        assertEquals("", redacted.connectionIssue);
    }

    @Test
    public void hidesUriShapedLabelsAndBoundsUntrustedText() throws Exception {
        JSONObject value = new JSONObject()
                .put("activeNodeInfo", new JSONObject()
                        .put("key", "node-key")
                        .put("name", "Node \u202evless://uuid@secret.invalid:443"));

        ExitFyDashboardState state = ExitFyDashboardState.parse(value.toString());

        assertFalse(state.activeTitle().contains("uuid"));
        assertTrue(state.activeTitle().codePointCount(
                0, state.activeTitle().length()) <= 96);
    }

    @Test
    public void malformedJsonProducesSafeDisconnectedState() {
        ExitFyDashboardState state = ExitFyDashboardState.parse("{");

        assertEquals("STOPPED", state.runtimeState);
        assertFalse(state.enabled);
        assertFalse(state.hasActiveNode());
        assertFalse(state.providerAvailable(0));
        assertFalse(state.providerAvailable(1));
        assertTrue(state.providerAvailable(2));
    }

    @Test
    public void oversizedStateFailsClosedBeforeJsonAllocation() throws Exception {
        StringBuilder padding = new StringBuilder(
                ExitFyDashboardState.MAX_UI_STATE_UTF8_BYTES + 1);
        for (int index = 0;
             index <= ExitFyDashboardState.MAX_UI_STATE_UTF8_BYTES; index++) {
            padding.append('x');
        }
        ExitFyDashboardState state = ExitFyDashboardState.parse(
                new JSONObject().put("state", "RUNNING")
                        .put("padding", padding.toString()).toString());

        assertEquals("STOPPED", state.runtimeState);
        assertFalse(state.runtimeAvailable);
    }

    @Test
    public void unknownPreferenceTokensFallBackToCanonicalDefaults()
            throws Exception {
        ExitFyDashboardState state = ExitFyDashboardState.parse(new JSONObject()
                .put("pingType", "future")
                .toString());

        assertEquals(SettingsModel.PING_PROXY_GET, state.pingType);
    }

    @Test
    public void mapsAggregateCoreInstallationWithoutFamilyDetails()
            throws Exception {
        ExitFyDashboardState state = ExitFyDashboardState.parse(new JSONObject()
                .put("runtimeAvailable", true)
                .put("coreInstall", new JSONObject()
                        .put("required", true)
                        .put("state", "running")
                        .put("progress", 42)
                        .put("stage", "downloading")
                        .put("generation", 7))
                .toString());

        assertTrue(state.coreInstall.required);
        assertTrue(state.coreInstall.active());
        assertFalse(state.coreInstall.terminal());
        assertEquals(42, state.coreInstall.progress);
        assertEquals("downloading", state.coreInstall.stage);
        assertEquals(7L, state.coreInstall.generation);
        assertTrue(state.coreInstall.stageLabel().contains("…"));
    }

    @Test
    public void boundsMalformedCoreInstallationAndFallsBackToIdle()
            throws Exception {
        ExitFyDashboardState state = ExitFyDashboardState.parse(new JSONObject()
                .put("coreInstall", new JSONObject()
                        .put("required", true)
                        .put("state", "future state")
                        .put("progress", 800)
                        .put("stage", "future stage")
                        .put("generation", -4))
                .toString());

        assertTrue(state.coreInstall.required);
        assertFalse(state.coreInstall.active());
        assertFalse(state.coreInstall.terminal());
        assertEquals("idle", state.coreInstall.state);
        assertEquals("idle", state.coreInstall.stage);
        assertEquals(100, state.coreInstall.progress);
        assertEquals(0L, state.coreInstall.generation);
    }

    @Test
    public void tellsAFirstTimeUserWhatToDoNext() throws Exception {
        ExitFyDashboardState missing = ExitFyDashboardState.parse(new JSONObject()
                .put("coreInstall", new JSONObject()
                        .put("required", true)
                        .put("state", "idle")
                        .put("stage", "idle")
                        .put("generation", 1))
                .toString());
        assertFalse(missing.nextStepHint().isEmpty());

        ExitFyDashboardState noServer = ExitFyDashboardState.parse(
                new JSONObject().toString());
        assertFalse(noServer.nextStepHint().isEmpty());
        assertNotEquals(missing.nextStepHint(), noServer.nextStepHint());

        // A running install already explains itself, and an error owns the line.
        ExitFyDashboardState installing = ExitFyDashboardState.parse(new JSONObject()
                .put("coreInstall", new JSONObject()
                        .put("required", true)
                        .put("state", "running")
                        .put("stage", "downloading")
                        .put("generation", 2))
                .toString());
        assertEquals("", installing.nextStepHint());
        ExitFyDashboardState failure = ExitFyDashboardState.parse(new JSONObject()
                .put("state", "ERROR")
                .toString());
        assertEquals("", failure.nextStepHint());
    }

    @Test
    public void distinguishesPartialAndFullCoreInstallTerminals()
            throws Exception {
        ExitFyDashboardState partial = ExitFyDashboardState.parse(new JSONObject()
                .put("coreInstall", new JSONObject()
                        .put("state", "error")
                        .put("stage", "partial")
                        .put("generation", 3))
                .toString());
        ExitFyDashboardState failed = ExitFyDashboardState.parse(new JSONObject()
                .put("coreInstall", new JSONObject()
                        .put("state", "error")
                        .put("stage", "failed")
                        .put("generation", 4))
                .toString());
        ExitFyDashboardState success = ExitFyDashboardState.parse(new JSONObject()
                .put("coreInstall", new JSONObject()
                        .put("state", "success")
                        .put("stage", "done")
                        .put("generation", 5))
                .toString());

        assertTrue(partial.coreInstall.terminal());
        assertTrue(partial.coreInstall.partial());
        assertFalse(partial.coreInstall.successful());
        assertTrue(partial.coreInstall.terminalMessage().toLowerCase()
                .contains(I18n.isRussian() ? "автоматически" : "automatically"));
        assertTrue(failed.coreInstall.terminal());
        assertFalse(failed.coreInstall.partial());
        // Mirrors already cover a blocked asset host, so a full failure points
        // at GitHub itself rather than at the user's connection.
        assertTrue(failed.coreInstall.terminalMessage().toLowerCase()
                .contains("github"));
        assertTrue(failed.coreInstall.terminalMessage().toLowerCase()
                .contains(I18n.isRussian() ? "vpn" : "vpn"));
        assertTrue(success.coreInstall.successful());
        assertFalse(success.coreInstall.partial());
    }

    @Test
    public void primaryActionUsesInstallStateThenReadinessThenEnabled()
            throws Exception {
        String[] installStates = {"idle", "running", "error"};
        for (int readyCount = 0; readyCount <= 2; readyCount++) {
            boolean required = readyCount < 2;
            for (boolean enabled : new boolean[]{false, true}) {
                for (String installState : installStates) {
                    ExitFyDashboardState state = ExitFyDashboardState.parse(
                            new JSONObject()
                                    .put("enabled", enabled)
                                    .put("coreInstall", new JSONObject()
                                            .put("required", required)
                                            .put("state", installState)
                                            .put("stage", "error".equals(installState)
                                                    ? "failed" : "idle")
                                            .put("generation", 9))
                                    .toString());

                    ExitFyDashboardState.PrimaryAction expected;
                    if ("running".equals(installState)) {
                        expected = ExitFyDashboardState.PrimaryAction.INSTALLING;
                    } else if (required) {
                        expected = ExitFyDashboardState.PrimaryAction.INSTALL_CORES;
                    } else {
                        expected = enabled
                                ? ExitFyDashboardState.PrimaryAction.DISCONNECT
                                : ExitFyDashboardState.PrimaryAction.CONNECT;
                    }
                    assertEquals(
                            "ready=" + readyCount
                                    + ", enabled=" + enabled
                                    + ", installState=" + installState,
                            expected, state.primaryAction());
                    assertFalse(state.primaryAction().label().isEmpty());
                }
            }
        }
    }

    @Test
    public void providerAvailabilityIsBoundedAndCustomAlwaysRemainsAvailable()
            throws Exception {
        ExitFyDashboardState state = ExitFyDashboardState.parse(new JSONObject()
                .put("providerAvailability", new JSONArray()
                        .put(false).put(true).put(false).put(true))
                .toString());

        assertFalse(state.providerAvailable(-1));
        assertFalse(state.providerAvailable(0));
        assertTrue(state.providerAvailable(1));
        assertTrue(state.providerAvailable(2));
        assertFalse(state.providerAvailable(3));
    }

    @Test
    public void mapsEveryTerminalPingFailureToVisibleState() throws Exception {
        for (String status : new String[]{"timeout", "tls_failed", "socks_failed",
                "tcp_failed", "start_failed", "guard_unavailable"}) {
            ExitFyDashboardState state = ExitFyDashboardState.parse(new JSONObject()
                    .put("activeNodeInfo", new JSONObject()
                            .put("key", "node")
                            .put("pingStatus", status))
                    .toString());
            assertTrue("failure was shown as unchecked: " + status,
                    state.activePingSummary().toLowerCase().contains("response")
                            || state.activePingSummary().toLowerCase().contains("ответ"));
        }
        ExitFyDashboardState restart = ExitFyDashboardState.parse(new JSONObject()
                .put("activeNodeInfo", new JSONObject()
                        .put("key", "node")
                        .put("pingStatus", "restart_required"))
                .toString());
        assertTrue(restart.activePingSummary().toLowerCase().contains("unavailable")
                || restart.activePingSummary().toLowerCase().contains("недоступ"));

        ExitFyDashboardState quic = ExitFyDashboardState.parse(new JSONObject()
                .put("activeNodeInfo", new JSONObject()
                        .put("key", "node")
                        .put("pingStatus", "tcp_failed_quic"))
                .toString());
        String quicLabel = quic.activePingSummary().toLowerCase();
        assertTrue(quicLabel.contains("not applicable")
                || quicLabel.contains("неприменима"));
        assertFalse(quicLabel.contains("no response")
                || quicLabel.contains("нет ответа"));
    }
}
