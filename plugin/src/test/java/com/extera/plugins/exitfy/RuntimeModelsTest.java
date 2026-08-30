package com.extera.plugins.exitfy;

import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.math.BigInteger;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class RuntimeModelsTest {
    @Test
    public void dashboardFactoryDoesNotExpandPublicBridgeAbi() throws Exception {
        Method factory = ExitFyBridge.class.getDeclaredMethod("createDashboardFragment");
        assertTrue(Modifier.isStatic(factory.getModifiers()));
        assertFalse(Modifier.isPublic(factory.getModifiers()));
        assertEquals("org.telegram.ui.ActionBar.BaseFragment",
                factory.getReturnType().getName());
    }

    @Test
    public void stateMachineAllowsLifecycleAndRejectsInvalidTransition() {
        ConnectionStateMachine machine = new ConnectionStateMachine();
        machine.transition(RuntimeState.STARTING);
        machine.transition(RuntimeState.RUNNING);
        machine.transition(RuntimeState.STOPPING);
        machine.transition(RuntimeState.STOPPED);
        assertEquals(RuntimeState.STOPPED, machine.get());
        try {
            machine.transition(RuntimeState.RUNNING);
            throw new AssertionError("invalid state transition accepted");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("STOPPED"));
        }
    }

    @Test
    public void stateMachineSurvivesOneHundredConnectDisconnectCycles() {
        ConnectionStateMachine machine = new ConnectionStateMachine();
        for (int i = 0; i < 100; i++) {
            machine.transition(RuntimeState.STARTING);
            machine.transition(RuntimeState.RUNNING);
            machine.transition(RuntimeState.STOPPING);
            machine.transition(RuntimeState.STOPPED);
        }
        assertEquals(RuntimeState.STOPPED, machine.get());
    }

    @Test
    public void settingsAreBoundedAndRoundTrip() throws Exception {
        SettingsModel value = SettingsModel.fromJson(
                "{\"enabled\":true,\"provider_id\":99,"
                        + "\"custom_hwid\":\" custom \",\"ping_type\":\"tcp\"}"
        );
        assertTrue(value.enabled);
        assertEquals(SettingsModel.CUSTOM_PROVIDER_ID, value.providerId);
        assertEquals("custom", value.customHwid);
        assertEquals(SettingsModel.PING_TCP, value.pingType);
        assertEquals(6, value.schemaVersion);
        assertFalse(value.toJson().has("core_policy"));
    }

    @Test
    public void nativeUiSettingWhitelistIsStrictAndPreservesOtherValues() {
        SettingsModel base = new SettingsModel(true, 1, "device", 6,
                SettingsModel.PING_PROXY_GET);
        SettingsModel changed = base.withSetting("ping_type", SettingsModel.PING_TCP);
        assertTrue(changed.enabled);
        assertEquals(1, changed.providerId);
        assertEquals("device", changed.customHwid);
        assertEquals(SettingsModel.PING_TCP, changed.pingType);
        assertEquals(Boolean.TRUE, base.settingValue("enabled"));
        assertEquals(1, base.settingValue("provider_id"));

        for (Object invalidProvider : new Object[]{1.5d, Double.NaN, Long.MAX_VALUE,
                BigInteger.ONE.shiftLeft(64), "1"}) {
            try {
                base.withSetting("provider_id", invalidProvider);
                throw new AssertionError("invalid provider value accepted: " + invalidProvider);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("provider_id"));
            }
        }
        String removedSelectionKey = new StringBuilder("auto_").append("switch").toString();
        for (String key : new String[]{
                "mode", removedSelectionKey, "core_policy", "schema_version", "unknown"
        }) {
            try {
                base.withSetting(key, false);
                throw new AssertionError("non-whitelisted setting accepted: " + key);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("setting"));
            }
        }
    }

    @Test
    public void localeCodesFollowHostLanguageIdentifiers() {
        assertTrue(I18n.isRussianCode("ru"));
        assertTrue(I18n.isRussianCode("ru-RU"));
        assertTrue(I18n.isRussianCode("RU_ru"));
        assertFalse(I18n.isRussianCode("en"));
        assertFalse(I18n.isRussianCode(null));
    }

    @Test
    public void unavailableBuiltInProviderFallsBackWithoutDisabling() {
        ProviderSelectionDecision decision = RuntimePolicy.normalizeProviderSelection(
                0, new boolean[]{false, true}, false, true);
        assertEquals(1, decision.providerId);
        assertFalse(decision.disable);
    }

    @Test
    public void unavailableBuiltInsFallBackToConfiguredCustomProvider() {
        ProviderSelectionDecision decision = RuntimePolicy.normalizeProviderSelection(
                1, new boolean[]{false, false}, true, true);
        assertEquals(SettingsModel.CUSTOM_PROVIDER_ID, decision.providerId);
        assertFalse(decision.disable);
    }

    @Test
    public void unavailableBuiltInsDisableEmptyFallbackInsteadOfReconnectLoop() {
        ProviderSelectionDecision decision = RuntimePolicy.normalizeProviderSelection(
                0, new boolean[]{false, false}, false, true);
        assertEquals(SettingsModel.CUSTOM_PROVIDER_ID, decision.providerId);
        assertTrue(decision.disable);
    }

    @Test
    public void explicitlySelectedCustomProviderIsNeverReplacedByCatalogPolicy() {
        ProviderSelectionDecision decision = RuntimePolicy.normalizeProviderSelection(
                SettingsModel.CUSTOM_PROVIDER_ID,
                new boolean[]{true, true}, false, true);
        assertEquals(SettingsModel.CUSTOM_PROVIDER_ID, decision.providerId);
        assertFalse(decision.disable);
    }

    @Test
    public void customHwidIsUnicodeBoundedAndCannotInjectHeaders() {
        StringBuilder oversized = new StringBuilder();
        for (int i = 0; i < 300; i++) oversized.append("🚀");
        SettingsModel value = new SettingsModel(false, 0,
                oversized.toString(), 6,
                SettingsModel.PING_PROXY_GET);
        assertEquals(256, value.customHwid.codePointCount(0, value.customHwid.length()));
        assertTrue(value.customHwid.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 1_024);
        assertFalse(Character.isHighSurrogate(
                value.customHwid.charAt(value.customHwid.length() - 1)));
        SettingsModel injected = new SettingsModel(false, 0,
                "ok\r\n\u0085Injected: value", 6,
                SettingsModel.PING_PROXY_GET);
        assertFalse(injected.customHwid.contains("\r"));
        assertFalse(injected.customHwid.contains("\n"));
        assertFalse(injected.customHwid.contains("\u0085"));
        SettingsModel malformed = new SettingsModel(false, 0,
                "\ud83dvalue", 6,
                SettingsModel.PING_PROXY_GET);
        assertEquals(0xfffd, malformed.customHwid.codePointAt(0));
        SettingsModel parity = new SettingsModel(false, 0,
                " \tA\u0085B\ud83dC\udc00D \n", 6,
                SettingsModel.PING_PROXY_GET);
        assertEquals("AB\ufffdC\ufffdD", parity.customHwid);
        SettingsModel nonBreakingSpace = new SettingsModel(false, 0,
                "\u00a0value\u00a0", 6,
                SettingsModel.PING_PROXY_GET);
        assertEquals("\u00a0value\u00a0", nonBreakingSpace.customHwid);

        String controlsThenVisible = "\u0085".repeat(1_000_000) + "visible";
        SettingsModel defensiveBound = new SettingsModel(false, 0,
                controlsThenVisible, 6, "proxy_get");
        assertEquals("", defensiveBound.customHwid);

        String logicalBoundary = "\u0085".repeat(4_095) + "🚀";
        SettingsModel boundaryValue = new SettingsModel(false, 0,
                logicalBoundary, 6, "proxy_get");
        assertEquals("🚀", boundaryValue.customHwid);
    }

    @Test
    public void nodePageCommandBoundsOffsetAndLimit() {
        assertTrue(SubscriptionManager.validPageRequest(0, 1));
        assertTrue(SubscriptionManager.validPageRequest(
                SubscriptionManager.MAX_TOTAL_NODES, SubscriptionManager.MAX_PAGE_SIZE));
        assertFalse(SubscriptionManager.validPageRequest(-1, 50));
        assertFalse(SubscriptionManager.validPageRequest(
                SubscriptionManager.MAX_TOTAL_NODES + 1, 50));
        assertFalse(SubscriptionManager.validPageRequest(0, 0));
        assertFalse(SubscriptionManager.validPageRequest(
                0, SubscriptionManager.MAX_PAGE_SIZE + 1));
        // Probing stays bounded where it was even though listing grew.
        assertEquals(50, SubscriptionManager.MAX_PING_KEYS);
        assertEquals(50, SubscriptionManager.DEFAULT_PAGE_SIZE);
    }

    @Test
    public void bootstrapRequiresCurrentVersionSchemaFiveAndPrivateArm64Bridge()
            throws Exception {
        File root = Files.createTempDirectory("exitfy-bootstrap").toFile();
        File bridge = new File(root, "bridge/arm64-v8a/libexitfy_bridge.so");
        assertTrue(bridge.getParentFile().mkdirs());
        assertTrue(bridge.createNewFile());
        try {
            String valid = new org.json.JSONObject()
                    .put("pluginId", "exitFy_v2")
                    .put("pluginVersion", "4.1.0")
                    .put("settingsSchema", 6)
                    .put("dataDir", root.getAbsolutePath())
                    .put("nativeBridgePath", bridge.getAbsolutePath())
                    .put("nativeAbi", "arm64-v8a")
                    .toString();
            assertEquals("arm64-v8a", BootstrapConfig.parse(valid).nativeAbi);
            try {
                BootstrapConfig.parse(new org.json.JSONObject(valid)
                        .put("nativeAbi", "x86_64").toString());
                throw new AssertionError("non-arm64 bootstrap ABI accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("ABI"));
            }
            try {
                BootstrapConfig.parse(valid.replace("exitFy_v2", "exitfy"));
                throw new AssertionError("old plugin id accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("plugin id"));
            }
            try {
                BootstrapConfig.parse(valid.replace(
                        "4.1.0", "4.0.0-beta.23"));
                throw new AssertionError("old bootstrap version accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("version"));
            }
            File versionedBridge = new File(root,
                    "bridge/4.1.0/arm64-v8a/libexitfy_bridge.so");
            assertTrue(versionedBridge.getParentFile().mkdirs());
            assertTrue(versionedBridge.createNewFile());
            try {
                BootstrapConfig.parse(new org.json.JSONObject(valid)
                        .put("nativeBridgePath", versionedBridge.getAbsolutePath())
                        .toString());
                throw new AssertionError("versioned native bridge path accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("stable"));
            }
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void proxySnapshotRestoresExactFlagsAndCredentials() throws Exception {
        ProxySnapshotModel.ProxyValue proxy = new ProxySnapshotModel.ProxyValue(
                "proxy.example", 1080, "user", "password", "secret");
        ProxySnapshotModel.Preferences prefs = new ProxySnapshotModel.Preferences(
                "proxy.example", 1080, "user", "password", "secret", true, false);
        ProxySnapshotModel original = new ProxySnapshotModel(false, proxy, "My proxy", prefs, "")
                .withOwnedFingerprint("owned-link");
        ProxySnapshotModel restored = ProxySnapshotModel.fromJson(original.toJson());
        assertTrue(restored.active);
        assertEquals(proxy, restored.previous);
        assertEquals("My proxy", restored.previousName);
        assertTrue(restored.preferences.enabled);
        assertFalse(restored.preferences.calls);
        assertEquals("owned-link", restored.ownedFingerprint);
    }

    @Test
    public void proxyStateGuardRejectsProxyOrCallPreferenceChanges() {
        ProxySnapshotModel.ProxyValue proxy = new ProxySnapshotModel.ProxyValue(
                "proxy.example", 1080, "user", "password", "secret");
        ProxySnapshotModel.Preferences preferences = new ProxySnapshotModel.Preferences(
                "proxy.example", 1080, "user", "password", "secret", true, false);
        ProxySession.StateGuard guard = new ProxySession.StateGuard(proxy, preferences);
        assertTrue(guard.matches(new ProxySession.StateGuard(proxy, preferences)));
        assertTrue(guard.matches(new ProxySnapshotModel(
                false, proxy, "", preferences, "")));
        assertFalse(guard.matches(new ProxySnapshotModel(false,
                new ProxySnapshotModel.ProxyValue(
                        "other.example", 1080, "user", "password", "secret"),
                "", preferences, "")));
        assertFalse(guard.matches(new ProxySnapshotModel(false, proxy, "",
                new ProxySnapshotModel.Preferences(
                        "proxy.example", 1080, "user", "password", "secret", true, true),
                "")));
        assertFalse(guard.matches(new ProxySession.StateGuard(proxy,
                new ProxySnapshotModel.Preferences(
                        "proxy.example", 1080, "user", "password", "secret", true, true))));
    }

    @Test
    public void proxyCallsOwnershipAndRestorePreserveExternalToggle() {
        assertTrue(ProxySession.ownsCallsPreference(true));
        assertFalse(ProxySession.ownsCallsPreference(false));

        // While the plugin-owned value is unchanged, restore the pre-session value.
        assertFalse(ProxySession.callsPreferenceAfterRestore(false, true));
        assertTrue(ProxySession.callsPreferenceAfterRestore(true, true));

        // A user toggle during ownership wins over the stale pre-session snapshot.
        assertFalse(ProxySession.callsPreferenceAfterRestore(true, false));
    }

    @Test
    public void proxyProbeRejectsExternalSelectionBeforeRestoreClosure() {
        ProxySession.StateGuard durable = new ProxySession.StateGuard(
                new ProxySnapshotModel.ProxyValue(
                        "original.example", 1080, "user", "password", "secret"),
                new ProxySnapshotModel.Preferences(
                        "original.example", 1080, "user", "password", "secret", true, false));
        ProxySession.StateGuard external = new ProxySession.StateGuard(
                new ProxySnapshotModel.ProxyValue(
                        "external.example", 443, "other", "private", ""),
                new ProxySnapshotModel.Preferences(
                        "external.example", 443, "other", "private", "", true, true));

        // restoreSaved() reports PRESERVED when the UI closure observes the
        // external proxy. It must terminate the probe instead of adopting it.
        assertFalse(ProxySession.probeResumeAllowed(
                ProxySession.RestoreOutcome.PRESERVED, durable, null, external));
    }

    @Test
    public void proxyProbeRejectsExternalSelectionBetweenRestoreAndCapture() {
        ProxySession.StateGuard durable = new ProxySession.StateGuard(
                new ProxySnapshotModel.ProxyValue(
                        "original.example", 1080, "user", "password", "secret"),
                new ProxySnapshotModel.Preferences(
                        "original.example", 1080, "user", "password", "secret", true, false));
        ProxySession.StateGuard external = new ProxySession.StateGuard(
                new ProxySnapshotModel.ProxyValue(
                        "external.example", 443, "other", "private", ""),
                new ProxySnapshotModel.Preferences(
                        "external.example", 443, "other", "private", "", true, true));

        // Restore itself completed, but capture saw a later user selection.
        assertFalse(ProxySession.probeResumeAllowed(
                ProxySession.RestoreOutcome.RESTORED, durable, null, external));
        // Even if the explicit probe guard matches the now-current proxy, the
        // retained durable guard is independently required at activation.
        assertFalse(ProxySession.activationGuardsMatch(durable, external, external));
        assertTrue(ProxySession.activationGuardsMatch(durable, durable, durable));
        // A cancelled probe may continue only with its exact retained guard.
        assertTrue(ProxySession.probeResumeAllowed(
                ProxySession.RestoreOutcome.INACTIVE, durable, durable, durable));
    }

    @Test
    public void inactiveProbeRequiresFreshExplicitRetainedGuard() {
        ProxySession.StateGuard captured = new ProxySession.StateGuard(
                new ProxySnapshotModel.ProxyValue(
                        "original.example", 1080, "user", "password", "secret"),
                new ProxySnapshotModel.Preferences(
                        "original.example", 1080, "user", "password", "secret", true, false));
        ProxySession.StateGuard changed = new ProxySession.StateGuard(
                new ProxySnapshotModel.ProxyValue(
                        "manual.example", 443, "other", "private", ""),
                new ProxySnapshotModel.Preferences(
                        "manual.example", 443, "other", "private", "", true, true));

        // Manual Proxy GET from ERROR/INACTIVE uses this exact
        // retained==pending==fresh-capture admission.
        assertTrue(ProxySession.probeResumeAllowed(
                ProxySession.RestoreOutcome.INACTIVE, captured, captured, captured));
        assertFalse(ProxySession.probeResumeAllowed(
                ProxySession.RestoreOutcome.INACTIVE, captured, null, captured));
        // A user change after retention is confirmed external and rejected.
        assertFalse(ProxySession.probeResumeAllowed(
                ProxySession.RestoreOutcome.INACTIVE, captured, captured, changed));
    }

    @Test
    public void unknownProbeGuardUsesSafeOutcomes() {
        // Capture timeout/error is UNKNOWN: never disable or claim a manual
        // proxy change, but let the ordinary reconnect/backoff reconcile it.
        assertFalse(RuntimePolicy.shouldDisableAfterProbePauseFailure(false));
        assertTrue(RuntimePolicy.shouldReconnectAfterProbePauseFailure(
                true, true, false));
        // Only a confirmed guard mismatch is EXTERNALLY_CHANGED.
        assertTrue(RuntimePolicy.shouldDisableAfterProbePauseFailure(true));
        assertFalse(RuntimePolicy.shouldReconnectAfterProbePauseFailure(
                true, true, true));

        // Replacing a paused Proxy GET with TCP must restore the guarded
        // connection before the TCP-only task. Proxy -> Proxy intentionally
        // reuses the same retained guard without an intermediate restart.
        assertTrue(RuntimePolicy.replacementNeedsGuardedRestore("TCP", true));
        assertFalse(RuntimePolicy.replacementNeedsGuardedRestore("PROXY_GET", true));
        assertFalse(RuntimePolicy.replacementNeedsGuardedRestore("TCP", false));
    }

    @Test
    public void proxyResumeGuardSurvivesCancellationAndEnabledGenerationSupersession() {
        // cancel Proxy GET -> immediate next ping: no guarded restart has
        // completed, so the next task must inherit the original guard.
        assertFalse(RuntimePolicy.shouldClearProbeResumeGuard(true, true, false));
        // updateSettings superseding the runtime generation while exitFy
        // remains enabled has the same transfer semantics.
        assertTrue(RuntimePolicy.shouldTransferProbeResumeGuard(true, true, 2L, 1L));
        assertFalse(RuntimePolicy.shouldTransferProbeResumeGuard(true, true, 2L, 2L));
        assertFalse(RuntimePolicy.shouldTransferProbeResumeGuard(true, false, 2L, 1L));
        assertTrue(RuntimePolicy.shouldClearProbeResumeGuard(true, true, true));
        assertTrue(RuntimePolicy.shouldClearProbeResumeGuard(true, false, false));
        assertTrue(RuntimePolicy.shouldClearProbeResumeGuard(false, true, false));
    }

    @Test
    public void proxyProbeDoesNotStartBatchInsideRestorationReserve() {
        assertFalse(RuntimePolicy.hasProxyProbeBatchBudget(21_999L));
        assertTrue(RuntimePolicy.hasProxyProbeBatchBudget(22_000L));
    }

    @Test
    public void processOwnerGuardRejectsAnotherDexClassLoaderToken() {
        String key = "exitfy.test.dex_owner." + System.nanoTime();
        try {
            assertTrue(ExitFyBridge.claimProcessOwner(key, "first"));
            assertTrue(ExitFyBridge.claimProcessOwner(key, "first"));
            assertFalse(ExitFyBridge.claimProcessOwner(key, "second"));
            ExitFyBridge.releaseProcessOwner(key, "second");
            assertFalse(ExitFyBridge.claimProcessOwner(key, "second"));
            ExitFyBridge.releaseProcessOwner(key, "first");
            assertTrue(ExitFyBridge.claimProcessOwner(key, "second"));
        } finally {
            ExitFyBridge.releaseProcessOwner(key, "first");
            ExitFyBridge.releaseProcessOwner(key, "second");
        }
    }

    @Test
    public void dexKeeperEnsureIsIdempotentAndRootsOwningClassLoader() throws Exception {
        ClassLoader owner = ExitFyBridge.class.getClassLoader();
        Class.forName(ExitFyBridge.class.getName(), true, owner);
        ExitFyBridge.ensureDexKeeper();
        ExitFyBridge.ensureDexKeeper();
        Thread found = null;
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (ExitFyBridge.DEX_KEEPER_NAME.equals(thread.getName())) {
                if (found != null) throw new AssertionError("duplicate exitFy DEX keeper");
                found = thread;
            }
        }
        assertNotNull("process-lifetime DEX keeper was not started", found);
        assertTrue("DEX keeper must not hold process shutdown", found.isDaemon());
        assertTrue("DEX keeper unexpectedly stopped", found.isAlive());
        assertSame(owner, found.getContextClassLoader());
    }

    @Test
    public void nativeLoadFailureRetainsWinnerForSameLoaderRetry() {
        String key = "exitfy.test.native_retry." + System.nanoTime();
        AtomicInteger loads = new AtomicInteger();
        try {
            try {
                ExitFyBridge.loadNativeBridge("test", key, "winner", path -> {
                    loads.incrementAndGet();
                    throw new UnsatisfiedLinkError("first load failed");
                });
                throw new AssertionError("native load failure was swallowed");
            } catch (UnsatisfiedLinkError expected) {
                assertTrue(expected.getMessage().contains("first load"));
            }
            assertFalse(ExitFyBridge.claimProcessOwner(key, "loser"));

            ExitFyBridge.loadNativeBridge("test", key, "winner",
                    path -> loads.incrementAndGet());
            assertEquals(2, loads.get());
            assertFalse(ExitFyBridge.claimProcessOwner(key, "loser"));
        } finally {
            ExitFyBridge.releaseProcessOwner(key, "winner");
            ExitFyBridge.releaseProcessOwner(key, "loser");
        }
    }

    @Test
    public void concurrentLosingLoaderNeverRunsOrCreatesAnotherKeeper() throws Exception {
        String key = "exitfy.test.concurrent_owner." + System.nanoTime();
        CountDownLatch winnerEntered = new CountDownLatch(1);
        CountDownLatch releaseWinner = new CountDownLatch(1);
        AtomicInteger winnerLoads = new AtomicInteger();
        AtomicInteger loserLoads = new AtomicInteger();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<?> winner = workers.submit(() -> ExitFyBridge.loadNativeBridge(
                    "winner", key, "winner", path -> {
                        winnerLoads.incrementAndGet();
                        winnerEntered.countDown();
                        try {
                            if (!releaseWinner.await(2, TimeUnit.SECONDS)) {
                                throw new IllegalStateException("winner release timed out");
                            }
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(interrupted);
                        }
                    }));
            assertTrue(winnerEntered.await(2, TimeUnit.SECONDS));
            Future<?> loser = workers.submit(() -> {
                try {
                    ExitFyBridge.loadNativeBridge("loser", key, "loser",
                            path -> loserLoads.incrementAndGet());
                    throw new AssertionError("concurrent loser acquired native ownership");
                } catch (IllegalStateException expected) {
                    assertTrue(expected.getMessage().contains("already owned"));
                }
            });
            loser.get(2, TimeUnit.SECONDS);
            releaseWinner.countDown();
            winner.get(2, TimeUnit.SECONDS);

            assertEquals(1, winnerLoads.get());
            assertEquals(0, loserLoads.get());
            int keepers = 0;
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (ExitFyBridge.DEX_KEEPER_NAME.equals(thread.getName())) keepers++;
            }
            assertEquals("losing loader created a duplicate DEX keeper", 1, keepers);
        } finally {
            releaseWinner.countDown();
            workers.shutdownNow();
            ExitFyBridge.releaseProcessOwner(key, "winner");
            ExitFyBridge.releaseProcessOwner(key, "loser");
        }
    }

    @Test
    public void unloadUsesOldImmutableSessionSnapshotAfterNewMarkerIsWritten() throws Exception {
        File root = Files.createTempDirectory("exitfy-proxy-snapshot").toFile();
        try {
            AtomicStore store = new AtomicStore(root);
            org.json.JSONObject oldMarker = new org.json.JSONObject()
                    .put("active", true).put("ownedFingerprint", "old-fingerprint")
                    .put("preferences", new org.json.JSONObject());
            store.writeJson("proxy_session.json", oldMarker);
            ProxySession oldSession = new ProxySession(store);
            assertFalse(oldSession.recoveryReady());
            assertFalse(oldSession.markActiveIfCurrent(oldSession.beginOperation()));

            store.writeJson("proxy_session.json", new org.json.JSONObject()
                    .put("active", true).put("ownedFingerprint", "new-fingerprint")
                    .put("preferences", new org.json.JSONObject()));

            assertEquals("old-fingerprint", oldSession.sessionSnapshotForUnload()
                    .getString("ownedFingerprint"));
            assertEquals("new-fingerprint", store.readJson("proxy_session.json")
                    .getString("ownedFingerprint"));
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void corruptProxyMarkerKeepsRecoveryClosedUntilStateIsRepaired() throws Exception {
        File root = Files.createTempDirectory("exitfy-proxy-corrupt-marker").toFile();
        ProxySession session = null;
        byte[] corrupt = "{not-json".getBytes(StandardCharsets.UTF_8);
        try {
            Files.write(new File(root, "proxy_session.json").toPath(), corrupt);
            session = new ProxySession(new AtomicStore(root));

            assertFalse(session.recoveryReady());
            assertFalse(session.recoverIfNeeded());
            assertEquals(new String(corrupt, StandardCharsets.UTF_8),
                    new String(Files.readAllBytes(
                            new File(root, "proxy_session.json").toPath()),
                            StandardCharsets.UTF_8));

            new AtomicStore(root).writeJson("proxy_session.json",
                    new JSONObject().put("active", false));
            assertTrue(session.recoverIfNeeded());
            assertTrue(session.recoveryReady());
        } finally {
            if (session != null) session.beginShutdown();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void supersededProxySessionCannotEraseReplacementMarker() throws Exception {
        File root = Files.createTempDirectory("exitfy-proxy-marker-lease").toFile();
        ProxySession oldSession = null;
        ProxySession replacement = null;
        try {
            AtomicStore store = new AtomicStore(root);
            JSONObject oldMarker = new JSONObject()
                    .put("active", true).put("ownedFingerprint", "old-fingerprint")
                    .put("preferences", new JSONObject());
            store.writeJson("proxy_session.json", oldMarker);
            oldSession = new ProxySession(store);

            oldSession.beginShutdown();
            try {
                oldSession.beginOperation();
                throw new AssertionError("shutting-down proxy accepted a new operation");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("shutting down"));
            }
            try {
                oldSession.activate(1080, ProxySession.newCredentials(), 0L);
                throw new AssertionError("shutting-down proxy accepted activation");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("shutting down"));
            }

            // Simulate the replacement coordinator's activation marker before
            // it claims the writer lease. Production writes use the same
            // AtomicStore commit lock through ProxySession.
            store.writeJson("proxy_session.json", new JSONObject()
                    .put("active", true).put("ownedFingerprint", "new-fingerprint")
                    .put("sessionNonce", "new-session")
                    .put("preferences", new JSONObject()));
            replacement = new ProxySession(new AtomicStore(root));
            JSONObject newMarker = new JSONObject()
                    .put("active", true).put("ownedFingerprint", "new-fingerprint")
                    .put("sessionNonce", "new-session")
                    .put("preferences", new JSONObject());
            assertTrue(replacement.persistRestoreIntent(newMarker, true));

            assertFalse("superseded restore intent overwrote replacement state",
                    oldSession.persistRestoreIntent(oldMarker, false));
            try {
                oldSession.markInactive("proxy_session.json", oldMarker);
                throw new AssertionError("superseded session marked replacement inactive");
            } catch (AtomicStore.StaleWriteException expected) {
                // The old lease was revoked before the replacement claimed it.
            }
            JSONObject durable = store.readJson("proxy_session.json");
            assertTrue(durable.getBoolean("active"));
            assertEquals("new-fingerprint", durable.getString("ownedFingerprint"));
        } finally {
            if (oldSession != null) oldSession.beginShutdown();
            if (replacement != null) replacement.beginShutdown();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void cancelledRunningUiCompletionCannotMarkSessionActive() throws Exception {
        File root = Files.createTempDirectory("exitfy-proxy-generation").toFile();
        try {
            ProxySession session = new ProxySession(new AtomicStore(root));
            long runningToken = session.beginOperation();
            session.cancelPending();
            assertFalse(session.markActiveIfCurrent(runningToken));
            assertTrue(session.markActiveIfCurrent(session.beginOperation()));
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void ownershipReadCannotSupersedePendingLifecycleMutation() throws Exception {
        File root = Files.createTempDirectory("exitfy-proxy-read-generation").toFile();
        try {
            ProxySession session = new ProxySession(new AtomicStore(root));
            long restoreToken = session.beginOperation();

            // A health ownership read may start after restoreForDisable() has
            // queued its UI mutation. The read must share the observed token,
            // not advance it or cancel the pending restore.
            assertEquals(restoreToken, session.beginReadOperation());
            assertTrue(session.markActiveIfCurrent(restoreToken));

            // A real lifecycle mutation still invalidates both the old
            // mutation token and any read that captured it.
            long replacementToken = session.beginOperation();
            assertFalse(session.markActiveIfCurrent(restoreToken));
            assertTrue(session.markActiveIfCurrent(replacementToken));
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void serializedCommandCancelsQueuedButWaitsForRunningMutation() throws Exception {
        RuntimeCoordinator.SerializedCommand queued = new RuntimeCoordinator.SerializedCommand(
                () -> "must-not-run");
        assertTrue(queued.cancelIfQueued());
        try {
            queued.call();
            throw new AssertionError("cancelled queued command executed");
        } catch (java.util.concurrent.CancellationException expected) {
            // Expected: the caller may safely report a busy queue.
        }

        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<String> result = new AtomicReference<>();
        RuntimeCoordinator.SerializedCommand running = new RuntimeCoordinator.SerializedCommand(() -> {
            entered.countDown();
            assertTrue(release.await(2, TimeUnit.SECONDS));
            return "committed";
        });
        Thread worker = new Thread(() -> {
            try {
                result.set(running.call());
            } catch (Exception error) {
                throw new AssertionError(error);
            }
        });
        worker.start();
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        assertTrue(running.isRunning());
        assertFalse(running.cancelIfQueued());
        release.countDown();
        worker.join(2_000L);
        assertFalse(worker.isAlive());
        assertEquals("committed", result.get());
    }

    @Test
    public void proxyGetCancellationIsGentleAndRejectsLateSockets() {
        assertFalse(RuntimePolicy.interruptPingOnCancel("PROXY_GET"));
        assertTrue(RuntimePolicy.interruptPingOnCancel("TCP"));
        assertTrue(RuntimePolicy.interruptPingOnCancel("HEALTH"));

        SocksHttpProbe probe = new SocksHttpProbe();
        SocksHttpProbe.Session cancelledSession = probe.beginSession();
        probe.cancelActive();
        SocksHttpProbe.Result result = probe.probe(
                1, "", "", 50L, cancelledSession);
        assertFalse(result.ok);
        assertEquals("cancelled", result.status);
        SocksHttpProbe.Session next = probe.beginSession();
        SocksHttpProbe.Session oldBatch = probe.beginChildSession(next);
        probe.closeSession(oldBatch);
        SocksHttpProbe.Session nextBatch = probe.beginChildSession(next);
        SocksHttpProbe.Result late = probe.probe(1, "", "", 50L, oldBatch);
        assertEquals("cancelled", late.status);
        // Closing an old batch must not invalidate a later batch or parent.
        assertTrue(probe.isSessionCurrent(next));
        assertTrue(probe.isSessionCurrent(nextBatch));
        probe.closeSession(nextBatch);
        probe.closeSession(next);
        probe.close();
    }

    @Test
    public void errorSanitizerRedactsCredentialsUrlsAndHwid() {
        String safe = ErrorSanitizer.clean("https://example.com/path?token=abc "
                + "vless://uuid@example.com:443#name {\"password\":\"secret\",\"hwid\":\"0123456789abcdef\"}");
        assertFalse(safe.contains("example.com/path"));
        assertFalse(safe.contains("uuid@example"));
        assertFalse(safe.contains("secret"));
        assertFalse(safe.contains("0123456789abcdef"));
        String escaped = ErrorSanitizer.clean("{\"password\":\"prefix\\\\\\\"still-secret suffix\"}");
        assertFalse(escaped.contains("still-secret"));
        assertFalse(escaped.contains("suffix"));
        String nativeError = ErrorSanitizer.clean(
                "SOCKS failed username=alice user:bob password=topsecret");
        assertFalse(nativeError.contains("alice"));
        assertFalse(nativeError.contains("bob"));
        assertFalse(nativeError.contains("topsecret"));
        String quotedNativeError = ErrorSanitizer.clean(
                "id=client-42 username=\"private user\" user='escaped\\' name' done");
        assertFalse(quotedNativeError.contains("client-42"));
        assertFalse(quotedNativeError.contains("private user"));
        assertFalse(quotedNativeError.contains("escaped"));
        assertFalse(quotedNativeError.contains(" name"));

        String multiword = ErrorSanitizer.clean(
                "password=top secret status=failed Authorization: Bearer abc def; retry=true");
        assertFalse(multiword.contains("top"));
        assertFalse(multiword.contains("secret"));
        assertFalse(multiword.contains("Bearer"));
        assertFalse(multiword.contains("abc"));
        assertFalse(multiword.contains("def"));
        assertFalse(multiword.contains("status=failed"));
        assertFalse(multiword.contains("retry=true"));

        String commaSecret = ErrorSanitizer.clean(
                "password=correct horse, battery staple status=retry");
        assertFalse(commaSecret.contains("correct"));
        assertFalse(commaSecret.contains("horse"));
        assertFalse(commaSecret.contains("battery"));
        assertFalse(commaSecret.contains("staple"));
        assertFalse(commaSecret.contains("status=retry"));

        String semicolonSecret = ErrorSanitizer.clean(
                "Authorization=Bearer abc;def status=retry");
        assertFalse(semicolonSecret.contains("Bearer"));
        assertFalse(semicolonSecret.contains("abc"));
        assertFalse(semicolonSecret.contains("def"));
        assertFalse(semicolonSecret.contains("status=retry"));

        String structured = ErrorSanitizer.clean(
                "{\"token\":123456,\"hwid\":{\"parts\":[\"hidden-tail\",42]},"
                        + "\"to\\u006ben\":[\"array-secret\"],\"user\":false,"
                        + "\"authorization\":null,\"ok\":true}");
        assertFalse(structured.contains("123456"));
        assertFalse(structured.contains("hidden-tail"));
        assertFalse(structured.contains("array-secret"));
        assertFalse(structured.contains("false"));
        assertFalse(structured.contains("null"));
        assertTrue(structured.contains("\"ok\":true"));

        String malformedScalar = ErrorSanitizer.clean(
                "{\"token\": top secret tail, \"ok\":true}");
        assertFalse(malformedScalar.contains("top"));
        assertFalse(malformedScalar.contains("secret"));
        assertFalse(malformedScalar.contains("tail"));
        assertFalse(malformedScalar.contains("\"ok\":true"));

        String mismatchedComposite = ErrorSanitizer.clean(
                "{\"token\":{\"a\":\"hidden\"] trailing-secret, \"ok\":true}");
        assertFalse(mismatchedComposite.contains("hidden"));
        assertFalse(mismatchedComposite.contains("trailing-secret"));
        assertFalse("malformed composite exposed an unproven following field",
                mismatchedComposite.contains("\"ok\":true"));

        String unclosedComposite = ErrorSanitizer.clean(
                "{\"token\":[\"hidden\", {\"nested\":1}, \"tail\", \"ok\":true}");
        assertFalse(unclosedComposite.contains("hidden"));
        assertFalse(unclosedComposite.contains("tail"));
        assertFalse(unclosedComposite.contains("\"ok\":true"));

        for (String malformedBoundary : new String[]{
                "{\"token\":\"hidden\" trailing-string-secret, \"ok\":true}",
                "{\"token\":{\"a\":1} trailing-object-secret, \"ok\":true}",
                "{\"token\":123 trailing-primitive-secret, \"ok\":true}"
        }) {
            String cleaned = ErrorSanitizer.clean(malformedBoundary);
            assertFalse(cleaned.contains("hidden"));
            assertFalse(cleaned.contains("secret"));
            assertFalse(cleaned.contains("\"ok\":true"));
        }

        String protocolSecrets = ErrorSanitizer.clean(
                "{\"auth_str\":\"hysteria-secret\",\"auth-str\":\"hyphen-secret\","
                        + "\"auth\":\"legacy-secret\",\"encryption\":\"vless-secret\","
                        + "\"pass\":\"socks-secret\",\"obfs\":{\"password\":\"cover-secret\"},"
                        + "\"obfs-password\":\"hy2-secret\",\"legacy_seed\":\"kcp-secret\","
                        + "\"path\":\"/private-key\",\"headers\":{\"Cookie\":\"session-secret\"},"
                        + "\"proxy-authorization\":\"bearer-secret\","
                        + "\"x-api-key\":\"api-secret\","
                        + "\"private_\\u006bey\":\"private-secret\","
                        + "\"pre_shared_key\":\"preshared-secret\","
                        + "\"psk\":\"psk-secret\",\"status\":\"failed\"}");
        assertFalse(protocolSecrets.contains("hysteria-secret"));
        assertFalse(protocolSecrets.contains("hyphen-secret"));
        assertFalse(protocolSecrets.contains("legacy-secret"));
        assertFalse(protocolSecrets.contains("vless-secret"));
        assertFalse(protocolSecrets.contains("socks-secret"));
        assertFalse(protocolSecrets.contains("cover-secret"));
        assertFalse(protocolSecrets.contains("hy2-secret"));
        assertFalse(protocolSecrets.contains("kcp-secret"));
        assertFalse(protocolSecrets.contains("private-key"));
        assertFalse(protocolSecrets.contains("session-secret"));
        assertFalse(protocolSecrets.contains("bearer-secret"));
        assertFalse(protocolSecrets.contains("api-secret"));
        assertFalse(protocolSecrets.contains("private-secret"));
        assertFalse(protocolSecrets.contains("preshared-secret"));
        assertFalse(protocolSecrets.contains("psk-secret"));
        assertTrue(protocolSecrets.contains("\"status\":\"failed\""));
        String plainProtocolSecret = ErrorSanitizer.clean(
                "auth_str=hidden auth-str=hidden2 encryption=hidden3 pass=hidden4 "
                        + "obfs-password=hidden5 legacy-seed=hidden6 path=/hidden7 "
                        + "proxy-authorization=hidden8 x-api-key=hidden9 status=failed");
        assertFalse(plainProtocolSecret.contains("hidden"));
        assertFalse(plainProtocolSecret.contains("status=failed"));

        String escapedProtocolKeys = ErrorSanitizer.clean(
                "{\"auth_\\u0073tr\":\"escaped-auth\","
                        + "\"proxy-\\u0061uthorization\":\"escaped-header\","
                        + "\"status\":\"kept\"}");
        assertFalse(escapedProtocolKeys.contains("escaped-auth"));
        assertFalse(escapedProtocolKeys.contains("escaped-header"));
        assertTrue(escapedProtocolKeys.contains("\"status\":\"kept\""));
        String malformedQuotedKey = ErrorSanitizer.clean(
                "{'password':'single-quoted-secret', 'status':'must-not-leak'}");
        assertFalse(malformedQuotedKey.contains("single-quoted-secret"));
        assertFalse(malformedQuotedKey.contains("must-not-leak"));
        String quotedTail = ErrorSanitizer.clean(
                "password=\"quoted-secret\" trailing-secret status=failed");
        assertFalse(quotedTail.contains("quoted-secret"));
        assertFalse(quotedTail.contains("trailing-secret"));
        assertFalse(quotedTail.contains("status=failed"));

        StringBuilder hugeError = new StringBuilder(2 * 1024 * 1024);
        hugeError.append("{\"password\":\"huge-secret-");
        while (hugeError.length() < 2 * 1024 * 1024) {
            hugeError.append("attacker-controlled-secret-");
        }
        String hugeCleaned = ErrorSanitizer.clean(hugeError.toString());
        assertFalse(hugeCleaned.contains("huge-secret"));
        assertFalse(hugeCleaned.contains("attacker-controlled-secret"));
        assertTrue(hugeCleaned.codePointCount(0, hugeCleaned.length()) <= 1024);
        assertTrue(hugeCleaned.getBytes(StandardCharsets.UTF_8).length <= 4096);

        StringBuilder surrogateBoundary = new StringBuilder(64 * 1024 + 2);
        while (surrogateBoundary.length() < 64 * 1024 - 1) surrogateBoundary.append('a');
        surrogateBoundary.appendCodePoint(0x1f642).append('z');
        String boundaryCleaned = ErrorSanitizer.clean(surrogateBoundary.toString());
        assertFalse(boundaryCleaned.endsWith("\ud83d"));
        assertTrue(boundaryCleaned.codePointCount(0, boundaryCleaned.length()) <= 1024);
        assertTrue(boundaryCleaned.getBytes(StandardCharsets.UTF_8).length <= 4096);
        assertEquals("abc", ErrorSanitizer.prefixUtf16("abc\ud83d\ude42z", 4));
        assertEquals("abc\ud83d\ude42", ErrorSanitizer.prefixUtf16("abc\ud83d\ude42z", 5));
        assertFalse(ErrorSanitizer.clean("visible\u0000\u001btext").contains("\u001b"));
        assertEquals("", ErrorSanitizer.clean(null));
    }

    @Test
    public void runtimePoliciesPreserveExternalProxyAndBlockQuarantinedCore() {
        assertTrue(RuntimePolicy.preserveCurrentTelegramProxy(
                RuntimePolicy.TELEGRAM_PROXY_CHANGED));
        assertFalse(RuntimePolicy.preserveCurrentTelegramProxy("nodes_cleared"));
        assertTrue(RuntimePolicy.reconnectBlocked(true));
        assertFalse(RuntimePolicy.reconnectBlocked(false));
    }

    @Test
    public void freshCoreInstallReconnectsOnlyWhenItCanBeLoadedInThisProcess() {
        assertTrue(RuntimePolicy.shouldReconnectAfterCoreInstall(true, true,
                null, CoreFamily.SING_BOX, CoreFamily.SING_BOX));
        assertTrue(RuntimePolicy.shouldReconnectAfterCoreInstall(true, true,
                null, CoreFamily.XRAY, CoreFamily.XRAY));
        assertFalse(RuntimePolicy.shouldReconnectAfterCoreInstall(true, true,
                null, CoreFamily.XRAY, CoreFamily.SING_BOX));
        assertFalse(RuntimePolicy.shouldReconnectAfterCoreInstall(true, true,
                CoreFamily.SING_BOX, CoreFamily.SING_BOX, CoreFamily.SING_BOX));
        assertFalse(RuntimePolicy.shouldReconnectAfterCoreInstall(false, true,
                null, CoreFamily.SING_BOX, CoreFamily.SING_BOX));
        assertFalse(RuntimePolicy.shouldReconnectAfterCoreInstall(true, false,
                null, CoreFamily.SING_BOX, CoreFamily.SING_BOX));
    }

    @Test
    public void installButtonRemainsRequiredUntilBothCoreFamiliesAreReady() {
        assertTrue(RuntimePolicy.needsCoreInstall(false, false));
        assertTrue(RuntimePolicy.needsCoreInstall(true, false));
        assertTrue(RuntimePolicy.needsCoreInstall(false, true));
        assertFalse(RuntimePolicy.needsCoreInstall(true, true));

        assertFalse(RuntimePolicy.mayRunAutomaticCoreMaintenance(false, false));
        assertTrue(RuntimePolicy.mayRunAutomaticCoreMaintenance(true, false));
        assertTrue(RuntimePolicy.mayRunAutomaticCoreMaintenance(false, true));
        assertTrue(RuntimePolicy.mayRunAutomaticCoreMaintenance(true, true));

        assertEquals(0, RuntimePolicy.readyCoreCount(false, false));
        assertEquals(1, RuntimePolicy.readyCoreCount(true, false));
        assertEquals(1, RuntimePolicy.readyCoreCount(false, true));
        assertEquals(2, RuntimePolicy.readyCoreCount(true, true));
    }

    @Test
    public void mappedCoreCanRestartWithoutItsInstallFile() {
        assertTrue(RuntimePolicy.shouldWaitForCorePreparation(null, false));
        assertFalse(RuntimePolicy.shouldWaitForCorePreparation(
                CoreFamily.SING_BOX, false));
        assertFalse(RuntimePolicy.shouldWaitForCorePreparation(
                CoreFamily.XRAY, false));
        assertFalse(RuntimePolicy.shouldWaitForCorePreparation(null, true));
    }

    @Test
    public void settingsRevisionAndLifecycleGenerationAreIndependent() {
        assertTrue(RuntimePolicy.settingsRevisionIsCurrent(2L, 2L));
        assertFalse(RuntimePolicy.settingsRevisionIsCurrent(2L, 1L));
        // A stale reconnect generation never invalidates a newer settings
        // revision; it is rejected by its own lifecycle gate.
        assertFalse(RuntimePolicy.callbackIsCurrent(true, true, 4L, 3L));
        assertTrue(RuntimePolicy.callbackIsCurrent(true, true, 4L, 4L));
        assertFalse(RuntimePolicy.callbackIsCurrent(false, true, 4L, 4L));
    }

    @Test
    public void queuedDisableInvalidatesLateActivationBeforeCoordinatorAppliesIt() {
        RuntimeRevisionGate gate = new RuntimeRevisionGate();
        long enableRevision = gate.requestSettingsChange();
        RuntimeOperationToken starting = gate.token(gate.advanceLifecycle(), enableRevision);
        assertTrue(gate.isCurrent(starting, true, true));

        // updateSettings(false) advances this revision synchronously, before
        // its applySettings task can wait behind StartCore on the coordinator.
        long disableRevision = gate.requestSettingsChange();
        assertFalse(gate.isCurrent(starting, true, true));
        RuntimeOperationToken disabled = gate.token(gate.advanceLifecycle(), disableRevision);
        assertFalse(gate.isCurrent(disabled, true, false));
    }

    @Test
    public void netSameRapidSettingsUpdateStillReconcilesInterruptedLifecycle() {
        SettingsModel enabled = new SettingsModel(true, 0, "", 6,
                SettingsModel.PING_PROXY_GET);
        SettingsModel disabled = SettingsModel.defaults();
        assertTrue(RuntimePolicy.settingsNeedLifecycleReconcile(
                enabled, enabled, RuntimeState.STARTING));
        assertTrue(RuntimePolicy.settingsNeedLifecycleReconcile(
                enabled, enabled, RuntimeState.STOPPED));
        assertFalse(RuntimePolicy.settingsNeedLifecycleReconcile(
                enabled, enabled, RuntimeState.RUNNING));
        assertTrue(RuntimePolicy.settingsNeedLifecycleReconcile(
                disabled, disabled, RuntimeState.STOPPING));
        assertFalse(RuntimePolicy.settingsNeedLifecycleReconcile(
                disabled, disabled, RuntimeState.STOPPED));
    }

    @Test
    public void cancelledOrSupersededProxyProbeCannotStopAnotherCoreGeneration() {
        RuntimeRevisionGate gate = new RuntimeRevisionGate();
        long revision = gate.requestSettingsChange();
        RuntimeOperationToken probe = gate.token(gate.advanceLifecycle(), revision);
        long ping = 7L;
        assertTrue(RuntimePolicy.proxyProbeMayStopCore(true, true, ping, ping,
                gate.generation(), probe.generation,
                gate.settingsRevision(), probe.settingsRevision));

        assertFalse(RuntimePolicy.proxyProbeMayStopCore(true, true, ping + 1L, ping,
                gate.generation(), probe.generation,
                gate.settingsRevision(), probe.settingsRevision));
        gate.advanceLifecycle();
        assertFalse(RuntimePolicy.proxyProbeMayStopCore(true, true, ping, ping,
                gate.generation(), probe.generation,
                gate.settingsRevision(), probe.settingsRevision));
    }

    @Test
    public void reconnectCoalescingPromotesConfigChangeOverNetworkFlapping() {
        ReconnectRequestGate gate = new ReconnectRequestGate();
        assertTrue(gate.offer("network_available", false));
        ReconnectRequestGate.Request network = gate.beginNext();
        assertEquals("network_available", network.reason);

        assertFalse(gate.offer("node_selected", true));
        assertFalse(gate.offer("network_lost", false));
        assertTrue(gate.complete(network));
        ReconnectRequestGate.Request promoted = gate.beginNext();
        assertEquals("node_selected", promoted.reason);
        assertEquals(2, promoted.priority);
        assertFalse(gate.offer("subscription_refresh", true));
        assertTrue(gate.complete(promoted));
        ReconnectRequestGate.Request latestConfig = gate.beginNext();
        assertEquals("subscription_refresh", latestConfig.reason);
        assertFalse(gate.complete(latestConfig));

        assertTrue(gate.offer("app_resume", false));
        assertEquals("app_resume", gate.beginNext().reason);
    }

    @Test
    public void importAdmissionIsHeldUntilQueuedApplyCompletes() {
        ImportRequestGate gate = new ImportRequestGate();
        ImportRequestGate.Ticket first = gate.tryStart(10L, 0);
        assertNotNull(first);
        assertNull(gate.tryStart(10L, 0));

        AtomicReference<Runnable> queuedApply = new AtomicReference<>();
        AtomicInteger applied = new AtomicInteger();
        assertTrue(gate.enqueueApply(
                first, task -> queuedApply.compareAndSet(null, task),
                applied::incrementAndGet));

        // Worker parsing has finished and coordinator apply is queued. The
        // second import must still be BUSY; the old ordering released here.
        assertNull(gate.tryStart(11L, 2));
        assertTrue(gate.settingsAreCurrent(first, 10L, 0));
        queuedApply.get().run();
        assertEquals(1, applied.get());

        ImportRequestGate.Ticket second = gate.tryStart(11L, 2);
        assertNotNull(second);
        assertFalse(gate.isLatest(first));
        assertTrue(gate.settingsAreCurrent(second, 11L, 2));
        gate.finish(second);
    }

    @Test
    public void rejectedImportApplyReleasesAdmissionWithoutRunningMutation() {
        ImportRequestGate gate = new ImportRequestGate();
        ImportRequestGate.Ticket rejected = gate.tryStart(7L, 1);
        AtomicInteger applied = new AtomicInteger();

        assertFalse(gate.enqueueApply(
                rejected, task -> false, applied::incrementAndGet));
        assertEquals(0, applied.get());
        assertNotNull("rejected coordinator enqueue left import permanently BUSY",
                gate.tryStart(8L, 1));
    }

    @Test
    public void unloadCancellationInvalidatesQueuedApplyWithoutReleasingReplacement() {
        ImportRequestGate gate = new ImportRequestGate();
        ImportRequestGate.Ticket unloading = gate.tryStart(5L, 0);
        AtomicReference<Runnable> queuedApply = new AtomicReference<>();
        AtomicInteger applied = new AtomicInteger();
        assertTrue(gate.enqueueApply(
                unloading, task -> queuedApply.compareAndSet(null, task),
                () -> {
                    if (gate.isLatest(unloading)) applied.incrementAndGet();
                }));

        // unload() cancels admission before shutting down the worker/executor.
        gate.cancel();
        ImportRequestGate.Ticket replacement = gate.tryStart(6L, 3);
        assertNotNull(replacement);

        // A coordinator task that escaped shutdownNow is stale. Its finally
        // must neither mutate state nor release the newer import's admission.
        queuedApply.get().run();
        assertEquals(0, applied.get());
        assertTrue(gate.isLatest(replacement));
        assertNull(gate.tryStart(7L, 3));
        gate.finish(replacement);
        assertNotNull(gate.tryStart(7L, 3));
    }

    @Test
    public void manualRefreshReplacementKeepsRequiredStartOnFailure() {
        RefreshCompletionGate gate = new RefreshCompletionGate();
        RuntimeOperationToken lifecycle = new RuntimeOperationToken(4L, 9L);
        RefreshCompletionGate.Ticket requiredRefresh = gate.begin(true, lifecycle);
        assertTrue(gate.isCurrent(requiredRefresh));
        assertTrue(requiredRefresh.requiredForStart);

        RefreshCompletionGate.Ticket manualReplacement = gate.begin(
                false, new RuntimeOperationToken(4L, 9L));
        assertTrue(manualReplacement.requiredForStart);
        assertFalse(gate.claim(requiredRefresh));
        // applySubscriptionRefresh takes this ticket flag into its failure
        // branch, transitions STARTING to ERROR, and schedules reconnect.
        assertTrue(gate.claim(manualReplacement));
        assertFalse(gate.claim(manualReplacement));
    }

    @Test
    public void manualRefreshReplacementTimeoutRetainsRequiredStartAndWinsOnce() {
        RefreshCompletionGate gate = new RefreshCompletionGate();
        RuntimeOperationToken lifecycle = new RuntimeOperationToken(7L, 12L);
        RefreshCompletionGate.Ticket requiredRefresh = gate.begin(true, lifecycle);
        RefreshCompletionGate.Ticket replacement = gate.begin(false, lifecycle);

        assertTrue(replacement.requiredForStart);
        assertTrue(gate.isCurrent(replacement));
        assertTrue(gate.claim(replacement)); // timeout owns the terminal failure
        assertFalse(gate.claim(replacement)); // late HTTP worker is ignored
        assertFalse(gate.claim(requiredRefresh));

        RefreshCompletionGate nextLifecycleGate = new RefreshCompletionGate();
        nextLifecycleGate.begin(true, lifecycle);
        RefreshCompletionGate.Ticket newLifecycle = nextLifecycleGate.begin(
                false, new RuntimeOperationToken(8L, 12L));
        assertFalse(newLifecycle.requiredForStart);
    }

    @Test
    public void refreshDeadlineIsTerminalAndQueuedSuccessCannotWinAfterIt() {
        RuntimeOperationToken lifecycle = new RuntimeOperationToken(9L, 14L);
        RefreshCompletionGate gate = new RefreshCompletionGate();
        RefreshCompletionGate.Ticket queuedBeforeDeadline = gate.begin(
                true, lifecycle, 3, 1_000L);

        // The worker may have queued a success before D, but admission happens
        // on the coordinator. Releasing that coordinator at or after D must
        // not let success claim the ticket.
        assertFalse(gate.claimAt(queuedBeforeDeadline, 1_000L));
        assertTrue(gate.expireAt(queuedBeforeDeadline, 1_000L));
        assertTrue(gate.isTerminal(queuedBeforeDeadline));
        assertFalse(gate.claimAt(queuedBeforeDeadline, 1_001L));
        assertFalse(gate.expireAt(queuedBeforeDeadline, 1_001L));

        RefreshCompletionGate beforeDeadline = new RefreshCompletionGate();
        RefreshCompletionGate.Ticket timely = beforeDeadline.begin(
                false, lifecycle, 3, 2_000L);
        assertTrue(beforeDeadline.claimAt(timely, 1_999L));
        assertTrue(beforeDeadline.isTerminal(timely));
        assertFalse(beforeDeadline.expireAt(timely, 2_000L));
    }

    @Test
    public void refreshContextClaimRejectsAnAlreadyExpiredTicket() {
        RefreshCompletionGate gate = new RefreshCompletionGate();
        RuntimeOperationToken lifecycle = new RuntimeOperationToken(10L, 15L);
        long past = System.nanoTime() - 1L;
        RefreshCompletionGate.Ticket expired = gate.begin(
                false, lifecycle, 4, past);

        assertFalse(gate.claimIfCurrent(expired, lifecycle, 4, true));
        assertTrue(gate.expireAt(expired, System.nanoTime()));
        assertTrue(gate.isTerminal(expired));
    }

    @Test
    public void staleDeadlineAbandonsManualAttemptForLatestSettingsRevision() {
        ManualRefreshIntentGate intent = new ManualRefreshIntentGate();
        assertTrue(intent.request());
        assertTrue(intent.beginRunner());
        long attempt = intent.claim();
        assertTrue(attempt != 0L);

        RuntimeOperationToken oldSettings = new RuntimeOperationToken(12L, 20L);
        RefreshCompletionGate gate = new RefreshCompletionGate();
        RefreshCompletionGate.Ticket expired = gate.begin(
                false, oldSettings, 0, 100L);
        assertTrue(gate.expireAt(expired, 100L));

        RuntimeOperationToken newSettings = new RuntimeOperationToken(12L, 21L);
        if (expired.contextIsCurrent(newSettings, 0, true)) {
            intent.complete(attempt);
        } else {
            intent.abandon(attempt);
        }

        assertTrue("enabled settings change lost the manual refresh intent",
                intent.isPending());
        assertTrue(intent.schedulePending());
        assertTrue(intent.beginRunner());
        assertTrue("latest revision cannot reclaim the refresh intent",
                intent.claim() != 0L);
    }

    @Test
    public void disabledRequiredRefreshCannotPublishFailureOrReconnect() {
        RefreshCompletionGate gate = new RefreshCompletionGate();
        RuntimeOperationToken enabled = new RuntimeOperationToken(12L, 30L);
        RefreshCompletionGate.Ticket refresh = gate.begin(true, enabled, 0);
        AtomicInteger uiMutations = new AtomicInteger();
        AtomicInteger reconnects = new AtomicInteger();

        RuntimeOperationToken disabled = new RuntimeOperationToken(13L, 31L);
        if (gate.claimIfCurrent(refresh, disabled, 0, true)) {
            uiMutations.incrementAndGet();
            reconnects.incrementAndGet();
        }
        gate.cancel();
        assertFalse(gate.claimIfCurrent(refresh, disabled, 0, true));
        assertEquals(0, uiMutations.get());
        assertEquals(0, reconnects.get());
    }

    @Test
    public void manualRefreshFromPreviousProviderCannotAnnounce() {
        RefreshCompletionGate gate = new RefreshCompletionGate();
        RuntimeOperationToken providerA = new RuntimeOperationToken(5L, 18L);
        RefreshCompletionGate.Ticket refresh = gate.begin(false, providerA, 0);
        AtomicInteger announcements = new AtomicInteger();

        RuntimeOperationToken providerB = new RuntimeOperationToken(6L, 19L);
        if (gate.claimIfCurrent(refresh, providerB, 1, true)) {
            announcements.incrementAndGet();
        }
        assertEquals(0, announcements.get());
        assertFalse(refresh.contextIsCurrent(providerB, 1, true));
    }

    @Test
    public void settingsApplyRevokesRefreshQueuedAfterEagerCancellation() {
        RefreshCompletionGate gate = new RefreshCompletionGate();
        gate.cancel(); // updateSettings() eager cancellation

        // A manual command already ahead of applySettings on the coordinator
        // can now start with the new revision but the old SettingsModel/HWID.
        RuntimeOperationToken requestedRevision = new RuntimeOperationToken(4L, 21L);
        RefreshCompletionGate.Ticket slipped = gate.begin(
                false, requestedRevision, 0);
        assertTrue(gate.isPending(slipped));

        gate.cancel(); // applySettings() ordering-boundary cancellation
        assertFalse(gate.isPending(slipped));
        assertFalse(gate.claimIfCurrent(
                slipped, requestedRevision, 0, true));
    }

    @Test
    public void queuedRefreshCannotOpenOldProviderBeforeRequestedSettingsAreApplied() {
        RuntimeRevisionGate revisions = new RuntimeRevisionGate();
        AppliedSettingsGate applied = new AppliedSettingsGate();
        AtomicInteger httpOpens = new AtomicInteger();
        AtomicReference<String> transmittedContext = new AtomicReference<>();

        RuntimeOperationToken initial = revisions.currentToken();
        assertTrue(applied.allows(initial, true, revisions.settingsRevision()));

        // updateSettings() publishes the requested revision synchronously, but
        // its coordinator apply is still queued behind the manual refresh.
        long requested = revisions.requestSettingsChange();
        RuntimeOperationToken queuedRefresh = revisions.currentToken();
        assertTrue(applied.hasPendingApply(revisions.settingsRevision()));
        assertTrue(applied.shouldDeferManualRefresh(
                true, true, revisions.settingsRevision()));
        if (applied.allows(queuedRefresh, true, revisions.settingsRevision())) {
            httpOpens.incrementAndGet();
            transmittedContext.set("old-provider/old-hwid");
        }
        assertEquals("queued refresh opened an old URL", 0, httpOpens.get());
        assertNull(transmittedContext.get());

        // The one deferred coordinator task may start only after settings and
        // their provider/HWID snapshot have reached the same revision.
        applied.markApplied(requested);
        RuntimeOperationToken afterApply = revisions.currentToken();
        if (applied.allows(afterApply, true, revisions.settingsRevision())) {
            httpOpens.incrementAndGet();
            transmittedContext.set("new-provider/new-hwid");
        }
        assertEquals(1, httpOpens.get());
        assertEquals("new-provider/new-hwid", transmittedContext.get());

        // A disable request creates another unapplied revision and again closes
        // admission immediately, before its coordinator task can run. Unlike an
        // enabled provider/HWID update, disable also drops the deferred command
        // instead of starting network work after its apply task.
        revisions.requestSettingsChange();
        assertFalse(applied.shouldDeferManualRefresh(
                true, false, revisions.settingsRevision()));
        if (applied.allows(revisions.currentToken(), true,
                revisions.settingsRevision())) {
            httpOpens.incrementAndGet();
        }
        assertEquals("disable request allowed a stale HTTP open", 1, httpOpens.get());
        assertFalse(applied.allows(afterApply, false, revisions.settingsRevision()));
    }

    @Test
    public void manualRefreshIntentSurvivesSuccessiveEnabledSettingsAndFlushesOnce() {
        RuntimeRevisionGate revisions = new RuntimeRevisionGate();
        AppliedSettingsGate applied = new AppliedSettingsGate();
        ManualRefreshIntentGate refresh = new ManualRefreshIntentGate();
        AtomicInteger starts = new AtomicInteger();

        assertTrue(refresh.request());
        assertFalse("second click must coalesce into the same intent", refresh.request());
        assertTrue(refresh.beginRunner());

        long revisionA = revisions.requestSettingsChange();
        long revisionB = revisions.requestSettingsChange();
        long revisionC = revisions.requestSettingsChange();
        assertTrue(revisionA < revisionB && revisionB < revisionC);
        assertTrue(applied.hasPendingApply(revisions.settingsRevision()));
        assertTrue("pending intent was dropped by an intermediate revision", refresh.isPending());

        // Stale A/B apply tasks return without consuming the intent. Only the
        // latest C boundary schedules one runner and transmits C's context.
        applied.markApplied(revisionC);
        assertTrue(refresh.schedulePending());
        assertFalse("latest apply scheduled duplicate refresh runners",
                refresh.schedulePending());
        assertTrue(refresh.beginRunner());
        RuntimeOperationToken current = revisions.currentToken();
        long attempt = refresh.claim();
        if (applied.allows(current, true, revisions.settingsRevision()) && attempt != 0L) {
            starts.incrementAndGet();
            refresh.complete(attempt);
        }
        assertEquals(1, starts.get());
        assertFalse(refresh.isPending());
        assertFalse("completed intent was flushed twice", refresh.schedulePending());
    }

    @Test
    public void enabledSettingsCancellationRequeuesActiveManualRefreshForLatestApply() {
        ManualRefreshIntentGate refresh = new ManualRefreshIntentGate();
        assertTrue(refresh.request());
        assertTrue(refresh.beginRunner());
        long oldAttempt = refresh.claim();
        assertTrue(oldAttempt != 0L);

        // updateSettings(enabled) cancels the old URL/HWID request, but the
        // user intent remains pending for the latest settings boundary.
        refresh.abandon(oldAttempt);
        assertTrue(refresh.isPending());
        assertTrue(refresh.schedulePending());
        assertTrue(refresh.beginRunner());
        long latestAttempt = refresh.claim();
        assertTrue(latestAttempt != 0L && latestAttempt != oldAttempt);

        // A stale completion from the cancelled request cannot consume the
        // replacement attempt or clear the pending intent.
        refresh.complete(oldAttempt);
        assertTrue(refresh.isPending());
        refresh.complete(latestAttempt);
        assertFalse(refresh.isPending());
    }

    @Test
    public void disableClearsDeferredManualRefreshAndEscapedRunnerIsHarmless() {
        ManualRefreshIntentGate refresh = new ManualRefreshIntentGate();
        assertTrue(refresh.request());
        assertTrue(refresh.beginRunner());
        long cancelledAttempt = refresh.claim();
        assertTrue(cancelledAttempt != 0L);
        refresh.clear(); // synchronous disabled-settings publication

        assertFalse("disable left a queued network intent", refresh.isPending());
        assertFalse("runner which escaped cancellation started after disable",
                refresh.beginRunner());
        refresh.complete(cancelledAttempt);
        assertFalse("stale completion resurrected disabled refresh", refresh.isPending());
        assertFalse(refresh.schedulePending());
    }

    @Test
    public void networkCancelledManualRefreshResumesExactlyOnceAtRunning() {
        ManualRefreshIntentGate refresh = new ManualRefreshIntentGate();
        assertTrue(refresh.request());
        assertTrue(refresh.beginRunner());
        long cancelled = refresh.claim();

        // onLost/reconnect cancellation preserves the user intent but must not
        // schedule it while the network is still unavailable.
        refresh.abandon(cancelled);
        assertTrue(refresh.isPending());

        // RuntimeCoordinator calls schedulePendingManualRefresh only when a
        // connection actually publishes RUNNING. Repeated publications/flaps
        // cannot enqueue a second runner.
        assertTrue(refresh.schedulePending());
        assertFalse(refresh.schedulePending());
        assertTrue(refresh.beginRunner());
        long resumed = refresh.claim();
        assertTrue(resumed != 0L);
        assertFalse(refresh.beginRunner());
        refresh.complete(resumed);
        assertFalse(refresh.isPending());

        // Disable/unload remains terminal and cannot resurrect the old intent.
        refresh.clear();
        refresh.abandon(cancelled);
        assertFalse(refresh.isPending());
        assertFalse(refresh.schedulePending());
    }

    @Test
    public void requiredEmptyCacheRefreshConsumesPendingManualIntent() {
        ManualRefreshIntentGate refresh = new ManualRefreshIntentGate();
        assertTrue(refresh.request());
        assertTrue(refresh.beginRunner());
        long interrupted = refresh.claim();
        refresh.abandon(interrupted);

        // A required refresh for an empty cache claims the pending intent and
        // becomes its single authoritative network operation.
        long attachedToRequired = refresh.claim();
        assertTrue(attachedToRequired != 0L);
        assertFalse(refresh.schedulePending());
        refresh.complete(attachedToRequired);
        assertFalse(refresh.isPending());
    }

    @Test
    public void settingsDuringProxyGetChooseExactlyOneLifecycleOwner() {
        SettingsModel running = new SettingsModel(true, 0, "old", 6,
                SettingsModel.PING_PROXY_GET);
        SettingsModel nonLifecycle = new SettingsModel(true, 0, "new", 6,
                SettingsModel.PING_TCP);
        assertFalse(RuntimePolicy.connectionSettingsChanged(running, nonLifecycle));
        assertTrue(RuntimePolicy.shouldQueueSettingsProbeRestore(
                false, true, 1L, false, false));
        assertFalse(RuntimePolicy.shouldQueueSettingsProbeRestore(
                false, false, 0L, false, false));
        // A rapid second setting arrives after cancelPing changed PingKind to
        // NONE; the queued/active context still requires the latest restore.
        assertTrue(RuntimePolicy.shouldQueueSettingsProbeRestore(
                false, false, 0L, false, true));
        assertFalse(RuntimePolicy.settingsNeedLifecycleReconcile(
                running, nonLifecycle, RuntimeState.STOPPED, true));
        RuntimeRevisionGate revisions = new RuntimeRevisionGate();
        RuntimeOperationToken firstRestore = revisions.token(
                revisions.generation(), revisions.requestSettingsChange());
        RuntimeOperationToken latestRestore = revisions.token(
                revisions.generation(), revisions.requestSettingsChange());
        assertFalse(revisions.isCurrent(firstRestore, true, true));
        assertTrue(revisions.isCurrent(latestRestore, true, true));

        SettingsModel disabled = new SettingsModel(false, 0, "old", 6,
                SettingsModel.PING_PROXY_GET);
        SettingsModel providerChanged = new SettingsModel(true, 1, "old", 6,
                SettingsModel.PING_PROXY_GET);
        assertTrue(RuntimePolicy.connectionSettingsChanged(running, disabled));
        assertTrue(RuntimePolicy.connectionSettingsChanged(running, providerChanged));
        assertFalse(RuntimePolicy.shouldQueueSettingsProbeRestore(
                true, true, 1L, true, true));
        assertTrue(RuntimePolicy.settingsNeedLifecycleReconcile(
                running, providerChanged, RuntimeState.STOPPED, true));

        // The stale probe generation may never stop a core started by the
        // lifecycle owner selected above.
        assertFalse(RuntimePolicy.proxyProbeMayStopCore(
                true, true, 9L, 8L, 4L, 4L, 22L, 22L));
    }

    @Test
    public void normalDisableClearsGuardWhileProbeAndLateCompensationRetainIt() {
        ActivationGuardState<Object> guards = new ActivationGuardState<>();
        Object probeSnapshot = new Object();
        guards.restored(probeSnapshot, true);
        assertSame(probeSnapshot, guards.current());

        guards.disabled();
        assertNull(guards.current());

        Object lateCompensation = new Object();
        guards.restored(lateCompensation, true);
        assertSame(lateCompensation, guards.current());
        guards.restored(new Object(), false);
        assertNull(guards.current());
    }

    @Test
    public void pluginSettingPersistenceUsesIndependentKeyRevisions() {
        ArrayDeque<Runnable> pluginsQueue = new ArrayDeque<>();
        KeyedRevisionGate revisions = new KeyedRevisionGate();
        AtomicInteger writes = new AtomicInteger();
        revisions.record("enabled", 4L);
        PluginSettingDispatcher.dispatch(4L, () -> revisions.current("enabled"),
                pluginsQueue::addLast, writes::incrementAndGet);
        assertEquals(0, writes.get());
        assertEquals(1, pluginsQueue.size());

        // A later request for another key must not cancel this write.
        revisions.record("provider_id", 5L);
        pluginsQueue.removeFirst().run();
        assertEquals(1, writes.get());

        PluginSettingDispatcher.dispatch(4L, () -> revisions.current("enabled"),
                pluginsQueue::addLast, writes::incrementAndGet);
        revisions.record("enabled", 6L);
        pluginsQueue.removeFirst().run();
        assertEquals(1, writes.get());

        // An older scheduling path cannot move a key revision backwards.
        revisions.record("enabled", 5L);
        assertEquals(6L, revisions.current("enabled"));
    }

    @Test
    public void queuedPluginSettingWriteIsDroppedAfterUnloadLifecycle() {
        ArrayDeque<Runnable> pluginsQueue = new ArrayDeque<>();
        AtomicLong revision = new AtomicLong(7L);
        AtomicLong lifecycle = new AtomicLong(3L);
        AtomicBoolean loaded = new AtomicBoolean(true);
        AtomicInteger oldCoordinatorWrites = new AtomicInteger();
        long expectedLifecycle = lifecycle.get();

        PluginSettingDispatcher.dispatch(7L, revision::get,
                loaded::get,
                pluginsQueue::addLast, oldCoordinatorWrites::incrementAndGet);
        assertEquals(1, pluginsQueue.size());

        // Ordinary reconnect/start/stop generations do not supersede a
        // preference request from this same coordinator.
        lifecycle.incrementAndGet();
        pluginsQueue.removeFirst().run();
        assertEquals(1, oldCoordinatorWrites.get());

        PluginSettingDispatcher.dispatch(7L, revision::get, loaded::get,
                pluginsQueue::addLast, oldCoordinatorWrites::incrementAndGet);
        // The host plugins queue can outlive the DEX coordinator. Even if a
        // replacement starts with the same revision, the old closure must not
        // write into that replacement's Python preferences.
        loaded.set(false);
        pluginsQueue.removeFirst().run();
        assertEquals(1, oldCoordinatorWrites.get());
    }

    @Test
    public void probeAndDnsExecutorsStayBoundedUnderPermanentBlocking() throws Exception {
        ThreadPoolExecutor dns = RuntimeExecutors.bounded(4, 8, "test-dns");
        ThreadPoolExecutor probes = RuntimeExecutors.bounded(4, 64, "test-probe");
        CountDownLatch dnsEntered = new CountDownLatch(4);
        CountDownLatch probeEntered = new CountDownLatch(4);
        CountDownLatch release = new CountDownLatch(1);
        try {
            for (int index = 0; index < 4; index++) {
                dns.execute(() -> awaitIgnoringInterrupts(dnsEntered, release));
                probes.execute(() -> awaitIgnoringInterrupts(probeEntered, release));
            }
            assertTrue(dnsEntered.await(2, TimeUnit.SECONDS));
            assertTrue(probeEntered.await(2, TimeUnit.SECONDS));

            List<Future<?>> dnsQueued = new ArrayList<>();
            int rejectedDns = 0;
            for (int index = 0; index < 100; index++) {
                try {
                    dnsQueued.add(dns.submit(() -> null));
                } catch (RejectedExecutionException expected) {
                    rejectedDns++;
                }
            }
            assertEquals(8, dns.getQueue().size());
            assertTrue(rejectedDns > 0);
            for (Future<?> future : dnsQueued) {
                RuntimeExecutors.cancelAndRemove(dns, future);
            }
            assertEquals(0, dns.getQueue().size());

            // Model hundreds of rapidly replaced 50-node pages while all four
            // workers are stuck. The submitted FutureTask is the actual queued
            // object, so cancellation removes it instead of leaving an
            // ExecutorCompletionService QueueingFuture behind.
            for (int page = 0; page < 100; page++) {
                BlockingQueue<Future<Integer>> completion = new LinkedBlockingQueue<>();
                List<Future<Integer>> pageTasks = new ArrayList<>();
                for (int node = 0; node < 50; node++) {
                    pageTasks.add(RuntimeExecutors.submitCompletion(
                            probes, completion, () -> 1, -1));
                }
                assertTrue(probes.getQueue().size() <= 64);
                for (Future<Integer> task : pageTasks) {
                    RuntimeExecutors.cancelAndRemove(probes, task);
                }
                assertEquals(0, probes.getQueue().size());
            }
            assertTrue(dns.getLargestPoolSize() <= 4);
            assertTrue(probes.getLargestPoolSize() <= 4);

            long started = System.nanoTime();
            dns.shutdownNow();
            probes.shutdownNow();
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertTrue("bounded executor shutdown blocked for " + elapsedMillis + " ms",
                    elapsedMillis < 500L);
        } finally {
            release.countDown();
            dns.shutdownNow();
            probes.shutdownNow();
            dns.awaitTermination(2, TimeUnit.SECONDS);
            probes.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    @Test
    public void replacingPingExecutorRetainsOnlyLatestQueuedPage() throws Exception {
        ScheduledThreadPoolExecutor ping = RuntimeExecutors.replacing("test-ping");
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            Future<?> running = ping.submit(() -> awaitIgnoringInterrupts(entered, release));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            running.cancel(false); // Proxy GET remains in native-safe cleanup.

            Future<?> latest = null;
            for (int page = 0; page < 1_000; page++) {
                if (latest != null) latest.cancel(false);
                latest = ping.submit(() -> { });
                assertTrue(ping.getQueue().size() <= 1);
            }
            if (latest != null) latest.cancel(false);
            assertEquals(0, ping.getQueue().size());
            assertTrue(ping.getLargestPoolSize() <= 1);
        } finally {
            release.countDown();
            ping.shutdownNow();
            ping.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    @Test
    public void coreExecutorRejectsSpamBeyondOnePendingOperation() throws Exception {
        ThreadPoolExecutor core = RuntimeExecutors.bounded(1, 1, "test-core");
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            core.execute(() -> awaitIgnoringInterrupts(entered, release));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            core.execute(() -> { });
            try {
                core.execute(() -> { });
                throw new AssertionError("saturated core executor accepted unbounded work");
            } catch (RejectedExecutionException expected) {
                assertEquals(1, core.getQueue().size());
            }
        } finally {
            release.countDown();
            core.shutdownNow();
            core.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    private static void awaitIgnoringInterrupts(CountDownLatch entered,
                                                CountDownLatch release) {
        entered.countDown();
        while (release.getCount() != 0L) {
            try {
                release.await();
            } catch (InterruptedException ignored) {
                // Model native DNS/Proxy GET code which cannot be interrupted.
            }
        }
    }

    @Test
    public void reconnectBackoffIsExactAndCapsAtOneMinute() {
        long[] expected = {1L, 2L, 5L, 10L, 30L, 60L, 60L, 60L};
        for (int attempt = 0; attempt < expected.length; attempt++) {
            assertEquals(expected[attempt], ReconnectBackoff.delaySeconds(attempt));
        }
    }

    @Test
    public void dashboardRefreshesAreThrottledAfterFirstDelivery() {
        long interval = DashboardRefreshThrottle.INTERVAL_NANOS;
        long completedAt = TimeUnit.SECONDS.toNanos(10L);
        assertEquals(0L, DashboardRefreshThrottle.delayNanos(
                completedAt, 0L));
        assertEquals(interval, DashboardRefreshThrottle.delayNanos(
                completedAt, completedAt));
        assertEquals(interval / 2L, DashboardRefreshThrottle.delayNanos(
                completedAt + interval / 2L, completedAt));
        assertEquals(0L, DashboardRefreshThrottle.delayNanos(
                completedAt + interval, completedAt));
    }

    @Test
    public void explicitReconnectResetsBackoffButNetworkFlappingDoesNot() {
        ReconnectBackoff backoff = new ReconnectBackoff();
        assertFalse(ReconnectBackoff.resetsForReason("network_available"));
        assertFalse(ReconnectBackoff.resetsForReason("network_lost"));
        assertTrue(ReconnectBackoff.resetsForReason("manual"));
        assertTrue(ReconnectBackoff.resetsForReason("node_selected"));

        long[] expected = {1L, 2L, 5L, 10L, 30L, 60L, 60L};
        for (long delay : expected) {
            assertEquals(delay, backoff.nextDelaySeconds(false));
        }

        assertEquals(60L, backoff.nextDelaySeconds(
                ReconnectBackoff.resetsForReason("network_available")));
        assertEquals(1L, backoff.nextDelaySeconds(
                ReconnectBackoff.resetsForReason("manual")));
        assertEquals(2L, backoff.nextDelaySeconds(false));
    }

    @Test
    public void restartIsRequiredOnlyWhenAnotherCoreFamilyIsAlreadyLoaded() {
        assertFalse(CoreProcessState.requiresRestart(null, CoreFamily.XRAY));
        assertFalse(CoreProcessState.requiresRestart(CoreFamily.XRAY, CoreFamily.XRAY));
        assertTrue(CoreProcessState.requiresRestart(CoreFamily.SING_BOX, CoreFamily.XRAY));
        assertTrue(CoreProcessState.requiresRestart(CoreFamily.XRAY, CoreFamily.SING_BOX));
    }


    @Test
    public void aRefreshThatChangesNothingDoesNotReconnect() throws Exception {
        // Every successful refresh used to reconnect. A source that never
        // refreshes keeps the provider stale, so the next start refreshed
        // again and the connection dropped over and over.
        String uri = "vless://33333333-3333-3333-3333-333333333333@edge.example:443"
                + "?security=reality&pbk=" + "a".repeat(43) + "&sni=edge.example&fp=chrome";
        ProtocolParser.Node before = ProtocolParser.parse(uri + "#Server");
        ProtocolParser.Node renamed = ProtocolParser.parse(uri + "#Server%20renamed");
        ProtocolParser.Node moved = ProtocolParser.parse(
                uri.replace("edge.example:443", "other.example:443") + "#Server");

        assertFalse(RuntimePolicy.activeConfigurationChanged(before, before));
        assertFalse(RuntimePolicy.activeConfigurationChanged(before, renamed));
        assertTrue(RuntimePolicy.activeConfigurationChanged(before, moved));
        assertTrue(RuntimePolicy.activeConfigurationChanged(null, before));
        assertTrue(RuntimePolicy.activeConfigurationChanged(before, null));
    }

    @Test
    public void failoverMovesToTheNextServerAndWrapsAround() throws Exception {
        String base = "vless://33333333-3333-3333-3333-333333333333@edge.example:443"
                + "?security=tls&sni=edge.example";
        ProtocolParser.Node first = ProtocolParser.parse(base + "#One");
        ProtocolParser.Node second = ProtocolParser.parse(
                base.replace("edge.example:443", "second.example:443") + "#Two");
        ProtocolParser.Node third = ProtocolParser.parse(
                base.replace("edge.example:443", "third.example:443") + "#Three");
        java.util.List<ProtocolParser.Node> nodes =
                java.util.Arrays.asList(first, second, third);

        assertEquals(second.normalizedKey,
                RuntimePolicy.nextServerAfterFailure(nodes, first.normalizedKey));
        assertEquals(first.normalizedKey,
                RuntimePolicy.nextServerAfterFailure(nodes, third.normalizedKey));
    }

    @Test
    public void failoverStaysPutWhenThereIsNowhereToGo() throws Exception {
        ProtocolParser.Node only = ProtocolParser.parse(
                "vless://33333333-3333-3333-3333-333333333333@edge.example:443"
                        + "?security=tls&sni=edge.example#Only");
        // One server cannot be "switched" onto itself, and an unknown key must
        // not silently move the user somewhere they did not choose.
        assertEquals("", RuntimePolicy.nextServerAfterFailure(
                java.util.Collections.singletonList(only), only.normalizedKey));
        assertEquals("", RuntimePolicy.nextServerAfterFailure(
                java.util.Arrays.asList(only, only), "missing-key"));
        assertEquals("", RuntimePolicy.nextServerAfterFailure(null, only.normalizedKey));
    }

    @Test
    public void failoverAndTheCoreExperimentAreOffUntilAskedFor() {
        // Switching servers changes the exit country under the user, and the
        // second core maps a runtime that cannot be unmapped.
        assertFalse(SettingsModel.defaults().failover);
        assertFalse(SettingsModel.defaults().dualCore);
        assertFalse(SettingsModel.fromJson("{}").failover);
        assertFalse(SettingsModel.fromJson("{\"failover\":\"yes\"}").failover);
        assertTrue(SettingsModel.fromJson("{\"failover\":true}").failover);
    }

    @Test
    public void onlyTelegramReflectorsAreEverForwarded() {
        // The relay listens on loopback. Without this check anything on the
        // device that found the port could route through the user's server.
        assertTrue(TelegramReflectors.isReflector("91.108.4.1"));
        assertTrue(TelegramReflectors.isReflector("149.154.175.50"));
        assertTrue(TelegramReflectors.isReflector("91.108.58.255"));
        assertFalse(TelegramReflectors.isReflector("8.8.8.8"));
        assertFalse(TelegramReflectors.isReflector("127.0.0.1"));
        assertFalse(TelegramReflectors.isReflector("91.108.60.1"));
        assertFalse(TelegramReflectors.isReflector("10.0.0.1"));
    }

    @Test
    public void reflectorAddressParsingRejectsAnythingIrregular() {
        assertEquals(0L, TelegramReflectors.toIpv4("0.0.0.0"));
        // Surrounding whitespace is trimmed on purpose; whitespace inside is
        // not an address.
        assertEquals(16909060L, TelegramReflectors.toIpv4(" 1.2.3.4 "));
        assertEquals(4294967295L, TelegramReflectors.toIpv4("255.255.255.255"));
        for (String rejected : new String[]{
                null, "", "1.2.3", "1.2.3.4.5", "1.2.3.256", "1.2.3.-1",
                "01.2.3.4", "1.2.3.", ".1.2.3", "1.2. 3.4", "a.b.c.d",
                "1.2.3.4.", "12345678901234567",
        }) {
            assertEquals(rejected + " was accepted", -1L,
                    TelegramReflectors.toIpv4(rejected));
        }
    }

    @Test
    public void theScheduledCheckPeriodOnlyAcceptsOfferedValues() {
        SettingsModel base = SettingsModel.defaults();
        assertEquals(SettingsModel.PING_TCP, base.pingType);
        assertEquals(0, base.autoCheckMinutes);
        assertFalse(base.refreshOnOpen);
        assertEquals(60, base.withSetting("auto_check_minutes", 60).autoCheckMinutes);
        for (Object rejected : new Object[]{7, -15, 1440, 1.5d, "60"}) {
            try {
                base.withSetting("auto_check_minutes", rejected);
                throw new AssertionError("unexpected period accepted: " + rejected);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("auto_check_minutes"));
            }
        }
        // A stored value outside the offered set falls back to off rather than
        // scheduling something nobody chose.
        assertEquals(0, SettingsModel.fromJson(
                "{\"auto_check_minutes\":3}").autoCheckMinutes);
    }

    @Test
    public void normalizingAProviderKeepsEverySetting() {
        SettingsModel value = new SettingsModel(true, 0, "hwid", 6,
                SettingsModel.PING_TCP, true, true, true, 60);
        SettingsModel rebuilt = value.withSetting("provider_id", 1);

        assertTrue(rebuilt.dualCore);
        assertTrue(rebuilt.failover);
        assertEquals(SettingsModel.PING_TCP, rebuilt.pingType);
        assertEquals("hwid", rebuilt.customHwid);
        assertTrue(rebuilt.refreshOnOpen);
        assertEquals(60, rebuilt.autoCheckMinutes);
    }
}
