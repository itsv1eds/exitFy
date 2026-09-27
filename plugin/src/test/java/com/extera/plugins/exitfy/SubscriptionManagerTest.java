package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SubscriptionManagerTest {
    private static final String A1 =
            "vless://11111111-1111-1111-1111-111111111111@a-one.example:443?security=tls#A1";
    private static final String A2 =
            "vless://22222222-2222-2222-2222-222222222222@a-two.example:443?security=tls#A2";
    private static final String B1 =
            "vless://33333333-3333-3333-3333-333333333333@b-one.example:443?security=tls#B1";

    @Test
    public void cacheTimestampsRejectClockRollbackAndFutureValues() {
        long now = 50_000_000L;
        assertTrue(SubscriptionManager.staleTimestamp(now, 0L));
        assertTrue(SubscriptionManager.staleTimestamp(now, now + 1L));
        assertTrue(SubscriptionManager.staleTimestamp(now,
                now - 6L * 60L * 60L * 1000L));
        assertFalse(SubscriptionManager.staleTimestamp(now, now - 1L));
    }

    @Test
    public void missingConcurrentLatencyIsRenderedAsUnchecked() {
        Map<String, Long> cache = new ConcurrentHashMap<>();
        cache.put("node", 42L);
        assertEquals(42L, SubscriptionManager.cachedLatency(cache, "node"));
        cache.clear();
        assertEquals(-1L, SubscriptionManager.cachedLatency(cache, "node"));
    }

    @Test
    public void corruptDurableStoreIsPreservedInsteadOfResetToEmptyShape() throws Exception {
        File root = Files.createTempDirectory("exitfy-subscriptions-corrupt").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] corrupt = "{not-json".getBytes(StandardCharsets.UTF_8);
        File durable = new File(root, "subscriptions.json");
        try {
            Files.write(durable.toPath(), corrupt);
            try {
                new SubscriptionManager(new AtomicStore(root), http);
                throw new AssertionError("corrupt subscription state was accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("unreadable"));
            }
            assertEquals(new String(corrupt, StandardCharsets.UTF_8),
                    new String(Files.readAllBytes(durable.toPath()), StandardCharsets.UTF_8));
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void dynamicRequestHeadersRemoveControlsAndStayBounded() {
        String value = "  Pixel\r\nInjected: true\u0000🚀  ";
        String cleaned = SubscriptionManager.safeHeaderValue(value, "Android");
        assertFalse(cleaned.contains("\r"));
        assertFalse(cleaned.contains("\n"));
        assertFalse(cleaned.contains("\u0000"));
        assertTrue(cleaned.contains("Pixel"));
        assertTrue(cleaned.contains("🚀"));
        String bounded = SubscriptionManager.safeHeaderValue("🚀".repeat(400), "Android");
        assertTrue(bounded.codePointCount(0, bounded.length()) <= 256);
        assertTrue(bounded.getBytes(StandardCharsets.UTF_8).length <= 1024);
        assertEquals("Android", SubscriptionManager.safeHeaderValue("\r\n", "Android"));
    }

    @Test
    public void subscriptionFetchUsesTheConfiguredUserAgent() throws Exception {
        MiniServer server = new MiniServer(new AtomicReference<>(A1),
                new AtomicInteger(200));
        File root = Files.createTempDirectory("exitfy-subscription-ua").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
        try {
            manager.addCustomUrl("http://127.0.0.1:" + server.port() + "/first");
            assertEquals(1, manager.refresh(
                    SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults()).size());
            assertTrue(server.lastRequest().contains(
                    "User-Agent: " + SettingsModel.DEFAULT_SUBSCRIPTION_USER_AGENT));

            SettingsModel custom = SettingsModel.defaults()
                    .withSetting("subscription_user_agent", "Happ/1.63.1");
            assertEquals(1, manager.refresh(
                    SettingsModel.CUSTOM_PROVIDER_ID, custom).size());
            assertTrue(server.lastRequest().contains("User-Agent: Happ/1.63.1"));
            assertFalse(server.lastRequest().contains(
                    SettingsModel.DEFAULT_SUBSCRIPTION_USER_AGENT));
        } finally {
            manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void defaultHwidIsStableAndSelectedNodeHasACompactProjection()
            throws Exception {
        File root = Files.createTempDirectory("exitfy-default-hwid").toFile();
        LimitedHttpClient firstHttp = new LimitedHttpClient();
        SubscriptionManager first = new SubscriptionManager(
                new AtomicStore(root), firstHttp);
        String hwid;
        try {
            hwid = first.defaultHwid();
            assertTrue(hwid.matches("[0-9a-f]{16}"));
            assertEquals(hwid, first.defaultHwid());

            assertEquals(1, first.importText(A1).nodes);
            assertEquals(0, first.selectedUiNodeInfo(
                    SettingsModel.CUSTOM_PROVIDER_ID).length());
            ProtocolParser.Node selected = first.selected(
                    SettingsModel.CUSTOM_PROVIDER_ID);
            JSONObject projection = first.selectedUiNodeInfo(
                    SettingsModel.CUSTOM_PROVIDER_ID);
            assertEquals(selected.normalizedKey, projection.getString("key"));
            assertEquals("A1", projection.getString("name"));
            assertFalse(projection.has("outbound"));
        } finally {
            first.close();
            firstHttp.close();
        }

        LimitedHttpClient secondHttp = new LimitedHttpClient();
        SubscriptionManager second = new SubscriptionManager(
                new AtomicStore(root), secondHttp);
        try {
            assertEquals(hwid, second.defaultHwid());
        } finally {
            second.close();
            secondHttp.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void onlyBuiltInSourcesExposeReferralLinks() throws Exception {
        File root = Files.createTempDirectory("exitfy-provider-referrals").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
        try {
            for (int provider = 0; provider < ProviderCatalog.size(); provider++) {
                assertEquals(ProviderCatalog.isEnabled(provider),
                        !manager.referral(provider).isEmpty());
            }
            assertEquals("", manager.referral(SettingsModel.CUSTOM_PROVIDER_ID));
            assertEquals("", manager.referral(SettingsModel.CUSTOM_PROVIDER_ID + 1));
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void partialRefreshKeepsLastKnownGoodNodesPerUrl() throws Exception {
        AtomicReference<String> firstBody = new AtomicReference<>(A1);
        AtomicInteger secondStatus = new AtomicInteger(200);
        MiniServer server = new MiniServer(firstBody, secondStatus);

        File root = Files.createTempDirectory("exitfy-subscriptions").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
        try {
            String base = "http://127.0.0.1:" + server.port();
            manager.addCustomUrl(base + "/first");
            manager.addCustomUrl(base + "/second");
            assertEquals(2, manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults()).size());

            firstBody.set(A2);
            secondStatus.set(503);
            List<ProtocolParser.Node> after = manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults());
            assertEquals(2, after.size());
            assertTrue(after.stream().anyMatch(node -> "a-two.example".equals(node.outbound.optString("server"))));
            assertTrue(after.stream().anyMatch(node -> "b-one.example".equals(node.outbound.optString("server"))));
        } finally {
            manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void paginatesAtFiftyAndAcceptsOnlyExactCurrentNodeKeys() throws Exception {
        File root = Files.createTempDirectory("exitfy-pagination").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
        try {
            StringBuilder importBody = new StringBuilder();
            for (int i = 0; i < 120; i++) {
                importBody.append("vless://11111111-1111-1111-1111-")
                        .append(String.format("%012d", i))
                        .append("@node-").append(i).append(".example:443?security=tls#Node-")
                        .append(i).append('\n');
            }
            assertEquals(120, manager.importText(importBody.toString()).nodes);

            JSONObject page = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID, 50, 500);
            assertEquals(120, page.getInt("total"));
            // An oversized request is clamped to the maximum page, which now
            // holds a whole ordinary source at once.
            assertEquals(SubscriptionManager.MAX_PAGE_SIZE, page.getInt("limit"));
            assertEquals(70, page.getJSONArray("nodes").length());
            assertTrue(page.getBoolean("hasPrevious"));
            assertFalse(page.getBoolean("hasNext"));

            JSONObject firstFifty = manager.uiState(
                    SettingsModel.CUSTOM_PROVIDER_ID, 50, SubscriptionManager.DEFAULT_PAGE_SIZE);
            assertEquals(50, firstFifty.getJSONArray("nodes").length());
            assertTrue(firstFifty.getBoolean("hasNext"));

            List<String> keys = new ArrayList<>();
            JSONArray values = firstFifty.getJSONArray("nodes");
            for (int i = 0; i < values.length(); i++) {
                keys.add(values.getJSONObject(i).getString("key"));
            }
            assertEquals(50, manager.nodesByKeys(SettingsModel.CUSTOM_PROVIDER_ID, keys).size());
            keys.add("missing-key");
            try {
                manager.nodesByKeys(SettingsModel.CUSTOM_PROVIDER_ID, keys);
                throw new AssertionError("more than 50 probe keys accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("50"));
            }

            JSONObject overflow = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID, Integer.MAX_VALUE, 50);
            assertEquals(120, overflow.getInt("offset"));
            assertEquals(0, overflow.getJSONArray("nodes").length());
            assertTrue(overflow.getBoolean("hasPrevious"));
            assertFalse("overflowed offset exposed a phantom next page",
                    overflow.getBoolean("hasNext"));
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void nativeUiFiltersBeforePaginationAndReturnsCompactNodes() throws Exception {
        File root = Files.createTempDirectory("exitfy-ui-filters").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
        try {
            String common = "vless://11111111-1111-1111-1111-111111111111"
                    + "@common.example:443?security=tls&type=ws&path=%2Fws#Alpha%20Common";
            String singOnly = "hysteria2://password@hy2.example:443"
                    + "?sni=hy2.example#Fast%20QUIC";
            String xrayOnly = "vless://22222222-2222-2222-2222-222222222222"
                    + "@xray.example:443?security=tls&type=xhttp&path=%2Fx"
                    + "&mode=packet-up#Xray%20Only";
            assertEquals(3, manager.importText(
                    common + "\n" + singOnly + "\n" + xrayOnly).nodes);

            JSONObject searched = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID,
                    0, 50, "fast", "all");
            assertEquals(1, searched.getInt("total"));
            assertEquals(3, searched.getInt("unfilteredTotal"));
            JSONObject fast = searched.getJSONArray("nodes").getJSONObject(0);
            assertEquals("hysteria2", fast.getString("protocol"));
            assertEquals("quic", fast.getString("transport"));
            assertFalse(fast.has("supportsSingBox"));
            assertFalse(fast.has("supportsXray"));
            assertFalse(searched.has("compatibility"));

            JSONObject vless = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID,
                    0, 1, "", "vless");
            assertEquals(2, vless.getInt("total"));
            assertEquals(1, vless.getJSONArray("nodes").length());
            assertTrue(vless.getBoolean("hasNext"));
            assertEquals("Alpha Common",
                    vless.getJSONArray("nodes").getJSONObject(0).getString("name"));

            JSONObject all = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID,
                    0, 50, "", "all");
            assertEquals(3, all.getInt("total"));
            JSONObject xrayOnlyInfo = null;
            for (int i = 0; i < all.getJSONArray("nodes").length(); i++) {
                JSONObject item = all.getJSONArray("nodes").getJSONObject(i);
                if ("Xray Only".equals(item.getString("name"))) xrayOnlyInfo = item;
            }
            assertTrue(xrayOnlyInfo != null);
            assertEquals("xhttp", xrayOnlyInfo.getString("transport"));
            assertFalse(xrayOnlyInfo.has("supportsSingBox"));
            assertFalse(xrayOnlyInfo.has("supportsXray"));
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void nativeUiQueryAndProtocolFiltersAreStrictlyBounded() {
        String accepted = "🚀".repeat(128);
        assertEquals(accepted, SubscriptionManager.requireUiQuery(accepted));
        try {
            SubscriptionManager.requireUiQuery(accepted + "🚀");
            throw new AssertionError("129-code-point query accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().toLowerCase().contains("query")
                    || expected.getMessage().toLowerCase().contains("запрос"));
        }
        try {
            SubscriptionManager.requireUiProtocol("wireguard");
            throw new AssertionError("unknown UI protocol accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().toLowerCase().contains("protocol")
                    || expected.getMessage().toLowerCase().contains("протокол"));
        }
    }

    @Test
    public void importsOnlyExplicitUrlLinesAndCapsCustomSources() throws Exception {
        File root = Files.createTempDirectory("exitfy-url-import").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            SubscriptionManager.ImportResult embedded = manager.importText(
                    "{\"message\":\"documentation: https://example.com/not-a-subscription\"}");
            assertEquals(0, embedded.urls);
            assertEquals(0, manager.customUrlCount());

            StringBuilder lines = new StringBuilder();
            for (int i = 0; i < 300; i++) {
                lines.append("https://subscriptions.example/source-").append(i).append('\n');
            }
            SubscriptionManager.ImportResult capped = manager.importText(lines.toString());
            assertEquals(SubscriptionManager.MAX_CUSTOM_URLS, capped.urls);
            assertEquals(SubscriptionManager.MAX_CUSTOM_URLS, manager.customUrlCount());
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void failedMixedImportRollsBackNodesAndUrlsTogether() throws Exception {
        File root = Files.createTempDirectory("exitfy-import-transaction").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            try {
                manager.importText(A1 + "\nhttp://invalid_host");
                throw new AssertionError("invalid URL did not fail import");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("URL"));
            }
            assertEquals(0, manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
            assertEquals(0, manager.customUrlCount());
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void closeCancelsPendingProbesWithoutWaitingForManagerMonitor() throws Exception {
        File root = Files.createTempDirectory("exitfy-probe-close").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            manager.importText(A1);
            List<ProtocolParser.Node> nodes = manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID);
            manager.markProbePending(nodes);
            Thread closer = new Thread(manager::close, "exitfy-test-close");
            synchronized (manager) {
                closer.start();
                closer.join(500L);
                assertFalse("close waited for manager monitor", closer.isAlive());
            }
            JSONObject state = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID, 0, 50);
            assertEquals("cancelled", state.getJSONArray("nodes")
                    .getJSONObject(0).getString("pingStatus"));
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void selectedNodeReportsPersistenceFailure() throws Exception {
        File root = Files.createTempDirectory("exitfy-selected-persist").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            manager.importText(A1 + "\n" + A2);
            String second = manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).get(1).normalizedKey;
            TestFiles.deleteRecursively(root);
            Files.write(root.toPath(), new byte[]{1});
            assertFalse(manager.setSelectedKey(SettingsModel.CUSTOM_PROVIDER_ID, second));
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void lateRefreshCannotResurrectRemovedCustomSource() throws Exception {
        CountDownLatch requestSeen = new CountDownLatch(1);
        CountDownLatch releaseResponse = new CountDownLatch(1);
        MiniServer server = new MiniServer(new AtomicReference<>(A1),
                new AtomicInteger(200), requestSeen, releaseResponse);
        File root = Files.createTempDirectory("exitfy-stale-refresh").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        AtomicReference<Throwable> refreshError = new AtomicReference<>();
        try {
            String url = "http://127.0.0.1:" + server.port() + "/slow";
            assertTrue(manager.addCustomUrl(url));
            String id = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID).getJSONArray("customSources")
                    .getJSONObject(0).getString("id");
            Thread refresh = new Thread(() -> {
                try {
                    manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults());
                } catch (Throwable error) {
                    refreshError.set(error);
                }
            }, "exitfy-stale-refresh");
            refresh.start();
            assertTrue("refresh did not reach HTTP server",
                    requestSeen.await(2, TimeUnit.SECONDS));
            assertTrue(manager.removeCustomUrl(id));
            releaseResponse.countDown();
            refresh.join(3000L);
            assertFalse("refresh did not finish", refresh.isAlive());
            assertTrue("stale refresh unexpectedly succeeded", refreshError.get() != null);
            assertEquals(0, manager.customUrlCount());
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());

            LimitedHttpClient reloadHttp = new LimitedHttpClient();
            SubscriptionManager reloaded = new SubscriptionManager(
                    new AtomicStore(root), reloadHttp);
            try {
                assertEquals(0, reloaded.customUrlCount());
                assertTrue(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());
            } finally {
                reloaded.close();
                reloadHttp.close();
            }
        } finally {
            releaseResponse.countDown();
            manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void refreshNeverContactsNextUrlAfterMembershipChanges() throws Exception {
        CountDownLatch requestSeen = new CountDownLatch(1);
        CountDownLatch releaseResponse = new CountDownLatch(1);
        MiniServer server = new MiniServer(new AtomicReference<>(A1),
                new AtomicInteger(200), requestSeen, releaseResponse);
        File root = Files.createTempDirectory("exitfy-refresh-membership-network").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        AtomicReference<Throwable> refreshError = new AtomicReference<>();
        try {
            String base = "http://127.0.0.1:" + server.port();
            assertTrue(manager.addCustomUrl(base + "/first"));
            assertTrue(manager.addCustomUrl(base + "/second"));
            JSONArray sources = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID).getJSONArray("customSources");
            String secondId = sources.getJSONObject(1).getString("id");

            Thread refresh = new Thread(() -> {
                try {
                    manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults());
                } catch (Throwable error) {
                    refreshError.set(error);
                }
            }, "exitfy-refresh-membership-network");
            refresh.start();
            assertTrue(requestSeen.await(2, TimeUnit.SECONDS));
            assertTrue(manager.removeCustomUrl(secondId));
            releaseResponse.countDown();
            refresh.join(3000L);

            assertFalse(refresh.isAlive());
            assertTrue("stale refresh unexpectedly succeeded", refreshError.get() != null);
            assertEquals("removed URL was contacted after membership changed",
                    1, server.requests());
            assertEquals(1, manager.customUrlCount());
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());
        } finally {
            releaseResponse.countDown();
            manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void clearInvalidatesDelayedRefreshAndRemainsEmptyAfterReload() throws Exception {
        CountDownLatch requestSeen = new CountDownLatch(1);
        CountDownLatch releaseResponse = new CountDownLatch(1);
        MiniServer server = new MiniServer(new AtomicReference<>(A1),
                new AtomicInteger(200), requestSeen, releaseResponse);
        File root = Files.createTempDirectory("exitfy-clear-refresh").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        AtomicReference<Throwable> refreshError = new AtomicReference<>();
        try {
            String url = "http://127.0.0.1:" + server.port() + "/slow";
            assertTrue(manager.addCustomUrl(url));
            Thread refresh = new Thread(() -> {
                try {
                    manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults());
                } catch (Throwable error) {
                    refreshError.set(error);
                }
            }, "exitfy-clear-refresh");
            refresh.start();
            assertTrue("refresh did not reach HTTP server",
                    requestSeen.await(2, TimeUnit.SECONDS));
            manager.clearNodesKeepSubscriptions();
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());
            releaseResponse.countDown();
            refresh.join(3000L);
            assertFalse("refresh did not finish", refresh.isAlive());
            assertTrue("refresh fetched before clear was accepted", refreshError.get() != null);
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());

            manager.close();
            LimitedHttpClient reloadHttp = new LimitedHttpClient();
            SubscriptionManager reloaded = new SubscriptionManager(
                    new AtomicStore(root), reloadHttp);
            try {
                assertEquals(1, reloaded.customUrlCount());
                assertTrue(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());
            } finally {
                reloaded.close();
                reloadHttp.close();
            }
        } finally {
            releaseResponse.countDown();
            manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void snapshotNeverPublishesSelectionMissingFromCurrentNodes() throws Exception {
        AtomicReference<String> body = new AtomicReference<>(A1);
        MiniServer server = new MiniServer(body, new AtomicInteger(200));
        File root = Files.createTempDirectory("exitfy-selected-snapshot").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            String url = "http://127.0.0.1:" + server.port() + "/first";
            assertTrue(manager.addCustomUrl(url));
            List<ProtocolParser.Node> first = manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults());
            assertEquals(1, first.size());
            assertTrue(manager.setSelected(SettingsModel.CUSTOM_PROVIDER_ID, first.get(0)));
            assertEquals(first.get(0).normalizedKey,
                    manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID).getString("selectedKey"));

            body.set(A2);
            List<ProtocolParser.Node> replaced = manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults());
            assertEquals(1, replaced.size());
            assertEquals("", manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID).getString("selectedKey"));

            assertTrue(manager.setSelected(SettingsModel.CUSTOM_PROVIDER_ID, replaced.get(0)));
            String sourceId = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID).getJSONArray("customSources")
                    .getJSONObject(0).getString("id");
            assertTrue(manager.removeCustomUrl(sourceId));
            JSONObject empty = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID);
            assertEquals(0, empty.getInt("total"));
            assertEquals("", empty.getString("selectedKey"));
        } finally {
            manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void refreshCancellationStopsBeforeSecondUrlAndCommitsNothingLater() throws Exception {
        MiniServer server = new MiniServer(new AtomicReference<>(A1), new AtomicInteger(200));
        File root = Files.createTempDirectory("exitfy-refresh-cancel-scope").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            String base = "http://127.0.0.1:" + server.port();
            assertTrue(manager.addCustomUrl(base + "/first"));
            assertTrue(manager.addCustomUrl(base + "/second"));
            try {
                manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults(), Long.MAX_VALUE,
                        () -> server.requests() >= 1);
                throw new AssertionError("cancelled refresh unexpectedly succeeded");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("cancel"));
            }
            assertEquals(1, server.requests());
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());
        } finally {
            manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void interruptedRefreshPersistKeepsLiveAndDurableStateForNextWrite() throws Exception {
        AtomicReference<String> body = new AtomicReference<>(A1);
        MiniServer server = new MiniServer(body, new AtomicInteger(200));
        File root = Files.createTempDirectory("exitfy-refresh-persist-interrupt").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        CancelAtPersistObserver observer = new CancelAtPersistObserver();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http, observer);
        AtomicReference<Throwable> refreshError = new AtomicReference<>();
        try {
            String url = "http://127.0.0.1:" + server.port() + "/first";
            assertEquals(1, manager.importText(B1).nodes);
            assertTrue(manager.addCustomUrl(url));
            assertEquals(2, manager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults()).size());

            body.set(A2);
            observer.arm();
            SubscriptionManager activeManager = manager;
            Thread refresh = new Thread(() -> {
                try {
                    activeManager.refresh(SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults());
                } catch (Throwable error) {
                    refreshError.set(error);
                }
            }, "exitfy-refresh-persist-interrupt");
            refresh.start();
            assertTrue("refresh never reached persist preflight",
                    observer.persistEntered.await(2, TimeUnit.SECONDS));
            refresh.interrupt();
            observer.persistRelease.countDown();
            refresh.join(3_000L);

            assertFalse("cancelled refresh did not finish", refresh.isAlive());
            assertTrue("cancelled refresh unexpectedly succeeded", refreshError.get() != null);
            assertTrue(refreshError.get().getMessage().contains("cancel"));
            assertEquals(2, manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                    "a-one.example".equals(node.outbound.optString("server"))));
            assertFalse(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                    "a-two.example".equals(node.outbound.optString("server"))));

            // A later successful persist must extend the recovered snapshot,
            // never publish an ambiguous empty fallback over the durable file.
            assertEquals(1, manager.addManualUri(A2));
            assertEquals(3, manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
            manager.close();
            manager = null;

            SubscriptionManager reloaded = new SubscriptionManager(
                    new AtomicStore(root), http);
            try {
                assertEquals(1, reloaded.customUrlCount());
                assertEquals(3, reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
                assertTrue(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                        "a-one.example".equals(node.outbound.optString("server"))));
                assertTrue(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                        "a-two.example".equals(node.outbound.optString("server"))));
            } finally {
                reloaded.close();
            }
        } finally {
            observer.persistRelease.countDown();
            if (manager != null) manager.close();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void interruptedImportPersistRollsBackBeforeNextDurableWrite() throws Exception {
        File root = Files.createTempDirectory("exitfy-import-persist-interrupt").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        CancelAtPersistObserver observer = new CancelAtPersistObserver();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http, observer);
        AtomicReference<Throwable> importError = new AtomicReference<>();
        try {
            assertEquals(1, manager.importText(A1).nodes);
            observer.arm();
            SubscriptionManager activeManager = manager;
            Thread imported = new Thread(() -> {
                try {
                    activeManager.importText(A2);
                } catch (Throwable error) {
                    importError.set(error);
                }
            }, "exitfy-import-persist-interrupt");
            imported.start();
            assertTrue("import never reached persist preflight",
                    observer.persistEntered.await(2, TimeUnit.SECONDS));
            imported.interrupt();
            observer.persistRelease.countDown();
            imported.join(3_000L);

            assertFalse("cancelled import did not finish", imported.isAlive());
            assertTrue("cancelled import unexpectedly succeeded", importError.get() != null);
            assertEquals(1, manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                    "a-one.example".equals(node.outbound.optString("server"))));
            assertFalse(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                    "a-two.example".equals(node.outbound.optString("server"))));

            assertEquals(1, manager.addManualUri(B1));
            manager.close();
            manager = null;
            SubscriptionManager reloaded = new SubscriptionManager(
                    new AtomicStore(root), http);
            try {
                assertEquals(2, reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
                assertFalse(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                        "a-two.example".equals(node.outbound.optString("server"))));
            } finally {
                reloaded.close();
            }
        } finally {
            observer.persistRelease.countDown();
            if (manager != null) manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void ambiguousRecoveryFailurePoisonsWriterBeforeAnyLaterCommit() throws Exception {
        File root = Files.createTempDirectory("exitfy-persist-recovery-poison").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        HideDurableCommitObserver observer = new HideDurableCommitObserver();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root, observer), http);
        try {
            assertEquals(1, manager.importText(A1).nodes);
            observer.arm();
            try {
                manager.importText(A2);
                throw new AssertionError("ambiguous commit/recovery failure was ignored");
            } catch (Exception expected) {
                assertTrue(expected.getSuppressed().length > 0);
            }

            try {
                manager.addManualUri(B1);
                throw new AssertionError("poisoned manager accepted another mutation");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("requires reload"));
            }

            observer.restore();
            manager.close();
            manager = null;
            SubscriptionManager reloaded = new SubscriptionManager(
                    new AtomicStore(root), http);
            try {
                assertEquals(1, reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
                assertTrue(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                        "a-one.example".equals(node.outbound.optString("server"))));
                assertFalse(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).stream().anyMatch(node ->
                        "a-two.example".equals(node.outbound.optString("server"))
                                || "b-one.example".equals(node.outbound.optString("server"))));
            } finally {
                reloaded.close();
            }
        } finally {
            observer.restore();
            if (manager != null) manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void closeDuringImportParseCannotCommitOverReplacementManager() throws Exception {
        File root = Files.createTempDirectory("exitfy-close-import").toFile();
        LimitedHttpClient oldHttp = new LimitedHttpClient();
        BlockingObserver observer = new BlockingObserver();
        SubscriptionManager oldManager = new SubscriptionManager(
                new AtomicStore(root), oldHttp, observer);
        AtomicReference<Throwable> oldError = new AtomicReference<>();
        LimitedHttpClient replacementHttp = new LimitedHttpClient();
        SubscriptionManager replacement = null;
        try {
            observer.blockParse.set(true);
            Thread oldImport = new Thread(() -> {
                try {
                    oldManager.importText(A1);
                } catch (Throwable error) {
                    oldError.set(error);
                }
            }, "exitfy-close-import");
            oldImport.start();
            assertTrue("import did not enter parse phase",
                    observer.parseEntered.await(2, TimeUnit.SECONDS));

            oldManager.close();
            replacement = new SubscriptionManager(
                    new AtomicStore(root), replacementHttp);
            assertEquals(1, replacement.importText(A2).nodes);
            observer.parseRelease.countDown();
            oldImport.join(3000L);
            assertFalse("revoked import did not finish", oldImport.isAlive());
            assertTrue("revoked import unexpectedly succeeded", oldError.get() != null);

            replacement.close();
            LimitedHttpClient reloadHttp = new LimitedHttpClient();
            SubscriptionManager reloaded = new SubscriptionManager(
                    new AtomicStore(root), reloadHttp);
            try {
                List<ProtocolParser.Node> nodes = reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID);
                assertEquals(1, nodes.size());
                assertEquals("a-two.example", nodes.get(0).outbound.optString("server"));
            } finally {
                reloaded.close();
                reloadHttp.close();
            }
        } finally {
            observer.parseRelease.countDown();
            oldManager.close();
            if (replacement != null) replacement.close();
            oldHttp.close();
            replacementHttp.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void olderImportCannotResurrectNewerManualDeletion() throws Exception {
        File root = Files.createTempDirectory("exitfy-import-delete-race").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        BlockingObserver observer = new BlockingObserver();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http, observer);
        AtomicReference<Throwable> importError = new AtomicReference<>();
        try {
            assertEquals(1, manager.addManualUri(A1));
            String removedKey = manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).get(0).normalizedKey;
            observer.blockParse.set(true);
            Thread importer = new Thread(() -> {
                try {
                    manager.importText(A1 + "\n" + A2);
                } catch (Throwable error) {
                    importError.set(error);
                }
            }, "exitfy-import-delete-race");
            importer.start();
            assertTrue(observer.parseEntered.await(2, TimeUnit.SECONDS));
            assertTrue(manager.removeManualNode(removedKey));
            observer.parseRelease.countDown();
            importer.join(3000L);

            assertFalse(importer.isAlive());
            assertTrue("older import unexpectedly overwrote manual deletion",
                    importError.get() != null);
            assertTrue(manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());

            manager.close();
            LimitedHttpClient reloadHttp = new LimitedHttpClient();
            SubscriptionManager reloaded = new SubscriptionManager(
                    new AtomicStore(root), reloadHttp);
            try {
                assertTrue(reloaded.nodes(SettingsModel.CUSTOM_PROVIDER_ID).isEmpty());
            } finally {
                reloaded.close();
                reloadHttp.close();
            }
        } finally {
            observer.parseRelease.countDown();
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void immutableUiSnapshotDoesNotWaitForParseOrPersistMonitor() throws Exception {
        File root = Files.createTempDirectory("exitfy-ui-snapshot").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        BlockingObserver observer = new BlockingObserver();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http, observer);
        AtomicReference<Throwable> importError = new AtomicReference<>();
        try {
            assertEquals(1, manager.importText(A1).nodes);
            observer.blockParse.set(true);
            observer.blockPersist.set(true);
            Thread importer = new Thread(() -> {
                try {
                    manager.importText(A2 + "\nhttps://subscriptions.example/new");
                } catch (Throwable error) {
                    importError.set(error);
                }
            }, "exitfy-ui-snapshot-import");
            importer.start();
            assertTrue("import did not enter parse phase",
                    observer.parseEntered.await(2, TimeUnit.SECONDS));
            assertEquals(1, manager.nodeCountFast(SettingsModel.CUSTOM_PROVIDER_ID));
            assertEquals(0, manager.customUrlCount());
            assertEquals(1, manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID, 0, 50).getInt("total"));

            observer.parseRelease.countDown();
            assertTrue("import did not reach persist barrier",
                    observer.persistEntered.await(2, TimeUnit.SECONDS));
            AtomicInteger observedCount = new AtomicInteger(-1);
            AtomicInteger observedCustomUrls = new AtomicInteger(-1);
            AtomicInteger observedTotal = new AtomicInteger(-1);
            CountDownLatch readDone = new CountDownLatch(1);
            Thread reader = new Thread(() -> {
                try {
                    observedCount.set(manager.nodeCountFast(SettingsModel.CUSTOM_PROVIDER_ID));
                    // RuntimeCoordinator.getUiState() invokes both fast counts;
                    // neither may fall back to the transaction monitor.
                    observedCustomUrls.set(manager.customUrlCount());
                    observedTotal.set(manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID, 0, 50).optInt("total", -1));
                } finally {
                    readDone.countDown();
                }
            }, "exitfy-ui-snapshot-reader");
            reader.start();
            boolean responsive = readDone.await(750, TimeUnit.MILLISECONDS);
            observer.persistRelease.countDown();
            importer.join(3000L);
            reader.join(3000L);

            assertTrue("UI snapshot waited for the persistence monitor", responsive);
            assertEquals(1, observedCount.get());
            assertEquals(0, observedCustomUrls.get());
            assertEquals(1, observedTotal.get());
            assertTrue("import failed: " + importError.get(), importError.get() == null);
            assertEquals(2, manager.nodeCountFast(SettingsModel.CUSTOM_PROVIDER_ID));
            assertEquals(1, manager.customUrlCount());
            assertEquals(2, manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID, 0, 50).getInt("total"));
        } finally {
            observer.parseRelease.countDown();
            observer.persistRelease.countDown();
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void uiSnapshotIsCompactAndSelectionOrHwidAvoidFullReparse() throws Exception {
        File root = Files.createTempDirectory("exitfy-ui-compact").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        BlockingObserver observer = new BlockingObserver();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http, observer);
        try {
            assertEquals(2, manager.importText(A1 + "\n" + A2).nodes);
            int fullAfterImport = observer.fullSnapshots.get();
            int validationsAfterImport = observer.nodeLimitValidations.get();

            Field cacheField = SubscriptionManager.class.getDeclaredField("nodeCache");
            cacheField.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<Integer, List<ProtocolParser.Node>> cache =
                    (Map<Integer, List<ProtocolParser.Node>>) cacheField.get(manager);
            assertTrue(cache.isEmpty());
            manager.warmCache();
            assertTrue("runtime load eagerly retained every full node", cache.isEmpty());

            Field snapshotField = SubscriptionManager.class.getDeclaredField("viewSnapshot");
            snapshotField.setAccessible(true);
            Object snapshot = snapshotField.get(manager);
            Field providersField = snapshot.getClass().getDeclaredField("providers");
            providersField.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<Integer, List<?>> providers = (Map<Integer, List<?>>) providersField.get(snapshot);
            Object summary = providers.get(SettingsModel.CUSTOM_PROVIDER_ID).get(0);
            for (Field field : summary.getClass().getDeclaredFields()) {
                assertFalse("UI snapshot retained full proxy node",
                        ProtocolParser.Node.class.isAssignableFrom(field.getType()));
                assertFalse("UI snapshot retained outbound JSON",
                        JSONObject.class.isAssignableFrom(field.getType()));
            }

            ProtocolParser.Node second = manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).get(1);
            assertEquals(1, cache.size());
            assertTrue(cache.containsKey(SettingsModel.CUSTOM_PROVIDER_ID));
            manager.nodes(0);
            assertEquals("full node cache retained an inactive provider", 1, cache.size());
            assertTrue(cache.containsKey(0));
            assertTrue(manager.setSelected(SettingsModel.CUSTOM_PROVIDER_ID, second));
            assertEquals(fullAfterImport, observer.fullSnapshots.get());
            assertEquals(1, observer.selectionSnapshots.get());
            assertEquals(validationsAfterImport, observer.nodeLimitValidations.get());
            assertEquals(second.normalizedKey,
                    manager.selected(SettingsModel.CUSTOM_PROVIDER_ID).normalizedKey);
            assertEquals(1, manager.nodesByKeys(SettingsModel.CUSTOM_PROVIDER_ID,
                    java.util.Collections.singletonList(second.normalizedKey)).size());
            assertEquals(1, cache.size());
            assertTrue(cache.containsKey(SettingsModel.CUSTOM_PROVIDER_ID));

            Method hwid = SubscriptionManager.class.getDeclaredMethod(
                    "hwid", SettingsModel.class);
            hwid.setAccessible(true);
            String generated = (String) hwid.invoke(manager, SettingsModel.defaults());
            assertFalse(generated.isEmpty());
            assertEquals(fullAfterImport, observer.fullSnapshots.get());
            assertEquals(1, observer.selectionSnapshots.get());
            assertEquals(validationsAfterImport, observer.nodeLimitValidations.get());
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void largeImportDoesNotCloneWholeStoreBeforeAtomicWrite() throws Exception {
        File root = Files.createTempDirectory("exitfy-large-import").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            manager.importText(A1);
            Field field = SubscriptionManager.class.getDeclaredField("data");
            field.setAccessible(true);
            JSONObject original = (JSONObject) field.get(manager);
            CountingJSONObject counting = new CountingJSONObject(original.toString());
            JSONArray largeUnrelatedState = new JSONArray();
            for (int index = 0; index < 120; index++) {
                largeUnrelatedState.put(repeat('x', 50 * 1024));
            }
            counting.getJSONObject("meta").put("largeUnrelatedState", largeUnrelatedState);
            counting.calls = 0;
            field.set(manager, counting);

            assertEquals(1, manager.importText(A2).nodes);
            // One serialization is required for the atomic durable write. A
            // second call would be the removed JSONObject(toString()) clone.
            assertEquals(1, counting.calls);
            assertEquals(2, manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void directCustomUrlPreservesFunctionalTrailingPunctuation() throws Exception {
        File root = Files.createTempDirectory("exitfy-url-punctuation").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            String exact = "https://subscriptions.example/path.;";
            assertTrue(manager.addCustomUrl("  " + exact + "  "));
            Field field = SubscriptionManager.class.getDeclaredField("data");
            field.setAccessible(true);
            JSONObject data = (JSONObject) field.get(manager);
            assertEquals(exact, data.getJSONArray("customUrls")
                    .getJSONObject(0).getString("url"));
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void clipboardPreservesExactUrlAndStripsOnlyBalancedOuterWrapper() throws Exception {
        File root = Files.createTempDirectory("exitfy-import-url-punctuation").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            String exact = "https://subscriptions.example/exact-path.;";
            String wrappedInner = "https://subscriptions.example/wrapped-path.;";
            SubscriptionManager.ImportResult imported = manager.importText(
                    exact + "\n(" + wrappedInner + ").");
            assertEquals(2, imported.urls);

            Field field = SubscriptionManager.class.getDeclaredField("data");
            field.setAccessible(true);
            JSONArray urls = ((JSONObject) field.get(manager)).getJSONArray("customUrls");
            assertEquals(exact, urls.getJSONObject(0).getString("url"));
            assertEquals(wrappedInner, urls.getJSONObject(1).getString("url"));

            SubscriptionManager.ImportResult proof = manager.importText(
                    "[https://subscriptions.example/a(b)c]\n"
                            + "(https://subscriptions.example/early)b)\n"
                            + "(https://subscriptions.example/mismatch]\n");
            assertEquals(1, proof.urls);
            JSONArray updated = ((JSONObject) field.get(manager)).getJSONArray("customUrls");
            assertEquals("https://subscriptions.example/a(b)c",
                    updated.getJSONObject(2).getString("url"));
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void customSubscriptionRejectsOutOfRangeExplicitPort() throws Exception {
        File root = Files.createTempDirectory("exitfy-url-port").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(
                new AtomicStore(root), http);
        try {
            for (String url : new String[]{
                    "https://subscriptions.example:0/path",
                    "https://subscriptions.example:65536/path",
                    "https://subscriptions.example:-1/path",
                    "https://subscriptions.example:/path",
                    "https://subscriptions.example:not-a-port/path",
            }) {
                try {
                    manager.addCustomUrl(url);
                    throw new AssertionError("out-of-range URL port accepted: " + url);
                } catch (IllegalArgumentException expected) {
                    assertTrue(expected.getMessage() != null && !expected.getMessage().isEmpty());
                }
            }
        } finally {
            manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void legacyBuiltInEndpointIsReplacedAndItsUnversionedCacheIsInvalidated() throws Exception {
        File root = Files.createTempDirectory("exitfy-builtin-storage").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = null;
        try {
            String first = ProviderCatalog.isEnabled(0)
                    ? ProviderCatalog.endpoint(0) : "https://disabled-zero.example/sub";
            String second = ProviderCatalog.isEnabled(1)
                    ? ProviderCatalog.endpoint(1) : "https://disabled-one.example/sub";
            JSONObject seeded = new JSONObject()
                    .put("providers", new JSONObject()
                            .put("0", seededProvider(first, 0, 1))
                            .put("1", seededProvider(second, 1, 1))
                            .put("2", new JSONObject().put("sources", new JSONArray())))
                    .put("manual", new JSONArray())
                    .put("customUrls", new JSONArray())
                    .put("activeKeys", new JSONObject()
                            .put("0", "legacy-zero")
                            .put("1", "legacy-one"))
                    .put("meta", new JSONObject().put("providerLayout", 3));
            AtomicStore store = new AtomicStore(root);
            store.writeJson("subscriptions.json", seeded);

            manager = new SubscriptionManager(new AtomicStore(root), http);

            JSONObject persisted = store.readJsonStrict("subscriptions.json");
            String serialized = persisted.toString();
            assertFalse(serialized.contains(first));
            assertFalse(serialized.contains(second));
            String[] names = {"Shrimp", "Elix", "Sworkle"};
            for (int providerId = 0; providerId < ProviderCatalog.size(); providerId++) {
                JSONArray sources = persisted.getJSONObject("providers")
                        .getJSONObject(String.valueOf(providerId)).getJSONArray("sources");
                if (ProviderCatalog.isEnabled(providerId)) {
                    assertEquals(1, sources.length());
                    JSONObject source = sources.getJSONObject(0);
                    assertEquals(ProviderCatalog.storageKey(providerId), source.getString("url"));
                    assertEquals(names[providerId], source.getString("title"));
                    assertEquals(ProviderCatalog.revision(providerId),
                            source.getString("catalogRevision"));
                    assertEquals(0L, source.getLong("updatedAt"));
                    assertEquals(0, source.getJSONArray("nodes").length());
                    assertEquals(0, manager.nodeCountFast(providerId));
                } else {
                    assertEquals(0, sources.length());
                    assertEquals(0, manager.nodeCountFast(providerId));
                }
                assertFalse(persisted.getJSONObject("activeKeys")
                        .has(String.valueOf(providerId)));
            }
        } finally {
            if (manager != null) manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void matchingBuiltInCatalogRevisionPreservesCachedNodesAndSelection() throws Exception {
        int providerId = firstEnabledProvider();
        if (providerId < 0) return;
        File root = Files.createTempDirectory("exitfy-builtin-revision-match").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = null;
        try {
            JSONObject providers = new JSONObject();
            for (int provider = 0; provider < ProviderCatalog.size(); provider++) {
                providers.put(String.valueOf(provider),
                        new JSONObject().put("sources", new JSONArray()));
            }
            JSONObject retained = seededProvider(
                    ProviderCatalog.storageKey(providerId), 0, 1)
                    .getJSONArray("sources").getJSONObject(0)
                    .put("catalogRevision", ProviderCatalog.revision(providerId));
            providers.put(String.valueOf(providerId),
                    new JSONObject().put("sources", new JSONArray().put(retained)));
            JSONObject seeded = new JSONObject()
                    .put("providers", providers)
                    .put("manual", new JSONArray())
                    .put("customUrls", new JSONArray())
                    .put("activeKeys", new JSONObject()
                            .put(String.valueOf(providerId), "retained-selection"))
                    .put("meta", new JSONObject().put("providerLayout", 3));
            AtomicStore store = new AtomicStore(root);
            store.writeJson("subscriptions.json", seeded);

            manager = new SubscriptionManager(new AtomicStore(root), http);

            JSONObject persisted = store.readJsonStrict("subscriptions.json");
            JSONObject source = persisted.getJSONObject("providers")
                    .getJSONObject(String.valueOf(providerId))
                    .getJSONArray("sources").getJSONObject(0);
            assertEquals(1L, source.getLong("updatedAt"));
            assertEquals(1, source.getJSONArray("nodes").length());
            assertEquals(1, manager.nodeCountFast(providerId));
            assertEquals("retained-selection", persisted.getJSONObject("activeKeys")
                    .getString(String.valueOf(providerId)));
        } finally {
            if (manager != null) manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void changedBuiltInCatalogRevisionDropsOnlyThatCacheAndSelection() throws Exception {
        int providerId = firstEnabledProvider();
        if (providerId < 0) return;
        File root = Files.createTempDirectory("exitfy-builtin-revision-change").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = null;
        try {
            JSONObject providers = new JSONObject();
            for (int provider = 0; provider < ProviderCatalog.size(); provider++) {
                providers.put(String.valueOf(provider),
                        new JSONObject().put("sources", new JSONArray()));
            }
            JSONObject stale = seededProvider(
                    ProviderCatalog.storageKey(providerId), 0, 1)
                    .getJSONArray("sources").getJSONObject(0)
                    .put("catalogRevision", "00000000000000000000000000000000");
            providers.put(String.valueOf(providerId),
                    new JSONObject().put("sources", new JSONArray().put(stale)));
            JSONObject seeded = new JSONObject()
                    .put("providers", providers)
                    .put("manual", new JSONArray())
                    .put("customUrls", new JSONArray())
                    .put("activeKeys", new JSONObject()
                            .put(String.valueOf(providerId), "stale-selection"))
                    .put("meta", new JSONObject().put("providerLayout", 3));
            AtomicStore store = new AtomicStore(root);
            store.writeJson("subscriptions.json", seeded);

            manager = new SubscriptionManager(new AtomicStore(root), http);

            JSONObject persisted = store.readJsonStrict("subscriptions.json");
            JSONObject source = persisted.getJSONObject("providers")
                    .getJSONObject(String.valueOf(providerId))
                    .getJSONArray("sources").getJSONObject(0);
            assertEquals(ProviderCatalog.revision(providerId),
                    source.getString("catalogRevision"));
            assertEquals(0L, source.getLong("updatedAt"));
            assertEquals(0, source.getJSONArray("nodes").length());
            assertEquals(0, manager.nodeCountFast(providerId));
            assertFalse(persisted.getJSONObject("activeKeys")
                    .has(String.valueOf(providerId)));
        } finally {
            if (manager != null) manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void legacyProviderLayoutDropsRemovedSlotAndPreservesCustomData() throws Exception {
        File root = Files.createTempDirectory("exitfy-provider-layout").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = null;
        try {
            String customUrl = "https://custom.example/sub";
            JSONObject providers = new JSONObject()
                    .put("0", new JSONObject().put("sources", new JSONArray()))
                    .put("1", new JSONObject().put("sources", new JSONArray()))
                    .put("2", seededProvider("https://removed.example/sub", 0, 1))
                    .put("3", seededProvider(customUrl, 1, 1));
            JSONObject seeded = new JSONObject().put("providers", providers)
                    .put("manual", new JSONArray())
                    .put("customUrls", new JSONArray().put(new JSONObject()
                            .put("id", "custom-source")
                            .put("url", customUrl)
                            .put("title", "Custom source")))
                    .put("activeKeys", new JSONObject()
                            .put("2", "removed-selection")
                            .put("3", "custom-selection"))
                    .put("meta", new JSONObject());
            AtomicStore store = new AtomicStore(root);
            store.writeJson("subscriptions.json", seeded);

            manager = new SubscriptionManager(new AtomicStore(root), http);

            JSONObject migrated = store.readJsonStrict("subscriptions.json");
            assertEquals(3, migrated.getJSONObject("meta").getInt("providerLayout"));
            // Custom now lives one slot further along. Slot 2 belongs to a
            // built-in again, so what matters is that the removed provider
            // left nothing of its own behind on it.
            String custom = String.valueOf(SettingsModel.CUSTOM_PROVIDER_ID);
            assertFalse(migrated.toString().contains("removed.example"));
            assertFalse(migrated.getJSONObject("activeKeys").has("2"));
            assertEquals(ProviderCatalog.storageKey(2),
                    migrated.getJSONObject("providers").getJSONObject("2")
                            .getJSONArray("sources").getJSONObject(0).getString("url"));
            assertEquals("custom-selection",
                    migrated.getJSONObject("activeKeys").getString(custom));
            assertEquals(customUrl, migrated.getJSONObject("providers")
                    .getJSONObject(custom).getJSONArray("sources")
                    .getJSONObject(0).getString("url"));
            assertEquals(1, manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());
        } finally {
            if (manager != null) manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void seededCrossProviderStoreIsBoundedToGlobalTenThousand() throws Exception {
        File root = Files.createTempDirectory("exitfy-global-node-limit").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = null;
        try {
            String customUrl = "https://custom.example/large-sub";
            JSONObject providers = new JSONObject()
                    .put("0", seededBuiltInProvider(0, 0, 4_000))
                    .put("1", seededBuiltInProvider(1, 4_000, 4_000))
                    .put(String.valueOf(SettingsModel.CUSTOM_PROVIDER_ID),
                            seededProvider(customUrl, 8_000, 2_001));
            JSONObject seeded = new JSONObject().put("providers", providers)
                    .put("manual", new JSONArray())
                    .put("customUrls", new JSONArray().put(new JSONObject()
                            .put("id", "large-custom-source")
                            .put("url", customUrl)
                            .put("title", "Large custom source")))
                    .put("activeKeys", new JSONObject())
                    .put("meta", new JSONObject().put("providerLayout", 3));
            new AtomicStore(root).writeJson("subscriptions.json", seeded);

            manager = new SubscriptionManager(new AtomicStore(root), http);
            int total = 0;
            for (int provider = 0; provider <= SettingsModel.CUSTOM_PROVIDER_ID; provider++) {
                int count = manager.nodeCountFast(provider);
                assertTrue("per-provider node cap exceeded", count <= 10_000);
                total += count;
            }
            int builtInCount = (ProviderCatalog.isEnabled(0) ? 4_000 : 0)
                    + (ProviderCatalog.isEnabled(1) ? 4_000 : 0);
            int expectedCustom = Math.min(2_001, 10_000 - builtInCount);
            assertEquals(builtInCount + expectedCustom, total);
            assertEquals(expectedCustom,
                    manager.nodeCountFast(SettingsModel.CUSTOM_PROVIDER_ID));
        } finally {
            if (manager != null) manager.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void oversizedProfileTitleIsIgnoredBeforeBase64Decode() {
        Map<String, String> headers = new HashMap<>();
        headers.put("profile-title", "base64:" + repeat('A', 17 * 1024));
        LimitedHttpClient.Response response = new LimitedHttpClient.Response(
                200, new byte[0], headers);
        assertEquals("subscriptions.example", SubscriptionManager.responseTitle(
                response, "https://subscriptions.example/path"));
    }

    @Test
    public void profileTitleLimitNeverSplitsSupplementaryCharacters() {
        String title = "a".repeat(119) + "🚀" + "tail";
        Map<String, String> headers = new HashMap<>();
        headers.put("profile-title", title);
        LimitedHttpClient.Response response = new LimitedHttpClient.Response(
                200, new byte[0], headers);
        String result = SubscriptionManager.responseTitle(
                response, "https://subscriptions.example/path");
        assertEquals(120, result.codePointCount(0, result.length()));
        assertTrue(result.endsWith("🚀"));
    }

    private static String repeat(char value, int count) {
        StringBuilder output = new StringBuilder(count);
        for (int i = 0; i < count; i++) output.append(value);
        return output.toString();
    }

    private static int firstEnabledProvider() {
        for (int provider = 0; provider < ProviderCatalog.size(); provider++) {
            if (ProviderCatalog.isEnabled(provider)) return provider;
        }
        return -1;
    }

    private static JSONObject seededProvider(String url, int start, int count) throws Exception {
        JSONArray nodes = new JSONArray();
        for (int index = 0; index < count; index++) {
            JSONObject outbound = new JSONObject().put("type", "vless")
                    .put("server", "seed-" + (start + index) + ".example")
                    .put("server_port", 443)
                    .put("uuid", "11111111-1111-1111-1111-111111111111")
                    .put("encryption", "none");
            nodes.put(new JSONObject().put("uri", "").put("name", "seed")
                    .put("outbound", outbound));
        }
        JSONObject source = new JSONObject().put("url", url).put("title", "seed")
                .put("updatedAt", 1L).put("nodes", nodes);
        return new JSONObject().put("sources", new JSONArray().put(source));
    }

    private static JSONObject seededBuiltInProvider(int providerId, int start, int count)
            throws Exception {
        String url = ProviderCatalog.isEnabled(providerId)
                ? ProviderCatalog.storageKey(providerId)
                : "https://disabled-" + providerId + ".example/sub";
        JSONObject provider = seededProvider(url, start, count);
        if (ProviderCatalog.isEnabled(providerId)) {
            provider.getJSONArray("sources").getJSONObject(0)
                    .put("catalogRevision", ProviderCatalog.revision(providerId));
        }
        return provider;
    }

    private static final class CountingJSONObject extends JSONObject {
        int calls;

        CountingJSONObject(String source) throws Exception {
            super(source);
        }

        @Override
        public String toString() {
            calls++;
            return super.toString();
        }
    }

    private static final class BlockingObserver
            implements SubscriptionManager.OperationObserver {
        final AtomicBoolean blockParse = new AtomicBoolean();
        final AtomicBoolean blockPersist = new AtomicBoolean();
        final CountDownLatch parseEntered = new CountDownLatch(1);
        final CountDownLatch parseRelease = new CountDownLatch(1);
        final CountDownLatch persistEntered = new CountDownLatch(1);
        final CountDownLatch persistRelease = new CountDownLatch(1);
        final AtomicInteger fullSnapshots = new AtomicInteger();
        final AtomicInteger selectionSnapshots = new AtomicInteger();
        final AtomicInteger nodeLimitValidations = new AtomicInteger();

        @Override
        public void onImportParseStarted() {
            if (!blockParse.get()) return;
            parseEntered.countDown();
            await(parseRelease, "parse barrier was not released");
        }

        @Override
        public void onBeforePersist() {
            if (!blockPersist.get()) return;
            persistEntered.countDown();
            await(persistRelease, "persist barrier was not released");
        }

        @Override
        public void onSnapshotPublished(String kind) {
            if ("full".equals(kind)) fullSnapshots.incrementAndGet();
            else if ("selection".equals(kind)) selectionSnapshots.incrementAndGet();
        }

        @Override
        public void onNodeLimitValidation() {
            nodeLimitValidations.incrementAndGet();
        }

        private static void await(CountDownLatch latch, String message) {
            try {
                if (!latch.await(5, TimeUnit.SECONDS)) throw new AssertionError(message);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new AssertionError(message, error);
            }
        }
    }

    private static final class CancelAtPersistObserver
            implements SubscriptionManager.OperationObserver {
        private final AtomicBoolean armed = new AtomicBoolean();
        final CountDownLatch persistEntered = new CountDownLatch(1);
        final CountDownLatch persistRelease = new CountDownLatch(1);

        void arm() {
            armed.set(true);
        }

        @Override
        public void onBeforePersist() {
            if (!armed.compareAndSet(true, false)) return;
            persistEntered.countDown();
            boolean interrupted = false;
            try {
                while (true) {
                    try {
                        if (!persistRelease.await(5, TimeUnit.SECONDS)) {
                            throw new AssertionError("persist interrupt barrier timed out");
                        }
                        return;
                    } catch (InterruptedException error) {
                        interrupted = true;
                    }
                }
            } finally {
                if (interrupted) Thread.currentThread().interrupt();
            }
        }
    }

    private static final class HideDurableCommitObserver
            implements AtomicStore.CommitObserver {
        private final AtomicBoolean armed = new AtomicBoolean();
        private File durable;
        private File hidden;

        void arm() {
            armed.set(true);
        }

        @Override
        public void onCommitPinned(File target, File staged) throws Exception {
            if (!armed.compareAndSet(true, false)) return;
            durable = target;
            hidden = new File(target.getParentFile(), target.getName() + ".hidden-test");
            Files.move(target.toPath(), hidden.toPath());
            throw new java.io.IOException("injected durable recovery failure");
        }

        void restore() throws Exception {
            if (durable != null && hidden != null && hidden.isFile() && !durable.exists()) {
                Files.move(hidden.toPath(), durable.toPath());
            }
        }
    }

    private static final class MiniServer implements Closeable {
        private final AtomicReference<String> firstBody;
        private final AtomicInteger secondStatus;
        private final ServerSocket listener;
        private final Thread worker;
        private final CountDownLatch requestSeen;
        private final CountDownLatch releaseResponse;
        private final AtomicInteger requests = new AtomicInteger();
        private volatile String lastRequest = "";
        private volatile boolean running = true;

        MiniServer(AtomicReference<String> firstBody, AtomicInteger secondStatus) throws Exception {
            this(firstBody, secondStatus, null, null);
        }

        MiniServer(AtomicReference<String> firstBody, AtomicInteger secondStatus,
                   CountDownLatch requestSeen, CountDownLatch releaseResponse) throws Exception {
            this.firstBody = firstBody;
            this.secondStatus = secondStatus;
            this.requestSeen = requestSeen;
            this.releaseResponse = releaseResponse;
            listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            worker = new Thread(this::loop, "exitfy-test-http");
            worker.setDaemon(true);
            worker.start();
        }

        int port() {
            return listener.getLocalPort();
        }

        int requests() {
            return requests.get();
        }

        String lastRequest() {
            return lastRequest;
        }

        private void loop() {
            while (running) {
                try (Socket socket = listener.accept()) {
                    socket.setSoTimeout(2000);
                    String request = readHeaders(socket.getInputStream());
                    requests.incrementAndGet();
                    lastRequest = request;
                    if (requestSeen != null) requestSeen.countDown();
                    if (releaseResponse != null
                            && !releaseResponse.await(3, TimeUnit.SECONDS)) continue;
                    boolean second = request.startsWith("GET /second ");
                    int status = second ? secondStatus.get() : 200;
                    String body = second ? B1 : firstBody.get();
                    String title = second ? "Second source" : "First source";
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    String headers = "HTTP/1.1 " + status + (status == 200 ? " OK" : " Error") + "\r\n"
                            + "Content-Length: " + bytes.length + "\r\n"
                            + "Profile-Title: " + title + "\r\nConnection: close\r\n\r\n";
                    OutputStream output = socket.getOutputStream();
                    output.write(headers.getBytes(StandardCharsets.ISO_8859_1));
                    output.write(bytes);
                    output.flush();
                } catch (Exception ignored) {
                }
            }
        }

        private static String readHeaders(InputStream input) throws Exception {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            int matched = 0;
            while (output.size() < 32 * 1024) {
                int value = input.read();
                if (value < 0) break;
                output.write(value);
                int expected = matched == 0 || matched == 2 ? '\r' : '\n';
                if (value == expected) {
                    if (++matched == 4) break;
                } else {
                    matched = value == '\r' ? 1 : 0;
                }
            }
            return new String(output.toByteArray(), StandardCharsets.ISO_8859_1);
        }

        @Override
        public void close() {
            running = false;
            try { listener.close(); } catch (Exception ignored) { }
            try { worker.join(500); } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        }
    }

    @Test
    public void aBase64TitleSurvivesItsPlusCharacters() {
        // Verbatim header from a live subscription. Standard base64 uses '+',
        // and percent-decoding before the prefix is examined turns it into a
        // space, which destroyed the payload and left the raw header on screen.
        Map<String, String> headers = new HashMap<>();
        headers.put("profile-title", "base64:8J+TsSBJLlNocmltcCBMVEU=");
        LimitedHttpClient.Response response = new LimitedHttpClient.Response(
                200, new byte[0], headers);

        assertEquals("\uD83D\uDCF1 I.Shrimp LTE",
                SubscriptionManager.responseTitle(response, "https://example.invalid/sub"));
    }

    @Test
    public void aTitleWithoutBase64StillGetsPercentDecoded() {
        Map<String, String> headers = new HashMap<>();
        headers.put("profile-title", "My%20Source");
        LimitedHttpClient.Response response = new LimitedHttpClient.Response(
                200, new byte[0], headers);

        assertEquals("My Source",
                SubscriptionManager.responseTitle(response, "https://example.invalid/sub"));
    }

    @Test
    public void anInvalidKeyNamesWhatTheParserRefused() {
        // "Invalid key" alone left people comparing a key another client
        // accepts against no information at all.
        assertEquals(I18n.t("этот способ передачи не поддерживается выбранным ядром",
                        "the selected core cannot run this transport"),
                RejectionReason.describe("transport_unsupported"));
        assertNotEquals(RejectionReason.describe("uri_too_large"),
                RejectionReason.describe("transport_unsupported"));
        assertEquals(RejectionReason.describe("anything_unmapped"),
                RejectionReason.describe("something_new_we_did_not_map"));
        assertEquals("", RejectionReason.describe(null));
    }

    @Test
    public void aRefusalSummaryStaysShortAndFreeOfRepeats() {
        assertEquals("", RejectionReason.summarize(java.util.Collections.emptyList()));
        assertEquals(RejectionReason.describe("mux_unsupported"),
                RejectionReason.summarize(java.util.Arrays.asList(
                        "mux_unsupported", "mux_unsupported")));
        String many = RejectionReason.summarize(java.util.Arrays.asList(
                "mux_unsupported", "uri_too_large", "vless_vision_tls_required",
                "bind_unsupported"));
        assertEquals(2, many.split("; ", -1).length - 1);
    }

    @Test
    public void hidingASubscriptionKeepsItButDropsItsServers() throws Exception {
        AtomicReference<String> firstBody = new AtomicReference<>(A1);
        AtomicInteger secondStatus = new AtomicInteger(200);
        MiniServer server = new MiniServer(firstBody, secondStatus);
        File root = Files.createTempDirectory("exitfy-hide").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
        try {
            String base = "http://127.0.0.1:" + server.port();
            assertTrue(manager.addCustomUrl(base + "/first"));
            assertTrue(manager.addCustomUrl(base + "/second"));
            assertEquals(2, manager.refresh(
                    SettingsModel.CUSTOM_PROVIDER_ID, SettingsModel.defaults()).size());

            JSONObject before = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID);
            assertEquals(2, before.getJSONArray("customSources").length());
            assertEquals(2, before.getJSONArray("nodes").length());
            String firstId = before.getJSONArray("customSources")
                    .getJSONObject(0).getString("id");

            assertTrue(manager.setCustomUrlHidden(firstId, true));
            JSONObject hidden = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID);
            // The subscription stays listed and keeps its URL, but the list the
            // screen renders drops its servers -- that list is a separate
            // snapshot, so filtering the parsed nodes alone changed nothing.
            assertEquals(2, hidden.getJSONArray("customSources").length());
            assertTrue(hidden.getJSONArray("customSources")
                    .getJSONObject(0).getBoolean("hidden"));
            assertEquals(1, hidden.getJSONArray("nodes").length());
            assertEquals(1, manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID).size());

            assertTrue(manager.setCustomUrlHidden(firstId, false));
            assertEquals(2, manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID)
                    .getJSONArray("nodes").length());
            assertFalse(manager.setCustomUrlHidden(firstId, false));
            assertFalse(manager.setCustomUrlHidden("missing", true));
        } finally {
            server.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void movingASubscriptionStaysInsideTheList() throws Exception {
        File root = Files.createTempDirectory("exitfy-move").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
        try {
            assertTrue(manager.addCustomUrl("https://first.example/sub"));
            assertTrue(manager.addCustomUrl("https://second.example/sub"));
            JSONArray sources = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID)
                    .getJSONArray("customSources");
            String firstId = sources.getJSONObject(0).getString("id");
            String secondId = sources.getJSONObject(1).getString("id");

            assertTrue(manager.moveCustomUrl(firstId, 1));
            JSONArray moved = manager.uiState(SettingsModel.CUSTOM_PROVIDER_ID)
                    .getJSONArray("customSources");
            assertEquals(secondId, moved.getJSONObject(0).getString("id"));
            assertEquals(firstId, moved.getJSONObject(1).getString("id"));

            // The ends of the list have nowhere to go, and an unknown id is
            // not silently applied to whatever sits at that position.
            assertFalse(manager.moveCustomUrl(firstId, 1));
            assertFalse(manager.moveCustomUrl(secondId, -1));
            assertFalse(manager.moveCustomUrl("missing", 1));
            assertFalse(manager.moveCustomUrl(firstId, 0));
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }
}
