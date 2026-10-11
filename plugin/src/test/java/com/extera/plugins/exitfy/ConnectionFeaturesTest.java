package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import java.io.File;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import static org.junit.Assert.*;

public class ConnectionFeaturesTest {
    private static String key(int seed) {
        byte[] value = new byte[32]; Arrays.fill(value, (byte) seed);
        return Base64.getEncoder().encodeToString(value);
    }
    private static String awg() {
        return "[Interface]\nPrivateKey = " + key(1)
                + "\nAddress = 10.23.0.2/32, fd00::2/128\nDNS = 1.1.1.1\nMTU = 1280\n"
                + "Jc = 3\nJmin = 32\nJmax = 64\nS1 = 24\nS2 = 24\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890\n"
                + "[Peer]\nPublicKey = " + key(2) + "\nPresharedKey = " + key(3)
                + "\nEndpoint = example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";
    }
    private static ProtocolParser.Node vless(int id) throws Exception {
        return ProtocolParser.parse("vless://11111111-1111-1111-1111-111111111111@node"
                + id + ".example:443?security=tls#Server" + id);
    }

    @Test public void settingsPreserveSiblingPreferencesAndRoundTrip() throws Exception {
        SettingsModel settings = SettingsModel.fromJson("{}").withSetting("balance_mode", "round_robin")
                .withSetting("sort_by_ping", true).withSetting("tutorial_step", 4)
                .withSetting("enabled", true).withSetting("provider_id", 3)
                .withSetting("subscription_user_agent", "CustomClient/1");
        SettingsModel saved = SettingsModel.fromJson(settings.toJson().toString());
        assertEquals(settings, saved);
        assertTrue(saved.enabled); assertTrue(saved.sortByPing); assertEquals(4, saved.tutorialStep);
        assertEquals("round_robin", saved.balanceMode);
        assertEquals("CustomClient/1", saved.withSetting("dual_core", false).subscriptionUserAgent);
        assertEquals(4, saved.withSetting("dual_core", false).tutorialStep);
        assertArrayEquals(new String[]{"Happ/5.2.0"}, SettingsModel.subscriptionUserAgents(""));
        assertEquals("off", SettingsModel.fromJson("{}").balanceMode);
    }

    @Test public void awgConfPreservesObfuscationPeersAndPrivateStore() throws Exception {
        ProtocolParser.Node node = AwgConfigParser.parse(awg() + "\n[Peer]\nPublicKey = " + key(4)
                + "\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 10.99.0.0/16\n");
        assertTrue(node.supports(CoreFamily.SING_BOX)); assertFalse(node.supports(CoreFamily.XRAY));
        assertEquals("", node.uri); assertEquals("AmneziaWG", node.name);
        JSONObject outbound = node.outbound;
        assertEquals("3", outbound.getJSONObject("awg").getString("jc"));
        assertEquals(2, outbound.getJSONArray("peers").length());
        assertEquals(2, outbound.getJSONArray("local_address").length());
        assertEquals(node.normalizedKey, ProtocolParser.fromStoredJson(node.toStoredJson()).normalizedKey);
        assertEquals(1, SubscriptionParser.parseDetailed(awg()).nodes.size());
        assertEquals("amneziawg", ProtocolParser.buildConfig(node, 28765, "u", "p")
                .getJSONArray("outbounds").getJSONObject(0).getString("type"));
    }

    @Test public void awgRejectsCommandsBadKeysAndInvalidEndpointWithoutLeaking() throws Exception {
        for (String invalid : new String[]{awg().replace("Jc = 3", "PostUp = secret-command"),
                awg().replace(key(1), "secret-key"), awg().replace("example.com:51820", "example.com:99999")}) {
            try { AwgConfigParser.parse(invalid); fail("invalid AWG config accepted"); }
            catch (IllegalArgumentException expected) { assertFalse(expected.getMessage().contains("secret")); }
            assertTrue(SubscriptionParser.parseDetailed(invalid).nodes.isEmpty());
        }
    }

    @Test public void awgRejectsDangerousHandshakeSizesBeforeImport() throws Exception {
        for (String parameter : new String[]{"Jc = 4294967295", "I1 = <r -1>",
                "I1 = <r 999999999>", "Jc = 128\nJmax = 65000", "S4 = 65000"}) {
            String text = awg().replace("Jc = 3", parameter);
            assertTrue(SubscriptionParser.parseDetailed(text).nodes.isEmpty());
        }
        String valid = awg().replace("Jc = 3",
                "Jc = 3\nI1 = <b 0x0102><r 32><rc 8><rd 4><t><dz 2><d><ds>")
                .replace("PersistentKeepalive = 25", "PersistentKeepalive = 22-30");
        assertEquals(1, SubscriptionParser.parseDetailed(valid).nodes.size());
        assertEquals("22-30", AwgConfigParser.parse(valid).outbound.getJSONArray("peers")
                .getJSONObject(0).getString("persistent_keepalive_interval"));
    }

    @Test public void ownedPortIsRememberedAndForeignOrBusyPortsAreSkipped() throws Exception {
        File root = Files.createTempDirectory("exitfy-port-ownership").toFile();
        try {
            AtomicStore store = new AtomicStore(root);
            int first = new LocalPortAllocator(store).allocate(Collections.emptySet(), true);
            assertNotEquals(12334, first); assertNotEquals(10808, first);
            LocalPortAllocator reloaded = new LocalPortAllocator(store);
            assertEquals(first, reloaded.allocate(Collections.emptySet(), true));
            int alternate = reloaded.allocate(new HashSet<>(Arrays.asList(first, 12334, 10808)), true);
            assertNotEquals(first, alternate);
            try (ServerSocket foreign = new ServerSocket(alternate, 1, InetAddress.getByName("127.0.0.1"))) {
                int third = reloaded.allocate(Collections.emptySet(), true);
                assertNotEquals(alternate, third); assertFalse(foreign.isClosed());
            }
        } finally { TestFiles.deleteRecursively(root); }
    }

    @Test public void mixedBalancerUsesAuthenticatedPrivateRoutesAndEveryMember() throws Exception {
        File root = Files.createTempDirectory("exitfy-balancer-config").toFile();
        try {
            ProtocolParser.Node first = vless(1), second = AwgConfigParser.parse(awg());
            List<ProtocolParser.Node> nodes = Arrays.asList(first, second);
            ProxySession.Credentials auth = ProxySession.newCredentials();
            BalancerConfigRenderer.Plan plan = BalancerConfigRenderer.build(nodes, 29001, auth, "round_robin",
                    new LocalPortAllocator(new AtomicStore(root)),
                    Collections.unmodifiableSet(new HashSet<>(Arrays.asList(12334, 10808))));
            assertEquals(2, plan.memberCount); assertNotNull(plan.side);
            JSONArray members = plan.main.getJSONArray("outbounds"); assertEquals(2, members.length());
            JSONObject hop = members.getJSONObject(1).getJSONObject("settings").getJSONArray("servers").getJSONObject(0);
            int port = hop.getInt("port"); assertNotEquals(12334, port); assertNotEquals(10808, port);
            assertNotEquals(29001, port);
            assertEquals("127.0.0.1", hop.getString("address"));
            assertEquals(auth.username, hop.getJSONArray("users").getJSONObject(0).getString("user"));
            JSONObject inbound = plan.side.getJSONArray("inbounds").getJSONObject(0);
            assertEquals(port, inbound.getInt("listen_port"));
            assertEquals(auth.password, inbound.getJSONArray("users").getJSONObject(0).getString("password"));
            assertEquals("amneziawg", plan.side.getJSONArray("outbounds").getJSONObject(0).getString("type"));
            assertEquals("roundRobin", plan.main.getJSONObject("routing").getJSONArray("balancers")
                    .getJSONObject(0).getJSONObject("strategy").getString("type"));
            BalancerConfigRenderer.Plan sticky = BalancerConfigRenderer.build(Arrays.asList(first, vless(2)), 29002,
                    auth, "sticky", new LocalPortAllocator(new AtomicStore(root)), new HashSet<>());
            assertNull(sticky.side); assertEquals("leastPing", sticky.main.getJSONObject("routing")
                    .getJSONArray("balancers").getJSONObject(0).getJSONObject("strategy").getString("type"));
            assertNotEquals(BalancerConfigRenderer.poolKey(nodes), BalancerConfigRenderer.poolKey(Arrays.asList(first, vless(3))));
        } finally { TestFiles.deleteRecursively(root); }
    }

    @Test public void wrappersImportOnlyExplicitProfilesAndIgnoreMetadata() throws Exception {
        JSONObject proxy = vless(1).outbound;
        JSONObject wrapper = new JSONObject().put("response", new JSONObject().put("configs", new JSONArray()
                .put(new JSONObject().put("outbounds", new JSONArray().put(proxy)))))
                .put("metadata", new JSONObject().put("outbounds", new JSONArray().put(vless(2).outbound)));
        assertEquals(1, SubscriptionParser.parseNodes(wrapper.toString()).size());
        assertEquals(1, SubscriptionParser.parseNodes(new JSONArray().put(wrapper).toString()).size());
    }

    @Test public void sortingHappensBeforePaginationAndKeepsUnknownResultsLast() throws Exception {
        File root = Files.createTempDirectory("exitfy-ping-sort").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            SubscriptionManager manager = new SubscriptionManager(new AtomicStore(root), http);
            for (int i=0; i<12; i++) manager.addManualUri(vless(i).uri);
            List<ProtocolParser.Node> nodes = manager.nodes(SettingsModel.CUSTOM_PROVIDER_ID);
            manager.setProbeResult(nodes.get(10).normalizedKey, "ok", 50);
            manager.setProbeResult(nodes.get(11).normalizedKey, "ok", 10);
            JSONObject sorted = manager.uiState(3, 0, 10, "", "all", true);
            JSONArray list = sorted.getJSONArray("nodes");
            assertEquals(nodes.get(11).normalizedKey, list.getJSONObject(0).getString("key"));
            assertEquals(nodes.get(10).normalizedKey, list.getJSONObject(1).getString("key"));
            assertEquals(-1, list.getJSONObject(2).getLong("latency"));
            JSONObject unsorted = manager.uiState(3, 0, 10, "", "all", false);
            assertEquals(nodes.get(0).normalizedKey, unsorted.getJSONArray("nodes").getJSONObject(0).getString("key"));
            manager.close();
        } finally { http.close(); TestFiles.deleteRecursively(root); }
    }
}
