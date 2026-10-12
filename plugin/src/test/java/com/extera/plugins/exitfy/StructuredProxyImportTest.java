package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class StructuredProxyImportTest {
    @Test public void extraProtocolsAndUnknownServersAreNeverSilentlyLost() throws Exception {
        JSONObject good = endpoint("hysteria2").put("password", "pass").put("tls", tls());
        JSONObject invalid = new JSONObject(good.toString()).put("detour", "foreign");
        JSONObject unknown = endpoint("unsupported-test-protocol");
        JSONArray values = new JSONArray().put(good).put(invalid).put(unknown).put(new JSONObject().put("type", "direct"));
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(new JSONObject().put("outbounds", values).toString());
        assertEquals(1, result.nodes.size());
        assertEquals(2, result.rejected);
        assertEquals("hysteria2", result.nodes.get(0).outbound.getString("type"));
    }

    @Test public void httpHeaderAndSocksOptionsSurviveStorageWithoutAlteringTheirTypes() throws Exception {
        JSONObject source = endpoint("http").put("username", "user+").put("password", " pass ")
                .put("path", "/proxy").put("tls", tls()).put("headers", new JSONObject().put("X-Trace", new JSONArray().put("one").put("two")));
        ProtocolParser.Node parsed = StructuredProxyImport.parse(source, "HTTP server");
        ProtocolParser.Node stored = ProtocolParser.fromStoredJson(parsed.toStoredJson());
        JSONObject rendered = ProtocolParser.buildConfig(stored, 23415, "user", "password").getJSONArray("outbounds").getJSONObject(0);
        assertEquals(" pass ", rendered.getString("password"));
        assertEquals(2, rendered.getJSONObject("headers").getJSONArray("X-Trace").length());
        assertFalse(source.getJSONObject("tls").has("insecure"));
        assertFalse(stored.outbound.getJSONObject("tls").getBoolean("insecure"));
        assertFalse(stored.supports(CoreFamily.XRAY));
        JSONObject socks = endpoint("socks").put("version", "4a").put("udp_over_tcp", new JSONObject().put("enabled", true).put("version", 2));
        ProtocolParser.Node proxy = StructuredProxyImport.parse(socks, "SOCKS");
        assertEquals("4a", proxy.outbound.getString("version"));
        assertEquals(2, ProtocolParser.renderSingBoxOutbound(proxy.outbound).getJSONObject("udp_over_tcp").getInt("version"));
    }

    @Test public void multiplexChoosesSingBoxAndKeepsPaddingAndBrutalSettings() throws Exception {
        JSONObject mux = new JSONObject().put("enabled", true).put("protocol", "smux").put("padding", true)
                .put("max_connections", 4).put("min_streams", 2).put("max_streams", 8)
                .put("brutal", new JSONObject().put("enabled", true).put("up_mbps", 10).put("down_mbps", 20));
        JSONObject source = endpoint("vless").put("uuid", SubscriptionCompatibilityMatrixTest.ID).put("tls", tls()).put("multiplex", mux);
        ProtocolParser.Node node = SubscriptionParser.parseDetailed(source.toString()).nodes.get(0);
        assertTrue(node.supports(CoreFamily.SING_BOX));
        assertFalse(node.supports(CoreFamily.XRAY));
        JSONObject stored = ProtocolParser.fromStoredJson(node.toStoredJson()).outbound.getJSONObject("multiplex");
        assertTrue(stored.getBoolean("padding"));
        assertEquals(20, stored.getJSONObject("brutal").getInt("down_mbps"));
        assertEquals(4, stored.getInt("max_connections"));
    }

    @Test public void currentWireGuardEndpointKeepsAllPeersKeysAndReservedBytes() throws Exception {
        JSONObject first = peer("example.org", "0.0.0.0/0"), second = peer("2001:db8::1", "::/0");
        byte[] secondKey = new byte[32];
        java.util.Arrays.fill(secondKey, (byte) 3);
        second.put("public_key", java.util.Base64.getEncoder().encodeToString(secondKey));
        JSONObject source = new JSONObject().put("type", "wireguard").put("private_key", SubscriptionCompatibilityMatrixTest.KEY)
                .put("address", new JSONArray().put("10.0.0.2/32").put("fd00::2/128")).put("peers", new JSONArray().put(first).put(second));
        JSONObject profile = new JSONObject().put("remarks", "WG pool").put("endpoints", new JSONArray().put(source));
        JSONObject wrapped = new JSONObject().put("response", new JSONObject().put("profiles", new JSONArray().put(profile)));
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(wrapped.toString());
        assertEquals(result.reasons.toString(), 0, result.rejected);
        assertEquals(1, result.nodes.size());
        ProtocolParser.Node node = ProtocolParser.fromStoredJson(result.nodes.get(0).toStoredJson());
        assertEquals("WG pool", node.name);
        JSONObject settings = XrayConfigRenderer.renderOutbound(node).getJSONObject("settings");
        assertEquals(2, settings.getJSONArray("peers").length());
        assertEquals("[2001:db8::1]:51820", settings.getJSONArray("peers").getJSONObject(1).getString("endpoint"));
        assertEquals(25, settings.getJSONArray("peers").getJSONObject(0).getInt("keepAlive"));
        assertEquals(3, settings.getJSONArray("reserved").getInt(2));
        assertTrue(settings.getBoolean("noKernelTun"));
        profile.put("outbounds", "malformed");
        SubscriptionParser.ParseResult mixed = SubscriptionParser.parseDetailed(profile.toString());
        assertEquals(1, mixed.rejected);
        assertEquals(1, mixed.nodes.size());
    }

    @Test public void malformedFieldsCannotSmuggleLocalListenersOrReplaceSiblingServers() throws Exception {
        JSONObject good = endpoint("socks");
        JSONArray entries = new JSONArray().put(good);
        for (String key : new String[]{"detour", "bind_interface", "routing_mark", "sendThrough", "listen_port", "udp_over_tcp"}) {
            entries.put(new JSONObject(good.toString()).put(key, "forbidden"));
        }
        entries.put(endpoint("hysteria2").put("password", "pass").put("tls", tls()).put("up_mbps", "0"));
        entries.put(endpoint("tuic").put("uuid", SubscriptionCompatibilityMatrixTest.ID).put("password", "pass").put("tls", tls()).put("udp_relay_mode", "quic").put("udp_over_stream", true));
        entries.put(new JSONObject().put("type", "wireguard").put("server", "example.org").put("server_port", new java.math.BigInteger("18446744073709603436"))
                .put("private_key", SubscriptionCompatibilityMatrixTest.KEY).put("peer_public_key", SubscriptionCompatibilityMatrixTest.KEY)
                .put("local_address", "10.0.0.2/32"));
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(entries.toString());
        assertEquals(1, result.nodes.size());
        assertEquals(9, result.rejected);
    }

    @Test public void clashMixedProxyOrderAndOversizedSectionRemainConsistent() {
        String body = "proxies:\n - name: first\n   type: http\n   server: example.org\n   port: 8080\n"
                + " - name: second\n   type: trojan\n   server: example.org\n   port: 443\n   password: pass\n"
                + " - name: third\n   type: socks5\n   server: example.org\n   port: 1080\n";
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(body);
        assertEquals(0, result.rejected);
        assertEquals(3, result.nodes.size());
        assertEquals("first", result.nodes.get(0).name);
        assertEquals("second", result.nodes.get(1).name);
        assertEquals("third", result.nodes.get(2).name);
        assertTrue(SubscriptionParser.parseDetailed(body + "   password: " + "x".repeat(70_000)).nodes.isEmpty());
    }

    @Test public void anyTlsOfficialDefaultPortAndPasswordArePreserved() throws Exception {
        ProtocolParser.Node node = ProtocolParser.parse("anytls://pass%2Bword@example.org/?sni=real.example.org#Test");
        assertEquals("pass+word", node.outbound.getString("password"));
        assertEquals(443, node.outbound.getInt("server_port"));
        assertEquals("real.example.org", node.outbound.getJSONObject("tls").getString("server_name"));
        assertTrue(node.supports(CoreFamily.SING_BOX));
        assertFalse(node.supports(CoreFamily.XRAY));
    }

    private static JSONObject endpoint(String type) throws Exception { return SubscriptionCompatibilityMatrixTest.endpoint(type); }
    private static JSONObject tls() throws Exception { return new JSONObject().put("enabled", true); }
    private static JSONObject peer(String host, String allowed) throws Exception {
        return new JSONObject().put("address", host).put("port", 51820).put("public_key", SubscriptionCompatibilityMatrixTest.KEY)
                .put("allowed_ips", new JSONArray().put(allowed)).put("persistent_keepalive_interval", 25)
                .put("reserved", new JSONArray().put(1).put(2).put(3));
    }
}
