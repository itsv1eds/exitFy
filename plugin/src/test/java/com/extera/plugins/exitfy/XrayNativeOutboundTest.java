package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class XrayNativeOutboundTest {
    @Test
    public void subscriptionXrayJsonKeepsUnknownStreamSettingsForTheCore() throws Exception {
        JSONObject outbound = vnext("vless", "edge.example",
                "11111111-1111-1111-1111-111111111111")
                .put("streamSettings", new JSONObject()
                        .put("network", "xhttp")
                        .put("security", "tls")
                        .put("tlsSettings", new JSONObject().put("serverName", "sni.example"))
                        .put("xhttpSettings", new JSONObject().put("path", "/x").put("mode", "auto"))
                        .put("futureCoreSetting", "keep-me"));
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertEquals(1, nodes.size());
        ProtocolParser.Node node = nodes.get(0);
        assertTrue(node.supports(CoreFamily.XRAY));
        assertFalse(node.supports(CoreFamily.SING_BOX));
        assertEquals("edge.example", node.outbound.getString("server"));
        assertEquals("vless", node.outbound.getString("type"));
        assertEquals("xhttp", node.outbound.getJSONObject("transport").getString("type"));

        JSONObject rendered = XrayConfigRenderer.build(node, 32123, "", "");
        JSONObject proxy = rendered.getJSONArray("outbounds").getJSONObject(0);
        assertEquals("proxy", proxy.getString("tag"));
        assertEquals("vless", proxy.getString("protocol"));
        assertEquals("keep-me", proxy.getJSONObject("streamSettings")
                .getString("futureCoreSetting"));
        assertEquals("/x", proxy.getJSONObject("streamSettings")
                .getJSONObject("xhttpSettings").getString("path"));
        assertEquals(1, rendered.getJSONArray("outbounds").length());
        assertFalse(rendered.toString().contains("freedom"));
        assertEquals("socks", rendered.getJSONArray("inbounds").getJSONObject(0)
                .getString("protocol"));
    }

    @Test
    public void unknownXrayProtocolWithAddressIsXrayOnly() throws Exception {
        JSONObject outbound = new JSONObject()
                .put("protocol", "wireguard")
                .put("tag", "wg")
                .put("settings", new JSONObject()
                        .put("address", "wg.example")
                        .put("port", 51820)
                        .put("secretKey", "dGhpcy1pcy1ub3QtYS1yZWFsLWtleQ")
                        .put("peers", new JSONArray().put(new JSONObject()
                                .put("publicKey", "also-not-real")
                                .put("endpoint", "wg.example:51820"))));
        ProtocolParser.Node node = ProtocolParser.fromXrayOutbound("", "WG", outbound);
        assertTrue(node.supports(CoreFamily.XRAY));
        assertFalse(node.supports(CoreFamily.SING_BOX));
        assertEquals("wireguard", node.outbound.getString("type"));
        assertEquals("wg.example", node.outbound.getString("server"));
        assertEquals(51820, node.outbound.getInt("server_port"));
        JSONObject rendered = XrayConfigRenderer.renderOutbound(node);
        assertEquals("wireguard", rendered.getString("protocol"));
        assertEquals("also-not-real", rendered.getJSONObject("settings")
                .getJSONArray("peers").getJSONObject(0).getString("publicKey"));
    }

    @Test
    public void storedXrayOutboundRoundTripsUnknownFields() throws Exception {
        JSONObject outbound = vnext("trojan", "t.example", "")
                .put("settings", new JSONObject().put("servers", new JSONArray()
                        .put(new JSONObject().put("address", "t.example")
                                .put("port", 443).put("password", "secret"))))
                .put("streamSettings", new JSONObject().put("network", "raw")
                        .put("security", "tls")
                        .put("tlsSettings", new JSONObject().put("serverName", "t.example"))
                        .put("futureCoreSetting", true));
        ProtocolParser.Node original = ProtocolParser.fromXrayOutbound("", "T", outbound);
        ProtocolParser.Node restored = ProtocolParser.fromStoredJson(original.toStoredJson());
        assertTrue(restored.toStoredJson().has("xrayOutbound"));
        assertEquals("secret", restored.xrayOutbound.getJSONObject("settings")
                .getJSONArray("servers").getJSONObject(0).getString("password"));
        assertTrue(XrayConfigRenderer.renderOutbound(restored)
                .getJSONObject("streamSettings").getBoolean("futureCoreSetting"));
    }

    @Test
    public void rejectsLeakyAndChainedXrayOutbounds() throws Exception {
        assertRejected(new JSONObject().put("protocol", "freedom")
                .put("settings", new JSONObject().put("address", "1.1.1.1").put("port", 53)));
        assertRejected(vnext("vless", "mux.example",
                "11111111-1111-1111-1111-111111111111")
                .put("mux", new JSONObject().put("enabled", "true")));
        assertRejected(vnext("vless", "0.0.0.0",
                "11111111-1111-1111-1111-111111111111"));
        assertRejected(vnext("vless", "chain.example",
                "11111111-1111-1111-1111-111111111111")
                .put("proxySettings", new JSONObject().put("tag", "other")));
    }

    @Test
    public void muxProfilesKeepEveryOptionThroughImportStorageAndRendering() throws Exception {
        JSONObject mux = new JSONObject().put("enabled", true).put("concurrency", 6)
                .put("xudpConcurrency", 4).put("xudpProxyUDP443", "reject");
        JSONObject outbound = vnext("vless", "mux.example", "11111111-1111-1111-1111-111111111111")
                .put("mux", mux);
        JSONObject profile = new JSONObject().put("remarks", "Named server")
                .put("outbounds", new JSONArray().put(outbound));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(profile.toString());
        assertEquals(0, parsed.rejected);
        assertEquals(1, parsed.nodes.size());
        ProtocolParser.Node node = ProtocolParser.fromStoredJson(parsed.nodes.get(0).toStoredJson());
        assertEquals("Named server", node.name);
        assertEquals(parsed.nodes.get(0).normalizedKey, node.normalizedKey);
        JSONObject rendered = XrayConfigRenderer.renderOutbound(node).getJSONObject("mux");
        assertTrue(rendered.getBoolean("enabled"));
        assertEquals(6, rendered.getInt("concurrency"));
        assertEquals(4, rendered.getInt("xudpConcurrency"));
        assertEquals("reject", rendered.getString("xudpProxyUDP443"));
    }

    @Test
    public void muxAndNonMuxAtSameEndpointStayDistinctWhileExactMembersDeduplicate() throws Exception {
        JSONObject normal = vnext("vless", "same.example", "11111111-1111-1111-1111-111111111111");
        JSONObject mux = new JSONObject(normal.toString()).put("tag", "mux")
                .put("mux", new JSONObject().put("enabled", true).put("concurrency", 6));
        JSONArray profiles = new JSONArray()
                .put(new JSONObject().put("remarks", "Normal").put("outbounds", new JSONArray().put(normal)))
                .put(new JSONObject().put("remarks", "Mux").put("outbounds", new JSONArray().put(mux)))
                .put(new JSONObject().put("outbounds", new JSONArray().put(mux).put(normal)));
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(profiles.toString());
        assertEquals(2, result.nodes.size());
        assertEquals(0, result.rejected);
        assertFalse(result.nodes.get(0).normalizedKey.equals(result.nodes.get(1).normalizedKey));
    }

    @Test
    public void invalidMuxFailsOnlyItsOwnEntryAndSignedShortDefaultsRemainValid() throws Exception {
        Object[] invalid = {true, new JSONArray(), new JSONObject().put("enabled", 1),
                new JSONObject().put("concurrency", "6"), new JSONObject().put("concurrency", 1.5),
                new JSONObject().put("concurrency", 32768), new JSONObject().put("xudpConcurrency", -32769),
                new JSONObject().put("xudpProxyUDP443", "unknown"),
                new JSONObject().put("proxySettings", new JSONObject())};
        for (Object value : invalid) {
            JSONObject normal = vnext("vless", "valid.example", "11111111-1111-1111-1111-111111111111");
            JSONObject bad = new JSONObject(normal.toString()).put("mux", value);
            SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(
                    new JSONObject().put("outbounds", new JSONArray().put(bad).put(normal)).toString());
            assertEquals(1, result.nodes.size());
            assertEquals(1, result.rejected);
        }
        for (JSONObject mux : new JSONObject[]{new JSONObject(),
                new JSONObject().put("enabled", false).put("concurrency", -1).put("xudpConcurrency", 0),
                new JSONObject().put("concurrency", Short.MIN_VALUE).put("xudpConcurrency", Short.MAX_VALUE)
                        .put("xudpProxyUDP443", "skip")}) {
            ProtocolParser.Node node = ProtocolParser.fromXrayOutbound("", "Mux",
                    vnext("vless", "valid.example", "11111111-1111-1111-1111-111111111111").put("mux", mux));
            assertTrue(XrayConfigRenderer.renderOutbound(node).has("mux"));
        }
    }

    @Test
    public void stripsDialerProxyButKeepsTheRestOfStreamSettings() throws Exception {
        JSONObject outbound = vnext("vless", "sockopt.example",
                "11111111-1111-1111-1111-111111111111")
                .put("streamSettings", new JSONObject()
                        .put("network", "ws")
                        .put("wsSettings", new JSONObject().put("path", "/ws"))
                        .put("sockopt", new JSONObject()
                                .put("dialerProxy", "fragment")
                                .put("tcpMaxSeg", 1400)));
        JSONObject rendered = XrayConfigRenderer.renderOutbound(
                ProtocolParser.fromXrayOutbound("", "S", outbound));
        JSONObject sockopt = rendered.getJSONObject("streamSettings").optJSONObject("sockopt");
        assertNotNull(sockopt);
        assertFalse(sockopt.has("dialerProxy"));
        assertEquals(1400, sockopt.getInt("tcpMaxSeg"));
    }

    private static void assertRejected(JSONObject outbound) {
        try {
            ProtocolParser.fromXrayOutbound("", "bad", outbound);
            fail("expected rejection");
        } catch (Exception expected) {
            assertNotNull(expected.getMessage());
        }
    }

    private static JSONObject vnext(String protocol, String address, String id)
            throws Exception {
        JSONObject settings;
        if (protocol.equals("trojan") || protocol.equals("shadowsocks")) {
            settings = new JSONObject().put("servers", new JSONArray());
        } else {
            JSONObject user = new JSONObject().put("id", id).put("encryption", "none");
            settings = new JSONObject().put("vnext", new JSONArray()
                    .put(new JSONObject().put("address", address).put("port", 443)
                            .put("users", new JSONArray().put(user))));
        }
        return new JSONObject().put("protocol", protocol).put("settings", settings);
    }
}
