package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SubscriptionParserTest {
    private static final String VLESS =
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com#One";
    private static final String VALID_VLESS_ENCRYPTION =
            "mlkem768x25519plus.native.0rtt."
                    + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    @Test
    public void decodesBase64Subscription() {
        String body = Base64.getEncoder().encodeToString((VLESS + "\n").getBytes(StandardCharsets.UTF_8));
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(body);
        assertEquals(1, nodes.size());
        assertEquals("vless", nodes.get(0).outbound.optString("type"));
    }

    @Test
    public void structuredImportPreservesOpaqueWhitespaceAndExplicitPacketNone() throws Exception {
        JSONObject trojan = new JSONObject()
                .put("type", "trojan").put("server", "space.example")
                .put("server_port", 443).put("password", " secret ")
                .put("tls", new JSONObject().put("enabled", true)
                        .put("server_name", "space.example").put("insecure", false))
                .put("transport", new JSONObject().put("type", "ws")
                        .put("path", " /opaque path "));
        ProtocolParser.Node node = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(trojan)).toString()).get(0);
        assertEquals(" secret ", node.outbound.getString("password"));
        assertEquals(" /opaque path ", node.outbound.getJSONObject("transport")
                .getString("path"));
        assertEquals(" secret ", XrayConfigRenderer.renderOutbound(node.outbound)
                .getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
                .getString("password"));

        JSONObject vless = new JSONObject()
                .put("type", "vless").put("server", "none.example")
                .put("server_port", 443)
                .put("uuid", "11111111-1111-1111-1111-111111111111")
                .put("encryption", "none").put("packet_encoding", "");
        ProtocolParser.Node explicitNone = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(vless)).toString()).get(0);
        assertTrue(explicitNone.outbound.has("packet_encoding"));
        assertEquals("", explicitNone.outbound.getString("packet_encoding"));
        assertTrue(explicitNone.supports(CoreFamily.SING_BOX));
        assertFalse(explicitNone.supports(CoreFamily.XRAY));
    }

    @Test
    public void structuredAndClashImportsPreserveOpaqueSingleSpaceValues() throws Exception {
        JSONArray structured = new JSONArray()
                .put(new JSONObject().put("type", "vless")
                        .put("server", "vless-space.example").put("server_port", 443)
                        .put("uuid", " custom-id ").put("encryption", "none")
                        .put("transport", new JSONObject().put("type", "mkcp")
                                .put("legacy_seed", " ")))
                .put(new JSONObject().put("type", "vmess")
                        .put("server", "vmess-space.example").put("server_port", 443)
                        .put("uuid", " ").put("alter_id", 0).put("security", "auto"))
                .put(new JSONObject().put("type", "trojan")
                        .put("server", "trojan-space.example").put("server_port", 443)
                        .put("password", " "))
                .put(new JSONObject().put("type", "shadowsocks")
                        .put("server", "ss-space.example").put("server_port", 443)
                        .put("method", "aes-256-gcm").put("password", " "));
        SubscriptionParser.ParseResult structuredResult = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", structured).toString());
        assertEquals(structuredResult.reasons.toString(), 4, structuredResult.nodes.size());
        for (ProtocolParser.Node node : structuredResult.nodes) {
            String type = node.outbound.getString("type");
            String opaque = type.equals("vless") || type.equals("vmess")
                    ? node.outbound.getString("uuid") : node.outbound.getString("password");
            assertTrue(opaque.equals(" ") || opaque.equals(" custom-id "));
        }
        ProtocolParser.Node structuredVless = structuredResult.nodes.stream()
                .filter(node -> node.outbound.optString("type").equals("vless"))
                .findFirst().get();
        assertEquals(" ", structuredVless.outbound.getJSONObject("transport")
                .getString("legacy_seed"));
        assertEquals(" ", XrayConfigRenderer.renderOutbound(structuredVless.outbound)
                .getJSONObject("streamSettings").getJSONObject("finalmask")
                .getJSONArray("udp").getJSONObject(0).getJSONObject("settings")
                .getString("value"));

        String clash = "proxies:\n"
                + "  - name: VLESS space\n    type: vless\n"
                + "    server: vless-clash.example\n    port: 443\n"
                + "    uuid: \" custom-id \"\n"
                + "  - name: VMess space\n    type: vmess\n"
                + "    server: vmess-clash.example\n    port: 443\n"
                + "    uuid: \" \"\n"
                + "  - name: Trojan space\n    type: trojan\n"
                + "    server: trojan-clash.example\n    port: 443\n"
                + "    password: \" \"\n"
                + "  - name: SS space\n    type: ss\n"
                + "    server: ss-clash.example\n    port: 443\n"
                + "    cipher: aes-256-gcm\n    password: \" \"\n"
                + "  - name: Hysteria space\n    type: hysteria\n"
                + "    server: hy-clash.example\n    port: 443\n"
                + "    auth: \" \"\n    obfs: \" \"\n"
                + "  - name: Hysteria2 space\n    type: hysteria2\n"
                + "    server: hy2-clash.example\n    port: 443\n"
                + "    password: \" \"\n    obfs: salamander\n"
                + "    obfs-password: \" \"\n"
                + "  - name: TUIC space\n    type: tuic\n"
                + "    server: tuic-clash.example\n    port: 443\n"
                + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                + "    password: \" \"\n";
        SubscriptionParser.ParseResult clashResult = SubscriptionParser.parseDetailed(clash);
        assertEquals(clashResult.reasons.toString(), 7, clashResult.nodes.size());
        assertEquals(" ", clashResult.nodes.stream()
                .filter(node -> node.outbound.optString("type").equals("hysteria"))
                .findFirst().get().outbound.getString("auth_str"));
        assertEquals(" ", clashResult.nodes.stream()
                .filter(node -> node.outbound.optString("type").equals("hysteria2"))
                .findFirst().get().outbound.getJSONObject("obfs").getString("password"));
    }

    @Test
    public void rejectsMalformedStructuredUsersAndMalformedBase64Utf8() throws Exception {
        JSONArray invalid = new JSONArray();
        JSONObject base = new JSONObject()
                .put("type", "vless").put("server", "users.example")
                .put("server_port", 443)
                .put("encryption", "none");
        invalid.put(new JSONObject(base.toString()).put("users", new JSONArray()));
        invalid.put(new JSONObject(base.toString()).put("users",
                new JSONArray().put("not-an-object")));
        invalid.put(new JSONObject(base.toString()).put("users", new JSONArray()
                .put(new JSONObject().put("uuid",
                        "11111111-1111-1111-1111-111111111111"))
                .put(new JSONObject().put("uuid",
                        "22222222-2222-2222-2222-222222222222"))));
        invalid.put(new JSONObject(base.toString())
                .put("uuid", "11111111-1111-1111-1111-111111111111")
                .put("users", new JSONArray().put(new JSONObject().put(
                        "uuid", "22222222-2222-2222-2222-222222222222"))));
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(invalid.length(), rejected.rejected);

        byte[] prefix = "trojan://secret@invalid-utf8.example:443"
                .getBytes(StandardCharsets.UTF_8);
        byte[] malformed = new byte[prefix.length + 1];
        System.arraycopy(prefix, 0, malformed, 0, prefix.length);
        malformed[malformed.length - 1] = (byte) 0xff;
        assertTrue(SubscriptionParser.parseNodes(
                Base64.getEncoder().encodeToString(malformed)).isEmpty());
    }

    @Test
    public void extractsRemnawaveJsonAndDeduplicatesOnlyEqualConfigs() throws Exception {
        String sameConfigDifferentName = VLESS.substring(0, VLESS.indexOf('#')) + "#Two";
        JSONObject value = new JSONObject().put("links", new JSONArray().put(VLESS).put(sameConfigDifferentName))
                .put("ssConfLinks", new JSONObject().put("main", VLESS));
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(value.toString());
        assertEquals(1, nodes.size());
    }

    @Test
    public void extractsSingBoxJsonOutbound() throws Exception {
        JSONObject outbound = new JSONObject().put("type", "vless").put("tag", "JSON node")
                .put("server", "json.example").put("server_port", 443)
                .put("uuid", "22222222-2222-2222-2222-222222222222")
                .put("tls", new JSONObject().put("enabled", true).put("server_name", "sni.example"));
        String body = new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString();
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(body);
        assertEquals(1, nodes.size());
        assertEquals("json.example", nodes.get(0).outbound.optString("server"));
    }

    @Test
    public void extractsXrayVnextJsonAsNeutralNode() throws Exception {
        JSONObject user = new JSONObject()
                .put("id", "44444444-4444-4444-4444-444444444444")
                .put("flow", "xtls-rprx-vision");
        JSONObject endpoint = new JSONObject().put("address", "xray.example").put("port", 443)
                .put("users", new JSONArray().put(user));
        JSONObject stream = new JSONObject().put("network", "tcp").put("security", "reality")
                .put("realitySettings", new JSONObject().put("serverName", "edge.example")
                        .put("publicKey", realityPublicKey()).put("shortId", "42")
                        .put("fingerprint", "chrome"));
        JSONObject outbound = new JSONObject().put("protocol", "vless").put("tag", "Xray export")
                .put("settings", new JSONObject().put("vnext", new JSONArray().put(endpoint)))
                .put("streamSettings", stream);
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertEquals(1, nodes.size());
        JSONObject parsed = nodes.get(0).outbound;
        assertEquals("xray.example", parsed.optString("server"));
        assertEquals("xtls-rprx-vision", parsed.optString("flow"));
        assertFalse(parsed.has("transport"));
        assertEquals("edge.example", parsed.optJSONObject("tls").optString("server_name"));
    }

    @Test
    public void structuredGrpcWithoutServiceNameRemainsEmpty() throws Exception {
        JSONObject outbound = xrayVnext("vless", "grpc.example",
                "55555555-5555-5555-5555-555555555555", "none")
                .put("streamSettings", new JSONObject().put("network", "grpc")
                        .put("grpcSettings", new JSONObject()));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertEquals(1, parsed.nodes.size());
        JSONObject transport = parsed.nodes.get(0).outbound.getJSONObject("transport");
        assertEquals("grpc", transport.getString("type"));
        assertFalse(transport.has("service_name"));
        assertEquals("", XrayConfigRenderer.renderOutbound(parsed.nodes.get(0).outbound)
                .getJSONObject("streamSettings").getJSONObject("grpcSettings")
                .optString("serviceName", ""));
    }

    @Test
    public void structuredVisionRequirementsHaveCleanRejections() throws Exception {
        JSONObject direct = direct("vless").put("flow", "xtls-rprx-vision");
        JSONObject xray = xrayVnext("vless", "vision.example",
                "66666666-6666-6666-6666-666666666666", "none");
        xray.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0)
                .put("flow", "xtls-rprx-vision");

        JSONObject transported = direct("vless").put("flow", "xtls-rprx-vision")
                .put("tls", new JSONObject().put("enabled", true)
                        .put("server_name", "edge.example").put("insecure", false))
                .put("transport", new JSONObject().put("type", "ws").put("path", "/ws"));
        JSONObject xhttp = xrayVnext("vless", "xhttp.example",
                "77777777-7777-7777-7777-777777777777", "none");
        xhttp.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0)
                .put("flow", "xtls-rprx-vision");
        xhttp.put("streamSettings", new JSONObject().put("network", "xhttp")
                .put("security", "reality")
                .put("realitySettings", new JSONObject().put("serverName", "edge.example")
                        .put("publicKey", realityPublicKey()).put("shortId", "42")
                        .put("fingerprint", "chrome"))
                .put("xhttpSettings", new JSONObject().put("path", "/xhttp")
                        .put("mode", "stream-one")));

        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(direct).put(xray).put(transported).put(xhttp)).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(4, parsed.rejected);
        assertTrue(parsed.reasons.contains("vless_vision_tls_required"));
        assertTrue(parsed.reasons.contains("vless_vision_raw_required"));
    }

    @Test
    public void extractsOnlySupportedProxyOutboundsFromFullXrayJson() throws Exception {
        JSONArray outbounds = new JSONArray()
                .put(xrayVnext("vless", "v.example",
                        "11111111-1111-1111-1111-111111111111", "none"))
                .put(xrayVnext("vmess", "vm.example",
                        "22222222-2222-2222-2222-222222222222", "auto"))
                .put(new JSONObject().put("protocol", "trojan").put("tag", "trojan")
                        .put("settings", new JSONObject().put("servers", new JSONArray()
                                .put(new JSONObject().put("address", "t.example")
                                        .put("port", 443).put("password", "secret")))))
                .put(new JSONObject().put("protocol", "shadowsocks").put("tag", "ss")
                        .put("settings", new JSONObject().put("servers", new JSONArray()
                                .put(new JSONObject().put("address", "s.example")
                                        .put("port", 8388).put("method", "aes-256-gcm")
                                        .put("password", "password")))));
        JSONObject fakeRemoteInbound = xrayVnext("vless", "must-not-run.example",
                "99999999-9999-9999-9999-999999999999", "none");
        JSONObject full = new JSONObject()
                .put("log", new JSONObject().put("loglevel", "debug"))
                .put("dns", new JSONObject().put("servers", new JSONArray().put("8.8.8.8")))
                .put("routing", new JSONObject().put("domainStrategy", "AsIs"))
                .put("inbounds", new JSONArray().put(fakeRemoteInbound))
                .put("outbounds", outbounds);
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(full.toString());
        assertEquals(4, nodes.size());
        assertTrue(nodes.stream().noneMatch(node ->
                "must-not-run.example".equals(node.outbound.optString("server"))));
    }

    @Test
    public void preservesXhttpAndCurrentFinalmaskFromXrayJson() throws Exception {
        JSONObject xhttp = xrayVnext("vless", "xhttp.example",
                "33333333-3333-3333-3333-333333333333", "none")
                .put("streamSettings", new JSONObject().put("network", "xhttp")
                        .put("security", "tls")
                        .put("tlsSettings", new JSONObject().put("serverName", "edge.example"))
                        .put("xhttpSettings", new JSONObject()
                                .put("host", "host.example").put("path", "/x")
                                .put("mode", "packet-up")
                                .put("xPaddingBytes", "100-200")));
        List<ProtocolParser.Node> xhttpNodes = SubscriptionParser.parseNodes(
                new JSONObject().put("outbounds", new JSONArray().put(xhttp)).toString());
        assertEquals(1, xhttpNodes.size());
        JSONObject transport = xhttpNodes.get(0).outbound.optJSONObject("transport");
        assertEquals("xhttp", transport.optString("type"));
        assertEquals("packet-up", transport.optString("mode"));
        assertEquals("100-200", transport.optJSONObject("extra").optString("xPaddingBytes"));

        JSONObject mkcp = xrayVnext("vmess", "kcp.example",
                "44444444-4444-4444-4444-444444444444", "auto")
                .put("streamSettings", new JSONObject().put("network", "mkcp")
                        .put("kcpSettings", new JSONObject().put("tti", 20).put("mtu", 1350))
                        .put("finalmask", new JSONObject().put("udp", new JSONArray()
                                .put(new JSONObject().put("type", "mkcp-legacy")
                                        .put("settings", new JSONObject()
                                                .put("value", "mask.example")))
                                .put(new JSONObject().put("type", "mkcp-legacy")
                                        .put("settings", new JSONObject()
                                                .put("header", "dns"))))));
        List<ProtocolParser.Node> mkcpNodes = SubscriptionParser.parseNodes(
                new JSONObject().put("outbounds", new JSONArray().put(mkcp)).toString());
        assertEquals(1, mkcpNodes.size());
        JSONObject mkcpTransport = mkcpNodes.get(0).outbound.optJSONObject("transport");
        assertEquals("mkcp", mkcpTransport.optString("type"));
        assertEquals("dns", mkcpTransport.optString("legacy_header"));
        assertEquals("mask.example", mkcpTransport.optString("legacy_seed"));
    }

    @Test
    public void structuredXhttpRejectsBothAliasPointersEvenWhenEitherIsEmpty()
            throws Exception {
        JSONArray ambiguous = new JSONArray();
        for (JSONObject[] aliases : new JSONObject[][]{
                {new JSONObject(), new JSONObject().put("path", "/split")},
                {new JSONObject().put("path", "/xhttp"), new JSONObject()},
                {new JSONObject(), new JSONObject()},
        }) {
            JSONObject outbound = xrayVnext("vless", "ambiguous-xhttp.example",
                    "34343434-3434-3434-3434-343434343434", "none")
                    .put("streamSettings", new JSONObject().put("network", "xhttp")
                            .put("xhttpSettings", aliases[0])
                            .put("splithttpSettings", aliases[1]));
            ambiguous.put(outbound);
        }
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", ambiguous).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(3, parsed.rejected);
    }

    @Test
    public void structuredXhttpRejectsHybridOuterAndExtraSemantics() throws Exception {
        JSONObject overlapping = xrayVnext("vless", "overlap.example",
                "35353535-3535-3535-3535-353535353535", "none")
                .put("streamSettings", new JSONObject().put("network", "xhttp")
                        .put("xhttpSettings", new JSONObject().put("path", "/x")
                                .put("extra", new JSONObject().put("noSSEHeader", true))
                                .put("noSSEHeader", false)));
        JSONObject nonOverlapping = xrayVnext("vless", "nonoverlap.example",
                "36363636-3636-3636-3636-363636363636", "none")
                .put("streamSettings", new JSONObject().put("network", "xhttp")
                        .put("xhttpSettings", new JSONObject().put("path", "/x")
                                .put("extra", new JSONObject().put("xPaddingBytes", "10-20"))
                                .put("scMinPostsIntervalMs", 30)));
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(overlapping).put(nonOverlapping)).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(2, rejected.rejected);
    }

    @Test
    public void structuredMkcpRejectsEveryDuplicateRepresentation() throws Exception {
        JSONArray invalid = new JSONArray();

        JSONObject headerConflict = xrayVnext("vless", "header.example",
                "81818181-8181-8181-8181-818181818181", "none");
        headerConflict.put("streamSettings", new JSONObject().put("network", "mkcp")
                .put("kcpSettings", new JSONObject()
                        .put("header", new JSONObject().put("type", "dns"))
                        .put("headerType", "wechat")));
        invalid.put(headerConflict);

        JSONObject emptyAliasConflict = xrayVnext("vless", "capacity.example",
                "82828282-8282-8282-8282-828282828282", "none");
        emptyAliasConflict.put("streamSettings", new JSONObject().put("network", "mkcp")
                .put("kcpSettings", new JSONObject()
                        .put("uplinkCapacity", "")
                        .put("uplink_capacity", 10)));
        invalid.put(emptyAliasConflict);

        JSONObject finalmaskConflict = xrayVnext("vless", "mask.example",
                "83838383-8383-8383-8383-838383838383", "none");
        finalmaskConflict.put("streamSettings", new JSONObject().put("network", "mkcp")
                .put("kcpSettings", new JSONObject().put("seed", "settings-seed"))
                .put("finalmask", new JSONObject().put("udp", new JSONArray()
                        .put(new JSONObject().put("type", "mkcp-legacy")
                                .put("settings", new JSONObject()
                                        .put("value", "mask-seed"))))));
        invalid.put(finalmaskConflict);

        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(invalid.length(), parsed.rejected);
    }

    @Test
    public void structuredMkcpRejectsPresentEmptyNumericFields() throws Exception {
        JSONArray invalid = new JSONArray();
        String[] keys = {"mtu", "tti", "uplinkCapacity", "uplink_capacity",
                "downlinkCapacity", "downlink_capacity", "cwndMultiplier",
                "cwnd_multiplier", "maxSendingWindow", "max_sending_window"};
        for (int index = 0; index < keys.length; index++) {
            JSONObject outbound = xrayVnext("vless", "empty-" + index + ".example",
                    String.format("%08d-0000-0000-0000-000000000000", index + 1),
                    "none");
            outbound.put("streamSettings", new JSONObject().put("network", "mkcp")
                    .put("kcpSettings", new JSONObject().put(keys[index],
                            index % 2 == 0 ? "" : "   ")));
            invalid.put(outbound);
        }
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(keys.length, parsed.rejected);
    }

    @Test
    public void structuredMkcpUsesPinnedNumericBoundsWithoutOverflow() throws Exception {
        JSONObject valid = xrayVnext("vless", "bounds.example",
                "84848484-8484-8484-8484-848484848484", "none");
        valid.put("streamSettings", new JSONObject().put("network", "mkcp")
                .put("kcpSettings", new JSONObject().put("mtu", 21)
                        .put("uplinkCapacity", 0).put("downlinkCapacity", 4095)
                        .put("maxSendingWindow", 2 * 1024 * 1024)));
        SubscriptionParser.ParseResult accepted = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(valid)).toString());
        assertEquals(1, accepted.nodes.size());
        assertEquals(0, accepted.nodes.get(0).outbound.getJSONObject("transport")
                .getInt("uplink_capacity"));

        JSONObject capacityOverflow = new JSONObject(valid.toString());
        capacityOverflow.getJSONObject("streamSettings").getJSONObject("kcpSettings")
                .put("uplinkCapacity", 4096);
        JSONObject windowOverflow = new JSONObject(valid.toString());
        windowOverflow.getJSONObject("streamSettings").getJSONObject("kcpSettings")
                .put("uplinkCapacity", 4095).put("tti", 1000)
                .put("cwndMultiplier", 1024);
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(capacityOverflow).put(windowOverflow)).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(2, rejected.rejected);
    }

    @Test
    public void importsOfficialSimplifiedXrayProxyOutboundsStrictly() throws Exception {
        JSONArray outbounds = new JSONArray()
                .put(new JSONObject().put("protocol", "vless")
                        .put("settings", new JSONObject().put("address", "vless.example")
                                .put("port", 443).put("id",
                                        "11111111-1111-1111-1111-111111111111")
                                .put("encryption", "none")))
                .put(new JSONObject().put("protocol", "vmess")
                        .put("settings", new JSONObject().put("address", "vmess.example")
                                .put("port", 443).put("id",
                                        "22222222-2222-2222-2222-222222222222")
                                .put("security", "auto")))
                .put(new JSONObject().put("protocol", "trojan")
                        .put("settings", new JSONObject().put("address", "trojan.example")
                                .put("port", 443).put("password", " secret ")))
                .put(new JSONObject().put("protocol", "shadowsocks")
                        .put("settings", new JSONObject().put("address", "ss.example")
                                .put("port", 8388).put("password", "password")
                                .put("method", "aes-256-gcm")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", outbounds).toString());
        assertEquals("unexpected simplified Xray rejection: " + parsed.reasons,
                4, parsed.nodes.size());
        assertEquals(" secret ", parsed.nodes.stream()
                .filter(node -> node.outbound.optString("type").equals("trojan"))
                .findFirst().get().outbound.getString("password"));

        JSONObject conflicting = new JSONObject().put("protocol", "vless")
                .put("settings", new JSONObject().put("address", "conflict.example")
                        .put("port", 443).put("id",
                                "11111111-1111-1111-1111-111111111111")
                        .put("encryption", "none").put("vnext", new JSONArray()));
        JSONObject unsupported = new JSONObject().put("protocol", "vmess")
                .put("settings", new JSONObject().put("address", "unsupported.example")
                        .put("port", 443).put("id",
                                "22222222-2222-2222-2222-222222222222")
                        .put("security", "auto").put("experiments", "AuthenticatedLength"));
        JSONObject trojanFlow = new JSONObject().put("protocol", "trojan")
                .put("settings", new JSONObject().put("address", "flow.example")
                        .put("port", 443).put("password", "password")
                        .put("flow", "xtls-rprx-vision"));
        assertTrue(SubscriptionParser.parseNodes(new JSONObject().put("outbounds",
                new JSONArray().put(conflicting).put(unsupported).put(trojanFlow))
                .toString()).isEmpty());
    }

    @Test
    public void xrayIdentityImportUsesOnlyPinnedKeysWhileDirectAliasesRemainValid()
            throws Exception {
        JSONArray invalid = new JSONArray();

        JSONObject outerType = xrayVnext("vless", "outer-type.example",
                "11111111-1111-1111-1111-111111111111", "none");
        outerType.put("type", outerType.remove("protocol"));
        invalid.put(outerType);
        invalid.put(xrayVnext("vless", "outer-name.example",
                "11111111-1111-1111-1111-111111111111", "none")
                .put("name", "non-Xray alias"));

        JSONObject simplified = new JSONObject().put("protocol", "vless")
                .put("settings", new JSONObject().put("address", "simple.example")
                        .put("port", 443).put("id",
                                "22222222-2222-2222-2222-222222222222")
                        .put("encryption", "none"));
        for (String[] alias : new String[][]{
                {"address", "server"}, {"port", "server_port"},
                {"id", "uuid"}, {"id", "user"},
        }) {
            JSONObject candidate = new JSONObject(simplified.toString());
            JSONObject settings = candidate.getJSONObject("settings");
            settings.put(alias[1], settings.remove(alias[0]));
            invalid.put(candidate);
        }
        for (String packetKey : new String[]{"packetEncoding", "packet_encoding"}) {
            JSONObject candidate = new JSONObject(simplified.toString());
            candidate.getJSONObject("settings").put(packetKey, "xudp");
            invalid.put(candidate);
        }
        JSONObject simplifiedVmessEncryption = new JSONObject()
                .put("protocol", "vmess")
                .put("settings", new JSONObject().put("address", "vmess-simple.example")
                        .put("port", 443).put("id",
                                "33333333-3333-3333-3333-333333333333")
                        .put("encryption", "auto"));
        invalid.put(simplifiedVmessEncryption);

        JSONObject nested = xrayVnext("vless", "nested.example",
                "44444444-4444-4444-4444-444444444444", "none");
        for (String[] alias : new String[][]{
                {"address", "server"}, {"port", "server_port"},
        }) {
            JSONObject candidate = new JSONObject(nested.toString());
            JSONObject endpoint = candidate.getJSONObject("settings")
                    .getJSONArray("vnext").getJSONObject(0);
            endpoint.put(alias[1], endpoint.remove(alias[0]));
            invalid.put(candidate);
        }
        for (String alias : new String[]{"uuid", "user"}) {
            JSONObject candidate = new JSONObject(nested.toString());
            JSONObject user = candidate.getJSONObject("settings")
                    .getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0);
            user.put(alias, user.remove("id"));
            invalid.put(candidate);
        }
        for (String packetKey : new String[]{"packetEncoding", "packet_encoding"}) {
            JSONObject candidate = new JSONObject(nested.toString());
            candidate.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0).put(packetKey, "xudp");
            invalid.put(candidate);
        }
        for (String ignoredVmessKey : new String[]{"alterId", "alter_id", "encryption"}) {
            JSONObject candidate = xrayVnext("vmess", "nested-vmess.example",
                    "55555555-5555-5555-5555-555555555555", "auto");
            candidate.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0).put(ignoredVmessKey,
                            ignoredVmessKey.equals("encryption") ? "auto" : 0);
            invalid.put(candidate);
        }

        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(rejected.reasons.toString(), rejected.nodes.isEmpty());
        assertEquals(invalid.length(), rejected.rejected);

        JSONObject directVless = new JSONObject().put("type", "vless")
                .put("address", "direct-alias.example").put("port", 443)
                .put("user", "66666666-6666-6666-6666-666666666666")
                .put("encryption", "none").put("packetEncoding", "xudp");
        JSONObject directVmess = new JSONObject().put("type", "vmess")
                .put("address", "direct-vmess-alias.example").put("port", 443)
                .put("user", "77777777-7777-7777-7777-777777777777")
                .put("encryption", "auto").put("alter_id", 0);
        SubscriptionParser.ParseResult direct = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(directVless).put(directVmess)).toString());
        assertEquals(direct.reasons.toString(), 2, direct.nodes.size());
        assertEquals("xudp", direct.nodes.get(0).outbound.getString("packet_encoding"));
        assertEquals("auto", direct.nodes.get(1).outbound.getString("security"));
    }

    @Test
    public void xrayStructuredScalarsPreservePinnedTypesCaseAndPresence()
            throws Exception {
        JSONArray invalid = new JSONArray();

        JSONObject stringPort = xrayVnext("vless", "string-port.example",
                "81818181-8181-8181-8181-818181818181", "none");
        stringPort.getJSONObject("settings").getJSONArray("vnext")
                .getJSONObject(0).put("port", "443");
        invalid.put(stringPort);

        for (String field : new String[]{"mtu", "tti", "uplinkCapacity",
                "downlinkCapacity", "cwndMultiplier", "maxSendingWindow"}) {
            JSONObject stringKcp = xrayVnext("vless", "string-kcp.example",
                    "82828282-8282-8282-8282-828282828282", "none");
            stringKcp.put("streamSettings", new JSONObject().put("network", "kcp")
                    .put("kcpSettings", new JSONObject().put(field, "1")));
            invalid.put(stringKcp);
        }

        JSONObject uppercaseFlow = xrayVnext("vless", "flow-case.example",
                "83838383-8383-8383-8383-838383838383", "none");
        uppercaseFlow.getJSONObject("settings").getJSONArray("vnext")
                .getJSONObject(0).getJSONArray("users").getJSONObject(0)
                .put("flow", "XTLS-RPRX-VISION");
        invalid.put(uppercaseFlow);

        JSONObject uppercaseMode = xrayVnext("vless", "mode-case.example",
                "84848484-8484-8484-8484-848484848484", "none")
                .put("streamSettings", new JSONObject().put("network", "xhttp")
                        .put("xhttpSettings", new JSONObject()
                                .put("path", "/x").put("mode", "STREAM-ONE")));
        invalid.put(uppercaseMode);

        String ss2022Password = Base64.getEncoder().withoutPadding()
                .encodeToString(new byte[16]);
        JSONObject uppercase2022 = new JSONObject().put("protocol", "shadowsocks")
                .put("settings", new JSONObject().put("servers", new JSONArray()
                        .put(new JSONObject().put("address", "ss-case.example")
                                .put("port", 443)
                                .put("method", "2022-BLAKE3-AES-128-GCM")
                                .put("password", ss2022Password))));
        invalid.put(uppercase2022);

        JSONObject nullExtra = xrayVnext("vless", "null-extra.example",
                "85858585-8585-8585-8585-858585858585", "none")
                .put("streamSettings", new JSONObject().put("network", "xhttp")
                        .put("xhttpSettings", new JSONObject().put("path", "/x")
                                .put("extra", JSONObject.NULL)
                                .put("noSSEHeader", true)));
        invalid.put(nullExtra);

        JSONObject emptyAlpn = xrayVnext("vless", "empty-alpn.example",
                "86868686-8686-8686-8686-868686868686", "none")
                .put("streamSettings", new JSONObject().put("network", "tcp")
                        .put("security", "tls")
                        .put("tlsSettings", new JSONObject()
                                .put("serverName", "empty-alpn.example")
                                .put("alpn", "")));
        invalid.put(emptyAlpn);

        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(rejected.reasons.toString(), rejected.nodes.isEmpty());
        assertEquals(invalid.length(), rejected.rejected);

        JSONObject lowercase2022 = new JSONObject(uppercase2022.toString());
        lowercase2022.getJSONObject("settings").getJSONArray("servers")
                .getJSONObject(0).put("method", "2022-blake3-aes-128-gcm");
        SubscriptionParser.ParseResult accepted = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(lowercase2022)).toString());
        assertEquals(accepted.reasons.toString(), 1, accepted.nodes.size());
    }

    @Test
    public void importsPasswordlessShadowsocksNoneAcrossStructuredAndClash() throws Exception {
        for (String method : new String[]{"none", "plain", "dummy"}) {
            JSONObject structured = new JSONObject().put("type", "shadowsocks")
                    .put("server", "structured-" + method + ".example")
                    .put("server_port", 443)
                    .put("method", method).put("password", "");
            ProtocolParser.Node structuredNode = SubscriptionParser.parseNodes(
                    new JSONObject().put("outbounds", new JSONArray().put(structured))
                            .toString()).get(0);
            assertEquals("none", structuredNode.outbound.getString("method"));
            assertEquals("", ProtocolParser.renderSingBoxOutbound(structuredNode.outbound)
                    .getString("password"));
            assertFalse(structuredNode.supports(CoreFamily.XRAY));

            String clash = "proxies:\n"
                    + "  - name: Passwordless " + method + "\n"
                    + "    type: ss\n"
                    + "    server: clash-" + method + ".example\n"
                    + "    port: 443\n"
                    + "    cipher: " + method + "\n"
                    + "    password: \"\"\n";
            ProtocolParser.Node clashNode = SubscriptionParser.parseNodes(clash).get(0);
            assertEquals("none", clashNode.outbound.getString("method"));
            assertEquals("", clashNode.outbound.getString("password"));
            assertEquals("none", ProtocolParser.renderSingBoxOutbound(clashNode.outbound)
                    .getString("method"));
        }

        String invalid = "proxies:\n"
                + "  - name: Invalid empty encrypted password\n"
                + "    type: ss\n"
                + "    server: invalid.example\n"
                + "    port: 443\n"
                + "    cipher: aes-256-gcm\n"
                + "    password: \"\"\n";
        assertTrue(SubscriptionParser.parseNodes(invalid).isEmpty());
    }

    @Test
    public void rejectsMixedDirectAndSimplifiedXrayIdentityForEveryFamily()
            throws Exception {
        JSONArray invalid = new JSONArray()
                .put(new JSONObject().put("type", "vless")
                        .put("server", "direct.example").put("server_port", 443)
                        .put("uuid", "11111111-1111-1111-1111-111111111111")
                        .put("encryption", "none")
                        .put("settings", new JSONObject().put("address", "nested.example")
                                .put("port", 8443).put("id",
                                        "22222222-2222-2222-2222-222222222222")
                                .put("encryption", "none")))
                .put(new JSONObject().put("type", "vmess")
                        .put("server", "direct.example").put("server_port", 443)
                        .put("uuid", "33333333-3333-3333-3333-333333333333")
                        .put("security", "auto")
                        .put("settings", new JSONObject().put("address", "nested.example")
                                .put("port", 8443).put("id",
                                        "44444444-4444-4444-4444-444444444444")
                                .put("security", "auto")))
                .put(new JSONObject().put("type", "trojan")
                        .put("server", "direct.example").put("server_port", 443)
                        .put("password", "direct-secret")
                        .put("settings", new JSONObject().put("address", "nested.example")
                                .put("port", 8443).put("password", "nested-secret")))
                .put(new JSONObject().put("type", "shadowsocks")
                        .put("server", "direct.example").put("server_port", 8388)
                        .put("method", "aes-256-gcm").put("password", "direct-secret")
                        .put("settings", new JSONObject().put("address", "nested.example")
                                .put("port", 8488).put("method", "aes-256-gcm")
                                .put("password", "nested-secret")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(invalid.length(), parsed.rejected);
    }

    @Test
    public void rejectsOversizedXhttpExtraBeforeSerialization() throws Exception {
        JSONObject outbound = xrayVnext("vless", "xhttp.example",
                "33333333-3333-3333-3333-333333333333", "none")
                .put("streamSettings", new JSONObject().put("network", "xhttp")
                        .put("xhttpSettings", new JSONObject().put("path", "/x")
                                .put("extra", new JSONObject()
                                        .put("xPaddingBytes", repeat('1', 65 * 1024)))));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(1, parsed.rejected);
        assertTrue("unexpected reasons: " + parsed.reasons,
                parsed.reasons.contains("transport_unsupported")
                        || parsed.reasons.contains("json_string_too_large"));
    }

    @Test
    public void rejectsGiantOutboundScalarsBeforeGeneratingUri() throws Exception {
        for (JSONObject outbound : new JSONObject[]{
                xrayVnext("vless", "tag.example",
                        "33333333-3333-3333-3333-333333333333", "none")
                        .put("tag", repeat('n', 32 * 1024)),
                new JSONObject().put("protocol", "trojan").put("tag", "trojan")
                        .put("settings", new JSONObject().put("servers", new JSONArray()
                                .put(new JSONObject().put("address", "password.example")
                                        .put("port", 443)
                                        .put("password", repeat('p', 32 * 1024)))))
        }) {
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                    new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
            assertTrue(parsed.nodes.isEmpty());
            assertEquals(1, parsed.rejected);
            assertTrue(parsed.reasons.size() <= 20);
        }
    }

    @Test
    public void rejectsUnrepresentableFinalmaskInsteadOfFallingBack() throws Exception {
        JSONArray masks = new JSONArray()
                .put(new JSONObject().put("type", "mkcp-legacy")
                        .put("settings", new JSONObject().put("header", "dns")))
                .put(new JSONObject().put("type", "mkcp-legacy")
                        .put("settings", new JSONObject().put("value", "seed")));
        JSONArray invalidMasks = new JSONArray()
                .put(new JSONArray().put(new JSONObject().put("type", "salamander")
                        .put("settings", new JSONObject().put("password", "secret"))))
                .put(masks)
                .put(new JSONArray().put(new JSONObject().put("type", "mkcp-legacy")
                        .put("settings", new JSONObject()
                                .put("header", "dns").put("value", "seed"))));
        for (int index = 0; index < invalidMasks.length(); index++) {
            JSONObject outbound = xrayVnext("vless", "bad.example",
                    "55555555-5555-5555-5555-555555555555", "none")
                    .put("streamSettings", new JSONObject().put("network", "mkcp")
                            .put("finalmask", new JSONObject().put(
                                    "udp", invalidMasks.getJSONArray(index))));
            assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(outbound)).toString()).isEmpty());
        }
    }

    @Test
    public void preservesHeadersEarlyDataAndVlessEncryptionFromExplicitOutbound() throws Exception {
        JSONObject outbound = new JSONObject()
                .put("type", "vless").put("tag", "Strict import")
                .put("server", "strict.example").put("server_port", 443)
                .put("uuid", "66666666-6666-6666-6666-666666666666")
                .put("encryption", VALID_VLESS_ENCRYPTION)
                .put("tls", new JSONObject().put("enabled", true)
                        .put("server_name", "edge.example"))
                .put("transport", new JSONObject().put("type", "ws")
                        .put("path", "/ws")
                        .put("max_early_data", 2048)
                        .put("early_data_header_name", "Sec-WebSocket-Protocol")
                        .put("headers", new JSONObject()
                                .put("Host", "host.example")
                                .put("X-Test", "preserved")));
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertEquals(0, result.rejected);
        assertEquals(1, result.nodes.size());
        ProtocolParser.Node node = result.nodes.get(0);
        assertEquals(VALID_VLESS_ENCRYPTION,
                node.outbound.getString("encryption"));
        JSONObject transport = node.outbound.getJSONObject("transport");
        assertEquals(2048, transport.getInt("max_early_data"));
        assertEquals("Sec-WebSocket-Protocol",
                transport.getString("early_data_header_name"));
        assertEquals("preserved", transport.getJSONObject("headers").getString("X-Test"));
        assertTrue(node.supports(CoreFamily.XRAY));
        assertTrue(!node.supports(CoreFamily.SING_BOX));
    }

    @Test
    public void preservesFullUint32WebSocketEarlyDataAcrossStructuredForms() throws Exception {
        JSONObject direct = direct("vless")
                .put("transport", new JSONObject().put("type", "ws")
                        .put("path", "/direct").put("headers",
                                new JSONObject().put("Host", "edge.example"))
                        .put("max_early_data", 2147483648L)
                        .put("early_data_header_name", "Sec-WebSocket-Protocol"));
        JSONObject xray = xrayVnext("vless", "xray-ed.example",
                "67676767-6767-6767-6767-676767676767", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", new JSONObject()
                                .put("path", "/ws?ed=2147483647")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(direct).put(xray)).toString());
        assertEquals(2, parsed.nodes.size());
        assertEquals(2147483648L, parsed.nodes.get(0).outbound
                .getJSONObject("transport").getLong("max_early_data"));
        assertEquals(2147483647L, parsed.nodes.get(1).outbound
                .getJSONObject("transport").getLong("max_early_data"));
        assertFalse(parsed.nodes.get(1).supports(CoreFamily.SING_BOX));
        assertTrue(parsed.nodes.get(1).supports(CoreFamily.XRAY));

        xray.getJSONObject("streamSettings").getJSONObject("wsSettings")
                .put("path", "/ws?ed=2147483648");
        SubscriptionParser.ParseResult unsigned = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(xray)).toString());
        assertEquals(1, unsigned.nodes.size());
        assertEquals(2147483648L, unsigned.nodes.get(0).outbound
                .getJSONObject("transport").getLong("max_early_data"));
        assertTrue(unsigned.nodes.get(0).supports(CoreFamily.XRAY));

        xray.getJSONObject("streamSettings").getJSONObject("wsSettings")
                .put("path", "/ws?ed=4294967296");
        SubscriptionParser.ParseResult overflow = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(xray)).toString());
        assertTrue(overflow.nodes.isEmpty());
    }

    @Test
    public void reportsOnlySanitizedStrictRejectionCodes() throws Exception {
        JSONArray outbounds = new JSONArray()
                .put(xrayVnext("vless", "secret-host.example",
                        "77777777-7777-7777-7777-777777777777", "none")
                        .put("detour", "credential-bearing-value"))
                .put(new JSONObject().put("protocol", "trojan")
                        .put("settings", new JSONObject().put("servers", new JSONArray()
                                .put(new JSONObject().put("address", "trojan-secret.example")
                                        .put("port", 443).put("password", "super-secret")
                                        .put("flow", "unsupported-flow")))));
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", outbounds).toString());
        assertEquals(2, result.rejected);
        assertTrue(result.nodes.isEmpty());
        assertTrue(result.reasons.contains("detour_unsupported"));
        assertTrue(result.reasons.contains("trojan_flow_unsupported"));
        assertTrue(result.reasons.size() <= 20);
        String reasons = result.reasons.toString();
        assertTrue(!reasons.contains("secret-host"));
        assertTrue(!reasons.contains("super-secret"));
    }

    @Test
    public void boundsAndroidJsonNestingBeforeParsing() {
        StringBuilder allowed = new StringBuilder();
        for (int i = 0; i < 64; i++) allowed.append('[');
        for (int i = 0; i < 64; i++) allowed.append(']');
        SubscriptionParser.ParseResult accepted = SubscriptionParser.parseDetailed(allowed.toString());
        assertFalse(accepted.reasons.contains("json_depth_exceeded"));

        StringBuilder rejected = new StringBuilder();
        for (int i = 0; i < 65; i++) rejected.append('[');
        for (int i = 0; i < 65; i++) rejected.append(']');
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(rejected.toString());
        assertEquals(1, result.rejected);
        assertTrue(result.reasons.contains("json_depth_exceeded"));
    }

    @Test
    public void importsPinnedXrayHttpListsAndWebSocketPathEarlyData() throws Exception {
        JSONObject http = xrayVnext("vless", "http.example",
                "88888888-8888-8888-8888-888888888888", "none")
                .put("streamSettings", new JSONObject().put("network", "http")
                        .put("httpSettings", new JSONObject()
                                .put("path", new JSONArray().put("/h2"))
                                .put("headers", new JSONObject().put("X-Test",
                                        new JSONArray().put("one").put("two")))));
        JSONObject ws = xrayVnext("vless", "ws.example",
                "99999999-9999-9999-9999-999999999999", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", new JSONObject().put("path", "/ws?ed=2048&v=1")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(http).put(ws)).toString());
        assertEquals(0, parsed.rejected);
        assertEquals(2, parsed.nodes.size());
        JSONObject httpTransport = parsed.nodes.get(0).outbound.getJSONObject("transport");
        assertEquals("/h2", httpTransport.getString("path"));
        assertEquals(2, httpTransport.getJSONObject("headers")
                .getJSONArray("X-Test").length());
        assertTrue(parsed.nodes.get(0).supports(CoreFamily.SING_BOX));
        assertFalse(parsed.nodes.get(0).supports(CoreFamily.XRAY));
        JSONObject wsTransport = parsed.nodes.get(1).outbound.getJSONObject("transport");
        assertEquals("/ws?v=1", wsTransport.getString("path"));
        assertEquals(2048, wsTransport.getInt("max_early_data"));
        assertFalse(wsTransport.has("early_data_header_name"));
        assertEquals(ProtocolParser.WS_EARLY_DATA_XRAY_PATH,
                wsTransport.getString(ProtocolParser.WS_EARLY_DATA_MODE));
        assertTrue(wsTransport.getBoolean(ProtocolParser.WS_XRAY_PATH_SEMANTICS));
        assertFalse(parsed.nodes.get(1).supports(CoreFamily.SING_BOX));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(parsed.nodes.get(1), null, false, false));
        try {
            ProtocolParser.renderSingBoxOutbound(parsed.nodes.get(1).outbound);
            throw new AssertionError("sing-box accepted Xray WebSocket path semantics");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains(
                    ProtocolParser.SING_BOX_XRAY_WS_PATH_UNSUPPORTED));
        }
        JSONObject xrayWs = XrayConfigRenderer.build(parsed.nodes.get(1), 39012, "", "")
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("wsSettings");
        assertEquals("/ws?v=1&ed=2048", xrayWs.getString("path"));
        assertTrue(parsed.nodes.get(1).supports(CoreFamily.XRAY));
    }

    @Test
    public void structuredXrayCanonicalizesWebsocketAndAcceptsMethodAliasStrictly()
            throws Exception {
        JSONObject networkAlias = xrayVnext("vless", "network-websocket.example",
                "81818181-8181-8181-8181-818181818181", "none")
                .put("streamSettings", new JSONObject().put("network", "websocket")
                        .put("wsSettings", new JSONObject().put("path", "/network")));
        JSONObject methodAlias = xrayVnext("vless", "method-websocket.example",
                "82828282-8282-8282-8282-828282828282", "none")
                .put("streamSettings", new JSONObject().put("method", "websocket")
                        .put("wsSettings", new JSONObject().put("path", "/method")));
        SubscriptionParser.ParseResult accepted = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(networkAlias).put(methodAlias)).toString());
        assertEquals(accepted.reasons.toString(), 2, accepted.nodes.size());
        for (ProtocolParser.Node node : accepted.nodes) {
            assertEquals("ws", node.outbound.getJSONObject("transport")
                    .getString("type"));
            assertTrue(node.supports(CoreFamily.SING_BOX));
            assertTrue(node.supports(CoreFamily.XRAY));
        }

        JSONObject conflict = new JSONObject(networkAlias.toString());
        conflict.getJSONObject("streamSettings").put("method", "websocket");
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(conflict)).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(1, rejected.rejected);
    }

    @Test
    public void structuredXrayAcceptsOnlyRepresentablePinnedJsonTags()
            throws Exception {
        for (String key : new String[]{"maxEarlyData", "max_early_data",
                "earlyDataHeaderName", "early_data_header_name",
                "acceptProxyProtocol", "heartbeatPeriod"}) {
            Object value = key.toLowerCase(java.util.Locale.US).contains("header")
                    ? "Sec-WebSocket-Protocol"
                    : key.equals("acceptProxyProtocol") ? Boolean.TRUE : 1024;
            JSONObject invalid = xrayVnext("vless", "ws-tag.example",
                    "83838383-8383-8383-8383-838383838383", "none")
                    .put("streamSettings", new JSONObject().put("network", "ws")
                            .put("wsSettings", new JSONObject().put("path", "/ws")
                                    .put(key, value)));
            assertTrue(key, SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }
        JSONObject wsArrayHeader = xrayVnext("vless", "ws-header-type.example",
                "83838383-8383-8383-8383-838383838384", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", new JSONObject().put("path", "/ws")
                                .put("headers", new JSONObject()
                                        .put("X-Test", new JSONArray().put("one")))));
        assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(wsArrayHeader)).toString()).isEmpty());

        for (String key : new String[]{"path", "service_name"}) {
            JSONObject invalid = xrayVnext("vless", "grpc-tag.example",
                    "84848484-8484-8484-8484-848484848484", "none")
                    .put("streamSettings", new JSONObject().put("network", "grpc")
                            .put("grpcSettings", new JSONObject().put(key, "svc")));
            assertTrue(key, SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }
        JSONObject grpc = xrayVnext("vless", "grpc-exact.example",
                "85858585-8585-8585-8585-858585858585", "none")
                .put("streamSettings", new JSONObject().put("network", "grpc")
                        .put("grpcSettings", new JSONObject().put("serviceName", "svc")));
        assertEquals("svc", SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(grpc)).toString()).get(0)
                .outbound.getJSONObject("transport").getString("service_name"));

        JSONObject exactTls = xrayVnext("vless", "tls-exact.example",
                "86868686-8686-8686-8686-868686868686", "none")
                .put("streamSettings", new JSONObject().put("network", "raw")
                        .put("security", "tls")
                        .put("tlsSettings", new JSONObject()
                                .put("serverName", "edge.example")
                                .put("allowInsecure", false)
                                .put("fingerprint", "chrome")
                                .put("alpn", "h2,http/1.1")));
        ProtocolParser.Node tlsNode = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(exactTls)).toString()).get(0);
        assertEquals("edge.example", tlsNode.outbound.getJSONObject("tls")
                .getString("server_name"));
        assertEquals(2, tlsNode.outbound.getJSONObject("tls")
                .getJSONArray("alpn").length());

        for (Object[] alias : new Object[][]{
                {"insecure", false}, {"server_name", "edge.example"},
                {"sni", "edge.example"}, {"clientFingerprint", "chrome"},
        }) {
            JSONObject invalid = new JSONObject(exactTls.toString());
            JSONObject secure = invalid.getJSONObject("streamSettings")
                    .getJSONObject("tlsSettings");
            secure.remove("serverName");
            secure.remove("fingerprint");
            secure.put((String) alias[0], alias[1]);
            assertTrue((String) alias[0], SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }

        JSONObject exactReality = xrayVnext("vless", "reality-exact.example",
                "87878787-8787-8787-8787-878787878787", "none")
                .put("streamSettings", new JSONObject().put("network", "raw")
                        .put("security", "reality")
                        .put("realitySettings", new JSONObject()
                                .put("serverName", "edge.example")
                                .put("fingerprint", "chrome")
                                .put("password", realityPublicKey())
                                .put("shortId", "42").put("spiderX", "/probe")));
        ProtocolParser.Node reality = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(exactReality)).toString()).get(0);
        assertEquals(realityPublicKey(), reality.outbound.getJSONObject("tls")
                .getJSONObject("reality").getString("public_key"));

        for (String alias : new String[]{"server_name", "sni", "public_key", "pbk",
                "short_id", "sid", "spider_x", "spx", "insecure", "alpn",
                "mldsa65Verify"}) {
            JSONObject invalid = new JSONObject(exactReality.toString());
            invalid.getJSONObject("streamSettings").getJSONObject("realitySettings")
                    .put(alias, alias.equals("insecure") ? Boolean.FALSE : "value");
            assertTrue(alias, SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }
        JSONObject duplicateRealityKey = new JSONObject(exactReality.toString());
        duplicateRealityKey.getJSONObject("streamSettings")
                .getJSONObject("realitySettings")
                .put("publicKey", realityPublicKey());
        assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(duplicateRealityKey))
                .toString()).isEmpty());
    }

    @Test
    public void structuredXrayMkcpRejectsAliasesWhileDirectShapesKeepThem()
            throws Exception {
        Object[][] aliases = {
                {"uplink_capacity", 10}, {"downlink_capacity", 20},
                {"cwnd_multiplier", 1}, {"max_sending_window", 1350},
                {"legacy_header", "dns"}, {"legacy_seed", "mask.example"},
                {"headerType", "dns"},
        };
        for (Object[] alias : aliases) {
            JSONObject invalid = xrayVnext("vless", "mkcp-alias.example",
                    "88888888-8888-8888-8888-888888888881", "none")
                    .put("streamSettings", new JSONObject().put("network", "mkcp")
                            .put("kcpSettings", new JSONObject()
                                    .put((String) alias[0], alias[1])));
            assertTrue((String) alias[0], SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }
        JSONObject wrongBlock = xrayVnext("vless", "mkcp-block.example",
                "88888888-8888-8888-8888-888888888882", "none")
                .put("streamSettings", new JSONObject().put("network", "mkcp")
                        .put("mkcpSettings", new JSONObject().put("mtu", 1350)));
        assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(wrongBlock)).toString()).isEmpty());

        JSONObject directWs = direct("vless")
                .put("tls", new JSONObject().put("enabled", true)
                        .put("server_name", "direct.example").put("insecure", false))
                .put("transport", new JSONObject().put("type", "ws")
                        .put("path", "/direct").put("max_early_data", 1024)
                        .put("early_data_header_name", "Sec-WebSocket-Protocol"));
        JSONObject directGrpc = direct("vless").put("server", "grpc-direct.example")
                .put("transport", new JSONObject().put("type", "grpc")
                        .put("service_name", "direct-svc"));
        JSONObject directMkcp = direct("vmess").put("server", "mkcp-direct.example")
                .put("transport", new JSONObject().put("type", "mkcp")
                        .put("mtu", 1350).put("uplink_capacity", 10)
                        .put("downlink_capacity", 20).put("cwnd_multiplier", 1)
                        .put("max_sending_window", 1350)
                        .put("legacy_header", "dns").put("legacy_seed", "mask.example"));
        SubscriptionParser.ParseResult direct = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(directWs).put(directGrpc).put(directMkcp)).toString());
        assertEquals(direct.reasons.toString(), 3, direct.nodes.size());
        assertEquals("direct-svc", direct.nodes.get(1).outbound
                .getJSONObject("transport").getString("service_name"));
        assertEquals(10, direct.nodes.get(2).outbound
                .getJSONObject("transport").getInt("uplink_capacity"));
    }

    @Test
    public void structuredXrayHttpUpgradeHeadersAndSplitHttpBlocksAreExact()
            throws Exception {
        JSONObject base = xrayVnext("vless", "upgrade-header.example",
                "89898989-8989-8989-8989-898989898989", "none")
                .put("streamSettings", new JSONObject().put("network", "httpupgrade")
                        .put("httpupgradeSettings", new JSONObject().put("path", "/up")));
        for (JSONObject headers : new JSONObject[]{
                new JSONObject().put("Host", "edge.example"),
                new JSONObject().put("hOsT", "edge.example"),
                new JSONObject().put("X-Test", new JSONArray().put("one")),
        }) {
            JSONObject invalid = new JSONObject(base.toString());
            invalid.getJSONObject("streamSettings")
                    .getJSONObject("httpupgradeSettings").put("headers", headers);
            assertTrue(headers.toString(), SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }

        JSONObject split = xrayVnext("vless", "split-block.example",
                "90909090-9090-9090-9090-909090909090", "none")
                .put("streamSettings", new JSONObject().put("network", "splithttp")
                        .put("xhttpSettings", new JSONObject()
                                .put("path", "/split").put("mode", "stream-one")));
        ProtocolParser.Node node = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(split)).toString()).get(0);
        assertEquals("xhttp", node.outbound.getJSONObject("transport").getString("type"));
        assertEquals("/split", node.outbound.getJSONObject("transport").getString("path"));
    }

    @Test
    public void xrayWebSocketEarlyDataUsesDecodedAndCanonicalQuery()
            throws Exception {
        JSONObject encoded = xrayVnext("vless", "ws-encoded.example",
                "94949494-9494-9494-9494-949494949494", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", new JSONObject().put(
                                "path", "/ws?%65d=%32%30%34%38&token=%2Fraw&&x=1")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(encoded)).toString());
        assertEquals(parsed.reasons.toString(), 1, parsed.nodes.size());
        ProtocolParser.Node node = parsed.nodes.get(0);
        JSONObject neutral = node.outbound.getJSONObject("transport");
        assertEquals("/ws?token=%2Fraw&x=1", neutral.getString("path"));
        assertEquals(2048L, neutral.getLong("max_early_data"));
        assertEquals(ProtocolParser.WS_EARLY_DATA_XRAY_PATH,
                neutral.getString(ProtocolParser.WS_EARLY_DATA_MODE));
        assertTrue(neutral.getBoolean(ProtocolParser.WS_XRAY_PATH_SEMANTICS));
        assertFalse(node.supports(CoreFamily.SING_BOX));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(node, null, false, false));
        assertEquals("/ws?token=%2Fraw&x=1&ed=2048",
                XrayConfigRenderer.renderOutbound(node.outbound)
                        .getJSONObject("streamSettings").getJSONObject("wsSettings")
                        .getString("path"));

        JSONObject duplicate = new JSONObject(encoded.toString());
        duplicate.getJSONObject("streamSettings").getJSONObject("wsSettings")
                .put("path", "/ws?ed=1024&%65d=2048");
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(duplicate)).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(1, rejected.rejected);
    }

    @Test
    public void xrayHttpUpgradePathEarlyDataIsExtractedAndRemainsXrayOnly()
            throws Exception {
        JSONObject encoded = xrayVnext("vless", "upgrade-ed.example",
                "93939393-9393-9393-9393-939393939393", "none")
                .put("streamSettings", new JSONObject().put("network", "httpupgrade")
                        .put("httpupgradeSettings", new JSONObject().put(
                                "path", "/upgrade?%65d=%32%30%34%38&token=%2Fraw")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(encoded)).toString());
        assertEquals(parsed.reasons.toString(), 1, parsed.nodes.size());
        ProtocolParser.Node node = parsed.nodes.get(0);
        JSONObject transport = node.outbound.getJSONObject("transport");
        assertEquals("httpupgrade", transport.getString("type"));
        assertEquals("/upgrade?token=%2Fraw", transport.getString("path"));
        assertEquals(2048L, transport.getLong("max_early_data"));
        assertFalse(node.supports(CoreFamily.SING_BOX));
        assertTrue(node.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(node, null, false, false));
        assertEquals("/upgrade?token=%2Fraw&ed=2048",
                XrayConfigRenderer.renderOutbound(node.outbound)
                        .getJSONObject("streamSettings")
                        .getJSONObject("httpupgradeSettings").getString("path"));

        JSONObject duplicate = new JSONObject(encoded.toString());
        duplicate.getJSONObject("streamSettings").getJSONObject("httpupgradeSettings")
                .put("path", "/upgrade?ed=1&%65d=2");
        assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(duplicate)).toString()).isEmpty());

        JSONObject overflow = new JSONObject(encoded.toString());
        overflow.getJSONObject("streamSettings").getJSONObject("httpupgradeSettings")
                .put("path", "/upgrade?ed=2147483648");
        SubscriptionParser.ParseResult unsigned = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(overflow)).toString());
        assertEquals(unsigned.reasons.toString(), 1, unsigned.nodes.size());
        assertEquals(2147483648L, unsigned.nodes.get(0).outbound
                .getJSONObject("transport").getLong("max_early_data"));
        assertTrue(unsigned.nodes.get(0).supports(CoreFamily.XRAY));

        overflow.getJSONObject("streamSettings").getJSONObject("httpupgradeSettings")
                .put("path", "/upgrade?ed=4294967296");
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(overflow)).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(1, rejected.rejected);
    }

    @Test
    public void xrayPathEarlyDataZeroIsConsumedWithoutEnablingEarlyData()
            throws Exception {
        for (String network : new String[]{"ws", "httpupgrade"}) {
            String settingsKey = network.equals("ws")
                    ? "wsSettings" : "httpupgradeSettings";
            for (String query : new String[]{"ed=0", "%65d=%30"}) {
                JSONObject outbound = xrayVnext("vless",
                        network + "-zero.example",
                        "94949494-9494-9494-9494-949494949494", "none")
                        .put("streamSettings", new JSONObject().put("network", network)
                                .put(settingsKey, new JSONObject()
                                        .put("path", "/zero?" + query + "&v=1")));
                SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                        new JSONObject().put("outbounds",
                                new JSONArray().put(outbound)).toString());
                assertEquals(network + "/" + query + ": " + parsed.reasons,
                        1, parsed.nodes.size());
                JSONObject transport = parsed.nodes.get(0).outbound
                        .getJSONObject("transport");
                assertEquals("/zero?v=1", transport.getString("path"));
                assertFalse(transport.has("max_early_data"));
                assertEquals("/zero?v=1", XrayConfigRenderer
                        .renderOutbound(parsed.nodes.get(0).outbound)
                        .getJSONObject("streamSettings")
                        .getJSONObject(settingsKey).getString("path"));
            }
        }
    }

    @Test
    public void xrayPathEarlyDataZeroCanonicalizesWeirdRawQueryLikePinnedBuild()
            throws Exception {
        String rawPath = "/zero?z=last&&space=hello%20world&bare&token=%2fraw"
                + "&a=two&a=one&ed=0#fragment";
        String canonical = "/zero?a=two&a=one&bare=&space=hello+world"
                + "&token=%2Fraw&z=last#fragment";
        for (String network : new String[]{"ws", "httpupgrade"}) {
            String settingsKey = network.equals("ws")
                    ? "wsSettings" : "httpupgradeSettings";
            JSONObject outbound = xrayVnext("vless", network + "-weird-zero.example",
                    "95959595-9595-9595-9595-959595959595", "none")
                    .put("streamSettings", new JSONObject().put("network", network)
                            .put(settingsKey, new JSONObject().put("path", rawPath)));
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                    new JSONObject().put("outbounds",
                            new JSONArray().put(outbound)).toString());
            assertEquals(network + ": " + parsed.reasons, 1, parsed.nodes.size());
            JSONObject transport = parsed.nodes.get(0).outbound
                    .getJSONObject("transport");
            assertEquals(canonical, transport.getString("path"));
            assertFalse(transport.has("max_early_data"));
            assertEquals(canonical, XrayConfigRenderer
                    .renderOutbound(parsed.nodes.get(0).outbound)
                    .getJSONObject("streamSettings")
                    .getJSONObject(settingsKey).getString("path"));
        }
    }

    @Test
    public void xrayWebSocketQueryAndFragmentStayXrayOnlyAcrossRenderers()
            throws Exception {
        JSONObject exact = xrayVnext("vless", "ws-header.example",
                "96969696-9696-9696-9696-969696969696", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", new JSONObject()
                                .put("path", "/ws?token=%2Fraw&ed=2048#fragment")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(exact)).toString());
        assertEquals(0, parsed.rejected);
        assertEquals(1, parsed.nodes.size());
        ProtocolParser.Node node = parsed.nodes.get(0);
        JSONObject neutral = node.outbound.getJSONObject("transport");
        assertEquals("/ws?token=%2Fraw#fragment", neutral.getString("path"));
        assertEquals(2048, neutral.getInt("max_early_data"));
        assertEquals(ProtocolParser.WS_EARLY_DATA_XRAY_PATH,
                neutral.getString(ProtocolParser.WS_EARLY_DATA_MODE));
        assertTrue(neutral.getBoolean(ProtocolParser.WS_XRAY_PATH_SEMANTICS));
        assertFalse(node.supports(CoreFamily.SING_BOX));
        assertTrue(node.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(node, null, false, false));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(node, CoreFamily.SING_BOX, true, false));

        JSONObject normalXray = XrayConfigRenderer.build(node, 39017, "", "")
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("wsSettings");
        assertEquals("/ws?token=%2Fraw&ed=2048#fragment",
                normalXray.getString("path"));
        JSONObject probeXray = ProbeConfigRenderer.build(CoreFamily.XRAY,
                        java.util.Collections.singletonList(node),
                        java.util.Collections.singletonList(39018))
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("wsSettings");
        assertEquals("/ws?token=%2Fraw&ed=2048#fragment",
                probeXray.getString("path"));

        JSONObject forbiddenAlias = new JSONObject(exact.toString());
        forbiddenAlias.getJSONObject("streamSettings").getJSONObject("wsSettings")
                .put("earlyDataHeaderName", "Sec-WebSocket-Protocol");
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(forbiddenAlias)).toString());
        assertEquals(1, rejected.rejected);
        assertTrue(rejected.nodes.isEmpty());
    }

    @Test
    public void nativeSingBoxWebSocketEarlyDataKeepsPathMode() throws Exception {
        JSONObject outbound = new JSONObject()
                .put("type", "vless").put("tag", "native-sb")
                .put("server", "native.example").put("server_port", 443)
                .put("uuid", "98989898-9898-9898-9898-989898989898")
                .put("encryption", "none")
                .put("tls", new JSONObject().put("enabled", true)
                        .put("server_name", "native.example"))
                .put("transport", new JSONObject().put("type", "ws")
                        .put("path", "/native?ed=77#fragment")
                        .put("max_early_data", 2048));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertEquals(0, parsed.rejected);
        assertEquals(1, parsed.nodes.size());
        ProtocolParser.Node node = parsed.nodes.get(0);
        JSONObject neutral = node.outbound.getJSONObject("transport");
        assertEquals("/native?ed=77#fragment", neutral.getString("path"));
        assertFalse(neutral.has(ProtocolParser.WS_EARLY_DATA_MODE));
        assertFalse(neutral.has(ProtocolParser.WS_XRAY_PATH_SEMANTICS));
        assertTrue(node.supports(CoreFamily.SING_BOX));
        assertFalse(node.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(node, null, false, false));
        JSONObject rendered = ProtocolParser.buildConfig(node, 39013, "", "")
                .getJSONArray("outbounds").getJSONObject(0).getJSONObject("transport");
        assertEquals("/native?ed=77#fragment", rendered.getString("path"));
        assertFalse(rendered.has("early_data_header_name"));
    }

    @Test
    public void xrayOnlyVlessEncryptionCanImportPathEarlyDataBeforeFamilySelection()
            throws Exception {
        JSONObject outbound = xrayVnext("vless", "encrypted-ed.example",
                "97979797-9797-9797-9797-979797979797",
                VALID_VLESS_ENCRYPTION)
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("security", "tls")
                        .put("tlsSettings", new JSONObject()
                                .put("serverName", "encrypted-ed.example"))
                        .put("wsSettings", new JSONObject().put("path", "/ws?ed=1024")));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertEquals(0, parsed.rejected);
        assertEquals(1, parsed.nodes.size());
        ProtocolParser.Node node = parsed.nodes.get(0);
        assertFalse(node.supports(CoreFamily.SING_BOX));
        assertTrue(node.supports(CoreFamily.XRAY));
        assertEquals(ProtocolParser.WS_EARLY_DATA_XRAY_PATH,
                node.outbound.getJSONObject("transport")
                        .getString(ProtocolParser.WS_EARLY_DATA_MODE));
        assertEquals("/ws?ed=1024", XrayConfigRenderer.build(node, 39014, "", "")
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("wsSettings")
                .getString("path"));
    }

    @Test
    public void rejectsMultiplePinnedXrayHttpPaths() throws Exception {
        JSONObject outbound = xrayVnext("vless", "http.example",
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "none")
                .put("streamSettings", new JSONObject().put("network", "http")
                        .put("httpSettings", new JSONObject().put("path",
                                new JSONArray().put("/one").put("/two"))));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(1, parsed.rejected);
    }

    @Test
    public void capsOneSourceAtFiveThousandNodes() {
        StringBuilder source = new StringBuilder();
        for (int i = 0; i < 5_100; i++) {
            source.append("vless://11111111-1111-1111-1111-")
                    .append(String.format("%012d", i))
                    .append("@limit-").append(i).append(".example:443?security=tls\n");
        }
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(source.toString());
        assertEquals(SubscriptionParser.MAX_SOURCE_NODES, parsed.nodes.size());
        assertEquals(100, parsed.rejected);
        assertTrue(parsed.reasons.contains("source_node_limit"));
    }

    @Test
    public void capsTopLevelJsonArrayWithAccurateRejections() {
        JSONArray source = new JSONArray();
        for (int i = 0; i < SubscriptionParser.MAX_SOURCE_NODES + 2; i++) {
            source.put("vless://11111111-1111-1111-1111-"
                    + String.format("%012d", i) + "@array-" + i
                    + ".example:443?security=tls");
        }
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(source.toString());
        assertEquals(SubscriptionParser.MAX_SOURCE_NODES, parsed.nodes.size());
        assertEquals(2, parsed.rejected);
        assertTrue(parsed.reasons.contains("source_node_limit"));
    }

    @Test
    public void proseExtractionTrimsOnlyItsOwnWrappingPunctuation() {
        String wrapped = "vless://11111111-1111-1111-1111-111111111111"
                + "@wrapped.example:443?security=tls#Wrapped";
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                "Use (" + wrapped + "). next");
        assertEquals(1, parsed.nodes.size());
        assertEquals("Wrapped", parsed.nodes.get(0).name);
        assertEquals(wrapped, parsed.nodes.get(0).uri);
    }

    @Test
    public void standaloneUrisPreserveFunctionalTrailingPunctuation() {
        String prefix = "vless://11111111-1111-1111-1111-111111111111"
                + "@punctuation.example:443?type=ws&security=tls";
        String pathDot = prefix + "&path=%2Fsocket.";
        String querySemicolon = prefix + "&path=%2Fsocket&sni=edge.example;";
        String fragmentParenthesis = prefix + "&path=%2Fsocket#Node)";

        ProtocolParser.Node path = onlyNode(pathDot);
        assertEquals(pathDot, path.uri);
        assertEquals("/socket.", path.outbound.optJSONObject("transport").optString("path"));

        ProtocolParser.Node query = onlyNode(querySemicolon);
        assertEquals(querySemicolon, query.uri);
        assertEquals("edge.example;", query.outbound.optJSONObject("tls")
                .optString("server_name"));

        ProtocolParser.Node fragment = onlyNode(fragmentParenthesis);
        assertEquals(fragmentParenthesis, fragment.uri);
        assertEquals("Node)", fragment.name);
    }

    @Test
    public void rejectsProtocolIrrelevantClashFieldsInsteadOfDroppingThem() {
        String yaml = "proxies:\n"
                + "  - name: Invalid VLESS\n"
                + "    type: vless\n"
                + "    server: clash.example\n"
                + "    port: 443\n"
                + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                + "    ports: 443,8443\n";
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(1, parsed.rejected);
        assertTrue(parsed.reasons.contains("clash_field_unsupported"));
    }

    @Test
    public void clashSecurityMatrixPreservesVmessAndRejectsDanglingTlsFields() {
        String vmess = "proxies:\n"
                + "  - name: Reality VMess\n"
                + "    type: vmess\n"
                + "    server: vmess.example\n"
                + "    port: 443\n"
                + "    uuid: 44444444-4444-4444-4444-444444444444\n"
                + "    sni: edge.example\n"
                + "    skip-cert-verify: true\n"
                + "    reality-opts:\n"
                + "      public-key: " + realityPublicKey() + "\n"
                + "      short-id: 42\n";
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(vmess);
        assertEquals(1, parsed.nodes.size());
        JSONObject tls = parsed.nodes.get(0).outbound.optJSONObject("tls");
        assertEquals("edge.example", tls.optString("server_name"));
        assertTrue(tls.optBoolean("insecure"));
        assertEquals(realityPublicKey(),
                tls.optJSONObject("reality").optString("public_key"));
        assertEquals("42", tls.optJSONObject("reality").optString("short_id"));

        for (String invalid : new String[]{
                "proxies:\n  - name: Dangling SNI\n    type: vless\n"
                        + "    server: v.example\n    port: 443\n    uuid: uuid\n"
                        + "    sni: edge.example\n",
                "proxies:\n  - name: Dangling SID\n    type: vmess\n"
                        + "    server: v.example\n    port: 443\n    uuid: uuid\n"
                        + "    reality-opts:\n      short-id: 42\n"
        }) {
            SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(invalid);
            assertTrue(rejected.nodes.isEmpty());
            assertTrue(rejected.reasons.contains("clash_field_unsupported"));
        }

        String trojan = "proxies:\n  - name: Trojan TLS\n    type: trojan\n"
                + "    server: t.example\n    port: 443\n    password: secret\n"
                + "    sni: edge.example\n";
        assertEquals(1, SubscriptionParser.parseNodes(trojan).size());

        String incompleteTuic = "proxies:\n  - name: TUIC\n    type: tuic\n"
                + "    server: tuic.example\n    port: 443\n    uuid: only-uuid\n";
        SubscriptionParser.ParseResult tuicRejected =
                SubscriptionParser.parseDetailed(incompleteTuic);
        assertTrue(tuicRejected.nodes.isEmpty());
        assertEquals(1, tuicRejected.rejected);
    }

    @Test
    public void keepsSubscriptionRequestsOnExplicitUrlOnly() {
        List<String> urls = SubscriptionManager.subscriptionCandidateUrls(
                "https://raw.githubusercontent.com/owner/repo/refs/heads/main/path/sub.txt");
        assertEquals(1, urls.size());
        assertEquals("https://raw.githubusercontent.com/owner/repo/refs/heads/main/path/sub.txt",
                urls.get(0));
    }

    @Test
    public void convertsCommonClashYaml() {
        String yaml = "proxies:\n"
                + "  - name: Clash VLESS\n"
                + "    type: vless\n"
                + "    server: clash.example\n"
                + "    port: 443\n"
                + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                + "    tls: true\n"
                + "    servername: sni.example\n"
                + "    network: ws\n"
                + "    ws-opts:\n"
                + "      path: /ws\n";
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(yaml);
        assertEquals(1, nodes.size());
        assertEquals("ws", nodes.get(0).outbound.optJSONObject("transport").optString("type"));
        assertTrue(nodes.get(0).outbound.has("tls"));
    }

    @Test
    public void clashYamlSupportsIndentationlessProxySequence() {
        String yaml = "proxies:\n"
                + "- name: Indentationless\n"
                + "  type: trojan\n"
                + "  server: indentationless.example\n"
                + "  port: 443\n"
                + "  password: secret\n"
                + "- name: Sibling\n"
                + "  type: trojan\n"
                + "  server: sibling.example\n"
                + "  port: 443\n"
                + "  password: sibling-secret\n";
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(yaml);
        assertEquals(2, nodes.size());
        assertEquals("indentationless.example", nodes.get(0).outbound.optString("server"));
        assertEquals("sibling.example", nodes.get(1).outbound.optString("server"));
    }

    @Test
    public void clashYamlPreservesNestedWsFieldsInEitherOrder() throws Exception {
        String proxy = "proxies:\n"
                + "  - name: Ordered WS\n"
                + "    type: vless\n"
                + "    server: clash.example\n"
                + "    port: 443\n"
                + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                + "    network: ws\n"
                + "    ws-opts:\n";
        String pathBeforeHeaders = proxy
                + "      path: /ws\n"
                + "      headers:\n"
                + "        Host: edge.example\n";
        String headersBeforePath = proxy
                + "      headers:\n"
                + "        Host: edge.example\n"
                + "      path: /ws\n";

        ProtocolParser.Node pathFirst = SubscriptionParser.parseNodes(pathBeforeHeaders).get(0);
        ProtocolParser.Node headersFirst = SubscriptionParser.parseNodes(headersBeforePath).get(0);
        JSONObject firstTransport = pathFirst.outbound.getJSONObject("transport");
        JSONObject secondTransport = headersFirst.outbound.getJSONObject("transport");

        assertEquals("/ws", firstTransport.getString("path"));
        assertEquals("edge.example", firstTransport.getJSONObject("headers").getString("Host"));
        assertEquals(firstTransport.toString(), secondTransport.toString());
        assertEquals(pathFirst.normalizedKey, headersFirst.normalizedKey);
    }

    @Test
    public void clashYamlNeverPromotesNestedOrMisindentedListItems() {
        String nested = "proxies:\n"
                + "  - name: Unsupported outer\n"
                + "    type: unsupported\n"
                + "    children:\n"
                + "      - name: Hidden Trojan\n"
                + "        type: trojan\n"
                + "        server: hidden.example\n"
                + "        port: 443\n"
                + "        password: hidden-secret\n"
                + "  - name: Visible sibling\n"
                + "    type: trojan\n"
                + "    server: visible.example\n"
                + "    port: 443\n"
                + "    password: visible-secret\n";
        SubscriptionParser.ParseResult nestedResult =
                SubscriptionParser.parseDetailed(nested);
        assertEquals(1, nestedResult.nodes.size());
        assertEquals("visible.example", nestedResult.nodes.get(0).outbound.optString("server"));
        assertEquals(1, nestedResult.rejected);

        String inconsistent = "proxies:\n"
                + "    - name: First aligned item\n"
                + "      type: trojan\n"
                + "      server: first.example\n"
                + "      port: 443\n"
                + "      password: first-secret\n"
                + "  - name: Wrong indentation\n"
                + "    type: trojan\n"
                + "    server: wrong.example\n"
                + "    port: 443\n"
                + "    password: wrong-secret\n"
                + "    - name: Last aligned item\n"
                + "      type: trojan\n"
                + "      server: last.example\n"
                + "      port: 443\n"
                + "      password: last-secret\n";
        SubscriptionParser.ParseResult inconsistentResult =
                SubscriptionParser.parseDetailed(inconsistent);
        assertEquals(1, inconsistentResult.nodes.size());
        assertEquals("last.example",
                inconsistentResult.nodes.get(0).outbound.optString("server"));
        assertEquals(1, inconsistentResult.rejected);
    }

    @Test
    public void clashYamlRequiresExactlyOneRootProxySection() {
        String blockScalar = "notes: |\n"
                + "  proxies:\n"
                + "    - name: Hidden Trojan\n"
                + "      type: trojan\n"
                + "      server: hidden.example\n"
                + "      port: 443\n"
                + "      password: hidden-secret\n";
        SubscriptionParser.ParseResult nested =
                SubscriptionParser.parseDetailed(blockScalar);
        assertTrue(nested.nodes.isEmpty());
        assertEquals(1, nested.rejected);
        assertTrue(nested.reasons.contains("clash_root_invalid"));

        String duplicate = "proxies:\n"
                + "  - name: First\n"
                + "    type: trojan\n"
                + "    server: first.example\n"
                + "    port: 443\n"
                + "    password: first-secret\n"
                + "proxies:\n"
                + "  - name: Second\n"
                + "    type: trojan\n"
                + "    server: second.example\n"
                + "    port: 443\n"
                + "    password: second-secret\n";
        SubscriptionParser.ParseResult duplicateRoot =
                SubscriptionParser.parseDetailed(duplicate);
        assertTrue(duplicateRoot.nodes.isEmpty());
        assertEquals(1, duplicateRoot.rejected);
        assertTrue(duplicateRoot.reasons.contains("clash_root_invalid"));

        String nestedBeforeRoot = "metadata:\n"
                + "  proxies:\n"
                + "    - name: Hidden\n"
                + "      type: trojan\n"
                + "      server: hidden.example\n"
                + "      port: 443\n"
                + "      password: hidden-secret\n"
                + "proxies:\n"
                + "  - name: Visible\n"
                + "    type: trojan\n"
                + "    server: visible.example\n"
                + "    port: 443\n"
                + "    password: visible-secret\n";
        SubscriptionParser.ParseResult rootOnly =
                SubscriptionParser.parseDetailed(nestedBeforeRoot);
        assertEquals(1, rootOnly.nodes.size());
        assertEquals("visible.example", rootOnly.nodes.get(0).outbound.optString("server"));

        for (String root : new String[]{"\"proxies\":", "'proxies' :", "proxies :"}) {
            String alternateRoot = root + "\n"
                    + "  - name: Visible alternate root\n"
                    + "    type: trojan\n"
                    + "    server: alternate.example\n"
                    + "    port: 443\n"
                    + "    password: visible-secret\n"
                    + "notes: \"trojan://hidden@hidden.example:443\"\n";
            SubscriptionParser.ParseResult alternate =
                    SubscriptionParser.parseDetailed(alternateRoot);
            assertEquals(root, 1, alternate.nodes.size());
            assertEquals(root, "alternate.example",
                    alternate.nodes.get(0).outbound.optString("server"));
        }

        for (String invalidRoot : new String[]{"proxies: &proxy_list",
                "proxies: !!seq", "proxies: []", "proxies: null"}) {
            String yaml = invalidRoot + "\n"
                    + "  - name: Must not run\n"
                    + "    type: trojan\n"
                    + "    server: visible.example\n"
                    + "    port: 443\n"
                    + "    password: visible-secret\n"
                    + "notes: \"trojan://hidden@hidden.example:443\"\n";
            SubscriptionParser.ParseResult rejectedRoot =
                    SubscriptionParser.parseDetailed(yaml);
            assertTrue(invalidRoot, rejectedRoot.nodes.isEmpty());
            assertTrue(invalidRoot,
                    rejectedRoot.reasons.contains("clash_root_invalid"));
        }

        for (String unsupportedRootSyntax : new String[]{
                "!!str proxies:\n"
                        + "  - name: Tagged key\n"
                        + "    type: trojan\n"
                        + "    server: tagged.example\n"
                        + "    port: 443\n"
                        + "    password: visible-secret\n",
                "&key_anchor proxies:\n"
                        + "  - name: Anchored key\n"
                        + "    type: trojan\n"
                        + "    server: anchored.example\n"
                        + "    port: 443\n"
                        + "    password: visible-secret\n",
                "? proxies\n"
                        + ":\n"
                        + "  - name: Explicit key\n"
                        + "    type: trojan\n"
                        + "    server: explicit.example\n"
                        + "    port: 443\n"
                        + "    password: visible-secret\n",
                "rootkey: &k proxies\n"
                        + "*k:\n"
                        + "  - name: Alias key\n"
                        + "    type: trojan\n"
                        + "    server: alias.example\n"
                        + "    port: 443\n"
                        + "    password: visible-secret\n",
        }) {
            String yaml = unsupportedRootSyntax
                    + "notes: \"trojan://hidden@hidden.example:443\"\n";
            SubscriptionParser.ParseResult rejectedRoot =
                    SubscriptionParser.parseDetailed(yaml);
            assertTrue(unsupportedRootSyntax, rejectedRoot.nodes.isEmpty());
            assertTrue(unsupportedRootSyntax,
                    rejectedRoot.reasons.contains("clash_root_invalid"));
        }
    }

    @Test
    public void clashYamlOversizedRootCannotFallBackToHiddenUriRegex() {
        String yaml = "proxies:" + repeat(' ', 70 * 1024) + "\n"
                + "notes: \"trojan://hidden@hidden.example:443\"\n";
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
        assertTrue(parsed.nodes.isEmpty());
        assertTrue(parsed.reasons.contains("clash_line_too_large"));
    }

    @Test
    public void clashYamlFlowDocumentsAndNestedProxyKeysFailClosed() {
        for (String yaml : new String[]{
                "metadata: first\n"
                        + "--- {proxies: [], notes: \"trojan://secret@hidden.example:443\"}\n",
                "metadata: {proxies: [], notes: \"trojan://secret@hidden.example:443\"}\n",
                "metadata: [one, { proxies : [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}]\n",
                "metadata: {\"proxies\": [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {'proxies': [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {\"\\u0070roxies\": [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {\"\\x70roxies\": [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {? \"proxies\": [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {!!str \"proxies\": [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {&key \"proxies\": [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {key: &k proxies, *k: [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {? proxies # comment\n : [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {? \"proxies\" # comment\n : [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {key: &other something, *other: [], notes: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {title: foo\"bar, proxies: [], note: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {title: foo \"bar, proxies: [], note: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata:\n  nested: {title: foo\"bar, proxies: [], note: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "title: foo \"bar\nmetadata: {proxies: [], note: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
                "metadata: {\"\\U00000070\\U00000072\\U0000006f"
                        + "\\U00000078\\U00000069\\U00000065\\U00000073\": [], note: "
                        + "\"trojan://secret@hidden.example:443\"}\n",
        }) {
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue(yaml, parsed.nodes.isEmpty());
            assertTrue(yaml, parsed.reasons.contains("clash_root_invalid"));
        }
    }

    @Test
    public void clashYamlNormalizesCrOnlyBlockDocumentsBeforeParsing() {
        String yaml = "# c\r"
                + "proxies:\r"
                + "  - name: Visible CR\r"
                + "    type: trojan\r"
                + "    server: visible-cr.example\r"
                + "    port: 443\r"
                + "    password: visible-secret\r"
                + "notes: \"trojan://hidden@hidden.example:443\"\r";
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
        assertEquals(1, parsed.nodes.size());
        assertEquals("visible-cr.example",
                parsed.nodes.get(0).outbound.optString("server"));
    }

    @Test
    public void clashYamlExplicitBlockScalarKeysCannotBypassFlowDetection() {
        for (String indicator : new String[]{"|", "|-", "|+", ">", ">-", ">+"}) {
            String yaml = "? " + indicator + "\n"
                    + "  proxies\n"
                    + ":\n"
                    + "  []\n"
                    + "notes: \"trojan://secret@hidden.example:443\"\n";
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue(indicator, parsed.nodes.isEmpty());
            assertTrue(indicator, parsed.reasons.contains("clash_root_invalid"));
        }
    }

    @Test
    public void clashYamlFlowRootAllowsCommentsMarkersAndBoundedNodeProperties() {
        String hidden = "trojan://secret@hidden.example:443";
        for (String yaml : new String[]{
                "# leading comment\n{\"note\": \"" + hidden + "\"}\n",
                "--- !!map {note: \"" + hidden + "\"}\n",
                "--- &root\n{note: \"" + hidden + "\"}\n",
                "!!map {note: \"" + hidden + "\"}\n",
                "&root {note: \"" + hidden + "\"}\n",
                "metadata: first\n--- !<tag:yaml.org,2002:map> "
                        + "{note: \"" + hidden + "\"}\n",
                "metadata: first\n--- &root\n# between properties\n"
                        + "!!map\n{note: \"" + hidden + "\"}\n",
                "metadata: first\n--- &root !!map {note: \"" + hidden + "\"}\n",
                "# CR-only\r--- &root\r!!map\r{note: \"" + hidden + "\"}\r",
                "---\r{note: \"" + hidden + "\"}\r",
                "# comment\r{note: \"" + hidden + "\"}\r",
                "%TAG !e! tag:yaml.org,2002:\n"
                        + "--- !e!map {note: \"" + hidden + "\"}\n",
                "metadata: first\n...\n--- !!map {note: \"" + hidden + "\"}\n",
        }) {
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue(yaml, parsed.nodes.isEmpty());
            assertTrue(yaml, parsed.reasons.contains("clash_root_invalid"));
        }
    }

    @Test
    public void flowStyleClashRootNeverFallsThroughToGlobalUriRegex() {
        String unquoted = "{proxies: [{name: Visible, type: trojan, "
                + "server: visible.example, port: 443, password: secret}], "
                + "notes: \"trojan://meta@hidden.example:443\"}";
        String singleQuoted = "{'proxies': [{'name': 'Visible', 'type': 'trojan', "
                + "'server': 'visible.example', 'port': 443, "
                + "'password': 'secret'}], "
                + "'notes': 'trojan://meta@hidden.example:443'}";
        for (String document : new String[]{
                unquoted,
                singleQuoted,
                "--- " + unquoted,
                "--- " + singleQuoted,
                "%YAML 1.2\n---\n" + unquoted,
                "---\n[{note: \"trojan://meta@hidden.example:443\"}]",
        }) {
            SubscriptionParser.ParseResult parsed =
                    SubscriptionParser.parseDetailed(document);
            assertTrue(document, parsed.nodes.isEmpty());
        }
    }

    @Test
    public void clashYamlAcceptsOneDocumentBomButFailsClosedOnMultipleBoms() {
        String visible = "proxies:\n"
                + "  - name: Visible BOM node\n"
                + "    type: trojan\n"
                + "    server: visible-bom.example\n"
                + "    port: 443\n"
                + "    password: visible-secret\n"
                + "notes: \"trojan://hidden@hidden.example:443\"\n";
        SubscriptionParser.ParseResult accepted =
                SubscriptionParser.parseDetailed("\ufeff" + visible);
        assertEquals(1, accepted.nodes.size());
        assertEquals("visible-bom.example",
                accepted.nodes.get(0).outbound.optString("server"));

        SubscriptionParser.ParseResult invalid =
                SubscriptionParser.parseDetailed("\ufeff\ufeff" + visible);
        assertTrue(invalid.nodes.isEmpty());
        assertTrue(invalid.reasons.contains("invalid_document_bom"));
    }

    @Test
    public void jsonBomIsNormalizedBeforeStructuredDispatchAndRegexFallback() {
        String hidden = "trojan://secret@hidden.example:443";
        for (String document : new String[]{
                "\ufeff{\"note\":\"" + hidden + "\"}",
                "\ufeff[{\"note\":\"" + hidden + "\"}]",
        }) {
            SubscriptionParser.ParseResult parsed =
                    SubscriptionParser.parseDetailed(document);
            assertTrue(document, parsed.nodes.isEmpty());
        }

        String encoded = java.util.Base64.getEncoder().encodeToString(
                ("\ufeff{\"note\":\"" + hidden + "\"}")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertTrue(SubscriptionParser.parseDetailed(encoded).nodes.isEmpty());

        for (String invalid : new String[]{
                "\ufeff\ufeff{\"note\":\"" + hidden + "\"}",
                " \ufeff{\"note\":\"" + hidden + "\"}",
        }) {
            SubscriptionParser.ParseResult parsed =
                    SubscriptionParser.parseDetailed(invalid);
            assertTrue(invalid, parsed.nodes.isEmpty());
            assertTrue(invalid, parsed.reasons.contains("invalid_document_bom"));
        }
    }

    @Test
    public void clashYamlOversizedLineInvalidatesTheWholeProxySection() {
        String yaml = "proxies:\n"
                + "  - name: Must not run\n"
                + "    type: trojan\n"
                + "    server: direct.example\n"
                + "    port: 443\n"
                + "    password: secret\n"
                + "    dialer-proxy: " + repeat('x', 70 * 1024) + "\n";
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
        assertTrue(parsed.nodes.isEmpty());
        assertTrue(parsed.reasons.contains("clash_line_too_large"));
    }

    @Test
    public void clashYamlPreservesQuotedOpaquePasswordAndPath() throws Exception {
        String yaml = "proxies:\n"
                + "  - name: Opaque Clash\n"
                + "    type: trojan\n"
                + "    server: clash.example\n"
                + "    port: 443\n"
                + "    password: \" secret \"\n"
                + "    network: ws\n"
                + "    ws-opts:\n"
                + "      path: \" /opaque path \"\n";
        ProtocolParser.Node node = SubscriptionParser.parseNodes(yaml).get(0);
        assertEquals(" secret ", node.outbound.getString("password"));
        assertEquals(" /opaque path ", node.outbound.getJSONObject("transport")
                .getString("path"));
    }

    @Test
    public void clashYamlRejectsUnquotedNullScalarsButPreservesQuotedLiterals()
            throws Exception {
        for (String scalar : new String[]{"null", "Null", "NULL", "~"}) {
            String prefix = "proxies:\n"
                    + "  - name: YAML null " + scalar + "\n"
                    + "    type: trojan\n"
                    + "    server: null.example\n"
                    + "    port: 443\n"
                    + "    password: ";
            SubscriptionParser.ParseResult rejected =
                    SubscriptionParser.parseDetailed(prefix + scalar + "\n");
            assertTrue(scalar, rejected.nodes.isEmpty());
            assertEquals(scalar, 1, rejected.rejected);

            ProtocolParser.Node quoted = SubscriptionParser.parseNodes(
                    prefix + "\"" + scalar + "\"\n").get(0);
            assertEquals(scalar, quoted.outbound.getString("password"));
        }
    }

    @Test
    public void clashYamlRejectsAmbiguousUnquotedOctalIntegers() throws Exception {
        String prefix = "proxies:\n"
                + "  - name: YAML integer\n"
                + "    type: trojan\n"
                + "    server: integer.example\n"
                + "    port: ";
        String suffix = "\n    password: secret\n";
        SubscriptionParser.ParseResult ambiguous = SubscriptionParser.parseDetailed(
                prefix + "0443" + suffix);
        assertTrue(ambiguous.nodes.isEmpty());
        assertEquals(1, ambiguous.rejected);

        ProtocolParser.Node quoted = SubscriptionParser.parseNodes(
                prefix + "\"0443\"" + suffix).get(0);
        assertEquals(443, quoted.outbound.getInt("server_port"));
        ProtocolParser.Node decimal = SubscriptionParser.parseNodes(
                prefix + "443" + suffix).get(0);
        assertEquals(443, decimal.outbound.getInt("server_port"));
    }

    @Test
    public void clashYamlRejectsUnsupportedBlockScalarsPerEntry() {
        for (String indicator : new String[]{"|", "|-", "|2-", ">", ">+", ">2"}) {
            String yaml = "proxies:\n"
                    + "  - name: Block scalar\n"
                    + "    type: trojan\n"
                    + "    server: hidden.example\n"
                    + "    port: 443\n"
                    + "    password: " + indicator + "\n"
                    + "      hidden-secret\n"
                    + "  - name: Visible\n"
                    + "    type: trojan\n"
                    + "    server: visible.example\n"
                    + "    port: 443\n"
                    + "    password: visible-secret\n";
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertEquals(indicator, 1, parsed.nodes.size());
            assertEquals(indicator, "visible.example",
                    parsed.nodes.get(0).outbound.optString("server"));
            assertEquals(indicator, 1, parsed.rejected);
        }
    }

    @Test
    public void clashYamlRejectsUnquotedSemanticScalarsButKeepsQuotedOpaqueData() {
        for (String semantic : new String[]{"&pw secret", "*pw", "!!str secret",
                "[secret]", "{value: secret}"}) {
            String yaml = "proxies:\n"
                    + "  - name: Semantic scalar\n"
                    + "    type: trojan\n"
                    + "    server: hidden.example\n"
                    + "    port: 443\n"
                    + "    password: " + semantic + "\n"
                    + "  - name: Visible\n"
                    + "    type: trojan\n"
                    + "    server: visible.example\n"
                    + "    port: 443\n"
                    + "    password: \"" + semantic.replace("\"", "\\\"") + "\"\n";
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertEquals(semantic, 1, parsed.nodes.size());
            assertEquals(semantic, "visible.example",
                    parsed.nodes.get(0).outbound.optString("server"));
            assertEquals(semantic, semantic,
                    parsed.nodes.get(0).outbound.optString("password"));
            assertEquals(semantic, 1, parsed.rejected);
        }
    }

    @Test
    public void clashYamlDecodesQuotedEscapesAndSeparatesComments() throws Exception {
        String yaml = "proxies:\n"
                + "  - name: \"Escaped \\\"# Name\"\n"
                + "    type: trojan\n"
                + "    server: escaped.example\n"
                + "    port: 443\n"
                + "    password: \"abc\\\"#def\"\n"
                + "    network: ws\n"
                + "    ws-opts:\n"
                + "      path: \"/ws\\x20path\"\n"
                + "  - name: Single quote\n"
                + "    type: trojan\n"
                + "    server: single.example\n"
                + "    port: 443\n"
                + "    password: 'ab''cd'\n"
                + "  - name: Embedded hash\n"
                + "    type: trojan\n"
                + "    server: hash.example\n"
                + "    port: 443\n"
                + "    password: abc#def\n"
                + "  - name: Real comment\n"
                + "    type: trojan\n"
                + "    server: comment.example\n"
                + "    port: 443\n"
                + "    password: abc # ignored\n";
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(yaml);
        assertEquals(4, nodes.size());
        assertEquals("Escaped \"# Name", nodes.get(0).name);
        assertEquals("abc\"#def", nodes.get(0).outbound.getString("password"));
        assertEquals("/ws path", nodes.get(0).outbound.getJSONObject("transport")
                .getString("path"));
        assertEquals("ab'cd", nodes.get(1).outbound.getString("password"));
        assertEquals("abc#def", nodes.get(2).outbound.getString("password"));
        assertEquals("abc", nodes.get(3).outbound.getString("password"));

        for (String invalidPassword : new String[]{
                "\"bad\\q\"", "\"bad\\x0\"", "\"bad\\U00110000\"",
                "'bad'quote'", "\"unterminated"
        }) {
            SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                    "proxies:\n"
                            + "  - name: Invalid scalar\n"
                            + "    type: trojan\n"
                            + "    server: invalid.example\n"
                            + "    port: 443\n"
                            + "    password: " + invalidPassword + "\n");
            assertTrue("invalid quoted scalar accepted: " + invalidPassword,
                    rejected.nodes.isEmpty());
            assertEquals(1, rejected.rejected);
        }

        SubscriptionParser.ParseResult mixed = SubscriptionParser.parseDetailed(
                "proxies:\n"
                        + "  - name: Invalid sibling\n"
                        + "    type: trojan\n"
                        + "    server: invalid.example\n"
                        + "    port: 443\n"
                        + "    password: \"bad\\q\"\n"
                        + "  - name: Valid sibling\n"
                        + "    type: trojan\n"
                        + "    server: valid.example\n"
                        + "    port: 443\n"
                        + "    password: valid\n");
        assertEquals(1, mixed.nodes.size());
        assertEquals("valid.example", mixed.nodes.get(0).outbound.optString("server"));
        assertEquals(1, mixed.rejected);
    }

    @Test
    public void clashHysteriaAuthUsesExactlyOneRepresentation() throws Exception {
        for (String key : new String[]{"auth-str", "auth"}) {
            String yaml = "proxies:\n"
                    + "  - name: Hysteria auth\n"
                    + "    type: hysteria\n"
                    + "    server: hy.example\n"
                    + "    port: 443\n"
                    + "    " + key + ": \" secret \"\n";
            List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(yaml);
            assertEquals("failed alias: " + key, 1, nodes.size());
            assertEquals(" secret ", nodes.get(0).outbound.getString("auth_str"));
        }

        SubscriptionParser.ParseResult aliases = SubscriptionParser.parseDetailed(
                "proxies:\n"
                        + "  - name: Duplicate auth\n"
                        + "    type: hysteria\n"
                        + "    server: hy.example\n"
                        + "    port: 443\n"
                        + "    auth: one\n"
                        + "    auth-str: two\n");
        assertTrue(aliases.nodes.isEmpty());
        assertEquals(1, aliases.rejected);
    }

    @Test
    public void clashRejectsUnknownBooleansAndMalformedIntegersWithoutTlsDowngrade() {
        for (String field : new String[]{
                "    tls: maybe\n",
                "    skip-cert-verify: perhaps\n",
                "    port: 443x\n",
                "    alterId: not-a-number\n",
        }) {
            String yaml = "proxies:\n"
                    + "  - name: Strict VMess\n"
                    + "    type: vmess\n"
                    + "    server: vmess.example\n"
                    + (field.startsWith("    port:") ? "" : "    port: 443\n")
                    + "    uuid: 44444444-4444-4444-4444-444444444444\n"
                    + field;
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue("malformed Clash scalar was accepted: " + field,
                    parsed.nodes.isEmpty());
            assertEquals(1, parsed.rejected);
        }

        String explicitFalse = "proxies:\n"
                + "  - name: Plain VMess\n"
                + "    type: vmess\n"
                + "    server: vmess.example\n"
                + "    port: 443\n"
                + "    uuid: 44444444-4444-4444-4444-444444444444\n"
                + "    tls: false\n"
                + "    alterId: 0\n";
        assertEquals(1, SubscriptionParser.parseNodes(explicitFalse).size());
    }

    @Test
    public void structuredXrayRejectsMultiHostAndNonSelectedFunctionalBlocks()
            throws Exception {
        JSONObject multiHost = xrayVnext("vless", "http.example",
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "none")
                .put("streamSettings", new JSONObject().put("network", "http")
                        .put("httpSettings", new JSONObject()
                                .put("path", "/h2")
                                .put("host", new JSONArray().put("one.example")
                                        .put("two.example"))));
        JSONObject ignoredBlock = xrayVnext("vless", "grpc.example",
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "none")
                .put("streamSettings", new JSONObject().put("network", "grpc")
                        .put("grpcSettings", new JSONObject().put("serviceName", "svc"))
                        .put("wsSettings", new JSONObject().put("path", "/must-not-drop")));
        JSONObject wrongSecurityBlock = xrayVnext("vless", "tls.example",
                "cccccccc-cccc-cccc-cccc-cccccccccccc", "none")
                .put("streamSettings", new JSONObject().put("network", "tcp")
                        .put("security", "none")
                        .put("tlsSettings", new JSONObject().put("serverName", "secret")));

        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray()
                        .put(multiHost).put(ignoredBlock).put(wrongSecurityBlock)).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(3, parsed.rejected);
    }

    @Test
    public void structuredXrayVmessRejectsLegacySecurityWithoutChangingDirectSingBox()
            throws Exception {
        JSONArray xray = new JSONArray();
        for (String security : new String[]{"none", "zero", "aes-128-cfb"}) {
            xray.put(xrayVnext("vmess", security + ".example",
                    "abababab-abab-abab-abab-abababababab", security));
        }
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", xray).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(3, rejected.rejected);
        assertTrue(rejected.reasons.contains("security_unsupported"));

        JSONArray supported = new JSONArray();
        for (String security : new String[]{
                "auto", "aes-128-gcm", "chacha20-poly1305"}) {
            supported.put(xrayVnext("vmess", security + ".example",
                    "cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd", security));
        }
        SubscriptionParser.ParseResult accepted = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", supported).toString());
        assertEquals(accepted.reasons.toString(), 3, accepted.nodes.size());
        for (ProtocolParser.Node node : accepted.nodes) {
            assertTrue(node.supports(CoreFamily.XRAY));
        }

        JSONObject singBox = direct("vmess").put("security", "none");
        SubscriptionParser.ParseResult direct = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(singBox)).toString());
        assertEquals(direct.reasons.toString(), 1, direct.nodes.size());
        assertTrue(direct.nodes.get(0).supports(CoreFamily.SING_BOX));
        assertFalse(direct.nodes.get(0).supports(CoreFamily.XRAY));
    }

    @Test
    public void structuredImportRejectsWrongFunctionalTypesAndTlsDowngrade()
            throws Exception {
        JSONArray invalid = new JSONArray();
        for (Object tls : new Object[]{
                "garbage",
                new JSONObject().put("enabled", "maybe").put("server_name", "edge.example"),
                new JSONObject().put("enabled", false).put("server_name", "edge.example"),
                new JSONObject().put("enabled", true).put("server_name", "edge.example")
                        .put("alpn", new JSONArray().put("h2").put(7)),
        }) {
            invalid.put(new JSONObject().put("type", "vless")
                    .put("server", "strict.example").put("server_port", 443)
                    .put("uuid", "dddddddd-dddd-dddd-dddd-dddddddddddd")
                    .put("encryption", "none").put("tls", tls));
        }
        invalid.put(new JSONObject().put("type", "vless")
                .put("server", "strict.example").put("server_port", 443)
                .put("uuid", "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
                .put("encryption", "none").put("transport", new JSONArray()));
        invalid.put(new JSONObject().put("type", "vless")
                .put("server", "strict.example").put("server_port", "443x")
                .put("uuid", "edededed-eded-eded-eded-edededededed")
                .put("encryption", "none"));

        JSONObject badAlter = xrayVnext("vmess", "vmess.example",
                "ffffffff-ffff-ffff-ffff-ffffffffffff", "auto");
        badAlter.getJSONObject("settings").getJSONArray("vnext")
                .getJSONObject(0).getJSONArray("users").getJSONObject(0)
                .put("alterId", "garbage");
        invalid.put(badAlter);
        invalid.put(xrayVnext("vless", "ws.example",
                "12121212-1212-1212-1212-121212121212", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", "garbage")));
        invalid.put(xrayVnext("vless", "tls.example",
                "13131313-1313-1313-1313-131313131313", "none")
                .put("streamSettings", new JSONObject().put("network", "tcp")
                        .put("security", "tls").put("tlsSettings", new JSONArray())));
        invalid.put(xrayVnext("vless", "kcp.example",
                "14141414-1414-1414-1414-141414141414", "none")
                .put("streamSettings", new JSONObject().put("network", "mkcp")
                        .put("finalmask", "garbage")));

        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(result.nodes.isEmpty());
        assertEquals(invalid.length(), result.rejected);
    }

    @Test
    public void structuredWebSocketRejectsConflictingEarlyDataSources() throws Exception {
        JSONObject outbound = xrayVnext("vless", "ws.example",
                "15151515-1515-1515-1515-151515151515", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", new JSONObject()
                                .put("path", "/ws?ed=1024")
                                .put("maxEarlyData", 2048)));
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(outbound)).toString());
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(1, parsed.rejected);
    }

    @Test
    public void preservesClashGrpcAndHysteria2Options() {
        String grpc = "proxies:\n"
                + "  - name: Clash gRPC\n"
                + "    type: vless\n"
                + "    server: grpc.example\n"
                + "    port: 443\n"
                + "    uuid: 55555555-5555-5555-5555-555555555555\n"
                + "    tls: true\n"
                + "    network: grpc\n"
                + "    grpc-opts:\n"
                + "      grpc-service-name: telegram-service\n";
        List<ProtocolParser.Node> grpcNodes = SubscriptionParser.parseNodes(grpc);
        assertEquals(1, grpcNodes.size());
        assertEquals("telegram-service", grpcNodes.get(0).outbound
                .optJSONObject("transport").optString("service_name"));

        String hysteria2 = "proxies:\n"
                + "  - name: Clash H2\n"
                + "    type: hysteria2\n"
                + "    server: hy2.example\n"
                + "    port: 443\n"
                + "    ports: 443-8443\n"
                + "    password: user:password\n"
                + "    up: \" 100 mbps \"\n"
                + "    down: \"200 MbPS\"\n"
                + "    obfs: salamander\n"
                + "    obfs-password: cover\n"
                + "    hop-interval: 15s\n"
                + "    sni: edge.example\n";
        List<ProtocolParser.Node> h2Nodes = SubscriptionParser.parseNodes(hysteria2);
        assertEquals(1, h2Nodes.size());
        JSONObject outbound = h2Nodes.get(0).outbound;
        assertEquals("user:password", outbound.optString("password"));
        assertEquals("443:8443", outbound.optJSONArray("server_ports").optString(0));
        assertEquals("cover", outbound.optJSONObject("obfs").optString("password"));
        assertEquals("15s", outbound.optString("hop_interval"));
        assertEquals(100, outbound.optInt("up_mbps"));
        assertEquals(200, outbound.optInt("down_mbps"));
    }

    @Test
    public void normalizesClashHysteria2BitAndByteRateUnits() {
        String yaml = "proxies:\n"
                + "  - name: H2 normalized bandwidth\n"
                + "    type: hysteria2\n"
                + "    server: hy2.example\n"
                + "    port: 443\n"
                + "    password: secret\n"
                + "    up: \"2 GBPS\"\n"
                + "    down: \"8000 kbps\"\n";
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(yaml);
        assertEquals(1, nodes.size());
        assertEquals(16000, nodes.get(0).outbound.optInt("up_mbps"));
        assertEquals(8, nodes.get(0).outbound.optInt("down_mbps"));
    }

    @Test
    public void normalizesClashHysteriaBandwidthUnitsAndBareMaximum() {
        String yaml = "proxies:\n"
                + "  - name: H1 normalized bandwidth\n"
                + "    type: hysteria\n"
                + "    server: hy1.example\n"
                + "    port: 443\n"
                + "    auth: secret\n"
                + "    up: \"1 GBPS\"\n"
                + "    down: \"8000 kbps\"\n"
                + "  - name: H1 bare maximum\n"
                + "    type: hysteria\n"
                + "    server: hy1-max.example\n"
                + "    port: 443\n"
                + "    auth: secret\n"
                + "    up: 2147483647\n"
                + "    down: 0\n";
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(yaml);
        assertEquals(2, nodes.size());
        assertEquals(8000, nodes.get(0).outbound.optInt("up_mbps"));
        assertEquals(8, nodes.get(0).outbound.optInt("down_mbps"));
        assertEquals(Integer.MAX_VALUE, nodes.get(1).outbound.optInt("up_mbps"));
        assertFalse(nodes.get(1).outbound.has("down_mbps"));
    }

    @Test
    public void rejectsUnrepresentableOrOverflowingClashHysteriaBandwidth() {
        for (String invalid : new String[]{
                "500 Kbps", "2147483648", "2148 Tbps", "1.5 Mbps",
                "999999999999999999999999 Mbps"
        }) {
            String yaml = "proxies:\n"
                    + "  - name: Invalid H1 bandwidth\n"
                    + "    type: hysteria\n"
                    + "    server: hy1.example\n"
                    + "    port: 443\n"
                    + "    auth: secret\n"
                    + "    up: \"" + invalid + "\"\n";
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue("accepted invalid Hysteria bandwidth: " + invalid,
                    parsed.nodes.isEmpty());
            assertEquals(1, parsed.rejected);
        }
    }

    @Test
    public void importsClashHysteria2PortsWithoutRedundantPort() {
        String yaml = "proxies:\n"
                + "  - name: H2 ports only\n"
                + "    type: hy2\n"
                + "    server: hy2.example\n"
                + "    ports: 5000-6000,7044\n"
                + "    password: secret\n"
                + "    tls: true\n"
                + "    hop-interval: 15\n";
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(yaml);
        assertEquals(1, nodes.size());
        JSONObject outbound = nodes.get(0).outbound;
        assertEquals(5000, outbound.optInt("server_port"));
        assertEquals("5000:6000", outbound.optJSONArray("server_ports").optString(0));
        assertEquals("7044:7044", outbound.optJSONArray("server_ports").optString(1));
        assertEquals("15s", outbound.optString("hop_interval"));
    }

    @Test
    public void clashHysteria2ZeroHopIntervalUsesPinnedDefault() throws Exception {
        for (String zero : new String[]{
                "0", "+0", "-0", "0s", "+0s", "-0s", "00s", "0.0s",
                "0h0m", "0.1ns", "-0.1ns"
        }) {
            String yaml = "proxies:\n"
                    + "  - name: H2 zero interval\n"
                    + "    type: hysteria2\n"
                    + "    server: hy2.example\n"
                    + "    ports: 443-8443\n"
                    + "    password: secret\n"
                    + "    hop-interval: " + zero + "\n";
            ProtocolParser.Node node = SubscriptionParser.parseNodes(yaml).get(0);
            String expected = zero.matches("[0-9]+(?:\\.[0-9]+)?")
                    ? zero + "s" : zero;
            assertEquals(expected, node.outbound.getString("hop_interval"));
        }

        SubscriptionParser.ParseResult negative = SubscriptionParser.parseDetailed(
                "proxies:\n"
                        + "  - name: H2 negative interval\n"
                        + "    type: hysteria2\n"
                        + "    server: hy2.example\n"
                        + "    ports: 443-8443\n"
                        + "    password: secret\n"
                        + "    hop-interval: -1s\n");
        assertTrue(negative.nodes.isEmpty());
        assertEquals(1, negative.rejected);
    }

    @Test
    public void forcedTlsClashProtocolsRejectExplicitFalse() {
        for (String protocolFields : new String[]{
                "    type: hysteria\n    auth: secret\n",
                "    type: hysteria2\n    password: secret\n",
                "    type: tuic\n"
                        + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                        + "    password: secret\n",
        }) {
            String yaml = "proxies:\n"
                    + "  - name: Forced TLS\n"
                    + protocolFields
                    + "    server: quic.example\n"
                    + "    port: 443\n"
                    + "    tls: false\n";
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue(parsed.nodes.isEmpty());
            assertEquals(1, parsed.rejected);
        }
    }

    @Test
    public void clashTrojanRejectsExplicitTlsFalseInsteadOfForcingTls() {
        String prefix = "proxies:\n"
                + "  - name: Trojan TLS\n"
                + "    type: trojan\n"
                + "    server: trojan.example\n"
                + "    port: 443\n"
                + "    password: secret\n";
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                prefix + "    tls: false\n");
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(1, rejected.rejected);

        List<ProtocolParser.Node> accepted = SubscriptionParser.parseNodes(
                prefix + "    tls: true\n");
        assertEquals(1, accepted.size());
        assertTrue(accepted.get(0).outbound.optJSONObject("tls")
                .optBoolean("enabled", false));
    }

    @Test
    public void clashYamlNullScalarsAndUnknownEmptyMappingsCannotBecomeDefaults() {
        String endpoint = "    server: strict.example\n"
                + "    port: 443\n";
        String[] invalid = {
                "proxies:\n"
                        + "  - name: Null TLS\n"
                        + "    type: hysteria2\n"
                        + endpoint
                        + "    password: secret\n"
                        + "    tls:\n",
                "proxies:\n"
                        + "  - name: Null network\n"
                        + "    type: vless\n"
                        + endpoint
                        + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                        + "    network:\n",
                "proxies:\n"
                        + "  - name: Empty mux mapping\n"
                        + "    type: vless\n"
                        + endpoint
                        + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                        + "    mux:\n"
        };

        for (String yaml : invalid) {
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue(parsed.nodes.isEmpty());
            assertEquals(1, parsed.rejected);
            assertTrue(parsed.reasons.contains("clash_field_unsupported"));
        }
    }

    @Test
    public void rejectsClashHysteria2BandwidthThatSingBoxCannotRepresentSafely() {
        for (String invalid : new String[]{
                "500 Kbps", "3 GBps", "30 MiBps", "1.5 Mbps",
                "999999999999999999999999 Mbps"
        }) {
            String yaml = "proxies:\n"
                    + "  - name: Invalid H2 bandwidth\n"
                    + "    type: hysteria2\n"
                    + "    server: hy2.example\n"
                    + "    port: 443\n"
                    + "    password: secret\n"
                    + "    up: \"" + invalid + "\"\n";
            SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(yaml);
            assertTrue("accepted invalid Hysteria2 bandwidth: " + invalid,
                    parsed.nodes.isEmpty());
            assertEquals(1, parsed.rejected);
        }
    }

    @Test
    public void decodesCurrentHitVpnAndHitrayWrapper() throws Exception {
        byte[] uuid = new byte[16];
        byte[] publicKey = new byte[32];
        for (int i = 0; i < uuid.length; i++) uuid[i] = (byte) (i + 1);
        for (int i = 0; i < publicKey.length; i++) publicKey[i] = (byte) (31 - i);
        ByteArrayOutputStream config = new ByteArrayOutputStream();
        cborHeader(config, 5, 7);
        cborInt(config, 1); cborBytes(config, uuid);
        cborInt(config, 2); cborBytes(config, publicKey);
        cborInt(config, 3); cborInt(config, 0x01020304L);
        cborInt(config, 4); cborInt(config, 443);
        cborInt(config, 5); cborInt(config, 0);
        cborInt(config, 6); cborInt(config, 1);
        cborInt(config, 7); cborText(config, "edge.example");

        ByteArrayOutputStream item = new ByteArrayOutputStream();
        cborHeader(item, 5, 2);
        cborInt(item, 1); cborInt(item, 2);
        cborInt(item, 2); cborBytes(item, config.toByteArray());
        ByteArrayOutputStream root = new ByteArrayOutputStream();
        cborHeader(root, 5, 2);
        cborInt(root, 1); cborInt(root, 7);
        cborInt(root, 4); cborHeader(root, 4, 1); root.write(item.toByteArray());

        byte[] payload = root.toByteArray();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
        byte[] salt = new byte[]{1, 2, 3, 4};
        xorHitPayload(salt, payload);
        ByteArrayOutputStream wrapped = new ByteArrayOutputStream();
        wrapped.write(1);
        wrapped.write(salt);
        wrapped.write(digest, 0, 4);
        wrapped.write(payload);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(wrapped.toByteArray());
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes("https://hitray.io/" + encoded);
        assertEquals(1, nodes.size());
        assertEquals("vless", nodes.get(0).outbound.optString("type"));
        assertEquals("1.2.3.4", nodes.get(0).outbound.optString("server"));
    }

    @Test
    public void rejectsHostileHitVpnCborContainerWithoutAllocatingIt() throws Exception {
        byte[] payload = new byte[27];
        byte[] prefix = new byte[]{(byte) 0xa1, 0x04, (byte) 0x9a, 0x7f, (byte) 0xff,
                (byte) 0xff, (byte) 0xff};
        System.arraycopy(prefix, 0, payload, 0, prefix.length);
        assertTrue(SubscriptionParser.parseNodes(wrapHitPayload(payload)).isEmpty());
    }

    @Test
    public void rejectsHitVpnCborMapsWithDuplicateKeys() throws Exception {
        ByteArrayOutputStream root = new ByteArrayOutputStream();
        cborHeader(root, 5, 2);
        cborInt(root, 1); cborText(root, "large-enough-wrapper-value");
        cborInt(root, 1); cborInt(root, 8);

        String link = wrapHitPayload(root.toByteArray());
        Class<?> tracker = Class.forName(
                "com.extera.plugins.exitfy.SubscriptionParser$RejectionTracker");
        java.lang.reflect.Method decoder = SubscriptionParser.class.getDeclaredMethod(
                "decodeHitVpn", String.class, tracker);
        decoder.setAccessible(true);
        try {
            decoder.invoke(null, link, null);
            assertTrue("duplicate CBOR key was accepted", false);
        } catch (java.lang.reflect.InvocationTargetException expected) {
            assertEquals("duplicate CBOR map key", expected.getCause().getMessage());
        }
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                link);
        assertTrue(parsed.nodes.isEmpty());
        assertEquals(1, parsed.rejected);
        assertTrue(parsed.reasons.toString(), parsed.reasons.contains("hit_cbor_duplicate"));
    }

    @Test
    public void rejectsHitVpnInvalidKeyAndOversizedConfigBeforeUriExpansion() throws Exception {
        byte[] uuid = new byte[16];
        ByteArrayOutputStream invalidKey = new ByteArrayOutputStream();
        cborHeader(invalidKey, 5, 7);
        cborInt(invalidKey, 1); cborBytes(invalidKey, uuid);
        cborInt(invalidKey, 2); cborBytes(invalidKey, new byte[33]);
        cborInt(invalidKey, 3); cborInt(invalidKey, 0x01020304L);
        cborInt(invalidKey, 4); cborInt(invalidKey, 443);
        cborInt(invalidKey, 5); cborInt(invalidKey, 0);
        cborInt(invalidKey, 6); cborInt(invalidKey, 1);
        cborInt(invalidKey, 7); cborText(invalidKey, "edge.example");
        assertTrue(SubscriptionParser.parseNodes(
                hitLink(invalidKey.toByteArray())).isEmpty());

        // This remains a small deterministic boundary fixture. It verifies
        // that a nested config is rejected before a second CBOR parse and
        // before public-key Base64 / URI construction, without an OOM test.
        byte[] oversizedConfig = new byte[16 * 1024 + 1];
        SubscriptionParser.ParseResult oversized = SubscriptionParser.parseDetailed(
                hitLink(oversizedConfig));
        assertTrue(oversized.nodes.isEmpty());
        assertTrue(oversized.reasons.contains("hit_config_too_large"));
    }

    @Test
    public void structuredOutboundsRejectProtocolIrrelevantFieldsPerProtocol() throws Exception {
        JSONArray invalid = new JSONArray()
                .put(direct("vless").put("password", "wrong"))
                .put(direct("vless").put("alter_id", 0))
                .put(direct("vmess").put("flow", "xtls-rprx-vision"))
                .put(direct("trojan").put("method", "aes-256-gcm"))
                .put(direct("trojan").put("security", "auto"))
                .put(direct("shadowsocks").put("uuid",
                        "11111111-1111-1111-1111-111111111111"))
                .put(direct("shadowsocks").put("alter_id", 0));

        JSONObject xrayVless = xrayVnext("vless", "vless.example",
                "11111111-1111-1111-1111-111111111111", "none");
        xrayVless.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0).put("alterId", 0);
        JSONObject xrayVmess = xrayVnext("vmess", "vmess.example",
                "22222222-2222-2222-2222-222222222222", "auto");
        xrayVmess.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0).put("flow", "vision");
        JSONObject xrayTrojan = xrayServer("trojan", "trojan.example")
                .put("method", "aes-256-gcm");
        JSONObject xraySs = xrayServer("shadowsocks", "ss.example")
                .put("uuid", "33333333-3333-3333-3333-333333333333");
        invalid.put(xrayVless).put(xrayVmess)
                .put(new JSONObject().put("protocol", "trojan")
                        .put("settings", new JSONObject().put("servers",
                                new JSONArray().put(xrayTrojan))))
                .put(new JSONObject().put("protocol", "shadowsocks")
                        .put("settings", new JSONObject().put("servers",
                                new JSONArray().put(xraySs))));

        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(result.nodes.isEmpty());
        assertEquals(invalid.length(), result.rejected);
    }

    @Test
    public void structuredProxyIntentCannotFallBackToNestedLinks() throws Exception {
        JSONObject malformed = direct("vless")
                .put("protocol", new JSONArray().put("vless"))
                .put("description", VLESS);
        JSONObject conflicting = direct("vless")
                .put("protocol", "vmess").put("description", VLESS);
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(
                new JSONArray().put(malformed).put(conflicting).toString());
        assertTrue(result.nodes.isEmpty());
        assertEquals(2, result.rejected);

        assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", VLESS).put("description", VLESS).toString()).isEmpty());
        assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                .put("description", VLESS).put("metadata", new JSONObject()
                        .put("proxy", VLESS)).toString()).isEmpty());
    }

    @Test
    public void reportsPinnedXrayContractIncompatibilities() throws Exception {
        String xhttp = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?security=tls&insecure=true&type=xhttp&path=%2Fx&mode=packet-up";
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(xhttp);
        assertTrue(result.nodes.isEmpty());
        assertEquals(1, result.rejected);
        assertTrue(result.reasons.contains(
                ProtocolParser.XRAY_INSECURE_TLS_UNSUPPORTED));

        String encryption = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?encryption=mlkem768x25519plus.native.0rtt&security=tls&type=tcp";
        SubscriptionParser.ParseResult invalidEncryption =
                SubscriptionParser.parseDetailed(encryption);
        assertTrue(invalidEncryption.nodes.isEmpty());
        assertEquals(1, invalidEncryption.rejected);
        assertTrue(invalidEncryption.reasons.contains(
                ProtocolParser.VLESS_ENCRYPTION_UNSUPPORTED));

        JSONObject vmess = new JSONObject().put("v", "2").put("add", "vm.example")
                .put("port", 443).put("id", "22222222-2222-2222-2222-222222222222")
                .put("aid", 1).put("scy", "auto").put("net", "xhttp")
                .put("tls", "tls").put("path", "/x").put("mode", "packet-up");
        String vmessUri = "vmess://" + Base64.getEncoder().encodeToString(
                vmess.toString().getBytes(StandardCharsets.UTF_8));
        SubscriptionParser.ParseResult removedAlterId =
                SubscriptionParser.parseDetailed(vmessUri);
        assertTrue(removedAlterId.nodes.isEmpty());
        assertEquals(1, removedAlterId.rejected);
        assertTrue(removedAlterId.reasons.contains(
                ProtocolParser.XRAY_VMESS_ALTER_ID_UNSUPPORTED));
    }

    @Test
    public void structuredHeadersRequireTokensUniqueNamesAndMatchingHost() throws Exception {
        JSONArray invalid = new JSONArray();
        for (JSONObject headers : new JSONObject[]{
                new JSONObject().put("Bad Header", "value"),
                new JSONObject().put("Bad:Header", "value"),
                new JSONObject().put("Host", "edge.example").put("host", "edge.example"),
                new JSONObject().put("HOST", "other.example"),
        }) {
            invalid.put(direct("vless").put("transport", new JSONObject()
                    .put("type", "ws").put("path", "/")
                    .put("host", "edge.example").put("headers", headers)));
        }
        invalid.put(direct("vless").put("transport", new JSONObject()
                .put("type", "ws").put("path", "/")
                .put("host", new JSONArray().put("other.example"))
                .put("headers", new JSONObject().put("Host", "edge.example"))));
        SubscriptionParser.ParseResult rejected = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", invalid).toString());
        assertTrue(rejected.nodes.isEmpty());
        assertEquals(invalid.length(), rejected.rejected);

        JSONObject valid = direct("vless").put("transport", new JSONObject()
                .put("type", "ws").put("path", "/")
                .put("host", "edge.example")
                .put("headers", new JSONObject().put("HOST",
                        new JSONArray().put("edge.example"))));
        SubscriptionParser.ParseResult accepted = SubscriptionParser.parseDetailed(
                new JSONObject().put("outbounds", new JSONArray().put(valid)).toString());
        assertEquals("unexpected structured header rejection: " + accepted.reasons,
                1, accepted.nodes.size());
    }

    @Test
    public void structuredAlpnIsExactAndCannotEscapeCommaIntermediate() throws Exception {
        JSONObject valid = direct("vless").put("tls", new JSONObject()
                .put("enabled", true).put("server_name", "edge.example")
                .put("insecure", false).put("alpn", new JSONArray().put(" h2")));
        ProtocolParser.Node node = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(valid)).toString()).get(0);
        assertEquals(" h2", node.outbound.getJSONObject("tls")
                .getJSONArray("alpn").getString(0));

        for (String invalidValue : new String[]{"", "h2,http/1.1", "h2\n"}) {
            JSONObject invalid = direct("vless").put("tls", new JSONObject()
                    .put("enabled", true).put("server_name", "edge.example")
                    .put("insecure", false)
                    .put("alpn", new JSONArray().put(invalidValue)));
            assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }
    }

    @Test
    public void materializesPinnedXrayWebSocketHostFallbackWithoutTrimming() throws Exception {
        JSONObject implicit = xrayVnext("vless", "endpoint.example",
                "11111111-1111-1111-1111-111111111111", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("security", "tls")
                        .put("tlsSettings", new JSONObject()
                                .put("serverName", "sni.example"))
                        .put("wsSettings", new JSONObject().put("path", "/ws")));
        ProtocolParser.Node implicitNode = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(implicit)).toString()).get(0);
        assertEquals("sni.example", implicitNode.outbound.getJSONObject("transport")
                .getJSONObject("headers").getString("Host"));
        assertEquals("sni.example", ProtocolParser.renderSingBoxOutbound(
                implicitNode.outbound).getJSONObject("transport")
                .getJSONObject("headers").getString("Host"));

        JSONObject exact = xrayVnext("vless", "endpoint.example",
                "22222222-2222-2222-2222-222222222222", "none")
                .put("streamSettings", new JSONObject().put("network", "ws")
                        .put("wsSettings", new JSONObject().put("path", " /ws ")
                                .put("headers", new JSONObject()
                                        .put("Host", "edge.example"))));
        ProtocolParser.Node exactNode = SubscriptionParser.parseNodes(new JSONObject()
                .put("outbounds", new JSONArray().put(exact)).toString()).get(0);
        assertEquals(" /ws ", exactNode.outbound.getJSONObject("transport")
                .getString("path"));
        assertEquals("edge.example", exactNode.outbound.getJSONObject("transport")
                .getJSONObject("headers").getString("Host"));

        for (Object invalidHost : new Object[]{
                "", " edge.example", new JSONArray(),
                new JSONArray().put("one.example").put("two.example")
        }) {
            JSONObject invalid = xrayVnext("vless", "endpoint.example",
                    "33333333-3333-3333-3333-333333333333", "none")
                    .put("streamSettings", new JSONObject().put("network", "ws")
                            .put("wsSettings", new JSONObject().put("path", "/ws")
                                    .put("headers", new JSONObject()
                                            .put("Host", invalidHost))));
            assertTrue(SubscriptionParser.parseNodes(new JSONObject()
                    .put("outbounds", new JSONArray().put(invalid)).toString()).isEmpty());
        }
    }

    @Test
    public void clashSectionIsExclusiveAndDuplicateFieldsRejectWholeEntry() {
        String disabled = "# vless://11111111-1111-1111-1111-111111111111@hidden.example:443\n"
                + "proxies:\n"
                + "  - name: valid\n    type: vless\n    server: visible.example\n"
                + "    port: 443\n    uuid: 22222222-2222-2222-2222-222222222222\n";
        List<ProtocolParser.Node> visible = SubscriptionParser.parseNodes(disabled);
        assertEquals(1, visible.size());
        assertEquals("visible.example", visible.get(0).outbound.optString("server"));

        String duplicates = "proxies:\n"
                + "  - name: top\n    type: vless\n    server: one.example\n"
                + "    server: two.example\n    port: 443\n"
                + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                + "  - name: nested\n    type: vless\n    server: nested.example\n"
                + "    port: 443\n    uuid: 44444444-4444-4444-4444-444444444444\n"
                + "    network: ws\n    ws-opts:\n      path: /one\n"
                + "    ws-opts:\n      path: /two\n";
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(duplicates);
        assertTrue(result.nodes.isEmpty());
        assertEquals(2, result.rejected);
    }

    @Test
    public void rawImportLimitAndOversizedUriAreRejectedBeforeLargeCopies() {
        int limit = LimitedHttpClient.MAX_EXPANDED_BYTES;
        String exactHugeUri = "vless://" + repeat('a', limit - "vless://".length());
        SubscriptionParser.ParseResult exact = SubscriptionParser.parseDetailed(exactHugeUri);
        assertTrue(exact.nodes.isEmpty());
        assertTrue(exact.reasons.contains("uri_too_large"));

        SubscriptionParser.ParseResult oversized = SubscriptionParser.parseDetailed(
                exactHugeUri + "a");
        assertTrue(oversized.nodes.isEmpty());
        assertTrue(oversized.reasons.contains("source_too_large"));

        String encoded = Base64.getEncoder().encodeToString(VLESS.getBytes(StandardCharsets.UTF_8));
        StringBuilder whitespaceHeavy = new StringBuilder(encoded.length() * 1025);
        for (int index = 0; index < encoded.length(); index++) {
            whitespaceHeavy.append(encoded.charAt(index)).append(repeat(' ', 1024));
        }
        assertEquals(1, SubscriptionParser.parseNodes(whitespaceHeavy.toString()).size());
    }

    @Test
    public void wrapperProofHandlesNestingQuotesAndUnbalancedClosers() {
        String nested = "(https://example.com/a(b)c)";
        assertTrue(SubscriptionParser.balancedOuterWrapper(nested, 0, nested.length() - 1));
        String quoted = "[https://example.com/a(\"x\\\"y\")z]";
        assertTrue(SubscriptionParser.balancedOuterWrapper(quoted, 0, quoted.length() - 1));
        String unbalanced = "(https://example.com/a(b)c]";
        assertFalse(SubscriptionParser.balancedOuterWrapper(
                unbalanced, 0, unbalanced.length() - 1));
        String early = "(https://example.com/a)b)";
        assertFalse(SubscriptionParser.balancedOuterWrapper(early, 0, early.length() - 1));
    }

    @Test
    public void jsonPreflightReasonsDistinguishMalformedFromCapacityAndInterrupt()
            throws Exception {
        for (String malformed : new String[]{
                "{\"links\":[}",
                "{\"links\":[\"\\uZZZZ\"]}",
        }) {
            SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(malformed);
            assertTrue(result.nodes.isEmpty());
            assertTrue("unexpected malformed JSON reason: " + result.reasons,
                    result.reasons.contains("invalid_json"));
            assertFalse(result.reasons.contains("json_structure_too_large"));
        }

        Thread.currentThread().interrupt();
        try {
            SubscriptionParser.ParseResult interrupted = SubscriptionParser.parseDetailed(
                    new JSONObject().put("links", new JSONArray().put(VLESS)).toString());
            assertTrue(interrupted.nodes.isEmpty());
            assertTrue(interrupted.reasons.contains("import_interrupted"));
        } finally {
            Thread.interrupted();
        }
    }

    private static ProtocolParser.Node onlyNode(String source) {
        List<ProtocolParser.Node> nodes = SubscriptionParser.parseNodes(source);
        assertEquals(1, nodes.size());
        return nodes.get(0);
    }

    private static String realityPublicKey() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
    }

    private static String hitLink(byte[] config) throws Exception {
        ByteArrayOutputStream item = new ByteArrayOutputStream();
        cborHeader(item, 5, 2);
        cborInt(item, 1); cborInt(item, 2);
        cborInt(item, 2); cborBytes(item, config);
        ByteArrayOutputStream root = new ByteArrayOutputStream();
        cborHeader(root, 5, 2);
        cborInt(root, 1); cborInt(root, 7);
        cborInt(root, 4); cborHeader(root, 4, 1); root.write(item.toByteArray());
        return wrapHitPayload(root.toByteArray());
    }

    private static String wrapHitPayload(byte[] payload) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
        ByteArrayOutputStream wrapped = new ByteArrayOutputStream();
        wrapped.write(1);
        wrapped.write(new byte[4]);
        wrapped.write(digest, 0, 4);
        wrapped.write(payload);
        return "hitvpn://" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(wrapped.toByteArray());
    }

    private static void xorHitPayload(byte[] salt, byte[] payload) throws Exception {
        ByteArrayOutputStream seed = new ByteArrayOutputStream();
        seed.write("IIkYdtWtkU".getBytes(StandardCharsets.US_ASCII));
        seed.write(salt);
        byte[] current = MessageDigest.getInstance("SHA-256").digest(seed.toByteArray());
        int index = 0;
        for (int i = 0; i < payload.length; i++) {
            if (index == current.length) {
                seed.write(current, 0, 8);
                current = MessageDigest.getInstance("SHA-256").digest(seed.toByteArray());
                index = 0;
            }
            payload[i] ^= current[index++];
        }
    }

    private static JSONObject xrayVnext(String protocol, String address,
                                        String id, String security) throws Exception {
        JSONObject user = new JSONObject().put("id", id)
                .put(protocol.equals("vless") ? "encryption" : "security", security);
        return new JSONObject().put("protocol", protocol).put("tag", protocol)
                .put("settings", new JSONObject().put("vnext", new JSONArray()
                        .put(new JSONObject().put("address", address).put("port", 443)
                                .put("users", new JSONArray().put(user)))));
    }

    private static JSONObject direct(String type) throws Exception {
        JSONObject value = new JSONObject().put("type", type)
                .put("server", type + ".example").put("server_port", 443);
        if (type.equals("vless")) {
            value.put("uuid", "11111111-1111-1111-1111-111111111111")
                    .put("encryption", "none");
        } else if (type.equals("vmess")) {
            value.put("uuid", "22222222-2222-2222-2222-222222222222")
                    .put("security", "auto").put("alter_id", 0);
        } else if (type.equals("trojan")) {
            value.put("password", "password");
        } else {
            value.put("method", "aes-256-gcm").put("password", "password");
        }
        return value;
    }

    private static JSONObject xrayServer(String protocol, String address) throws Exception {
        JSONObject value = new JSONObject().put("address", address).put("port", 443)
                .put("password", "password");
        if (protocol.equals("shadowsocks")) value.put("method", "aes-256-gcm");
        return value;
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int i = 0; i < count; i++) result.append(value);
        return result.toString();
    }

    private static void cborInt(ByteArrayOutputStream output, long value) {
        if (value < 24) cborHeader(output, 0, (int) value);
        else if (value <= 0xff) { output.write(24); output.write((int) value); }
        else if (value <= 0xffff) { output.write(25); output.write((int) (value >>> 8)); output.write((int) value); }
        else {
            output.write(26);
            for (int shift = 24; shift >= 0; shift -= 8) output.write((int) (value >>> shift));
        }
    }

    private static void cborBytes(ByteArrayOutputStream output, byte[] value) {
        cborLength(output, 2, value.length);
        output.write(value, 0, value.length);
    }

    private static void cborText(ByteArrayOutputStream output, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        cborLength(output, 3, bytes.length);
        output.write(bytes, 0, bytes.length);
    }

    private static void cborLength(ByteArrayOutputStream output, int major, int length) {
        if (length < 24) cborHeader(output, major, length);
        else if (length <= 0xff) {
            output.write((major << 5) | 24);
            output.write(length);
        } else if (length <= 0xffff) {
            output.write((major << 5) | 25);
            output.write(length >>> 8);
            output.write(length);
        } else {
            output.write((major << 5) | 26);
            for (int shift = 24; shift >= 0; shift -= 8) output.write(length >>> shift);
        }
    }

    private static void cborHeader(ByteArrayOutputStream output, int major, int value) {
        output.write((major << 5) | value);
    }

    @Test
    public void placeholderNodesFromARefusingSourceAreRejectedWithTheirOwnReason() {
        // Verbatim shape of what a source returns when it does not accept the
        // client: routable-looking URIs whose address can never be dialled.
        String body = "dmxlc3M6Ly8wMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDBAMC4wLjAuMDoxP2VuY3J5cHRpb249bm9uZSZ0eXBlPXRjcCZzZWN1cml0eT1ub25lIyVFMiU5RCU4Qwp2bGVzczovLzAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMEAwLjAuMC4wOjE/ZW5jcnlwdGlvbj1ub25lJnR5cGU9dGNwJnNlY3VyaXR5PW5vbmUjSGFwcA==";
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(body);

        assertTrue(parsed.nodes.isEmpty());
        assertEquals(2, parsed.rejected);
        assertTrue(parsed.reasons.contains(SubscriptionParser.UNREACHABLE_ONLY));
    }
}
