package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertTrue;

public class ProtocolParserTest {
    @Test
    public void nodeNameLimitNeverSplitsSupplementaryCharacters() throws Exception {
        String name = "a".repeat(119) + "🚀" + "tail";
        ProtocolParser.Node node = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls#" + name);
        assertEquals(120, node.name.codePointCount(0, node.name.length()));
        assertTrue(node.name.endsWith("🚀"));
        assertFalse(Character.isSurrogate(node.name.charAt(node.name.length() - 1))
                && !Character.isLowSurrogate(node.name.charAt(node.name.length() - 1)));
    }

    @Test
    public void parsesVlessRealityAndBuildsAuthenticatedLoopbackInbound() throws Exception {
        ProtocolParser.Node node = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=reality&sni=edge.example&pbk=" + realityPublicKey()
                        + "&sid=42&type=ws&path=%2Fws#Node"
        );
        assertEquals("vless", node.outbound.getString("type"));
        assertEquals("edge.example", node.outbound.getJSONObject("tls").getString("server_name"));
        assertTrue(node.outbound.getJSONObject("tls").getJSONObject("reality").getBoolean("enabled"));
        assertEquals("ws", node.outbound.getJSONObject("transport").getString("type"));

        JSONObject config = ProtocolParser.buildConfig(node, 32123, "user", "pass");
        JSONObject inbound = config.getJSONArray("inbounds").getJSONObject(0);
        assertEquals("127.0.0.1", inbound.getString("listen"));
        assertEquals(32123, inbound.getInt("listen_port"));
        assertEquals("user", inbound.getJSONArray("users").getJSONObject(0).getString("username"));
    }

    @Test
    public void parsesVmess() throws Exception {
        JSONObject vmess = new JSONObject()
                .put("v", "2").put("ps", "VMess node").put("add", "vm.example")
                .put("port", "443").put("id", "22222222-2222-2222-2222-222222222222")
                .put("aid", 0).put("scy", "auto").put("net", "grpc")
                .put("tls", "tls").put("sni", "sni.example").put("path", "service");
        String uri = "vmess://" + Base64.getEncoder().encodeToString(
                vmess.toString().getBytes(StandardCharsets.UTF_8));
        ProtocolParser.Node node = ProtocolParser.parse(uri);
        assertEquals("vmess", node.outbound.getString("type"));
        assertEquals("grpc", node.outbound.getJSONObject("transport").getString("type"));
        assertEquals("service", node.outbound.getJSONObject("transport")
                .getString("service_name"));
        assertEquals("VMess node", node.name);
    }

    @Test
    public void acceptsCanonicalV2raynEmptyOptionalVmessFieldsAsNoOps() throws Exception {
        JSONObject payload = new JSONObject()
                .put("v", "2").put("ps", "Canonical")
                .put("add", "vmess.example").put("port", 443)
                .put("id", "22222222-2222-2222-2222-222222222222")
                .put("aid", 0).put("scy", "auto").put("net", "tcp")
                .put("type", "none").put("host", "").put("path", "")
                .put("tls", "").put("sni", "").put("alpn", "")
                .put("fp", "").put("ed", 0).put("insecure", 0)
                .put("headers", new JSONObject());
        ProtocolParser.Node node = ProtocolParser.parse(vmessUri(payload));
        assertEquals("vmess", node.outbound.getString("type"));
        assertFalse(node.outbound.has("tls"));
        assertFalse(node.outbound.has("transport"));
    }

    @Test
    public void grpcWithoutServiceNameNeverInheritsGenericSlashPath() throws Exception {
        ProtocolParser.Node node = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&type=grpc");
        JSONObject neutralTransport = node.outbound.getJSONObject("transport");
        assertEquals("grpc", neutralTransport.getString("type"));
        assertFalse(neutralTransport.has("service_name"));

        JSONObject singBoxTransport = ProtocolParser.buildConfig(node, 32124, "", "")
                .getJSONArray("outbounds").getJSONObject(0).getJSONObject("transport");
        assertFalse(singBoxTransport.has("service_name"));

        JSONObject xrayGrpc = XrayConfigRenderer.build(node, 32125, "", "")
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("grpcSettings");
        assertEquals("", xrayGrpc.optString("serviceName", ""));
        assertFalse("/".equals(xrayGrpc.optString("serviceName", "")));
    }

    @Test
    public void materializesDeterministicWebSocketHostForBothCoreFamilies() throws Exception {
        String base = "vless://11111111-1111-1111-1111-111111111111@example.com:443";
        ProtocolParser.Node tls = ProtocolParser.parse(
                base + "?security=tls&sni=edge.example&type=ws&path=%2Fws");
        assertEquals("edge.example", tls.outbound.getJSONObject("transport")
                .getJSONObject("headers").getString("Host"));

        ProtocolParser.Node plain = ProtocolParser.parse(base + "?type=ws&path=%2Fws");
        assertEquals("example.com", plain.outbound.getJSONObject("transport")
                .getJSONObject("headers").getString("Host"));

        JSONObject legacyStored = new JSONObject(plain.outbound.toString());
        legacyStored.getJSONObject("transport").remove("headers");
        ProtocolParser.Node migrated = ProtocolParser.fromStoredJson(new JSONObject()
                .put("name", "legacy").put("outbound", legacyStored));
        assertEquals("example.com", migrated.outbound.getJSONObject("transport")
                .getJSONObject("headers").getString("Host"));

        ProtocolParser.Node uriAlias = ProtocolParser.parse(
                base + "?type=websocket&path=%2Falias");
        assertEquals("ws", uriAlias.outbound.getJSONObject("transport")
                .getString("type"));
        assertTrue(uriAlias.supports(CoreFamily.SING_BOX));
        assertTrue(uriAlias.supports(CoreFamily.XRAY));

        JSONObject storedAlias = new JSONObject(uriAlias.outbound.toString());
        storedAlias.getJSONObject("transport").put("type", "websocket");
        ProtocolParser.Node normalized = ProtocolParser.fromStoredJson(new JSONObject()
                .put("name", "websocket alias").put("outbound", storedAlias));
        assertEquals("ws", normalized.outbound.getJSONObject("transport")
                .getString("type"));
    }

    @Test
    public void parsesTrojanAndShadowsocks() throws Exception {
        ProtocolParser.Node trojan = ProtocolParser.parse(
                "trojan://secret@trojan.example:443?type=tcp#Trojan");
        assertEquals("trojan", trojan.outbound.getString("type"));
        assertTrue(trojan.outbound.getJSONObject("tls").getBoolean("enabled"));

        String credentials = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("aes-256-gcm:p@ss".getBytes(StandardCharsets.UTF_8));
        ProtocolParser.Node shadowsocks = ProtocolParser.parse(
                "ss://" + credentials + "@ss.example:8388#SS");
        assertEquals("shadowsocks", shadowsocks.outbound.getString("type"));
        assertEquals("aes-256-gcm", shadowsocks.outbound.getString("method"));
        assertEquals("p@ss", shadowsocks.outbound.getString("password"));
    }

    @Test
    public void parsesHysteriaFamiliesAndTuic() throws Exception {
        ProtocolParser.Node h1 = ProtocolParser.parse(
                "hysteria://secret@hy.example:443?upmbps=20&downmbps=50#H1");
        ProtocolParser.Node h2 = ProtocolParser.parse(
                "hysteria2://password@hy2.example:443?sni=edge.example&obfs=salamander&obfs-password=o#H2");
        ProtocolParser.Node tuic = ProtocolParser.parse(
                "tuic://33333333-3333-3333-3333-333333333333:password@tuic.example:443?sni=edge.example#TUIC");
        assertEquals("hysteria", h1.outbound.getString("type"));
        assertEquals(20, h1.outbound.getInt("up_mbps"));
        assertEquals("hysteria2", h2.outbound.getString("type"));
        assertEquals("salamander", h2.outbound.getJSONObject("obfs").getString("type"));
        assertEquals("tuic", tuic.outbound.getString("type"));
        assertEquals("password", tuic.outbound.getString("password"));
    }

    @Test
    public void multiplexedGrpcIsKeptAndRunsOnTheCoreThatHasIt() throws Exception {
        // A live subscription serves fifteen of its twenty servers this way.
        // Rejecting the mode threw three quarters of it away.
        String uri = "vless://33333333-3333-3333-3333-333333333333@edge.example:443"
                + "?encryption=none&type=grpc&serviceName=Sosat&mode=multi"
                + "&security=reality&sni=edge.example&fp=firefox&pbk=" + "a".repeat(43);
        ProtocolParser.Node node = ProtocolParser.parse(uri + "#Multi");
        JSONObject transport = node.outbound.getJSONObject("transport");
        assertEquals("grpc", transport.getString("type"));
        assertEquals("Sosat", transport.getString("service_name"));
        assertTrue(transport.getBoolean(ProtocolParser.GRPC_MULTI_MODE));

        // sing-box has no option for it, so the node says so rather than
        // being started on a core that would run it as something else.
        assertTrue(node.supports(CoreFamily.XRAY));
        assertFalse(node.supports(CoreFamily.SING_BOX));

        JSONObject rendered = XrayConfigRenderer.build(node, 1080, "user", "pass");
        JSONObject grpc = rendered.getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("grpcSettings");
        assertTrue(grpc.getBoolean("multiMode"));
        assertEquals("Sosat", grpc.getString("serviceName"));

        // The stored form has to survive a reload, which is where the marker
        // was first refused as an unknown transport field.
        ProtocolParser.Node reloaded = ProtocolParser.fromStoredJson(node.toStoredJson());
        assertTrue(reloaded.outbound.getJSONObject("transport")
                .getBoolean(ProtocolParser.GRPC_MULTI_MODE));

        ProtocolParser.Node plain = ProtocolParser.parse(
                uri.replace("&mode=multi", "&mode=gun") + "#Gun");
        assertFalse(plain.outbound.getJSONObject("transport")
                .optBoolean(ProtocolParser.GRPC_MULTI_MODE, false));
        assertTrue(plain.supports(CoreFamily.SING_BOX));
    }

    @Test
    public void keepsQuicNodesCarryingClientHintsWeDoNotEnumerate() throws Exception {
        // A live provider decorates every Hysteria2 link with "fm", a client
        // hint for QUIC congestion control. Rejecting the whole node over it
        // hid three working servers that the previous plugin listed.
        ProtocolParser.Node hinted = ProtocolParser.parse(
                "hysteria2://password@hy2.example:443?sni=edge.example"
                        + "&fm=%7B%22quicParams%22%3A%7B%22congestion%22%3A%22bbr%22%7D%7D#Hinted");
        assertEquals("hysteria2", hinted.outbound.getString("type"));
        assertEquals("edge.example", hinted.outbound.getJSONObject("tls").getString("server_name"));
        assertFalse(hinted.supports(CoreFamily.XRAY));
        assertTrue(hinted.supports(CoreFamily.SING_BOX));

        ProtocolParser.Node tuic = ProtocolParser.parse(
                "tuic://33333333-3333-3333-3333-333333333333:password@tuic.example:443"
                        + "?sni=edge.example&fm=%7B%22a%22%3A1%7D#Hinted");
        assertEquals("tuic", tuic.outbound.getString("type"));
    }

    @Test
    public void rejectsAnOversizedUnknownQuicParameter() throws Exception {
        StringBuilder oversized = new StringBuilder();
        for (int index = 0; index < 600; index++) oversized.append('x');
        try {
            ProtocolParser.parse("hysteria2://password@hy2.example:443?sni=edge.example&fm="
                    + oversized + "#Oversized");
            fail("oversized parameter must not be ignored");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("oversized"));
        }
    }

    @Test
    public void preservesHysteria2UserpassDefaultPortAndPortHoppingButRejectsGecko() throws Exception {
        ProtocolParser.Node defaultPort = ProtocolParser.parse(
                "hysteria2://user%3Apassword@hy2.example/"
                        + "?sni=edge.example&obfs=salamander&obfs-password=cover#Default");
        assertEquals(443, defaultPort.outbound.getInt("server_port"));
        assertEquals("user:password", defaultPort.outbound.getString("password"));
        assertEquals("salamander", defaultPort.outbound.getJSONObject("obfs").getString("type"));

        try {
            ProtocolParser.parse("hysteria2://secret@hy2.example:443"
                    + "?obfs=gecko&obfs-password=cover");
            throw new AssertionError("unsupported Hysteria2 gecko obfs accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Hysteria2 obfs"));
        }

        ProtocolParser.Node hopping = ProtocolParser.parse(
                "hy2://secret@hy2.example:1234,5000-6000,7044"
                        + "?hop_interval=15s#Hopping");
        assertEquals(1234, hopping.outbound.getInt("server_port"));
        assertEquals("1234:1234", hopping.outbound.getJSONArray("server_ports").getString(0));
        assertEquals("5000:6000", hopping.outbound.getJSONArray("server_ports").getString(1));
        assertEquals("7044:7044", hopping.outbound.getJSONArray("server_ports").getString(2));
        assertEquals("15s", hopping.outbound.getString("hop_interval"));

        for (String invalid : new String[]{
                "hy2://secret@hy2.example:1-65535,1-65535?hop_interval=15s",
                "hy2://secret@hy2.example:443,443?hop_interval=15s",
                "hy2://secret@hy2.example:440-445,443?hop_interval=15s",
                "hy2://secret@hy2.example:443,?hop_interval=15s"
        }) {
            try {
                ProtocolParser.parse(invalid);
                throw new AssertionError("unsafe Hysteria2 port list accepted: " + invalid);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("Hysteria2 port"));
            }
        }
    }

    @Test
    public void rejectsAuthorityPathsInsteadOfSilentlyDiscardingThem() {
        for (String invalid : new String[]{
                "vless://11111111-1111-1111-1111-111111111111@example.com:443/path",
                "trojan://secret@example.com:443/",
                "hysteria2://secret@example.com/path",
                "hy2://secret@example.com:443//",
        }) {
            try {
                ProtocolParser.parse(invalid);
                throw new AssertionError("authority path was silently discarded: " + invalid);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("path"));
            } catch (Exception unexpected) {
                throw new AssertionError(unexpected);
            }
        }
    }

    @Test
    public void rejectsMalformedHysteria2AuthoritiesWithoutReinterpretingThem()
            throws Exception {
        ProtocolParser.Node ipv6 = ProtocolParser.parse(
                "hy2://secret@[2001:db8::1]:443/");
        assertEquals("2001:db8::1", ipv6.outbound.getString("server"));
        assertEquals(443, ipv6.outbound.getInt("server_port"));

        for (String invalid : new String[]{
                "hy2://secret@example.com:",
                "hy2://secret@[2001:db8::1]:",
                "hy2://secret@2001:db8::1",
        }) {
            try {
                ProtocolParser.parse(invalid);
                throw new AssertionError(
                        "malformed Hysteria2 authority was reinterpreted: " + invalid);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("port")
                        || expected.getMessage().contains("IPv6"));
            }
        }
    }

    @Test
    public void preservesLiteralPlusAndRejectsMalformedPercentEncoding() throws Exception {
        ProtocolParser.Node trojan = ProtocolParser.parse(
                "trojan://secret+token@trojan.example:443?type=tcp#Plus+Name");
        assertEquals("secret+token", trojan.outbound.getString("password"));
        assertEquals("Plus+Name", trojan.name);

        ProtocolParser.Node hysteria = ProtocolParser.parse(
                "hysteria://auth+token@hy.example:443");
        assertEquals("auth+token", hysteria.outbound.getString("auth_str"));

        ProtocolParser.Node tuic = ProtocolParser.parse(
                "tuic://33333333-3333-3333-3333-333333333333:pass+word@tuic.example:443");
        assertEquals("pass+word", tuic.outbound.getString("password"));

        for (String invalid : new String[]{
                "hysteria2://bad%ZZ@hy2.example:443",
                "tuic://uuid:bad%2@tuic.example:443",
                "vless://uuid@example.com:443?type=ws&path=%ZZ",
        }) {
            try {
                ProtocolParser.parse(invalid);
                throw new AssertionError("malformed percent encoding accepted");
            } catch (IllegalArgumentException expected) {
                assertFalse(expected.getMessage().contains("bad%"));
            }
        }
    }

    @Test
    public void rejectsMalformedUtf8InsideBase64Configurations() throws Exception {
        byte[] prefix = ("{\"v\":\"2\",\"add\":\"vm.example\",\"port\":443,"
                + "\"id\":\"").getBytes(StandardCharsets.UTF_8);
        byte[] suffix = "\",\"aid\":0,\"scy\":\"auto\",\"net\":\"tcp\"}"
                .getBytes(StandardCharsets.UTF_8);
        byte[] malformed = new byte[prefix.length + 2 + suffix.length];
        System.arraycopy(prefix, 0, malformed, 0, prefix.length);
        malformed[prefix.length] = (byte) 0xC3;
        malformed[prefix.length + 1] = 0x28;
        System.arraycopy(suffix, 0, malformed, prefix.length + 2, suffix.length);
        assertUriRejected("vmess://" + Base64.getEncoder().encodeToString(malformed),
                "UTF-8");
    }

    @Test
    public void mapsOfficialHysteriaOneObfsParameter() throws Exception {
        ProtocolParser.Node node = ProtocolParser.parse(
                "hysteria://hy.example:443?auth=secret&upmbps=20&downmbps=50"
                        + "&obfs=xplus&obfsParam=cover#H1");
        assertEquals("cover", node.outbound.getString("obfs"));
    }

    @Test
    public void rejectsUnsupportedAndInvalidPorts() {
        try {
            ProtocolParser.parse("socks://example.com:1080");
            throw new AssertionError("unsupported protocol accepted");
        } catch (Exception expected) {
            assertNotNull(expected.getMessage());
        }
        try {
            ProtocolParser.parse("vless://uuid@example.com:70000");
            throw new AssertionError("invalid port accepted");
        } catch (Exception expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test
    public void selectsCoreAdaptivelyByCompatibilityReadinessAndLoadedFamily() throws Exception {
        ProtocolParser.Node common = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&type=ws&path=%2Fws");
        assertTrue(common.supports(CoreFamily.SING_BOX));
        assertTrue(common.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(common, null, false, false));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(common, CoreFamily.XRAY, false, false));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(common, null, false, true));

        ProtocolParser.Node xhttp = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&type=xhttp&path=%2Fx&mode=packet-up"
                        + "&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D");
        assertFalse(xhttp.supports(CoreFamily.SING_BOX));
        assertTrue(xhttp.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(xhttp, null, false, false));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(xhttp, CoreFamily.SING_BOX, true, false));

        ProtocolParser.Node hysteria = ProtocolParser.parse(
                "hysteria2://secret@hy.example:443?sni=hy.example");
        assertTrue(hysteria.supports(CoreFamily.SING_BOX));
        assertFalse(hysteria.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(hysteria, CoreFamily.XRAY, false, true));
    }

    @Test
    public void xrayFailsClosedWhenPinnedCoreCannotRepresentInsecureTls() throws Exception {
        ProtocolParser.Node common = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&insecure=true&type=ws&path=%2Fws");
        assertTrue(common.supports(CoreFamily.SING_BOX));
        assertFalse(common.supports(CoreFamily.XRAY));
        assertEquals(ProtocolParser.XRAY_INSECURE_TLS_UNSUPPORTED,
                common.incompatibilityReason(CoreFamily.XRAY));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(common, null, false, false));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(common, CoreFamily.XRAY, false, true));

        try {
            XrayConfigRenderer.renderOutbound(common.outbound);
            throw new AssertionError("Xray renderer emitted removed allowInsecure");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Xray"));
        }
    }

    @Test
    public void xrayFailsClosedForRemovedVmessAlterIdAndUnsupportedShadowsocksMethod()
            throws Exception {
        JSONObject vmessValue = new JSONObject().put("v", "2").put("add", "vm.example")
                .put("port", 443).put("id", "11111111-1111-1111-1111-111111111111")
                .put("aid", 1).put("scy", "auto").put("net", "tcp");
        ProtocolParser.Node vmess = ProtocolParser.parse(vmessUri(vmessValue));
        assertTrue(vmess.supports(CoreFamily.SING_BOX));
        assertFalse(vmess.supports(CoreFamily.XRAY));
        assertEquals(ProtocolParser.XRAY_VMESS_ALTER_ID_UNSUPPORTED,
                vmess.incompatibilityReason(CoreFamily.XRAY));
        assertXraySelectionAndRendererReject(vmess);

        JSONObject modernVmessValue = new JSONObject(vmessValue.toString()).put("aid", 0);
        JSONObject xrayUser = XrayConfigRenderer.renderOutbound(
                ProtocolParser.parse(vmessUri(modernVmessValue)).outbound)
                .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0);
        assertFalse("removed alterId leaked into pinned Xray JSON", xrayUser.has("alterId"));
        assertEquals("auto", xrayUser.getString("security"));

        ProtocolParser.Node shadowsocks = ProtocolParser.parse(
                "ss://none:password@ss.example:443#None");
        assertTrue(shadowsocks.supports(CoreFamily.SING_BOX));
        assertFalse(shadowsocks.supports(CoreFamily.XRAY));
        assertEquals(ProtocolParser.XRAY_SHADOWSOCKS_METHOD_UNSUPPORTED,
                shadowsocks.incompatibilityReason(CoreFamily.XRAY));
        assertXraySelectionAndRendererReject(shadowsocks);

        ProtocolParser.Node passwordless = ProtocolParser.parse(
                "ss://bm9uZTo@passwordless.example:443#NoneEmpty");
        assertEquals("", passwordless.outbound.getString("password"));
        assertEquals("", ProtocolParser.renderSingBoxOutbound(passwordless.outbound)
                .getString("password"));
        assertTrue(passwordless.supports(CoreFamily.SING_BOX));
        assertFalse(passwordless.supports(CoreFamily.XRAY));
    }

    @Test
    public void rendersXhttpAndMkcpForCurrentXrayWithoutDirectFallback() throws Exception {
        ProtocolParser.Node xhttp = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&sni=edge.example&type=xhttp&path=%2Fx&mode=stream-up"
                        + "&extra=%7B%22noSSEHeader%22%3Atrue%7D");
        JSONObject xray = XrayConfigRenderer.build(xhttp, 33001, "user", "pass");
        assertEquals(1, xray.getJSONArray("outbounds").length());
        assertEquals("127.0.0.1", xray.getJSONArray("inbounds")
                .getJSONObject(0).getString("listen"));
        JSONObject stream = xray.getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings");
        assertEquals("xhttp", stream.getString("network"));
        assertEquals("stream-up", stream.getJSONObject("xhttpSettings").getString("mode"));
        assertTrue(stream.getJSONObject("xhttpSettings").getJSONObject("extra")
                .getBoolean("noSSEHeader"));

        ProtocolParser.Node mkcp = ProtocolParser.parse(
                "vmess://" + Base64.getEncoder().encodeToString(new JSONObject()
                        .put("v", "2").put("add", "kcp.example").put("port", 443)
                        .put("id", "22222222-2222-2222-2222-222222222222")
                        .put("aid", 0).put("net", "mkcp").put("headerType", "wechat-video")
                        .put("seed", "secret").put("tti", "20").toString()
                        .getBytes(StandardCharsets.UTF_8)));
        JSONObject mkcpStream = XrayConfigRenderer.build(mkcp, 33002, "u", "p")
                .getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings");
        assertEquals("mkcp", mkcpStream.getString("network"));
        JSONArray legacyMasks = mkcpStream.getJSONObject("finalmask").getJSONArray("udp");
        assertEquals(2, legacyMasks.length());
        assertEquals("secret", legacyMasks.getJSONObject(0).getJSONObject("settings")
                .getString("value"));
        assertEquals("wechat", legacyMasks.getJSONObject(1).getJSONObject("settings")
                .getString("header"));
        assertFalse(mkcpStream.getJSONObject("kcpSettings").has("header"));
        assertFalse(mkcpStream.getJSONObject("kcpSettings").has("seed"));

        ProtocolParser.Node seeded = ProtocolParser.parse(
                "vmess://" + Base64.getEncoder().encodeToString(new JSONObject()
                        .put("v", "2").put("add", "kcp.example").put("port", 443)
                        .put("id", "22222222-2222-2222-2222-222222222222")
                        .put("aid", 0).put("net", "mkcp").put("seed", "secret")
                        .toString().getBytes(StandardCharsets.UTF_8)));
        JSONObject seededLegacy = XrayConfigRenderer.build(seeded, 33003, "u", "p")
                .getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
                .getJSONObject("finalmask").getJSONArray("udp").getJSONObject(0)
                .getJSONObject("settings");
        assertFalse(seededLegacy.has("header"));
        assertEquals("secret", seededLegacy.getString("value"));
    }

    @Test
    public void rejectsUnknownTransportAndSecurityInsteadOfUsingRawTcp() {
        for (String uri : new String[]{
                "vless://uuid@example.com:443?type=made-up",
                "vless://uuid@example.com:443?security=made-up&type=tcp"
        }) {
            try {
                ProtocolParser.parse(uri);
                throw new AssertionError("unsupported stream field accepted");
            } catch (Exception expected) {
                assertNotNull(expected.getMessage());
            }
        }
    }

    @Test
    public void rejectsUnknownVlessFlowAtUriAndStoredTrustBoundaries() throws Exception {
        String prefix = "vless://11111111-1111-1111-1111-111111111111@example.com:443";
        ProtocolParser.Node vision = ProtocolParser.parse(
                prefix + "?security=tls&type=tcp&flow=xtls-rprx-vision");
        assertEquals("xtls-rprx-vision", vision.outbound.getString("flow"));
        try {
            ProtocolParser.parse(prefix + "?security=tls&type=tcp&flow=unknown-flow");
            throw new AssertionError("unknown VLESS flow accepted from URI");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("flow"));
        }
        assertStoredOutboundRejected(new JSONObject(vision.outbound.toString())
                .put("flow", "unknown-flow"));

        for (String query : new String[]{
                "type=tcp&flow=xtls-rprx-vision",
                "security=none&type=tcp&flow=xtls-rprx-vision",
        }) {
            try {
                ProtocolParser.parse(prefix + "?" + query);
                throw new AssertionError("VLESS Vision without TLS was accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("TLS or Reality"));
            }
        }

        JSONObject missingTls = new JSONObject(vision.outbound.toString());
        missingTls.remove("tls");
        assertStoredOutboundRejected(missingTls);

        for (String transport : new String[]{
                "ws", "grpc", "http", "h2", "httpupgrade", "xhttp", "kcp",
        }) {
            try {
                ProtocolParser.parse(prefix + "?security=tls&type=" + transport
                        + "&flow=xtls-rprx-vision");
                throw new AssertionError(
                        "VLESS Vision accepted non-RAW transport: " + transport);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("raw TCP"));
            }
        }
        try {
            ProtocolParser.parse(prefix + "?security=reality&pbk=" + realityPublicKey()
                    + "&sid=42"
                    + "&type=xhttp&flow=xtls-rprx-vision");
            throw new AssertionError("VLESS Vision accepted XHTTP+Reality");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("raw TCP"));
        }

        JSONObject transported = new JSONObject(vision.outbound.toString())
                .put("transport", new JSONObject().put("type", "ws").put("path", "/ws"));
        assertStoredOutboundRejected(transported);

        ProtocolParser.Node forged = ProtocolParser.parse(
                prefix + "?security=tls&type=tcp&flow=xtls-rprx-vision");
        forged.outbound.remove("tls");
        assertFalse(forged.supports(CoreFamily.SING_BOX));
        assertFalse(forged.supports(CoreFamily.XRAY));
        try {
            ProtocolParser.buildConfig(forged, 32126, "", "");
            throw new AssertionError("invalid Vision reached sing-box renderer");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("TLS or Reality"));
        }
        try {
            XrayConfigRenderer.build(forged, 32127, "", "");
            throw new AssertionError("invalid Vision reached Xray renderer");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("TLS or Reality"));
        }

        ProtocolParser.Node forgedTransport = ProtocolParser.parse(
                prefix + "?security=tls&type=tcp&flow=xtls-rprx-vision");
        forgedTransport.outbound.put("transport",
                new JSONObject().put("type", "grpc").put("service_name", "service"));
        assertFalse(forgedTransport.supports(CoreFamily.SING_BOX));
        assertFalse(forgedTransport.supports(CoreFamily.XRAY));
        try {
            ProtocolParser.buildConfig(forgedTransport, 32128, "", "");
            throw new AssertionError("transported Vision reached sing-box renderer");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("raw TCP"));
        }
        try {
            XrayConfigRenderer.build(forgedTransport, 32129, "", "");
            throw new AssertionError("transported Vision reached Xray renderer");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("raw TCP"));
        }
    }

    @Test
    public void rejectsDanglingAndMismatchedTlsParameters() throws Exception {
        String vless = "vless://11111111-1111-1111-1111-111111111111@example.com:443?";
        for (String query : new String[]{
                "security=none&sni=edge.example",
                "security=none&peer=edge.example",
                "security=none&fp=chrome",
                "security=none&alpn=h2",
                "security=none&insecure=false",
                "security=tls&pbk=public",
                "security=tls&sid=42",
                "security=tls&spx=%2F",
        }) {
            try {
                ProtocolParser.parse(vless + query);
                throw new AssertionError("dangling TLS parameter accepted: " + query);
            } catch (IllegalArgumentException expected) {
                assertNotNull(expected.getMessage());
            }
        }

        for (String security : new String[]{"made-up", "reality", "none"}) {
            try {
                ProtocolParser.parse("hysteria://auth@hy.example:443?security=" + security);
                throw new AssertionError("unsupported forced TLS security accepted: " + security);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("security"));
            }
        }
    }

    @Test
    public void preservesExactAlpnTokensAndRejectsEmptySegments() throws Exception {
        String base = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?security=tls&type=tcp&alpn=";
        ProtocolParser.Node exact = ProtocolParser.parse(base + "%20h2,http%2F1.1");
        JSONArray alpn = exact.outbound.getJSONObject("tls").getJSONArray("alpn");
        assertEquals(" h2", alpn.getString(0));
        assertEquals("http/1.1", alpn.getString(1));
        for (String invalid : new String[]{"h2,", ",h2", "h2,,http%2F1.1"}) {
            assertUriRejected(base + invalid, "ALPN");
        }
    }

    @Test
    public void rejectsCrossTransportFunctionalParameters() throws Exception {
        String prefix = "vless://11111111-1111-1111-1111-111111111111@example.com:443?";
        String[] invalidQueries = {
                "type=tcp&path=%2Fws",
                "type=tcp&host=edge.example",
                "type=ws&serviceName=rpc",
                "type=ws&mode=packet-up",
                "type=ws&extra=%7B%7D",
                "type=grpc&host=edge.example",
                "type=grpc&headers=%7B%7D",
                "type=grpc&ed=1024",
                "type=xhttp&headers=%7B%7D",
                "type=xhttp&serviceName=rpc",
                "type=xhttp&ed=1024",
        };
        for (String query : invalidQueries) {
            try {
                ProtocolParser.parse(prefix + query);
                throw new AssertionError("cross-transport parameter accepted: " + query);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("transport"));
            }
        }

        for (String invalidEarlyData : new String[]{
                "type=ws&ed=not-a-number",
                "type=ws&ed=0&eh=Sec-WebSocket-Protocol",
                "type=ws&eh=Sec-WebSocket-Protocol",
                "type=ws&ed=1&eh=Bad%20Header",
        }) {
            try {
                ProtocolParser.parse(prefix + invalidEarlyData);
                throw new AssertionError("invalid WebSocket early data accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("WebSocket"));
            }
        }

        ProtocolParser.Node uint32EarlyData = ProtocolParser.parse(prefix
                + "type=ws&ed=4294967295&eh=Sec-WebSocket-Protocol");
        assertEquals(4294967295L, uint32EarlyData.outbound.getJSONObject("transport")
                .getLong("max_early_data"));
        assertTrue(uint32EarlyData.supports(CoreFamily.SING_BOX));
        assertTrue(uint32EarlyData.supports(CoreFamily.XRAY));
        assertTrue(XrayConfigRenderer.renderOutbound(uint32EarlyData.outbound)
                .getJSONObject("streamSettings").getJSONObject("wsSettings")
                .getString("path").contains("ed=4294967295"));

        ProtocolParser.Node signed32EarlyData = ProtocolParser.parse(prefix
                + "type=ws&ed=2147483647&eh=Sec-WebSocket-Protocol");
        assertTrue(signed32EarlyData.supports(CoreFamily.XRAY));
        assertTrue(XrayConfigRenderer.renderOutbound(signed32EarlyData.outbound)
                .getJSONObject("streamSettings").getJSONObject("wsSettings")
                .getString("path").contains("ed=2147483647"));
        try {
            ProtocolParser.parse(prefix + "type=ws&ed=4294967296");
            throw new AssertionError("WebSocket early data above uint32 accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("WebSocket"));
        }
    }

    @Test
    public void httpUpgradeEarlyDataIsXrayOnlyAndKeepsUint32Limit()
            throws Exception {
        String prefix = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?type=httpupgrade&path=%2Fupgrade&ed=";
        ProtocolParser.Node node = ProtocolParser.parse(prefix + "2048");
        JSONObject transport = node.outbound.getJSONObject("transport");
        assertEquals(2048L, transport.getLong("max_early_data"));
        assertFalse(node.supports(CoreFamily.SING_BOX));
        assertTrue(node.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(node, null, false, false));
        assertEquals(ProtocolParser.SING_BOX_HTTP_UPGRADE_EARLY_DATA_UNSUPPORTED,
                node.incompatibilityReason(CoreFamily.SING_BOX));
        assertEquals("/upgrade?ed=2048", XrayConfigRenderer.renderOutbound(node.outbound)
                .getJSONObject("streamSettings").getJSONObject("httpupgradeSettings")
                .getString("path"));
        try {
            ProtocolParser.renderSingBoxOutbound(node.outbound);
            throw new AssertionError("sing-box renderer accepted HTTPUpgrade early data");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("http_upgrade_early_data"));
        }

        ProtocolParser.Node uint32Only = ProtocolParser.parse(prefix + "4294967295");
        assertFalse(uint32Only.supports(CoreFamily.SING_BOX));
        assertTrue(uint32Only.supports(CoreFamily.XRAY));
        assertEquals("/upgrade?ed=4294967295",
                XrayConfigRenderer.renderOutbound(uint32Only.outbound)
                        .getJSONObject("streamSettings")
                        .getJSONObject("httpupgradeSettings").getString("path"));
        assertUriRejected(prefix + "4294967296", "HTTPUpgrade early data");
    }

    @Test
    public void rejectsControlCharactersInUriTransportHeaders() throws Exception {
        String prefix = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?type=ws&path=%2F&headers=";
        for (JSONObject headers : new JSONObject[]{
                new JSONObject().put("X-Test\r\nInjected", "value"),
                new JSONObject().put("X-Test", "value\r\nInjected: yes"),
                new JSONObject().put("X-Test", "value\twith-tab"),
        }) {
            try {
                ProtocolParser.parse(prefix + URLEncoder.encode(
                        headers.toString(), "UTF-8").replace("+", "%20"));
                throw new AssertionError("control character accepted in transport header");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("header"));
            }
        }
    }

    @Test
    public void rejectsDecodedControlsInTransportAndTlsScalars() throws Exception {
        String base = "vless://11111111-1111-1111-1111-111111111111@example.com:443?";
        for (String query : new String[]{
                "security=tls&sni=edge.example%0Ainjected&type=tcp",
                "security=tls&type=ws&path=%2Fws%00tail",
                "security=tls&type=grpc&serviceName=svc%0Dtail",
                "security=tls&type=http&path=%2Fh%09tail",
                "security=tls&type=httpupgrade&path=%2Fu%0Atail",
                "security=tls&type=xhttp&path=%2Fx%00tail"
        }) {
            assertUriRejected(base + query, "invalid neutral");
        }

        for (String scheme : new String[]{"vless", "trojan"}) {
            String user = scheme.equals("vless")
                    ? "11111111-1111-1111-1111-111111111111" : "secret";
            assertUriRejected(scheme + "://" + user + "@example.com:443"
                    + "?security=tls&sni=one.example&peer=two.example&type=tcp", "SNI");
        }
    }

    @Test
    public void rejectsInvalidDuplicateAndConflictingWebSocketHeaders() throws Exception {
        String prefix = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?type=ws&path=%2F&host=edge.example&headers=";
        for (JSONObject headers : new JSONObject[]{
                new JSONObject().put("Bad Header", "value"),
                new JSONObject().put("Bad:Header", "value"),
                new JSONObject().put("Host", "edge.example").put("host", "edge.example"),
                new JSONObject().put("HOST", "other.example"),
        }) {
            try {
                ProtocolParser.parse(prefix + URLEncoder.encode(
                        headers.toString(), "UTF-8").replace("+", "%20"));
                throw new AssertionError("invalid/conflicting transport header accepted: " + headers);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("header")
                        || expected.getMessage().contains("Host"));
            }
        }
        ProtocolParser.Node exact = ProtocolParser.parse(prefix + URLEncoder.encode(
                new JSONObject().put("HOST", "edge.example").toString(),
                "UTF-8").replace("+", "%20"));
        assertEquals("edge.example", exact.outbound.getJSONObject("transport")
                .getJSONObject("headers").getString("Host"));
        assertFalse(exact.outbound.getJSONObject("transport")
                .getJSONObject("headers").has("HOST"));
    }

    @Test
    public void enforcesUriLimitAndKeepsVlessEncryptionXrayOnly() throws Exception {
        String oversized = "vless://uuid@example.com:443?type=ws&path=/" + repeat('a', 17 * 1024);
        try {
            ProtocolParser.parse(oversized);
            throw new AssertionError("oversized URI accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("16 KiB"));
        }

        ProtocolParser.Node encrypted = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?encryption=" + validVlessEncryption(32)
                        + "&security=tls&type=tcp");
        assertEquals(validVlessEncryption(32),
                encrypted.outbound.getString("encryption"));
        assertFalse(encrypted.supports(CoreFamily.SING_BOX));
        assertTrue(encrypted.supports(CoreFamily.XRAY));
        assertEquals(validVlessEncryption(32), XrayConfigRenderer.renderOutbound(
                encrypted.outbound).getJSONObject("settings").getJSONArray("vnext")
                .getJSONObject(0).getJSONArray("users").getJSONObject(0)
                .getString("encryption"));
    }

    @Test
    public void validatesFullPinnedXrayVlessEncryptionContract() throws Exception {
        for (int keyBytes : new int[]{32, 1184}) {
            String encryption = validVlessEncryption(keyBytes);
            ProtocolParser.Node accepted = ProtocolParser.parse(
                    "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                            + "?encryption=" + encryption + "&security=tls&type=tcp");
            assertTrue(accepted.supports(CoreFamily.XRAY));
            assertEquals(encryption, XrayConfigRenderer.renderOutbound(accepted.outbound)
                    .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0).getString("encryption"));
        }
        String relayChain = "mlkem768x25519plus.native.0rtt."
                + rawUrlKey(32) + "." + rawUrlKey(1184);
        ProtocolParser.Node chained = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?encryption=" + relayChain + "&security=tls&type=tcp");
        assertEquals(relayChain, XrayConfigRenderer.renderOutbound(chained.outbound)
                .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0).getString("encryption"));

        // Pinned Xray accepts zero or more ParsePadding triples before the
        // first key and all three exact mode/RTT variants.
        for (String mode : new String[]{"native", "xorpub", "random"}) {
            for (String rtt : new String[]{"1rtt", "0rtt"}) {
                ProtocolParser.Node padded = ProtocolParser.parse(
                                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                                + "?encryption=mlkem768x25519plus." + mode + "." + rtt
                                + ".100-35-35.50-0-10." + rawUrlKey(32)
                                + "&security=tls&type=tcp");
                assertTrue(padded.supports(CoreFamily.XRAY));
            }
        }

        for (String invalid : new String[]{
                "mlkem768x25519plus.native.0rtt",
                "future.native.0rtt." + rawUrlKey(32),
                "mlkem768x25519plus.unknown.0rtt." + rawUrlKey(32),
                "mlkem768x25519plus.native.future." + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt.100-35-35",
                "mlkem768x25519plus.native.0rtt.." + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt." + rawUrlKey(32) + ".100-35-35",
                "mlkem768x25519plus.native.0rtt.100-35." + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt.99-35-35." + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt.100-34-35." + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt.100-65554-65554." + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt.100-40000-40000.50-0-0."
                        + "50-30000-30000." + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt.100-2147483648-2147483648."
                        + rawUrlKey(32),
                "mlkem768x25519plus.native.0rtt.AAAAAAAAAAAAAAAAAAAA",
                "mlkem768x25519plus.native.0rtt.not+raw/url/base64/value"
        }) {
            try {
                ProtocolParser.parse(
                        "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                                + "?encryption=" + invalid + "&security=tls&type=tcp");
                throw new AssertionError("invalid VLESS encryption accepted: " + invalid);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("VLESS encryption")
                        || expected.getMessage().contains("proxy URI"));
            }
        }
    }

    @Test
    public void storedNeutralNodeRoundTripsWithoutUriReparseOrDirectFallback() throws Exception {
        ProtocolParser.Node original = ProtocolParser.fromOutbound("", "Stored", new JSONObject()
                .put("type", "vless")
                .put("server", "stored.example")
                .put("server_port", 443)
                .put("uuid", "11111111-1111-1111-1111-111111111111")
                .put("encryption", "none"));
        JSONObject stored = original.toStoredJson();
        assertSame(original.outbound, stored.getJSONObject("outbound"));
        ProtocolParser.Node restored = ProtocolParser.fromStoredJson(stored);
        assertEquals(original.normalizedKey, restored.normalizedKey);
        assertEquals("stored.example", restored.outbound.getString("server"));

        JSONObject config = ProtocolParser.buildConfig(restored, 39001, "", "");
        assertEquals(1, config.getJSONArray("outbounds").length());
        JSONObject singBoxOutbound = config.getJSONArray("outbounds").getJSONObject(0);
        assertEquals("vless", singBoxOutbound.getString("type"));
        assertFalse("neutral-only VLESS encryption reached strict sing-box JSON",
                singBoxOutbound.has("encryption"));
        assertEquals("none", XrayConfigRenderer.build(restored, 39002, "", "")
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                .getJSONArray("users").getJSONObject(0).getString("encryption"));
        JSONObject route = config.getJSONObject("route");
        assertEquals("proxy", route.getString("final"));
        assertEquals("dns-primary", route.getString("default_domain_resolver"));
        JSONArray dnsServers = config.getJSONObject("dns").getJSONArray("servers");
        assertEquals("dns-primary", dnsServers.getJSONObject(0).getString("tag"));
        assertEquals("dns-secondary", dnsServers.getJSONObject(1).getString("tag"));
    }

    @Test
    public void keepsPacketEncodingCoreNeutralWithoutInventingXrayFields() throws Exception {
        String prefix = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?security=tls&type=tcp&packetEncoding=";
        ProtocolParser.Node none = ProtocolParser.parse(prefix + "none");
        assertTrue(none.outbound.has("packet_encoding"));
        assertEquals("", none.outbound.getString("packet_encoding"));
        assertTrue(none.supports(CoreFamily.SING_BOX));
        assertFalse(none.supports(CoreFamily.XRAY));
        assertEquals("", ProtocolParser.renderSingBoxOutbound(none.outbound)
                .getString("packet_encoding"));

        ProtocolParser.Node xudp = ProtocolParser.parse(prefix + "xudp");
        assertEquals("xudp", xudp.outbound.getString("packet_encoding"));
        assertTrue(xudp.supports(CoreFamily.SING_BOX));
        assertTrue(xudp.supports(CoreFamily.XRAY));
        String rendered = XrayConfigRenderer.build(xudp, 39002, "", "").toString();
        assertFalse(rendered.contains("packetEncoding"));
        assertFalse(rendered.contains("packet_encoding"));

        ProtocolParser.Node packetAddr = ProtocolParser.parse(prefix + "packetaddr");
        assertTrue(packetAddr.supports(CoreFamily.SING_BOX));
        assertFalse(packetAddr.supports(CoreFamily.XRAY));
    }

    @Test
    public void treatsLegacyVmessTypeStrictlyAndUsesItOnlyForMkcp() throws Exception {
        JSONObject base = new JSONObject()
                .put("v", "2").put("add", "vm.example").put("port", 443)
                .put("id", "22222222-2222-2222-2222-222222222222")
                .put("aid", 0);
        for (String network : new String[]{"tcp", "ws"}) {
            JSONObject unsupported = new JSONObject(base.toString())
                    .put("net", network).put("type", "http");
            try {
                ProtocolParser.parse(vmessUri(unsupported));
                throw new AssertionError("VMess legacy type was silently discarded for " + network);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("headerType"));
            }
        }

        JSONObject mkcp = new JSONObject(base.toString())
                .put("net", "mkcp").put("type", "wechat-video").put("seed", "legacy");
        JSONObject transport = ProtocolParser.parse(vmessUri(mkcp)).outbound
                .getJSONObject("transport");
        assertEquals("mkcp", transport.getString("type"));
        assertEquals("wechat", transport.getString("legacy_header"));
        assertEquals("legacy", transport.getString("legacy_seed"));
    }

    @Test
    public void rejectsCamelCaseBindDnsAndRoutingParameters() {
        String prefix = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?security=tls&type=tcp&";
        for (String field : new String[]{
                "bindInterface", "domainStrategy", "dnsStrategy", "routingMark"
        }) {
            try {
                ProtocolParser.parse(prefix + field + "=unsupported");
                throw new AssertionError("functional parameter was silently discarded: " + field);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("unsupported proxy parameter"));
            } catch (Exception unexpected) {
                throw new AssertionError(unexpected);
            }
        }
    }

    @Test
    public void validatesXhttpExtraTypesRangesAndSizeBeforeRendering() throws Exception {
        JSONObject validExtra = new JSONObject()
                .put("xPaddingBytes", "1-1048576")
                .put("scMaxEachPostBytes", 8 * 1024 * 1024)
                .put("scMinPostsIntervalMs", "0-60000")
                .put("noSSEHeader", true);
        ProtocolParser.Node valid = ProtocolParser.parse(xhttpUri(validExtra));
        JSONObject parsedExtra = valid.outbound.getJSONObject("transport").getJSONObject("extra");
        assertEquals("1-1048576", parsedExtra.getString("xPaddingBytes"));
        assertEquals(8 * 1024 * 1024, parsedExtra.getInt("scMaxEachPostBytes"));
        JSONObject renderedExtra = XrayConfigRenderer.build(valid, 39003, "", "")
                .getJSONArray("outbounds").getJSONObject(0)
                .getJSONObject("streamSettings").getJSONObject("xhttpSettings")
                .getJSONObject("extra");
        assertEquals("0-60000", renderedExtra.getString("scMinPostsIntervalMs"));
        assertTrue(renderedExtra.getBoolean("noSSEHeader"));

        // An unknown scalar is carried through: sources name padding, sequence
        // and session options this client does not enumerate, and refusing one
        // discarded every server they offered.
        ProtocolParser.parse(xhttpUri(new JSONObject().put("unknown", 1)));

        JSONObject[] invalid = new JSONObject[]{
                new JSONObject().put("xPaddingBytes", "0-10"),
                new JSONObject().put("xPaddingBytes", "10-1"),
                new JSONObject().put("scMaxEachPostBytes", 8 * 1024 * 1024 + 1),
                new JSONObject().put("scMinPostsIntervalMs", "0-60001"),
                new JSONObject().put("scMinPostsIntervalMs", 1.5d),
                new JSONObject().put("noSSEHeader", "true"),
                new JSONObject().put("xPaddingBytes", new JSONObject().put("from", 1)),
        };
        for (JSONObject extra : invalid) {
            try {
                ProtocolParser.parse(xhttpUri(extra));
                throw new AssertionError("invalid XHTTP extra accepted: " + extra);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("XHTTP"));
            }
        }

        JSONObject oversized = new JSONObject().put("xPaddingBytes", repeat('1', 65 * 1024));
        try {
            ProtocolParser.fromOutbound("", "oversized", new JSONObject()
                    .put("type", "vless")
                    .put("server", "example.com")
                    .put("server_port", 443)
                    .put("uuid", "11111111-1111-1111-1111-111111111111")
                    .put("encryption", "none")
                    .put("transport", new JSONObject()
                            .put("type", "xhttp")
                            .put("path", "/")
                            .put("mode", "auto")
                            .put("extra", oversized)));
            throw new AssertionError("oversized XHTTP extra accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("64 KiB"));
        }
    }

    @Test
    public void clashUnknownFieldsAreRejectedWithSanitizedRejections() {
        String secret = "credential@example.invalid";
        String yaml = "proxies:\n"
                + "  - name: Strict Clash\n"
                + "    type: vless\n"
                + "    server: clash.example\n"
                + "    port: 443\n"
                + "    uuid: 33333333-3333-3333-3333-333333333333\n"
                + "    unsupported-field: " + secret + "\n";
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(yaml);
        assertTrue(result.nodes.isEmpty());
        assertEquals(1, result.rejected);
        assertFalse(result.reasons.isEmpty());
        assertFalse(result.reasons.toString().contains("credential"));
        assertFalse(result.reasons.toString().contains("example.invalid"));
    }

    @Test
    public void rejectsCorruptedStoredNeutralSchemaAtEveryTrustBoundary() throws Exception {
        ProtocolParser.Node valid = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&sni=edge.example&type=ws&path=%2Fws");
        String serialized = valid.outbound.toString();
        for (String forbidden : new String[]{
                "detour", "bind_interface", "dns_strategy", "routing", "mux", "unknown"
        }) {
            assertStoredOutboundRejected(new JSONObject(serialized).put(forbidden, "blocked"));
        }

        JSONObject badTls = new JSONObject(serialized);
        badTls.getJSONObject("tls").put("domainStrategy", "UseIP");
        assertStoredOutboundRejected(badTls);

        JSONObject badTransport = new JSONObject(serialized);
        badTransport.getJSONObject("transport").put("mux", new JSONObject().put("enabled", true));
        assertStoredOutboundRejected(badTransport);

        JSONObject rawFallback = new JSONObject(serialized)
                .put("transport", new JSONObject().put("type", "raw"));
        assertStoredOutboundRejected(rawFallback);

        JSONObject badHeaders = new JSONObject(serialized);
        badHeaders.getJSONObject("transport").put("headers",
                new JSONObject().put("Host", 42));
        assertStoredOutboundRejected(badHeaders);
        for (JSONObject injected : new JSONObject[]{
                new JSONObject().put("X-Test\r\nInjected", "value"),
                new JSONObject().put("X-Test", "value\r\nInjected: yes"),
                new JSONObject().put("X-Test", "value\u0000tail"),
        }) {
            JSONObject controlled = new JSONObject(serialized);
            controlled.getJSONObject("transport").put("headers", injected);
            assertStoredOutboundRejected(controlled);
        }

        JSONObject badReality = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=reality&sni=edge.example&pbk=" + realityPublicKey()
                        + "&sid=42&type=tcp")
                .outbound;
        badReality.getJSONObject("tls").getJSONObject("reality")
                .put("routing", new JSONObject());
        assertStoredOutboundRejected(badReality);

        JSONObject badXhttp = new JSONObject(serialized)
                .put("transport", new JSONObject().put("type", "xhttp")
                        .put("path", "/x").put("mode", "auto")
                        .put("extra", new JSONObject().put("downloadSettings", new JSONObject())));
        assertStoredOutboundRejected(badXhttp);

        JSONObject badMkcp = new JSONObject(serialized)
                .put("transport", new JSONObject().put("type", "mkcp")
                        .put("legacy_header", "http"));
        assertStoredOutboundRejected(badMkcp);

        ProtocolParser.Node mutated = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&type=tcp");
        mutated.outbound.put("routing", new JSONObject());
        try {
            ProtocolParser.buildConfig(mutated, 39004, "", "");
            throw new AssertionError("mutated node reached sing-box config");
        } catch (IllegalArgumentException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test
    public void parsesHysteriaBandwidthWithoutDigitConcatenation() throws Exception {
        ProtocolParser.Node valid = ProtocolParser.parse(
                "hysteria://auth@hy.example:443?up=20mbps&down=50m");
        assertEquals(20, valid.outbound.getInt("up_mbps"));
        assertEquals(50, valid.outbound.getInt("down_mbps"));

        for (String malformed : new String[]{"1.5", "1-2", "20kbps", "-1", "1e3"}) {
            try {
                ProtocolParser.parse("hysteria://auth@hy.example:443?up="
                        + URLEncoder.encode(malformed, "UTF-8"));
                throw new AssertionError("malformed Hysteria bandwidth accepted: " + malformed);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("bandwidth"));
            }
        }
    }

    @Test
    public void preservesHysteria2BandwidthForPinnedSingBoxWithout32BitOverflow()
            throws Exception {
        ProtocolParser.Node node = ProtocolParser.parse(
                "hysteria2://secret@hy2.example:443"
                        + "?upmbps=17179&down=200%20Mbps");
        assertEquals(17179, node.outbound.getInt("up_mbps"));
        assertEquals(200, node.outbound.getInt("down_mbps"));
        assertTrue(node.supports(CoreFamily.SING_BOX));
        assertFalse(node.supports(CoreFamily.XRAY));

        JSONObject rendered = ProtocolParser.renderSingBoxOutbound(node.outbound);
        assertEquals(17179, rendered.getInt("up_mbps"));
        assertEquals(200, rendered.getInt("down_mbps"));

        ProtocolParser.Node unlimited = ProtocolParser.parse(
                "hysteria2://secret@hy2.example:443?up=0&downmbps=0");
        assertFalse(unlimited.outbound.has("up_mbps"));
        assertFalse(unlimited.outbound.has("down_mbps"));

        for (String malformed : new String[]{
                "17180", "2147483648", "1.5", "20kbps", "-1", "1e3"
        }) {
            try {
                ProtocolParser.parse("hysteria2://secret@hy2.example:443?up="
                        + URLEncoder.encode(malformed, "UTF-8"));
                throw new AssertionError(
                        "unsafe Hysteria2 bandwidth accepted: " + malformed);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("bandwidth"));
            }
        }

        try {
            ProtocolParser.parse("hysteria2://secret@hy2.example:443?up=20&upmbps=20");
            throw new AssertionError("duplicate Hysteria2 bandwidth aliases accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("aliases"));
        }
    }

    @Test
    public void requiresExactHysteriaObfsAndTuicCredentials() throws Exception {
        ProtocolParser.Node valid = ProtocolParser.parse(
                "hysteria://auth@hy.example:443?obfs=xplus&obfsParam=cover");
        assertEquals("cover", valid.outbound.getString("obfs"));

        for (String invalid : new String[]{
                "hysteria://auth@hy.example:443?obfs=xplus",
                "hysteria://auth@hy.example:443?obfs=cover",
                "hysteria://auth@hy.example:443?obfsParam=cover",
                "tuic://33333333-3333-3333-3333-333333333333@tuic.example:443",
                "tuic://33333333-3333-3333-3333-333333333333:@tuic.example:443",
                "tuic://:password@tuic.example:443",
        }) {
            try {
                ProtocolParser.parse(invalid);
                throw new AssertionError("incomplete credential/obfs accepted: " + invalid);
            } catch (IllegalArgumentException expected) {
                assertNotNull(expected.getMessage());
            }
        }

        String clashTuicWithoutPassword = "proxies:\n"
                + "  - name: Missing password\n"
                + "    type: tuic\n"
                + "    server: tuic.example\n"
                + "    port: 443\n"
                + "    uuid: 33333333-3333-3333-3333-333333333333\n";
        SubscriptionParser.ParseResult clash = SubscriptionParser.parseDetailed(
                clashTuicWithoutPassword);
        assertTrue(clash.nodes.isEmpty());
        assertEquals(1, clash.rejected);
    }

    @Test
    public void rejectsUnknownFunctionalUriParameters() throws Exception {
        for (String parameter : new String[]{
                "zero_rtt_handshake=true", "heartbeat=10s", "udp_over_stream=true"
        }) {
            try {
                ProtocolParser.parse("tuic://33333333-3333-3333-3333-333333333333:password"
                        + "@tuic.example:443?" + parameter);
                throw new AssertionError("unknown TUIC parameter accepted: " + parameter);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("TUIC parameter"));
            }
        }
    }

    @Test
    public void vmessSecurityControlsXrayCompatibility() throws Exception {
        for (String security : new String[]{"auto", "aes-128-gcm", "chacha20-poly1305"}) {
            JSONObject value = new JSONObject().put("v", "2").put("add", "vm.example")
                    .put("port", 443).put("id", "11111111-1111-1111-1111-111111111111")
                    .put("aid", 0).put("scy", security).put("net", "tcp");
            assertTrue(ProtocolParser.parse(vmessUri(value)).supports(CoreFamily.XRAY));
        }
        for (String security : new String[]{"none", "zero", "aes-128-cfb"}) {
            JSONObject value = new JSONObject().put("v", "2").put("add", "vm.example")
                    .put("port", 443).put("id", "11111111-1111-1111-1111-111111111111")
                    .put("aid", 0).put("scy", security).put("net", "tcp");
            ProtocolParser.Node node = ProtocolParser.parse(vmessUri(value));
            assertTrue(node.supports(CoreFamily.SING_BOX));
            assertFalse(node.supports(CoreFamily.XRAY));
        }

        for (String invalidSecurity : new String[]{"future-unknown-cipher", "AUTO"}) {
            JSONObject invalidStored = new JSONObject()
                    .put("type", "vmess").put("server", "vm.example")
                    .put("server_port", 443)
                    .put("uuid", "11111111-1111-1111-1111-111111111111")
                    .put("alter_id", 0).put("security", invalidSecurity);
            try {
                ProtocolParser.fromOutbound("", "stored", invalidStored);
                throw new AssertionError("invalid stored VMess security reached sing-box");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("VMess security"));
            }
        }
    }

    @Test
    public void rejectsDeepVmessAndXhttpJsonBeforeAndroidParser() throws Exception {
        String nested = repeat('[', 64) + "0" + repeat(']', 64);
        String vmess = "{\"v\":\"2\",\"add\":\"vm.example\",\"port\":443,"
                + "\"id\":\"11111111-1111-1111-1111-111111111111\","
                + "\"aid\":0,\"net\":\"tcp\",\"padding\":" + nested + "}";
        String vmessUri = "vmess://" + Base64.getEncoder().encodeToString(
                vmess.getBytes(StandardCharsets.UTF_8));
        assertJsonDepthRejected(vmessUri);

        String xhttpExtra = "{\"scMaxEachPostBytes\":1,\"padding\":" + nested + "}";
        String xhttpUri = "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?security=tls&type=xhttp&extra="
                + URLEncoder.encode(xhttpExtra, "UTF-8").replace("+", "%20");
        assertJsonDepthRejected(xhttpUri);
    }

    @Test
    public void rejectsDuplicateQueryKeysAndUnknownBooleanValues() throws Exception {
        String base = "vless://11111111-1111-1111-1111-111111111111@example.com:443?";
        for (String query : new String[]{
                "security=tls&security=none",
                "security=tls&sec%75rity=none",
                "security=tls&insecure=maybe",
                "security=tls&allowInsecure=",
                "security=none&insecure=2",
                "security=tls&insecure=true&allowInsecure=false",
        }) {
            try {
                ProtocolParser.parse(base + query);
                throw new AssertionError("ambiguous proxy query accepted: " + query);
            } catch (IllegalArgumentException expected) {
                assertNotNull(expected.getMessage());
            }
        }

        for (String falseValue : new String[]{"0", "false", "no", "off"}) {
            ProtocolParser.Node node = ProtocolParser.parse(
                    base + "security=tls&insecure=" + falseValue);
            assertFalse(node.outbound.getJSONObject("tls").getBoolean("insecure"));
        }
        for (String trueValue : new String[]{"1", "true", "yes", "on"}) {
            ProtocolParser.Node node = ProtocolParser.parse(
                    base + "security=tls&insecure=" + trueValue);
            assertTrue(node.outbound.getJSONObject("tls").getBoolean("insecure"));
        }
    }

    @Test
    public void exactUriKeepsTrailingPunctuation() throws Exception {
        ProtocolParser.Node node = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls#Node.;");
        assertEquals("Node.;", node.name);
        assertTrue(node.uri.endsWith("#Node.;"));
    }

    @Test
    public void validatesPinnedProtocolSemanticsBeforeCoreStart() throws Exception {
        for (String invalid : new String[]{
                "tuic://not-a-uuid:password@tuic.example:443",
                "tuic://11111111-1111-1111-1111-111111111111:password@tuic.example:443"
                        + "?congestion_control=made-up",
                "tuic://11111111-1111-1111-1111-111111111111:password@tuic.example:443"
                        + "?udp_relay_mode=made-up",
                "hysteria2://password@hy.example:443-8443?hop_interval=forever",
                "hysteria2://password@hy.example:443-8443"
                        + "?hop_interval=9223372036854775808ns",
                "hysteria2://password@hy.example:443-8443"
                        + "?hop_interval=999999999999999999999h",
        }) {
            try {
                ProtocolParser.parse(invalid);
                throw new AssertionError("invalid pinned option accepted: " + invalid);
            } catch (IllegalArgumentException expected) {
                assertNotNull(expected.getMessage());
            }
        }
        assertEquals("9223372036854775807ns", ProtocolParser.parse(
                "hysteria2://password@hy.example:443-8443"
                        + "?hop_interval=9223372036854775807ns")
                .outbound.getString("hop_interval"));
        for (String duration : new String[]{".5s", "1.s", "1μs", "+1s", "1d"}) {
            String encoded = duration.startsWith("+") ? "%2B1s" : duration;
            assertEquals(duration, ProtocolParser.parse(
                    "hysteria2://password@hy.example:443-8443?hop_interval=" + encoded)
                    .outbound.getString("hop_interval"));
        }
        for (String zero : new String[]{
                "0", "+0", "-0", "0s", "+0s", "-0s", "00s", "0.0s",
                "0h0m", "0.1ns", "-0.1ns"
        }) {
            String encoded = zero.startsWith("+") ? "%2B" + zero.substring(1) : zero;
            ProtocolParser.Node parsed = ProtocolParser.parse(
                    "hysteria2://password@hy.example:443-8443?hop_interval=" + encoded);
            assertEquals(zero, parsed.outbound.getString("hop_interval"));

            JSONObject stored = new JSONObject(parsed.outbound.toString())
                    .put("hop_interval", zero);
            assertEquals(zero, ProtocolParser.fromOutbound("", "stored", stored)
                    .outbound.getString("hop_interval"));
        }
        assertUriRejected("hysteria2://password@hy.example:443-8443"
                + "?hop_interval=-1s", "hop interval");
        for (String sign : new String[]{"%2B", "-"}) {
            assertUriRejected("hysteria2://password@hy.example:443-8443"
                    + "?hop_interval=" + sign, "hop interval");
            JSONObject stored = new JSONObject(ProtocolParser.parse(
                    "hysteria2://password@hy.example:443-8443?hop_interval=0s")
                    .outbound.toString()).put("hop_interval", sign.equals("%2B") ? "+" : "-");
            try {
                ProtocolParser.fromOutbound("", "stored", stored);
                throw new AssertionError("sign-only stored duration accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("hop interval"));
            }
        }
        try {
            ProtocolParser.parse("hysteria2://password@hy.example:443-8443"
                    + "?hop_interval=106752d");
            throw new AssertionError("overflowing day duration accepted");
        } catch (IllegalArgumentException expected) {
            assertNotNull(expected.getMessage());
        }

        String unsupported = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "made-up:secret".getBytes(StandardCharsets.UTF_8));
        try {
            ProtocolParser.parse("ss://" + unsupported + "@ss.example:443");
            throw new AssertionError("unsupported Shadowsocks method accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Shadowsocks"));
        }

        String key2022 = Base64.getEncoder().withoutPadding().encodeToString(new byte[16]);
        String method2022 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("2022-blake3-aes-128-gcm:" + key2022)
                        .getBytes(StandardCharsets.UTF_8));
        ProtocolParser.Node shared = ProtocolParser.parse(
                "ss://" + method2022 + "@ss.example:443");
        assertTrue(shared.supports(CoreFamily.SING_BOX));
        assertTrue(shared.supports(CoreFamily.XRAY));
        assertEquals(Base64.getEncoder().encodeToString(new byte[16]),
                shared.outbound.getString("password"));

        String invalid2022 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "2022-blake3-aes-128-gcm:short".getBytes(StandardCharsets.UTF_8));
        try {
            ProtocolParser.parse("ss://" + invalid2022 + "@ss.example:443");
            throw new AssertionError("invalid Shadowsocks 2022 key accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("2022 key"));
        }
    }

    @Test
    public void selectsExactPinnedUtlsAndRealityCapabilities() throws Exception {
        String base = "vless://11111111-1111-1111-1111-111111111111@example.com:443";
        ProtocolParser.Node xrayOnly = ProtocolParser.parse(
                base + "?security=tls&type=ws&path=%2F&fp=hellochrome_120");
        assertFalse(xrayOnly.supports(CoreFamily.SING_BOX));
        assertTrue(xrayOnly.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(xrayOnly, null, false, false));
        assertEquals("hellochrome_120", XrayConfigRenderer.renderOutbound(xrayOnly.outbound)
                .getJSONObject("streamSettings").getJSONObject("tlsSettings")
                .getString("fingerprint"));

        ProtocolParser.Node singBoxOnly = ProtocolParser.parse(
                base + "?security=tls&fp=chrome_psk");
        assertTrue(singBoxOnly.supports(CoreFamily.SING_BOX));
        assertFalse(singBoxOnly.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(singBoxOnly, null, false, false));

        assertUriRejected(base + "?security=tls&fp=definitely-invalid", "fingerprint");
        for (String invalidReality : new String[]{
                "pbk=public&sid=42",
                "pbk=" + realityPublicKey() + "%3D&sid=42",
                "pbk=" + realityPublicKey() + "&sid=4",
                "pbk=" + realityPublicKey() + "&sid=zz",
                "pbk=" + realityPublicKey() + "&sid=001122334455667788",
                "pbk=" + realityPublicKey() + "&sid=42&spx=relative",
                "pbk=" + realityPublicKey() + "&sid=42&spx=%2Fprobe%00tail",
                "pbk=" + realityPublicKey() + "&sid=42&spx=%2Fprobe%0D%0Atail",
                "pbk=" + realityPublicKey() + "&sid=42&spx=%2Fprobe%25",
                "pbk=" + realityPublicKey() + "&sid=42&fp=unsafe",
        }) {
            assertUriRejected(base + "?security=reality&" + invalidReality,
                    invalidReality.contains("fp=unsafe") ? "fingerprint" : "Reality");
        }

        ProtocolParser.Node reality = ProtocolParser.parse(
                base + "?security=reality&sni=edge.example&pbk=" + realityPublicKey()
                        + "&sid=42&spx=%2Fprobe&fp=randomizednoalpn");
        assertFalse(reality.supports(CoreFamily.SING_BOX));
        assertTrue(reality.supports(CoreFamily.XRAY));
        assertEquals("/probe", reality.outbound.getJSONObject("tls")
                .getJSONObject("reality").getString("spider_x"));
    }

    @Test
    public void rejectsUtlsForPinnedSingBoxQuicProtocols() throws Exception {
        String[] validUris = {
                "hysteria://secret@hy.example:443?upmbps=20&downmbps=50",
                "hysteria2://password@hy2.example:443?sni=edge.example",
                "tuic://33333333-3333-3333-3333-333333333333:password"
                        + "@tuic.example:443?sni=edge.example",
        };
        for (String uri : validUris) {
            assertUriRejected(uri + (uri.contains("?") ? "&" : "?") + "fp=chrome", "fp");
            JSONObject structured = new JSONObject(
                    ProtocolParser.parse(uri).outbound.toString());
            structured.getJSONObject("tls").put("utls", new JSONObject()
                    .put("enabled", true).put("fingerprint", "chrome"));
            assertStoredOutboundRejected(structured);
        }
    }

    @Test
    public void canonicalizesShadowsocksAliasesAnd2022KeyChains() throws Exception {
        String[][] aliases = {
                {"aead_aes_128_gcm", "aes-128-gcm"},
                {"aead_aes_256_gcm", "aes-256-gcm"},
                {"aead_chacha20_poly1305", "chacha20-ietf-poly1305"},
                {"chacha20-poly1305", "chacha20-ietf-poly1305"},
                {"aead_xchacha20_poly1305", "xchacha20-ietf-poly1305"},
                {"xchacha20-poly1305", "xchacha20-ietf-poly1305"},
        };
        for (String[] alias : aliases) {
            ProtocolParser.Node node = ProtocolParser.parse(
                    shadowsocksUri(alias[0], "password"));
            assertEquals(alias[1], node.outbound.getString("method"));
            assertTrue(node.supports(CoreFamily.SING_BOX));
            assertTrue(node.supports(CoreFamily.XRAY));
        }

        for (String alias : new String[]{"plain", "dummy"}) {
            ProtocolParser.Node empty = ProtocolParser.parse(
                    shadowsocksUri(alias, ""));
            assertEquals("none", empty.outbound.getString("method"));
            assertEquals("", empty.outbound.getString("password"));
            assertTrue(empty.supports(CoreFamily.SING_BOX));
            assertFalse(empty.supports(CoreFamily.XRAY));
            JSONObject rendered = ProtocolParser.renderSingBoxOutbound(empty.outbound);
            assertEquals("none", rendered.getString("method"));
            assertEquals("", rendered.getString("password"));

            ProtocolParser.Node credential = ProtocolParser.parse(
                    shadowsocksUri(alias.toUpperCase(java.util.Locale.US), "secret"));
            assertEquals("none", credential.outbound.getString("method"));
            assertEquals("secret", credential.outbound.getString("password"));
            assertXraySelectionAndRendererReject(credential);
        }

        String keyA = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(new byte[16]);
        byte[] second = new byte[16];
        java.util.Arrays.fill(second, (byte) 7);
        String keyB = Base64.getUrlEncoder().withoutPadding().encodeToString(second);
        ProtocolParser.Node chain = ProtocolParser.parse(shadowsocksUri(
                "2022-blake3-aes-128-gcm", keyA + ":" + keyB));
        String canonical = Base64.getEncoder().encodeToString(new byte[16]) + ":"
                + Base64.getEncoder().encodeToString(second);
        assertEquals(canonical, chain.outbound.getString("password"));
        assertTrue(chain.supports(CoreFamily.SING_BOX));
        assertTrue(chain.supports(CoreFamily.XRAY));
        assertEquals(canonical, XrayConfigRenderer.renderOutbound(chain.outbound)
                .getJSONObject("settings").getJSONArray("servers")
                .getJSONObject(0).getString("password"));

        byte[] longKey = new byte[17];
        ProtocolParser.Node derivedAes128 = ProtocolParser.parse(shadowsocksUri(
                "2022-blake3-aes-128-gcm",
                Base64.getUrlEncoder().withoutPadding().encodeToString(longKey)));
        assertTrue(derivedAes128.supports(CoreFamily.SING_BOX));
        assertTrue(derivedAes128.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(derivedAes128, null, false, false));

        for (String method : new String[]{
                "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
        }) {
            byte[] oversized = new byte[33];
            ProtocolParser.Node derived = ProtocolParser.parse(shadowsocksUri(
                    method, Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(oversized)));
            assertTrue(derived.supports(CoreFamily.SING_BOX));
            assertTrue(derived.supports(CoreFamily.XRAY));
        }

        String key32 = Base64.getEncoder().encodeToString(new byte[32]);
        assertUriRejected(shadowsocksUri("2022-blake3-chacha20-poly1305",
                key32 + ":" + key32), "2022 key");
    }

    @Test
    public void normalizesHttpUpgradeHostAndRejectsInvalidMkcpWindow() throws Exception {
        String base = "vless://11111111-1111-1111-1111-111111111111@example.com:443";
        String headers = URLEncoder.encode(new JSONObject()
                .put("Host", "edge.example").put("X-Test", "ok").toString(), "UTF-8");
        ProtocolParser.Node node = ProtocolParser.parse(
                base + "?security=tls&type=httpupgrade&path=%2Fup&headers=" + headers);
        JSONObject neutral = node.outbound.getJSONObject("transport");
        assertEquals("edge.example", neutral.getString("host"));
        assertFalse(neutral.getJSONObject("headers").has("Host"));
        JSONObject rendered = XrayConfigRenderer.renderOutbound(node.outbound)
                .getJSONObject("streamSettings").getJSONObject("httpupgradeSettings");
        assertEquals("edge.example", rendered.getString("host"));
        assertFalse(rendered.getJSONObject("headers").has("Host"));

        ProtocolParser.Node http = ProtocolParser.parse(
                base + "?security=tls&type=http&path=%2Fh&headers=" + headers);
        JSONObject neutralHttp = http.outbound.getJSONObject("transport");
        assertEquals("edge.example", neutralHttp.getJSONArray("host").getString(0));
        assertFalse(neutralHttp.getJSONObject("headers").has("Host"));
        JSONObject renderedHttp = ProtocolParser.renderSingBoxOutbound(http.outbound)
                .getJSONObject("transport");
        assertEquals("edge.example", renderedHttp.getJSONArray("host").getString(0));

        String conflicting = URLEncoder.encode(
                new JSONObject().put("host", "other.example").toString(), "UTF-8");
        assertUriRejected(base + "?type=httpupgrade&host=edge.example&headers="
                + conflicting, "Host");
        assertUriRejected(base + "?type=http&host=edge.example&headers="
                + conflicting, "Host");
        String controlled = URLEncoder.encode(new JSONObject()
                .put("Host", "edge.example\r\nInjected: yes").toString(), "UTF-8");
        assertUriRejected(base + "?type=httpupgrade&headers=" + controlled, "header");

        JSONObject nonStringHost = new JSONObject(node.outbound.toString());
        nonStringHost.getJSONObject("transport")
                .put("host", 42)
                .put("headers", new JSONObject().put("Host", "42"));
        assertStoredOutboundRejected(nonStringHost);

        assertUriRejected(base + "?type=xhttp&mode=auto&host="
                + URLEncoder.encode("edge.example\r\nInjected: yes", "UTF-8"), "host");
        assertUriRejected(base + "?type=mkcp&mtu=1500&maxSendingWindow=1499",
                "window");
        assertUriRejected(base + "?type=mkcp&mtu=20", "mtu");
        assertEquals(21, ProtocolParser.parse(base + "?type=mkcp&mtu=21")
                .outbound.getJSONObject("transport").getInt("mtu"));
        ProtocolParser.Node zeroCapacity = ProtocolParser.parse(base
                + "?type=mkcp&uplinkCapacity=0&downlinkCapacity=0");
        assertEquals(0, zeroCapacity.outbound.getJSONObject("transport")
                .getInt("uplink_capacity"));
        ProtocolParser.parse(base + "?type=mkcp&uplinkCapacity=4095"
                + "&downlinkCapacity=4095&maxSendingWindow=2097152");
        ProtocolParser.Node unsigned32 = ProtocolParser.parse(base
                + "?type=mkcp&uplinkCapacity=0&cwndMultiplier=536870911"
                + "&maxSendingWindow=4294967295");
        JSONObject unsignedTransport = unsigned32.outbound.getJSONObject("transport");
        assertEquals(536870911L, unsignedTransport.getLong("cwnd_multiplier"));
        assertEquals(4294967295L, XrayConfigRenderer.renderOutbound(unsigned32.outbound)
                .getJSONObject("streamSettings").getJSONObject("kcpSettings")
                .getLong("maxSendingWindow"));
        assertUriRejected(base + "?type=mkcp&uplinkCapacity=0"
                + "&cwndMultiplier=536870912", "overflows");
        assertUriRejected(base + "?type=mkcp&cwndMultiplier=4294967296", "cwnd");
        assertUriRejected(base + "?type=mkcp&maxSendingWindow=4294967296", "window");
        assertUriRejected(base + "?type=mkcp&uplinkCapacity=4096", "uplink");
        assertUriRejected(base + "?type=mkcp&downlinkCapacity=4096", "downlink");
        assertUriRejected(base + "?type=mkcp&mtu=21&tti=1000"
                + "&uplinkCapacity=4095&cwndMultiplier=1024", "overflows");
        for (String key : new String[]{"mtu", "tti", "uplinkCapacity",
                "uplink_capacity", "downlinkCapacity", "downlink_capacity",
                "cwndMultiplier", "cwnd_multiplier", "maxSendingWindow",
                "max_sending_window"}) {
            assertUriRejected(base + "?type=mkcp&" + key + "=", "empty");
            assertUriRejected(base + "?type=mkcp&" + key + "=%20%20", "empty");
        }
        ProtocolParser.Node valid = ProtocolParser.parse(
                base + "?type=mkcp&mtu=1500&maxSendingWindow=1500");
        assertFalse(valid.supports(CoreFamily.SING_BOX));
        assertTrue(valid.supports(CoreFamily.XRAY));
    }

    @Test
    public void preservesCustomIdsAndXrayVisionUdp443WithoutWrongCoreChoice()
            throws Exception {
        for (String id : new String[]{
                "11111111111111111111111111111111",
                "custom-user-id",
        }) {
            ProtocolParser.Node node = ProtocolParser.parse(
                    "vless://" + id + "@example.com:443?security=tls");
            assertTrue(node.supports(CoreFamily.SING_BOX));
            assertTrue(node.supports(CoreFamily.XRAY));
            assertEquals(id, XrayConfigRenderer.renderOutbound(node.outbound)
                    .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0).getString("id"));
        }

        String longCustom = repeat('u', 31);
        ProtocolParser.Node singBoxOnly = ProtocolParser.parse(
                "vless://" + longCustom + "@example.com:443?security=tls");
        assertTrue(singBoxOnly.supports(CoreFamily.SING_BOX));
        assertFalse(singBoxOnly.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(singBoxOnly, null, false, false));

        ProtocolParser.Node udp443 = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&type=tcp&flow=xtls-rprx-vision-udp443");
        assertFalse(udp443.supports(CoreFamily.SING_BOX));
        assertTrue(udp443.supports(CoreFamily.XRAY));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(udp443, null, false, false));
        assertEquals("xtls-rprx-vision-udp443",
                XrayConfigRenderer.renderOutbound(udp443.outbound)
                        .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                        .getJSONArray("users").getJSONObject(0).getString("flow"));
    }

    @Test
    public void customVlessAndVmessIdsPreserveExactWhitespaceBytes() throws Exception {
        for (String id : new String[]{" custom-id ", " "}) {
            String encoded = id.equals(" ") ? "%20" : "%20custom-id%20";
            ProtocolParser.Node vless = ProtocolParser.parse(
                    "vless://" + encoded + "@vless.example:443?security=tls");
            assertEquals(id, vless.outbound.getString("uuid"));
            assertEquals(id, ProtocolParser.renderSingBoxOutbound(vless.outbound)
                    .getString("uuid"));
            assertEquals(id, XrayConfigRenderer.renderOutbound(vless.outbound)
                    .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0).getString("id"));

            JSONObject payload = new JSONObject()
                    .put("v", "2").put("add", "vmess.example").put("port", 443)
                    .put("id", id).put("aid", 0).put("scy", "auto").put("net", "tcp");
            ProtocolParser.Node vmess = ProtocolParser.parse(vmessUri(payload));
            assertEquals(id, vmess.outbound.getString("uuid"));
            assertEquals(id, ProtocolParser.renderSingBoxOutbound(vmess.outbound)
                    .getString("uuid"));
            assertEquals(id, XrayConfigRenderer.renderOutbound(vmess.outbound)
                    .getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
                    .getJSONArray("users").getJSONObject(0).getString("id"));
        }
    }

    @Test
    public void opaqueCredentialsAndLegacySeedPreserveSingleSpace() throws Exception {
        ProtocolParser.Node trojan = ProtocolParser.parse(
                "trojan://%20@trojan.example:443");
        assertEquals(" ", trojan.outbound.getString("password"));
        assertEquals(" ", XrayConfigRenderer.renderOutbound(trojan.outbound)
                .getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
                .getString("password"));

        ProtocolParser.Node shadowsocks = ProtocolParser.parse(
                shadowsocksUri("aes-256-gcm", " "));
        assertEquals(" ", shadowsocks.outbound.getString("password"));
        assertEquals(" ", XrayConfigRenderer.renderOutbound(shadowsocks.outbound)
                .getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
                .getString("password"));

        for (String auth : new String[]{"hysteria://%20@hy.example:443",
                "hysteria://hy.example:443?auth=%20",
                "hysteria://hy.example:443?auth_str=%20"}) {
            ProtocolParser.Node hysteria = ProtocolParser.parse(auth);
            assertEquals(" ", hysteria.outbound.getString("auth_str"));
            assertEquals(" ", ProtocolParser.renderSingBoxOutbound(hysteria.outbound)
                    .getString("auth_str"));
        }
        ProtocolParser.Node hysteriaObfs = ProtocolParser.parse(
                "hysteria://hy.example:443?obfs=xplus&obfsParam=%20");
        assertEquals(" ", hysteriaObfs.outbound.getString("obfs"));

        ProtocolParser.Node hysteria2 = ProtocolParser.parse(
                "hysteria2://%20@hy2.example:443"
                        + "?obfs=salamander&obfs-password=%20");
        assertEquals(" ", hysteria2.outbound.getString("password"));
        assertEquals(" ", hysteria2.outbound.getJSONObject("obfs")
                .getString("password"));

        ProtocolParser.Node tuic = ProtocolParser.parse(
                "tuic://33333333-3333-3333-3333-333333333333:%20"
                        + "@tuic.example:443");
        assertEquals(" ", tuic.outbound.getString("password"));

        ProtocolParser.Node mkcp = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@mkcp.example:443"
                        + "?type=mkcp&seed=%20");
        assertEquals(" ", mkcp.outbound.getJSONObject("transport")
                .getString("legacy_seed"));
        assertEquals(" ", XrayConfigRenderer.renderOutbound(mkcp.outbound)
                .getJSONObject("streamSettings").getJSONObject("finalmask")
                .getJSONArray("udp").getJSONObject(0).getJSONObject("settings")
                .getString("value"));
    }

    @Test
    public void rejectsMalformedVmessAlterIdInsteadOfDowngradingToZero() throws Exception {
        JSONObject value = new JSONObject().put("v", "2").put("add", "vm.example")
                .put("port", 443).put("id", "16161616-1616-1616-1616-161616161616")
                .put("aid", "garbage").put("scy", "auto").put("net", "tcp");
        try {
            ProtocolParser.parse(vmessUri(value));
            throw new AssertionError("malformed VMess aid was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("aid"));
        }

        value.put("aid", "0");
        assertEquals(0, ProtocolParser.parse(vmessUri(value))
                .outbound.getInt("alter_id"));
    }

    @Test
    public void rejectsNonScalarLegacyVmessFieldsBeforeStringCoercion() throws Exception {
        JSONObject baseline = new JSONObject().put("v", "2").put("add", "vm.example")
                .put("port", 443).put("id", "16161616-1616-1616-1616-161616161616")
                .put("aid", 0).put("scy", "auto").put("net", "ws");
        Object[][] invalid = new Object[][]{
                {"path", new JSONArray().put("/ws")},
                {"host", new JSONObject().put("value", "edge.example")},
                {"sni", new JSONArray().put("edge.example")},
                {"fp", new JSONObject().put("value", "chrome")},
                {"headers", new JSONArray().put("Host")},
                {"port", new JSONObject().put("value", 443)},
                {"insecure", new JSONArray().put(true)},
        };
        for (Object[] entry : invalid) {
            JSONObject value = new JSONObject(baseline.toString()).put((String) entry[0], entry[1]);
            try {
                ProtocolParser.parse(vmessUri(value));
                throw new AssertionError("non-scalar VMess field accepted: " + entry[0]);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("VMess"));
            }
        }
    }

    @Test
    public void hysteriaRejectsConflictingCredentialBandwidthAndSniAliases() throws Exception {
        for (String uri : new String[]{
                "hysteria://userinfo@hy.example:443?auth=query",
                "hysteria://hy.example:443?auth=one&auth_str=two",
                "hysteria://auth@hy.example:443?upmbps=10&up=20",
                "hysteria://auth@hy.example:443?downmbps=10&down=20",
                "hysteria://auth@hy.example:443?sni=one.example&peer=two.example",
        }) {
            try {
                ProtocolParser.parse(uri);
                throw new AssertionError("conflicting Hysteria aliases accepted: " + uri);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("Hysteria"));
            }
        }
    }

    @Test
    public void grpcRejectsConflictingServiceAliasesEvenWhenOneIsEmpty() throws Exception {
        String base = "vless://11111111-1111-1111-1111-111111111111"
                + "@grpc.example:443?security=tls&type=grpc";
        for (String aliases : new String[]{
                "&serviceName=svc-a&path=svc-b",
                "&path=svc-b&serviceName=svc-a",
                "&serviceName=&path=svc-b",
                "&path=&serviceName=svc-a",
        }) {
            try {
                ProtocolParser.parse(base + aliases);
                throw new AssertionError("conflicting gRPC aliases accepted: " + aliases);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("gRPC"));
            }
        }
    }

    @Test
    public void forcedTlsAndHysteria2OptionsCannotBeSilentlyDropped() throws Exception {
        for (String invalid : new String[]{
                "hysteria://auth@hy.example:443?security=none",
                "hysteria2://password@hy2.example:443?security=none",
                "tuic://17171717-1717-1717-1717-171717171717:password"
                        + "@tuic.example:443?security=none",
                "hysteria2://password@hy2.example:443?hop_interval=10s",
                "hysteria2://password@hy2.example:443?obfs-password=cover",
        }) {
            try {
                ProtocolParser.parse(invalid);
                throw new AssertionError("functional Hysteria option was dropped: " + invalid);
            } catch (IllegalArgumentException expected) {
                assertNotNull(expected.getMessage());
            }
        }
    }

    @Test
    public void storedWrongTypeOutboundCannotFallBackToUri() throws Exception {
        JSONObject stored = new JSONObject()
                .put("uri", "vless://11111111-1111-1111-1111-111111111111"
                        + "@fallback.example:443?security=tls")
                .put("outbound", "garbage");
        try {
            ProtocolParser.fromStoredJson(stored);
            throw new AssertionError("malformed stored outbound fell back to URI");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("invalid type"));
        }
    }

    @Test
    public void storedStructuredNodeStillBoundsOptionalUri() throws Exception {
        JSONObject outbound = ProtocolParser.parse(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443")
                .outbound;
        JSONObject atLimit = new JSONObject().put("uri", repeat('u', 16 * 1024))
                .put("name", "stored").put("outbound", outbound);
        assertEquals(16 * 1024, ProtocolParser.fromStoredJson(atLimit).uri.length());
        try {
            ProtocolParser.fromStoredJson(new JSONObject(atLimit.toString())
                    .put("uri", repeat('u', 16 * 1024 + 1)));
            throw new AssertionError("oversized optional stored URI accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("16 KiB"));
        }
    }

    private static void assertStoredOutboundRejected(JSONObject outbound) throws Exception {
        JSONObject stored = new JSONObject()
                .put("uri", "")
                .put("name", "corrupted")
                .put("outbound", outbound);
        try {
            ProtocolParser.fromStoredJson(stored);
            throw new AssertionError("corrupted neutral outbound accepted: " + outbound);
        } catch (IllegalArgumentException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    private static void assertJsonDepthRejected(String uri) throws Exception {
        try {
            ProtocolParser.parse(uri);
            throw new AssertionError("deep JSON was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("JSON nesting"));
        }
    }

    private static String vmessUri(JSONObject value) {
        return "vmess://" + Base64.getEncoder().encodeToString(
                value.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String validVlessEncryption(int keyBytes) {
        return "mlkem768x25519plus.native.0rtt." + rawUrlKey(keyBytes);
    }

    private static String realityPublicKey() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
    }

    private static String shadowsocksUri(String method, String password) {
        String credentials = Base64.getUrlEncoder().withoutPadding().encodeToString(
                (method + ":" + password).getBytes(StandardCharsets.UTF_8));
        return "ss://" + credentials + "@ss.example:443";
    }

    private static void assertUriRejected(String uri, String expectedMessage)
            throws Exception {
        try {
            ProtocolParser.parse(uri);
            throw new AssertionError("invalid proxy URI accepted: " + uri);
        } catch (IllegalArgumentException expected) {
            assertTrue("unexpected error: " + expected.getMessage(),
                    expected.getMessage() != null
                            && expected.getMessage().toLowerCase(java.util.Locale.US)
                            .contains(expectedMessage.toLowerCase(java.util.Locale.US)));
        }
    }

    private static String rawUrlKey(int decodedBytes) {
        int encodedLength = (decodedBytes * 8 + 5) / 6;
        return repeat('A', encodedLength);
    }

    private static void assertXraySelectionAndRendererReject(
            ProtocolParser.Node node) throws Exception {
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(node, null, false, false));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(node, CoreFamily.XRAY, false, true));
        try {
            XrayConfigRenderer.renderOutbound(node.outbound);
            throw new AssertionError("Xray renderer emitted incompatible field");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Xray"));
        }
    }

    private static String xhttpUri(JSONObject extra) throws Exception {
        return "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                + "?security=tls&type=xhttp&mode=packet-up&extra="
                + URLEncoder.encode(extra.toString(), "UTF-8").replace("+", "%20");
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int i = 0; i < count; i++) result.append(value);
        return result.toString();
    }
    @Test
    public void placeholderEntriesNeverBecomeServers() throws Exception {
        // A subscription that does not recognise the client answers with
        // entries whose names carry a message and whose address cannot be
        // dialled. Counting those would report servers that never connect.
        String uuid = "00000000-0000-0000-0000-000000000000";
        for (String host : new String[]{"0.0.0.0", "[::]"}) {
            String uri = "vless://" + uuid + "@" + host
                    + ":1?encryption=none&type=tcp&security=none#unsupported";
            try {
                ProtocolParser.parse(uri);
                throw new AssertionError("placeholder accepted: " + host);
            } catch (IllegalArgumentException expected) {
                assertEquals(ProtocolParser.UNREACHABLE_SERVER, expected.getMessage());
            }
        }

        // Loopback stays usable: a hand-written node may point at a local proxy.
        assertFalse(ProtocolParser.isUnreachableServer("127.0.0.1"));
        assertFalse(ProtocolParser.isUnreachableServer("localhost"));
        assertFalse(ProtocolParser.isUnreachableServer("example.invalid"));
        assertTrue(ProtocolParser.isUnreachableServer("0.0.0.0"));
        assertTrue(ProtocolParser.isUnreachableServer("  ::  "));
    }


    @Test
    public void realWorldXhttpAndGrpcOptionsStayUsable() throws Exception {
        // Shapes taken from a live subscription. Padding, sequence and session
        // options are named by the source, not by us, so rejecting an unknown
        // one discarded every server the source offered.
        ProtocolParser.Node xhttp = ProtocolParser.parse("vless://00000000-0000-0000-0000-000000000000@example.invalid:443?encryption=none&security=tls&sni=a.invalid&fp=firefox&type=xhttp&mode=packet-up&path=%2Fp&host=a.invalid&extra=%7B%22seqKey%22%3A%22offset%22%2C%22noSSEHeader%22%3Afalse%2C%22xPaddingKey%22%3A%22q%22%2C%22seqPlacement%22%3A%22query%22%2C%22sessionIDKey%22%3A%22sid%22%2C%22xPaddingBytes%22%3A%2248-256%22%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22uplinkHTTPMethod%22%3A%22DELETE%22%2C%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingPlacement%22%3A%22query%22%2C%22scMaxEachPostBytes%22%3A4000000%2C%22sessionIDPlacement%22%3A%22query%22%2C%22scMinPostsIntervalMs%22%3A0%2C%22serverMaxHeaderBytes%22%3A8192%7D#node");
        assertTrue(xhttp.supports(CoreFamily.XRAY));

        // "gun" is the plain gRPC mode subscriptions state explicitly.
        ProtocolParser.Node grpc = ProtocolParser.parse("vless://00000000-0000-0000-0000-000000000000@example.invalid:443?encryption=none&security=reality&sni=a.invalid&fp=firefox&type=grpc&mode=gun&serviceName=%2F&pbk=Zo1uT3ivgn6XzVcv2BnGyyU1BjWWB3DcV5vTuwo8SEY&sid=b2a8c903ef11d56a#node");
        assertTrue(grpc.supports(CoreFamily.XRAY));

        // Multiplexed gRPC is a different transport, and Xray is the core
        // that has it. It used to be refused outright, which threw away most
        // of a subscription that serves its servers this way.
        ProtocolParser.Node multi = ProtocolParser.parse("vless://00000000-0000-0000-0000-000000000000@example.invalid:443?encryption=none&security=reality&sni=a.invalid&fp=firefox&type=grpc&mode=gun&serviceName=%2F&pbk=Zo1uT3ivgn6XzVcv2BnGyyU1BjWWB3DcV5vTuwo8SEY&sid=b2a8c903ef11d56a#node".replace("mode=gun", "mode=multi"));
        assertTrue(multi.supports(CoreFamily.XRAY));
        assertFalse(multi.supports(CoreFamily.SING_BOX));

        // A mode neither core implements still is refused.
        try {
            ProtocolParser.parse("vless://00000000-0000-0000-0000-000000000000@example.invalid:443?encryption=none&security=reality&sni=a.invalid&fp=firefox&type=grpc&mode=gun&serviceName=%2F&pbk=Zo1uT3ivgn6XzVcv2BnGyyU1BjWWB3DcV5vTuwo8SEY&sid=b2a8c903ef11d56a#node".replace("mode=gun", "mode=whatever"));
            throw new AssertionError("an unknown gRPC mode was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("gRPC transport mode"));
        }
    }

    @Test
    public void xhttpExtraStillRejectsNestedAndOversizedValues() {
        String base = "vless://00000000-0000-0000-0000-000000000000@example.invalid:443?"
                + "encryption=none&security=tls&sni=a.invalid&type=xhttp&mode=auto&path=%2Fp&extra=";
        StringBuilder oversized = new StringBuilder();
        for (int index = 0; index < 300; index++) oversized.append('x');
        String[] rejected = {
                "{\"nested\":{\"a\":1}}",
                "{\"listed\":[1,2]}",
                "{\"long\":\"" + oversized + "\"}",
        };
        for (String extra : rejected) {
            try {
                ProtocolParser.parse(base + java.net.URLEncoder.encode(extra, "UTF-8"));
                throw new AssertionError("accepted unsafe XHTTP extra: " + extra);
            } catch (Exception expected) {
                assertTrue(expected.getMessage().toLowerCase().contains("xhttp"));
            }
        }
    }
}
