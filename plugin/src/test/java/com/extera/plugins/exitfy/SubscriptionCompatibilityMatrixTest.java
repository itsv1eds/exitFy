package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import static org.junit.Assert.*;

/** Public protocol/schema examples only; no provider responses or credentials. */
@RunWith(Parameterized.class)
public class SubscriptionCompatibilityMatrixTest {
    static final String ID = "11111111-1111-4111-8111-111111111111";
    static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);
    static final String REALITY = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
    private final String body;

    public SubscriptionCompatibilityMatrixTest(String label, String body) { this.body = body; }

    @Parameterized.Parameters(name = "{0}")
    public static List<Object[]> samples() throws Exception {
        List<Object[]> values = new ArrayList<>();
        String base = "vless://" + ID + "@example.org:443?";
        String[] links = {
                base + "security=tls#TCP-TLS",
                base + "security=reality&pbk=" + REALITY + "&sid=0123&fp=chrome#Reality",
                base + "security=tls&type=ws&path=%2Fws&host=cdn.example.org#WebSocket",
                base + "security=tls&type=grpc&serviceName=tunnel&mode=gun#gRPC",
                base + "security=tls&type=grpc&serviceName=tunnel&mode=multi#gRPC-multi",
                base + "security=tls&type=httpupgrade&path=%2Fupgrade#HTTPUpgrade",
                base + "security=tls&type=h2&path=%2Fh2#HTTP2",
                base + "security=tls&type=xhttp&mode=auto&path=%2Fx&extra=" + enc("{\"xmux\":{\"maxConcurrency\":\"4-8\"}}") + "#XHTTP-xmux",
                base + "security=tls&type=splithttp&path=%2Fx#SplitHTTP",
                "vless://" + ID + "@192.168.56.1:8443?type=kcp#KCP",
                "vmess://" + b64(new JSONObject().put("add", "example.org").put("port", 443).put("id", ID)
                        .put("aid", 0).put("scy", "auto").put("net", "ws").put("path", "/ws").put("tls", "tls").put("ps", "VMess").toString()),
                "trojan://pass%2Bword@example.org:443?sni=example.org#Trojan",
                "ss://" + b64("aes-128-gcm:pass+word") + "@example.org:8443#SS-SIP002",
                "ss://" + b64("aes-128-gcm:pass+word@example.org:8443") + "#SS-legacy",
                "ss://" + b64("2022-blake3-aes-128-gcm:" + Base64.getEncoder().encodeToString(new byte[16])) + "@example.org:8443#SS2022",
                "hysteria://auth@example.org:443?upmbps=10&downmbps=50#Hysteria1",
                "hy2://pass%2Bword@example.org/?sni=example.org#HY2-default-port",
                "hysteria2://pass@[2001:db8::1]:443,8443-8445?obfs=salamander&obfs-password=obfs&hop-interval=30s#HY2-hopping",
                "tuic://" + ID + ":pass@[2001:db8::1]:443?congestion_control=bbr&udp_relay_mode=quic#TUIC",
                "socks5://user:p%2Bss@example.org:1080#SOCKS-auth",
                "socks://example.org:1080#SOCKS-open",
                "http://user:pass@example.org:8080#HTTP",
                "https://user:pass@example.org:8443?sni=example.org#HTTPS",
                "wireguard://" + enc(KEY) + "@example.org:51820?publickey=" + enc(KEY) + "&address=10.0.0.2%2F32&reserved=1,2,3#WireGuard",
                "anytls://pass%2Bword@example.org/?sni=example.org#AnyTLS",
                "anytls://pass@[2001:db8::1]:8443/?insecure=1#AnyTLS-IPv6",
                "anytls://example.org/?sni=example.org#AnyTLS-no-auth"
        };
        for (int i = 0; i < links.length; i++) {
            values.add(new Object[]{"URI-" + i, links[i]});
            values.add(new Object[]{"Base64-" + i, b64(links[i])});
        }
        JSONObject tls = new JSONObject().put("enabled", true);
        for (String type : new String[]{"hysteria", "hysteria2", "tuic", "socks", "http", "anytls"}) {
            JSONObject proxy = endpoint(type).put("tag", "server-" + type);
            if (!type.equals("socks") && !type.equals("http")) proxy.put("tls", new JSONObject(tls.toString()));
            if (type.equals("hysteria")) proxy.put("auth_str", "pass").put("up_mbps", 10).put("down_mbps", 50);
            else if (type.equals("tuic")) proxy.put("uuid", ID).put("password", "pass").put("zero_rtt_handshake", true).put("heartbeat", "10s");
            else if (!type.equals("socks") && !type.equals("http")) proxy.put("password", "pass");
            values.add(new Object[]{"sing-box-" + type, new JSONObject().put("outbounds", new JSONArray().put(proxy)).toString()});
        }
        JSONObject hopping = endpoint("hysteria2").put("password", "pass").put("tls", new JSONObject(tls.toString()))
                .put("server_ports", new JSONArray().put("443").put("8443:8445")).put("hop_interval", "30s").put("up_mbps", 0);
        hopping.remove("server_port");
        values.add(new Object[]{"sing-box-hopping", hopping.toString()});
        values.add(new Object[]{"sing-box-http-options", endpoint("http").put("username", "user").put("password", "pass")
                .put("tls", new JSONObject(tls.toString())).put("path", "/connect").put("headers", new JSONObject().put("X-Proxy", new JSONArray().put("one").put("two"))).toString()});
        values.add(new Object[]{"sing-box-socks-uot", endpoint("socks").put("version", "4a").put("udp_over_tcp", new JSONObject().put("enabled", true).put("version", 2)).toString()});
        for (String type : new String[]{"vless", "vmess", "trojan", "shadowsocks"}) {
            JSONObject proxy = endpoint(type).put("multiplex", new JSONObject().put("enabled", true).put("protocol", "h2mux").put("max_connections", 2).put("padding", true));
            if (type.equals("vless") || type.equals("vmess")) proxy.put("uuid", ID);
            else proxy.put("password", "pass");
            if (type.equals("shadowsocks")) proxy.put("method", "aes-128-gcm");
            else proxy.put("tls", new JSONObject(tls.toString()));
            values.add(new Object[]{"sing-box-multiplex-" + type, proxy.toString()});
        }
        JSONObject wg = new JSONObject().put("type", "wireguard").put("tag", "WG-current").put("private_key", KEY)
                .put("address", new JSONArray().put("10.0.0.2/32")).put("peers", new JSONArray().put(new JSONObject()
                        .put("address", "example.org").put("port", 51820).put("public_key", KEY)
                        .put("allowed_ips", new JSONArray().put("0.0.0.0/0").put("::/0"))
                        .put("persistent_keepalive_interval", 25).put("reserved", new JSONArray().put(1).put(2).put(3))));
        values.add(new Object[]{"WireGuard-endpoint", new JSONObject().put("endpoints", new JSONArray().put(wg)).toString()});
        values.add(new Object[]{"WireGuard-legacy", new JSONObject().put("type", "wireguard").put("server", "example.org").put("server_port", 51820)
                .put("private_key", KEY).put("peer_public_key", KEY).put("local_address", new JSONArray().put("10.0.0.2/32")).toString()});
        for (String type : new String[]{"vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "tuic", "socks5", "http"}) {
            String yaml = "proxies:\n  - name: YAML-" + type + "\n    type: " + type + "\n    server: example.org\n    port: 443\n";
            if (type.equals("vless") || type.equals("vmess") || type.equals("tuic")) yaml += "    uuid: " + ID + "\n";
            if (type.equals("vless") || type.equals("vmess")) yaml += "    tls: true\n";
            if (type.equals("ss")) yaml += "    cipher: aes-128-gcm\n";
            if (type.equals("hysteria")) yaml += "    auth-str: pass\n    up: 10\n    down: 50\n";
            else if (!type.equals("vless") && !type.equals("vmess") && !type.equals("socks5") && !type.equals("http")) yaml += "    password: pass\n";
            values.add(new Object[]{"Clash-" + type, yaml});
        }
        return values;
    }

    @Test public void everySupportedExampleSurvivesImportStorageAndRendering() throws Exception {
        SubscriptionParser.ParseResult result = SubscriptionParser.parseDetailed(body);
        assertEquals("rejections=" + result.reasons, 0, result.rejected);
        assertEquals(1, result.nodes.size());
        ProtocolParser.Node before = result.nodes.get(0);
        ProtocolParser.Node node = ProtocolParser.fromStoredJson(new JSONObject(before.toStoredJson().toString()));
        assertEquals(before.name, node.name);
        assertEquals(before.normalizedKey, node.normalizedKey);
        assertTrue(node.supports(CoreFamily.XRAY) || node.supports(CoreFamily.SING_BOX));
        if (node.supports(CoreFamily.XRAY)) assertEquals(23147, XrayConfigRenderer.build(node, 23147, "user", "pass").getJSONArray("inbounds").getJSONObject(0).getInt("port"));
        if (node.supports(CoreFamily.SING_BOX)) assertEquals(23147, ProtocolParser.buildConfig(node, 23147, "user", "pass").getJSONArray("inbounds").getJSONObject(0).getInt("listen_port"));
    }

    static JSONObject endpoint(String type) throws Exception { return new JSONObject().put("type", type).put("server", "example.org").put("server_port", 443); }
    static String enc(String text) { return URLEncoder.encode(text, StandardCharsets.UTF_8).replace("+", "%20"); }
    static String b64(String text) { return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)); }
}
