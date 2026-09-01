package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

final class XrayConfigRenderer {
    private XrayConfigRenderer() {
    }

    static JSONObject build(ProtocolParser.Node node, int localPort,
                            String username, String password) throws Exception {
        if (node == null) throw new IllegalArgumentException("node is missing");
        if (node.xrayOutbound != null) {
            if (!node.supports(CoreFamily.XRAY)) {
                throw new IllegalArgumentException("node is not representable by Xray");
            }
            if (localPort <= 0 || localPort > 65535) {
                throw new IllegalArgumentException("invalid local SOCKS port");
            }
            JSONObject inbound = socksInbound(localPort, username, password);
            JSONObject outbound = renderOutbound(node).put("tag", "proxy");
            return new JSONObject()
                    .put("log", new JSONObject().put("loglevel", "none"))
                    .put("inbounds", new JSONArray().put(inbound))
                    .put("outbounds", new JSONArray().put(outbound));
        }
        ProtocolParser.validateNeutralOutbound(node.outbound);
        if (!node.supports(CoreFamily.XRAY)) {
            throw new IllegalArgumentException("node is not representable by Xray");
        }
        if (localPort <= 0 || localPort > 65535) {
            throw new IllegalArgumentException("invalid local SOCKS port");
        }

        JSONObject inbound = socksInbound(localPort, username, password);

        JSONObject outbound = renderOutbound(node.outbound).put("tag", "proxy");
        return new JSONObject()
                .put("log", new JSONObject().put("loglevel", "none"))
                .put("inbounds", new JSONArray().put(inbound))
                // There is deliberately no freedom/direct outbound. A failed
                // proxy configuration must never become a direct connection.
                .put("outbounds", new JSONArray().put(outbound));
    }

    static JSONObject renderOutbound(ProtocolParser.Node node) throws Exception {
        if (node == null) throw new IllegalArgumentException("node is missing");
        if (node.xrayOutbound != null) {
            return XrayNativeOutbound.runtimeOutbound(node.xrayOutbound, "proxy");
        }
        return renderOutbound(node.outbound);
    }

    private static JSONObject socksInbound(int localPort, String username, String password)
            throws Exception {
        JSONObject inboundSettings = new JSONObject().put("udp", true);
        if (!empty(username) && !empty(password)) {
            inboundSettings.put("auth", "password")
                    .put("accounts", new JSONArray().put(new JSONObject()
                            .put("user", username).put("pass", password)));
        } else {
            inboundSettings.put("auth", "noauth");
        }
        return new JSONObject()
                .put("tag", "socks-in")
                .put("listen", "127.0.0.1")
                .put("port", localPort)
                .put("protocol", "socks")
                .put("settings", inboundSettings);
    }

    static JSONObject renderOutbound(JSONObject source) throws Exception {
        ProtocolParser.validateNeutralOutbound(source);
        String incompatibility = ProtocolParser.incompatibilityReason(
                source, CoreFamily.XRAY);
        if (!incompatibility.isEmpty()) {
            throw new IllegalArgumentException("Xray incompatibility: " + incompatibility);
        }
        String protocol = source.optString("type", "");
        JSONObject settings = new JSONObject();
        if (protocol.equals("vless") || protocol.equals("vmess")) {
            JSONObject user = new JSONObject().put("id", require(source, "uuid"));
            if (protocol.equals("vless")) {
                user.put("encryption", source.optString("encryption", "none"));
                putIfNotEmpty(user, "flow", source.optString("flow", ""));
            } else {
                user.put("security", source.optString("security", "auto"));
            }
            settings.put("vnext", new JSONArray().put(new JSONObject()
                    .put("address", require(source, "server"))
                    .put("port", requirePort(source.optInt("server_port", 0)))
                    .put("users", new JSONArray().put(user))));
        } else if (protocol.equals("trojan")) {
            JSONObject server = new JSONObject()
                    .put("address", require(source, "server"))
                    .put("port", requirePort(source.optInt("server_port", 0)))
                    .put("password", require(source, "password"));
            putIfNotEmpty(server, "flow", source.optString("flow", ""));
            settings.put("servers", new JSONArray().put(server));
        } else if (protocol.equals("shadowsocks")) {
            settings.put("servers", new JSONArray().put(new JSONObject()
                    .put("address", require(source, "server"))
                    .put("port", requirePort(source.optInt("server_port", 0)))
                    .put("method", require(source, "method"))
                    .put("password", require(source, "password"))));
        } else {
            throw new IllegalArgumentException("unsupported Xray protocol: " + protocol);
        }

        JSONObject result = new JSONObject().put("protocol", protocol).put("settings", settings);
        JSONObject stream = renderStream(source);
        if (stream.length() > 0) result.put("streamSettings", stream);
        return result;
    }

    private static JSONObject renderStream(JSONObject source) throws Exception {
        JSONObject stream = new JSONObject();
        JSONObject transport = source.optJSONObject("transport");
        String network = transport == null ? "raw" : transport.optString("type", "raw");
        stream.put("network", network);

        if (network.equals("ws")) {
            String path = transport.optString("path", "/");
            if (transport.has("max_early_data")) {
                String earlyMode = transport.optString(
                        ProtocolParser.WS_EARLY_DATA_MODE, "");
                String earlyHeader = transport.optString("early_data_header_name", "");
                boolean xrayCompatible = ProtocolParser.WS_EARLY_DATA_XRAY_PATH
                        .equals(earlyMode) || ProtocolParser.WS_EARLY_DATA_XRAY_HEADER
                        .equalsIgnoreCase(earlyHeader);
                if (!xrayCompatible) {
                    throw new IllegalArgumentException(
                            "Xray cannot represent this WebSocket early-data mode");
                }
                path = appendQuery(path, "ed", String.valueOf(
                        transport.optLong("max_early_data", 0)));
            }
            JSONObject settings = new JSONObject().put("path", path);
            JSONObject headers = transport.optJSONObject("headers");
            if (headers != null && headers.length() > 0) {
                settings.put("headers", xrayHeaders(headers));
            }
            stream.put("wsSettings", settings);
        } else if (network.equals("grpc")) {
            JSONObject settings = new JSONObject()
                    .put("serviceName", transport.optString("service_name", ""));
            if (transport.optBoolean(ProtocolParser.GRPC_MULTI_MODE, false)) {
                settings.put("multiMode", true);
            }
            stream.put("grpcSettings", settings);
        } else if (network.equals("httpupgrade")) {
            String path = transport.optString("path", "/");
            if (transport.has("max_early_data")) {
                path = appendQuery(path, "ed", String.valueOf(
                        transport.optLong("max_early_data", 0)));
            }
            JSONObject settings = new JSONObject().put("path", path);
            putIfNotEmpty(settings, "host", transport.optString("host", ""));
            JSONObject headers = transport.optJSONObject("headers");
            if (headers != null && headers.length() > 0) {
                settings.put("headers", xrayHeaders(headers));
            }
            stream.put("httpupgradeSettings", settings);
        } else if (network.equals("xhttp")) {
            JSONObject settings = new JSONObject()
                    .put("path", transport.optString("path", "/"))
                    .put("mode", transport.optString("mode", "auto"));
            putIfNotEmpty(settings, "host", transport.optString("host", ""));
            JSONObject extra = transport.optJSONObject("extra");
            if (extra != null) {
                ProtocolParser.validateXhttpExtra(extra);
                settings.put("extra", new JSONObject(extra.toString()));
            }
            stream.put("xhttpSettings", settings);
        } else if (network.equals("mkcp")) {
            JSONObject settings = new JSONObject();
            copyNumber(transport, settings, "mtu", "mtu");
            copyNumber(transport, settings, "tti", "tti");
            copyNumber(transport, settings, "uplink_capacity", "uplinkCapacity");
            copyNumber(transport, settings, "downlink_capacity", "downlinkCapacity");
            copyNumber(transport, settings, "cwnd_multiplier", "cwndMultiplier");
            copyNumber(transport, settings, "max_sending_window", "maxSendingWindow");
            stream.put("kcpSettings", settings);
            String legacyHeader = transport.optString("legacy_header", "");
            String legacySeed = transport.optString("legacy_seed", "");
            if (!legacyHeader.isEmpty() || !legacySeed.isEmpty()) {
                JSONArray masks = new JSONArray();
                // Finalmask applies the chain in reverse order. Put the AES
                // seed mask first and the legacy packet header second so the
                // resulting wire format remains [header][nonce][ciphertext].
                if (!legacySeed.isEmpty()) {
                    masks.put(new JSONObject().put("type", "mkcp-legacy")
                            .put("settings", new JSONObject().put("value", legacySeed)));
                }
                if (!legacyHeader.isEmpty()) {
                    masks.put(new JSONObject().put("type", "mkcp-legacy")
                            .put("settings", new JSONObject().put("header", legacyHeader)));
                }
                stream.put("finalmask", new JSONObject().put("udp", masks));
            }
        } else if (!network.equals("raw")) {
            throw new IllegalArgumentException("unsupported Xray transport: " + network);
        }

        JSONObject tls = source.optJSONObject("tls");
        if (tls != null && tls.optBoolean("enabled", false)) {
            JSONObject reality = tls.optJSONObject("reality");
            boolean isReality = reality != null && reality.optBoolean("enabled", false);
            stream.put("security", isReality ? "reality" : "tls");
            JSONObject target = new JSONObject()
                    .put("serverName", tls.optString("server_name", ""))
                    .put("allowInsecure", tls.optBoolean("insecure", false));
            JSONArray alpn = tls.optJSONArray("alpn");
            if (alpn != null && alpn.length() > 0) target.put("alpn", new JSONArray(alpn.toString()));
            JSONObject utls = tls.optJSONObject("utls");
            if (utls != null && utls.optBoolean("enabled", false)) {
                putIfNotEmpty(target, "fingerprint", utls.optString("fingerprint", ""));
            }
            if (isReality) {
                target.put("publicKey", require(reality, "public_key"));
                putIfNotEmpty(target, "shortId", reality.optString("short_id", ""));
                putIfNotEmpty(target, "spiderX", reality.optString("spider_x", ""));
                stream.put("realitySettings", target);
            } else {
                stream.put("tlsSettings", target);
            }
        }
        return stream;
    }

    private static void copyNumber(JSONObject source, JSONObject target,
                                   String sourceKey, String targetKey) throws Exception {
        if (source.has(sourceKey)) target.put(targetKey, source.get(sourceKey));
    }

    private static JSONObject xrayHeaders(JSONObject source) throws Exception {
        JSONObject output = new JSONObject();
        java.util.Iterator<String> keys = source.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object raw = source.opt(key);
            if (raw instanceof String) {
                output.put(key, raw);
            } else if (raw instanceof JSONArray && ((JSONArray) raw).length() == 1
                    && ((JSONArray) raw).opt(0) instanceof String) {
                output.put(key, ((JSONArray) raw).optString(0));
            } else {
                throw new IllegalArgumentException("Xray header value is not singular");
            }
        }
        return output;
    }

    private static String appendQuery(String path, String key, String value) {
        String base = path == null || path.isEmpty() ? "/" : path;
        int fragment = base.indexOf('#');
        String suffix = fragment < 0 ? "" : base.substring(fragment);
        String beforeFragment = fragment < 0 ? base : base.substring(0, fragment);
        return beforeFragment + (beforeFragment.contains("?") ? "&" : "?")
                + key + "=" + value + suffix;
    }

    private static String require(JSONObject value, String key) {
        Object raw = value.opt(key);
        if (!(raw instanceof String)) {
            throw new IllegalArgumentException(key + " is missing");
        }
        String result = (String) raw;
        if (result.isEmpty()) throw new IllegalArgumentException(key + " is missing");
        return result;
    }

    private static int requirePort(int port) {
        if (port <= 0 || port > 65535) throw new IllegalArgumentException("invalid proxy port");
        return port;
    }

    private static void putIfNotEmpty(JSONObject target, String key, String value) throws Exception {
        if (!empty(value)) target.put(key, value);
    }

    private static boolean empty(String value) {
        return value == null || value.trim().isEmpty();
    }
}
