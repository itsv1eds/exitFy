package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.BitSet;
import java.util.Collections;
import java.util.Iterator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

final class ProtocolParser {
    static final int MAX_URI_BYTES = 16 * 1024;
    // A port can occur at most once. This caps the core's expanded []uint16
    // allocation to the complete valid port space instead of allowing many
    // overlapping 1-65535 ranges to multiply it without bound.
    private static final int MAX_HYSTERIA2_EXPANDED_PORTS = 65535;
    // Keep untrusted subscription rates bounded before sing-box multiplies the
    // Mbps value by 125000. The limit is deliberately conservative and remains
    // far above practical link rates; it is not an Android word-size fallback.
    static final int MAX_HYSTERIA2_MBPS = Integer.MAX_VALUE / 125_000;
    static final String XRAY_INSECURE_TLS_UNSUPPORTED = "xray_insecure_tls_unsupported";
    static final String XRAY_VMESS_ALTER_ID_UNSUPPORTED =
            "xray_vmess_alter_id_unsupported";
    static final String XRAY_SHADOWSOCKS_METHOD_UNSUPPORTED =
            "xray_shadowsocks_method_unsupported";
    static final String SING_BOX_SHADOWSOCKS_METHOD_UNSUPPORTED =
            "sing_box_shadowsocks_method_unsupported";
    static final String SING_BOX_SHADOWSOCKS_PASSWORD_UNSUPPORTED =
            "sing_box_shadowsocks_password_unsupported";
    static final String XRAY_SHADOWSOCKS_PASSWORD_UNSUPPORTED =
            "xray_shadowsocks_password_unsupported";
    static final String XRAY_UTLS_FINGERPRINT_UNSUPPORTED =
            "xray_utls_fingerprint_unsupported";
    static final String SING_BOX_UTLS_FINGERPRINT_UNSUPPORTED =
            "sing_box_utls_fingerprint_unsupported";
    static final String XRAY_USER_ID_UNSUPPORTED = "xray_user_id_unsupported";
    static final String SING_BOX_VLESS_FLOW_UNSUPPORTED =
            "sing_box_vless_flow_unsupported";
    static final String XRAY_VLESS_PACKET_ENCODING_UNSUPPORTED =
            "xray_vless_packet_encoding_unsupported";
    static final String SING_BOX_HTTP_UPGRADE_EARLY_DATA_UNSUPPORTED =
            "sing_box_http_upgrade_early_data_unsupported";
    static final String SING_BOX_XRAY_WS_PATH_UNSUPPORTED =
            "sing_box_xray_ws_path_unsupported";
    static final String VLESS_ENCRYPTION_UNSUPPORTED = "vless_encryption_unsupported";
    static final String WS_EARLY_DATA_MODE = "early_data_mode";
    static final String WS_EARLY_DATA_XRAY_PATH = "xray_path";
    static final String WS_EARLY_DATA_XRAY_HEADER = "Sec-WebSocket-Protocol";
    static final String WS_XRAY_PATH_SEMANTICS = "xray_path_semantics";
    static final String[] SCHEMES = {
            "vless://", "vmess://", "trojan://", "ss://", "hy2://",
            "hysteria2://", "hysteria://", "tuic://"
    };
    private static final String[] STREAM_PARAMS = {
            "security", "sni", "peer", "insecure", "allowInsecure", "allow_insecure",
            "alpn", "fp", "pbk", "sid", "spx", "type", "path", "host", "headers",
            "ed", "eh", "earlyDataHeaderName", "early_data_header_name", "serviceName",
            "mode", "extra", "headerType", "header_type", "header", "seed", "mtu",
            "tti", "uplinkCapacity", "uplink_capacity", "downlinkCapacity",
            "downlink_capacity", "cwndMultiplier", "cwnd_multiplier", "maxSendingWindow",
            "max_sending_window"
    };
    private static final java.util.regex.Pattern UUID = java.util.regex.Pattern.compile(
            "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    private ProtocolParser() {
    }

    static Node parse(String rawUri) throws Exception {
        if (utf8Exceeds(rawUri, MAX_URI_BYTES)) {
            throw new IllegalArgumentException("proxy URI exceeds 16 KiB");
        }
        return parseGenerated(rawUri, true);
    }

    static Node parseGeneratedBeforeCompatibility(String rawUri) throws Exception {
        return parseGenerated(rawUri, false);
    }

    private static Node parseGenerated(String rawUri, boolean requireCoreSupport)
            throws Exception {
        String uri = sanitize(rawUri);
        String lower = uri.toLowerCase(Locale.US);
        JSONObject outbound;
        String name;
        if (lower.startsWith("vless://")) {
            Parsed parsed = parseStandard(uri);
            outbound = parseVless(parsed);
            name = parsed.name;
        } else if (lower.startsWith("vmess://")) {
            JSONObject source = JsonGuard.object(
                    decodeBase64Text(uri.substring(8).split("#", 2)[0]));
            validateVmessSource(source);
            outbound = parseVmess(source);
            name = cleanName(source.optString("ps", ""));
        } else if (lower.startsWith("trojan://")) {
            Parsed parsed = parseStandard(uri);
            outbound = parseTrojan(parsed);
            name = parsed.name;
        } else if (lower.startsWith("ss://")) {
            ParsedSs parsed = parseShadowsocks(uri);
            outbound = parsed.outbound;
            name = parsed.name;
        } else if (lower.startsWith("hy2://") || lower.startsWith("hysteria2://")) {
            Parsed parsed = parseHysteria2Standard(uri);
            outbound = parseHysteria2(parsed);
            name = parsed.name;
        } else if (lower.startsWith("hysteria://")) {
            Parsed parsed = parseStandard(uri);
            outbound = parseHysteria(parsed);
            name = parsed.name;
        } else if (lower.startsWith("tuic://")) {
            Parsed parsed = parseStandard(uri);
            outbound = parseTuic(parsed);
            name = parsed.name;
        } else {
            throw new IllegalArgumentException("unsupported proxy protocol");
        }
        normalizeNeutralOutbound(outbound);
        validateNeutralOutbound(outbound);
        String canonical = canonical(outbound);
        Node node = new Node(uri, cleanName(name), outbound, sha256(canonical));
        if (requireCoreSupport) requireSupported(node);
        return node;
    }

    static Node fromOutbound(String uri, String name, JSONObject outbound) throws Exception {
        if (outbound == null) throw new IllegalArgumentException("proxy outbound is missing");
        // Bound depth, structure and serialized size before JSONObject.toString()
        // creates the defensive copy used by normalization.
        AtomicStore.jsonUtf8Size(outbound, AtomicStore.MAX_JSON_BYTES);
        JSONObject normalized = new JSONObject(outbound.toString());
        AtomicStore.jsonUtf8Size(normalized, AtomicStore.MAX_JSON_BYTES);
        normalizeNeutralOutbound(normalized);
        validateNeutralOutbound(normalized);
        Node node = new Node(uri == null ? "" : uri, cleanName(name), normalized,
                sha256(canonical(normalized)));
        requireSupported(node);
        return node;
    }

    private static void requireSupported(Node node) {
        if (!node.supports(CoreFamily.SING_BOX) && !node.supports(CoreFamily.XRAY)) {
            String reason = node.incompatibilityReason(CoreFamily.XRAY);
            if (!reason.isEmpty()) {
                throw new IllegalArgumentException("Xray incompatibility: " + reason);
            }
            throw new IllegalArgumentException("node is not representable by a supported core");
        }
    }

    static String incompatibilityReason(JSONObject outbound, CoreFamily family) {
        if (outbound == null) return "neutral_outbound_missing";
        JSONObject tls = outbound.optJSONObject("tls");
        JSONObject reality = tls == null ? null : tls.optJSONObject("reality");
        boolean realityEnabled = reality != null && reality.optBoolean("enabled", false);
        JSONObject utls = tls == null ? null : tls.optJSONObject("utls");
        if (utls != null && utls.optBoolean("enabled", false)) {
            String fingerprint = utls.optString("fingerprint", "");
            if (family == CoreFamily.SING_BOX && !singBoxUtlsFingerprint(fingerprint)) {
                return SING_BOX_UTLS_FINGERPRINT_UNSUPPORTED;
            }
            if (family == CoreFamily.XRAY
                    && !xrayUtlsFingerprint(fingerprint, realityEnabled)) {
                return XRAY_UTLS_FINGERPRINT_UNSUPPORTED;
            }
        }
        String protocol = outbound.optString("type", "");
        if ((protocol.equals("vless") || protocol.equals("vmess"))
                && family == CoreFamily.XRAY
                && !xrayUserId(outbound.optString("uuid", ""))) {
            return XRAY_USER_ID_UNSUPPORTED;
        }
        if (protocol.equals("vless") && family == CoreFamily.SING_BOX
                && "xtls-rprx-vision-udp443".equals(outbound.optString("flow", ""))) {
            return SING_BOX_VLESS_FLOW_UNSUPPORTED;
        }
        if (protocol.equals("vless") && family == CoreFamily.XRAY
                && outbound.has("packet_encoding")
                && !"xudp".equalsIgnoreCase(outbound.optString("packet_encoding", ""))) {
            return XRAY_VLESS_PACKET_ENCODING_UNSUPPORTED;
        }
        if (protocol.equals("shadowsocks")) {
            String method = outbound.optString("method", "");
            if (family == CoreFamily.SING_BOX && !singBoxShadowsocksMethod(method)) {
                return SING_BOX_SHADOWSOCKS_METHOD_UNSUPPORTED;
            }
            if (family == CoreFamily.XRAY && !xrayShadowsocksMethod(method)) {
                return XRAY_SHADOWSOCKS_METHOD_UNSUPPORTED;
            }
            if (isShadowsocks2022(method)) {
                String password = outbound.optString("password", "");
                if (family == CoreFamily.SING_BOX
                        && !singBoxShadowsocks2022Password(method, password)) {
                    return SING_BOX_SHADOWSOCKS_PASSWORD_UNSUPPORTED;
                }
                if (family == CoreFamily.XRAY
                        && !xrayShadowsocks2022Password(method, password)) {
                    return XRAY_SHADOWSOCKS_PASSWORD_UNSUPPORTED;
                }
            }
        }
        if (family == CoreFamily.XRAY) {
            JSONObject transport = outbound.optJSONObject("transport");
            String transportType = transport == null ? ""
                    : transport.optString("type", "");
            if (tls != null && tls.optBoolean("enabled", false)
                    && tls.optBoolean("insecure", false)) {
                // Xray-core 50231eaff98c (the core pinned by libXray v26.7.11)
                // removed allowInsecure. Silently dropping it would change the
                // requested certificate policy, so this configuration is not
                // representable by Xray.
                return XRAY_INSECURE_TLS_UNSUPPORTED;
            }
            if (protocol.equals("vmess") && outbound.optInt("alter_id", 0) != 0) {
                // The pinned VMessAccount has no alterId field. Letting json.Unmarshal
                // ignore it would silently change the requested protocol.
                return XRAY_VMESS_ALTER_ID_UNSUPPORTED;
            }
        }
        if (family == CoreFamily.SING_BOX) {
            JSONObject transport = outbound.optJSONObject("transport");
            if (transport != null && "ws".equals(transport.optString("type", ""))
                    && transport.optBoolean(WS_XRAY_PATH_SEMANTICS, false)) {
                return SING_BOX_XRAY_WS_PATH_UNSUPPORTED;
            }
            if (transport != null && "httpupgrade".equals(
                    transport.optString("type", ""))
                    && transport.has("max_early_data")) {
                return SING_BOX_HTTP_UPGRADE_EARLY_DATA_UNSUPPORTED;
            }
        }
        return "";
    }

    static Node fromStoredJson(JSONObject value) throws Exception {
        if (value == null) throw new IllegalArgumentException("stored node is missing");
        Object rawUri = value.opt("uri");
        if (value.has("uri") && rawUri != JSONObject.NULL && !(rawUri instanceof String)) {
            throw new IllegalArgumentException("stored node URI must be a string");
        }
        String storedUri = rawUri instanceof String ? (String) rawUri : "";
        if (!storedUri.isEmpty() && utf8Exceeds(storedUri, MAX_URI_BYTES)) {
            throw new IllegalArgumentException("stored proxy URI exceeds 16 KiB");
        }
        JSONObject outbound = value.optJSONObject("outbound");
        if (value.has("outbound") && outbound == null) {
            throw new IllegalArgumentException("stored neutral outbound has invalid type");
        }
        if (outbound != null) {
            return fromOutbound(storedUri, value.optString("name", ""), outbound);
        }
        return parse(storedUri);
    }

    static JSONObject buildConfig(Node node, int localPort, String username, String password) throws Exception {
        if (node == null) throw new IllegalArgumentException("node is missing");
        validateNeutralOutbound(node.outbound);
        if (!node.supports(CoreFamily.SING_BOX)) {
            throw new IllegalArgumentException("node is not representable by sing-box");
        }
        JSONObject inbound = new JSONObject()
                .put("type", "mixed")
                .put("tag", "socks-in")
                .put("listen", "127.0.0.1")
                .put("listen_port", localPort);
        if (!empty(username) && !empty(password)) {
            inbound.put("users", new JSONArray().put(new JSONObject()
                    .put("username", username)
                    .put("password", password)));
        }
        JSONObject proxy = renderSingBoxOutbound(node.outbound).put("tag", "proxy");
        JSONArray dnsServers = new JSONArray()
                .put(new JSONObject()
                        .put("type", "udp")
                        .put("tag", "dns-primary")
                        .put("server", "1.1.1.1"))
                .put(new JSONObject()
                        .put("type", "udp")
                        .put("tag", "dns-secondary")
                        .put("server", "8.8.8.8"));
        return new JSONObject()
                .put("log", new JSONObject().put("level", "panic"))
                .put("dns", new JSONObject().put("servers", dnsServers))
                .put("inbounds", new JSONArray().put(inbound))
                .put("outbounds", new JSONArray().put(proxy))
                .put("route", new JSONObject()
                        .put("final", "proxy")
                        // sing-box 1.13 treats an omitted resolver as an
                        // impending deprecated option when more than one DNS
                        // transport exists. Its CLI deprecated manager calls
                        // logger.Fatal(), which exits an embedded Android
                        // process with status 1. Select the resolver
                        // explicitly so provider changes can never enter that
                        // process-terminating compatibility path.
                        .put("default_domain_resolver", "dns-primary"));
    }

    /**
     * Converts the strict core-neutral model into the pinned sing-box contract.
     * Neutral-only compatibility metadata must never reach sing-box's
     * DisallowUnknownFields decoder.
     */
    static JSONObject renderSingBoxOutbound(JSONObject source) throws Exception {
        validateNeutralOutbound(source);
        String incompatibility = incompatibilityReason(source, CoreFamily.SING_BOX);
        if (!incompatibility.isEmpty()) {
            throw new IllegalArgumentException(
                    "sing-box incompatibility: " + incompatibility);
        }
        JSONObject rendered = new JSONObject(source.toString());
        if ("vless".equals(rendered.optString("type", ""))) {
            String encryption = rendered.optString("encryption", "none");
            if (!"none".equalsIgnoreCase(encryption)) {
                throw new IllegalArgumentException("VLESS encryption is not representable by sing-box");
            }
            // sing-box v1.13.14 has no VLESS `encryption` option. The field is
            // retained only in the neutral model for Xray.
            rendered.remove("encryption");
        }
        JSONObject transport = rendered.optJSONObject("transport");
        if (transport != null && "ws".equals(transport.optString("type", ""))) {
            String earlyDataMode = transport.optString(WS_EARLY_DATA_MODE, "");
            transport.remove(WS_EARLY_DATA_MODE);
            if (WS_EARLY_DATA_XRAY_PATH.equals(earlyDataMode)) {
                transport.put("early_data_header_name", WS_EARLY_DATA_XRAY_HEADER);
            }
        }
        return rendered;
    }

    static boolean supports(String value) {
        if (value == null) return false;
        String lower = value.trim().toLowerCase(Locale.US);
        for (String scheme : SCHEMES) {
            if (lower.startsWith(scheme)) return true;
        }
        return false;
    }

    static String sanitize(String value) {
        if (value == null) return "";
        // Once a caller has selected an exact URI, punctuation is data: it may
        // be part of a fragment, query value, or WebSocket path. Wrapping-text
        // cleanup belongs only to SubscriptionParser's regex extraction edge.
        String result = value.trim();
        for (int i = 0; i < result.length(); i++) {
            char current = result.charAt(i);
            if (current == '\r' || current == '\n' || current == 0) {
                throw new IllegalArgumentException("proxy URI contains control characters");
            }
        }
        return result;
    }

    private static JSONObject parseVless(Parsed parsed) throws Exception {
        rejectUnknownStreamParams(parsed.params, "VLESS", "encryption", "packetEncoding",
                "packet_encoding", "flow");
        requireOpaque(parsed.user, "VLESS UUID");
        String encryption = value(parsed.params, "encryption", "none").trim();
        if (encryption.isEmpty() || utf8Exceeds(encryption, MAX_URI_BYTES)
                || !xrayVlessEncryption(encryption)) {
            throw new IllegalArgumentException("unsupported VLESS encryption");
        }
        JSONObject outbound = endpoint("vless", parsed)
                .put("uuid", parsed.user)
                .put("encryption", encryption);
        String packetEncoding = nonEmpty(valueAny(parsed.params,
                "packetEncoding", "packet_encoding"), "xudp")
                .trim().toLowerCase(Locale.US);
        if (packetEncoding.equals("none")) {
            // A present empty string is required by sing-box to disable its
            // default xudp encoding. Absence would silently re-enable xudp.
            outbound.put("packet_encoding", "");
        } else if (packetEncoding.equals("xudp") || packetEncoding.equals("packetaddr")) {
            outbound.put("packet_encoding", packetEncoding);
        } else {
            throw new IllegalArgumentException("unsupported VLESS packet encoding");
        }
        String flow = value(parsed.params, "flow", "").trim().toLowerCase(Locale.US);
        if (!empty(flow)) {
            if (!flow.equals("xtls-rprx-vision")
                    && !flow.equals("xtls-rprx-vision-udp443")) {
                throw new IllegalArgumentException("unsupported VLESS flow");
            }
            outbound.put("flow", flow);
        }
        applyStream(outbound, parsed.params, parsed.host);
        validateVlessVisionRequirements(outbound);
        return outbound;
    }

    private static JSONObject parseVmess(JSONObject source) throws Exception {
        String host = source.optString("add", "").trim();
        int port = strictJsonInteger(source, "port", 0, 1, 65535);
        // VMess custom user IDs are opaque input. Both pinned cores derive a
        // UUIDv5 from the exact UTF-8 bytes when this is not a canonical UUID.
        String uuid = source.optString("id", "");
        require(host, "VMess server");
        requireOpaque(uuid, "VMess UUID");
        requirePort(port);
        String cipher = nonEmpty(source.optString("scy", "auto"), "auto")
                .trim().toLowerCase(Locale.US);
        if (!singBoxVmessSecurity(cipher)) {
            throw new IllegalArgumentException("unsupported VMess security");
        }
        JSONObject outbound = new JSONObject()
                .put("type", "vmess")
                .put("server", host)
                .put("server_port", port)
                .put("uuid", uuid)
                .put("alter_id", strictJsonInteger(
                        source, "aid", 0, 0, Integer.MAX_VALUE))
                .put("security", cipher);
        Map<String, String> stream = new TreeMap<>();
        String network = nonEmpty(source.optString("net", "tcp"), "tcp");
        String security = source.optString("tls", "");
        stream.put("type", network);
        copyVmessField(stream, source, "tls", "security");
        copyVmessField(stream, source, "sni", "sni");
        if (!stream.containsKey("sni") && !empty(security) && !security.equalsIgnoreCase("none")) {
            copyVmessField(stream, source, "host", "sni");
        }
        copyVmessField(stream, source, "host", "host");
        copyVmessField(stream, source, "path", "path");
        copyVmessField(stream, source, "fp", "fp");
        copyVmessField(stream, source, "alpn", "alpn");
        copyVmessField(stream, source, "pbk", "pbk");
        copyVmessField(stream, source, "sid", "sid");
        if (source.has("insecure")) {
            if (vmessBooleanTrue(source.opt("insecure"))) {
                stream.put("insecure", "true");
            }
        } else if (source.has("allowInsecure")) {
            if (vmessBooleanTrue(source.opt("allowInsecure"))) {
                stream.put("allowInsecure", "true");
            }
        }
        copyVmessField(stream, source, "mode", "mode");
        copyVmessField(stream, source, "extra", "extra");
        if (source.has("headerType")) {
            copyVmessField(stream, source, "headerType", "headerType");
        } else {
            copyVmessField(stream, source, "type", "headerType");
        }
        copyVmessField(stream, source, "seed", "seed");
        copyVmessField(stream, source, "mtu", "mtu");
        copyVmessField(stream, source, "tti", "tti");
        copyVmessField(stream, source, "uplinkCapacity", "uplinkCapacity");
        copyVmessField(stream, source, "downlinkCapacity", "downlinkCapacity");
        copyVmessField(stream, source, "cwndMultiplier", "cwndMultiplier");
        copyVmessField(stream, source, "maxSendingWindow", "maxSendingWindow");
        copyVmessField(stream, source, "ed", "ed");
        if (source.has("eh")) {
            copyVmessField(stream, source, "eh", "eh");
        } else {
            copyVmessField(stream, source, "earlyDataHeaderName", "eh");
        }
        copyVmessField(stream, source, "headers", "headers");
        applyStream(outbound, stream, host);
        return outbound;
    }

    private static void copyVmessField(Map<String, String> target, JSONObject source,
                                       String sourceKey, String targetKey) {
        if (!source.has(sourceKey)) return;
        Object raw = source.opt(sourceKey);
        if (raw instanceof String && ((String) raw).isEmpty()) return;
        if (raw instanceof JSONObject && ((JSONObject) raw).length() == 0) return;
        if (sourceKey.equals("ed") && raw instanceof Number
                && ((Number) raw).longValue() == 0L) return;
        if (sourceKey.equals("ed") && raw instanceof String
                && ((String) raw).matches("0+")) return;
        target.put(targetKey, String.valueOf(raw));
    }

    private static boolean vmessBooleanTrue(Object raw) {
        if (raw instanceof Boolean) return (Boolean) raw;
        if (raw instanceof Number) return ((Number) raw).longValue() == 1L;
        String normalized = raw instanceof String
                ? ((String) raw).trim().toLowerCase(Locale.US) : "";
        return normalized.equals("1") || normalized.equals("true")
                || normalized.equals("yes") || normalized.equals("on");
    }

    private static JSONObject parseTrojan(Parsed parsed) throws Exception {
        rejectUnknownStreamParams(parsed.params, "Trojan", "flow");
        requireOpaque(parsed.user, "Trojan password");
        if (!empty(value(parsed.params, "flow", ""))) {
            throw new IllegalArgumentException("unsupported Trojan flow");
        }
        parsed.params.putIfAbsent("security", "tls");
        String security = value(parsed.params, "security", "").toLowerCase(Locale.US);
        if (security.equals("tls") || security.equals("reality")) {
            parsed.params.putIfAbsent("sni", parsed.host);
        }
        JSONObject outbound = endpoint("trojan", parsed).put("password", parsed.user);
        applyStream(outbound, parsed.params, parsed.host);
        return outbound;
    }

    private static JSONObject parseHysteria2(Parsed parsed) throws Exception {
        rejectUnknownParams(parsed.params, "Hysteria2", "security", "sni", "peer",
                "insecure", "allowInsecure", "allow_insecure", "alpn",
                "obfs", "obfs-password", "hop_interval", "hop-interval", "hopInterval",
                "upmbps", "up", "downmbps", "down");
        rejectAliasConflict(parsed.params, "Hysteria2 upload", "upmbps", "up");
        rejectAliasConflict(parsed.params, "Hysteria2 download", "downmbps", "down");
        String password = parsed.user;
        requireOpaque(password, "Hysteria2 password");
        JSONObject outbound = endpoint("hysteria2", parsed)
                .put("password", password)
                .put("tls", tls(parsed.params, parsed.host, true, ""));
        int up = parseBandwidthMbps(
                value(parsed.params, "upmbps", value(parsed.params, "up", "")),
                "Hysteria2", "up", MAX_HYSTERIA2_MBPS);
        int down = parseBandwidthMbps(
                value(parsed.params, "downmbps", value(parsed.params, "down", "")),
                "Hysteria2", "down", MAX_HYSTERIA2_MBPS);
        if (up > 0) outbound.put("up_mbps", up);
        if (down > 0) outbound.put("down_mbps", down);
        String hopInterval = valueAny(parsed.params,
                "hop_interval", "hop-interval", "hopInterval");
        if (!empty(hopInterval) && parsed.serverPorts.isEmpty()) {
            throw new IllegalArgumentException(
                    "Hysteria2 hop interval requires an explicit port list");
        }
        if (!parsed.serverPorts.isEmpty()) {
            outbound.put("server_ports", new JSONArray(parsed.serverPorts));
            if (!empty(hopInterval)) outbound.put("hop_interval", hopInterval.trim());
        }
        String obfs = value(parsed.params, "obfs", "");
        String obfsPassword = value(parsed.params, "obfs-password", "");
        boolean hasObfsPassword = parsed.params.containsKey("obfs-password");
        if (hasObfsPassword && exactEmpty(obfsPassword)) {
            throw new IllegalArgumentException("Hysteria2 obfs password is missing");
        }
        if (empty(obfs) && hasObfsPassword) {
            throw new IllegalArgumentException("Hysteria2 obfs password requires obfs");
        }
        if (!empty(obfs)) {
            String type = obfs.toLowerCase(Locale.US);
            if (!type.equals("salamander")) {
                throw new IllegalArgumentException("unsupported Hysteria2 obfs");
            }
            requireOpaque(obfsPassword, "Hysteria2 obfs password");
            outbound.put("obfs", new JSONObject().put("type", type).put("password", obfsPassword));
        }
        return outbound;
    }

    private static JSONObject parseHysteria(Parsed parsed) throws Exception {
        rejectUnknownParams(parsed.params, "Hysteria", "security", "sni", "peer",
                "insecure", "allowInsecure", "allow_insecure", "alpn",
                "auth", "auth_str", "upmbps", "up", "downmbps", "down", "obfs",
                "obfsParam", "obfs-param", "obfs_password");
        rejectAliasConflict(parsed.params, "Hysteria auth", "auth", "auth_str");
        if (!exactEmpty(parsed.user) && containsAny(parsed.params, "auth", "auth_str")) {
            throw new IllegalArgumentException("duplicate Hysteria auth/userinfo");
        }
        if (containsAny(parsed.params, "auth", "auth_str")
                && exactEmpty(valueAny(parsed.params, "auth", "auth_str"))) {
            throw new IllegalArgumentException("Hysteria auth is missing");
        }
        rejectAliasConflict(parsed.params, "Hysteria upload", "upmbps", "up");
        rejectAliasConflict(parsed.params, "Hysteria download", "downmbps", "down");
        rejectAliasConflict(parsed.params, "Hysteria SNI", "sni", "peer");
        JSONObject outbound = endpoint("hysteria", parsed);
        JSONObject tls = tls(parsed.params,
                nonEmpty(value(parsed.params, "peer", ""), parsed.host), true, "h3");
        outbound.put("tls", tls);
        String auth = opaqueNonEmpty(value(parsed.params, "auth", ""),
                opaqueNonEmpty(value(parsed.params, "auth_str", ""), parsed.user));
        if (!exactEmpty(auth)) outbound.put("auth_str", auth);
        int up = parseBandwidthMbps(
                value(parsed.params, "upmbps", value(parsed.params, "up", "")),
                "Hysteria", "up", Integer.MAX_VALUE);
        int down = parseBandwidthMbps(
                value(parsed.params, "downmbps", value(parsed.params, "down", "")),
                "Hysteria", "down", Integer.MAX_VALUE);
        if (up > 0) outbound.put("up_mbps", up);
        if (down > 0) outbound.put("down_mbps", down);
        String obfsMode = value(parsed.params, "obfs", "");
        String obfsPassword = valueAny(parsed.params, "obfsParam", "obfs-param", "obfs_password");
        boolean hasObfsPassword = containsAny(
                parsed.params, "obfsParam", "obfs-param", "obfs_password");
        if (hasObfsPassword && exactEmpty(obfsPassword)) {
            throw new IllegalArgumentException("Hysteria obfs password is missing");
        }
        if (!empty(obfsMode) || hasObfsPassword) {
            if (!"xplus".equalsIgnoreCase(obfsMode)) {
                throw new IllegalArgumentException("unsupported Hysteria obfs mode");
            }
            requireOpaque(obfsPassword, "Hysteria obfs password");
            outbound.put("obfs", obfsPassword);
        }
        return outbound;
    }

    private static JSONObject parseTuic(Parsed parsed) throws Exception {
        rejectUnknownParams(parsed.params, "TUIC", "security", "sni", "peer",
                "insecure", "allowInsecure", "allow_insecure", "alpn",
                "congestion_control", "udp_relay_mode");
        String uuid = parsed.user;
        String password = "";
        int separator = uuid.indexOf(':');
        if (separator > 0 && separator < uuid.length() - 1) {
            password = uuid.substring(separator + 1);
            uuid = uuid.substring(0, separator);
        } else {
            throw new IllegalArgumentException("TUIC credentials must include UUID and password");
        }
        require(uuid, "TUIC UUID");
        requireOpaque(password, "TUIC password");
        return endpoint("tuic", parsed)
                .put("uuid", uuid)
                .put("password", password)
                .put("congestion_control", value(parsed.params,
                        "congestion_control", "bbr").trim().toLowerCase(Locale.US))
                .put("udp_relay_mode", value(parsed.params,
                        "udp_relay_mode", "native").trim().toLowerCase(Locale.US))
                .put("tls", tls(parsed.params, parsed.host, true, "h3"));
    }

    private static ParsedSs parseShadowsocks(String uri) throws Exception {
        String body = uri.substring(5);
        String name = fragmentName(body);
        int hash = body.indexOf('#');
        if (hash >= 0) body = body.substring(0, hash);
        int query = body.indexOf('?');
        if (query >= 0) {
            throw new IllegalArgumentException("unsupported Shadowsocks URI parameters");
        }
        String credentials;
        String server;
        if (body.contains("@")) {
            String[] parts = body.split("@", 2);
            credentials = decodeMaybeBase64(parts[0]);
            server = parts[1];
        } else {
            String decoded = decodeBase64Text(body);
            int at = decoded.lastIndexOf('@');
            if (at < 0) throw new IllegalArgumentException("invalid Shadowsocks URI");
            credentials = decoded.substring(0, at);
            server = decoded.substring(at + 1);
        }
        int separator = credentials.indexOf(':');
        if (separator <= 0) throw new IllegalArgumentException("invalid Shadowsocks credentials");
        HostPort hostPort = parseHostPort(server);
        JSONObject outbound = new JSONObject()
                .put("type", "shadowsocks")
                .put("server", hostPort.host)
                .put("server_port", hostPort.port)
                .put("method", credentials.substring(0, separator)
                        .trim().toLowerCase(Locale.US))
                .put("password", credentials.substring(separator + 1));
        return new ParsedSs(outbound, name);
    }

    private static JSONObject endpoint(String type, Parsed parsed) throws Exception {
        require(parsed.host, type + " server");
        requirePort(parsed.port);
        return new JSONObject()
                .put("type", type)
                .put("server", parsed.host)
                .put("server_port", parsed.port);
    }

    private static void applyStream(JSONObject outbound, Map<String, String> params, String defaultSni)
            throws Exception {
        JSONObject tls = tls(params, defaultSni, false, "");
        if (tls != null) outbound.put("tls", tls);
        JSONObject transport = transport(params);
        if (transport != null && "ws".equals(transport.optString("type", ""))) {
            String fallbackHost = tls == null ? defaultSni
                    : tls.optString("server_name", defaultSni);
            normalizeWebSocketHost(transport, fallbackHost);
        }
        if (transport != null) outbound.put("transport", transport);
    }

    private static void normalizeWebSocketHost(JSONObject transport, String fallbackHost)
            throws Exception {
        JSONObject headers = transport.optJSONObject("headers");
        if (headers == null) {
            headers = new JSONObject();
            transport.put("headers", headers);
        }
        String hostKey = null;
        Iterator<String> keys = headers.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!"host".equalsIgnoreCase(key)) continue;
            if (hostKey != null) {
                throw new IllegalArgumentException("duplicate WebSocket Host header");
            }
            hostKey = key;
        }
        String host = "";
        if (hostKey != null) {
            Object raw = headers.opt(hostKey);
            if (raw instanceof String) {
                host = (String) raw;
            } else if (raw instanceof JSONArray && ((JSONArray) raw).length() == 1
                    && ((JSONArray) raw).opt(0) instanceof String) {
                host = ((JSONArray) raw).optString(0);
            } else {
                throw new IllegalArgumentException(
                        "WebSocket Host header must contain one value");
            }
            if (empty(host)) {
                throw new IllegalArgumentException("WebSocket Host header is empty");
            }
        } else {
            host = fallbackHost == null ? "" : fallbackHost;
            if (empty(host)) {
                throw new IllegalArgumentException("WebSocket Host fallback is missing");
            }
        }
        if (utf8Exceeds(host, 1024) || containsWhitespaceOrControl(host)) {
            throw new IllegalArgumentException("invalid WebSocket Host header");
        }
        if (hostKey != null && !"Host".equals(hostKey)) headers.remove(hostKey);
        headers.put("Host", host);
    }

    private static JSONObject tls(Map<String, String> params, String defaultSni,
                                  boolean force, String defaultAlpn) throws Exception {
        String security = value(params, "security", "").toLowerCase(Locale.US);
        boolean insecure = strictBooleanParam(params,
                "insecure", "allowInsecure", "allow_insecure");
        boolean disabled = empty(security) || security.equals("none");
        if (force) {
            if (params.containsKey("security") && disabled) {
                throw new IllegalArgumentException(
                        "forced TLS protocol cannot disable security");
            }
            if (!disabled && !security.equals("tls")) {
                throw new IllegalArgumentException(
                        "unsupported forced TLS security: " + security);
            }
        } else if (disabled) {
            if (containsAny(params, "sni", "peer", "fp", "alpn", "pbk", "sid", "spx",
                    "insecure", "allowInsecure", "allow_insecure")) {
                throw new IllegalArgumentException("TLS parameters require security=tls/reality");
            }
            return null;
        } else if (!security.equals("tls") && !security.equals("reality")) {
            throw new IllegalArgumentException("unsupported transport security: " + security);
        }
        if (!security.equals("reality") && containsAny(params, "pbk", "sid", "spx")) {
            throw new IllegalArgumentException("Reality parameters require security=reality");
        }
        rejectAliasConflict(params, "TLS SNI", "sni", "peer");
        JSONObject tls = new JSONObject()
                .put("enabled", true)
                .put("server_name", nonEmpty(value(params, "sni", ""),
                        nonEmpty(value(params, "peer", ""), defaultSni)))
                .put("insecure", insecure);
        String alpn = nonEmpty(value(params, "alpn", ""), defaultAlpn);
        if (!empty(alpn)) {
            JSONArray values = new JSONArray();
            for (String item : alpn.split(",", -1)) {
                if (item.isEmpty() || utf8Exceeds(item, 255) || containsControl(item)) {
                    throw new IllegalArgumentException("invalid TLS ALPN value");
                }
                values.put(item);
            }
            if (values.length() > 0) tls.put("alpn", values);
        }
        String fingerprint = value(params, "fp", "");
        if (!empty(fingerprint)) {
            tls.put("utls", new JSONObject().put("enabled", true).put("fingerprint", fingerprint));
        }
        if (security.equals("reality")) {
            JSONObject reality = new JSONObject()
                    .put("enabled", true)
                    .put("public_key", value(params, "pbk", ""))
                    .put("short_id", value(params, "sid", ""));
            String spiderX = value(params, "spx", "");
            if (!spiderX.isEmpty()) reality.put("spider_x", spiderX);
            tls.put("reality", reality);
            if (!tls.has("utls")) {
                tls.put("utls", new JSONObject().put("enabled", true).put("fingerprint", "chrome"));
            }
        }
        return tls;
    }

    private static JSONObject transport(Map<String, String> params) throws Exception {
        String network = canonicalTransportType(value(params, "type", "tcp"));
        String path = value(params, "path", "/");
        // TLS SNI and transport Host are separate functional fields. Never
        // synthesize a transport Host header from SNI.
        String host = value(params, "host", "");
        boolean rawTransport = network.equals("tcp") || network.equals("raw")
                || network.equals("none") || network.isEmpty();
        boolean kcpTransport = network.equals("kcp") || network.equals("mkcp");
        if (!rawTransport && !kcpTransport) {
            rejectLegacyKcpParams(params, network);
        }
        if (network.equals("ws")) {
            rejectPresent(params, "WebSocket", "serviceName", "mode", "extra");
            JSONObject value = new JSONObject().put("type", "ws").put("path", path);
            JSONObject headers = headerObject(params, host);
            if (headers.length() > 0) value.put("headers", headers);
            String earlyHeader = valueAny(params,
                    "eh", "earlyDataHeaderName", "early_data_header_name");
            long earlyData = params.containsKey("ed")
                    ? boundedUnsigned32Param(params.get("ed"),
                    "WebSocket early data", 0) : 0;
            if (earlyData > 0) {
                value.put("max_early_data", earlyData);
                if (!empty(earlyHeader)) {
                    if (!validHeaderName(earlyHeader)) {
                        throw new IllegalArgumentException(
                                "invalid WebSocket early-data header name");
                    }
                    value.put("early_data_header_name", earlyHeader);
                }
            } else if (containsAny(params,
                    "eh", "earlyDataHeaderName", "early_data_header_name")) {
                throw new IllegalArgumentException(
                        "WebSocket early-data header requires positive ed");
            }
            return value;
        }
        if (network.equals("grpc")) {
            rejectPresent(params, "gRPC", "host", "headers", "ed", "eh",
                    "earlyDataHeaderName", "early_data_header_name", "extra");
            // "gun" is the plain single-stream mode this outbound already
            // describes, and subscriptions state it explicitly. Multiplexed
            // gRPC is a different transport that is not represented here.
            String grpcMode = value(params, "mode", "gun").toLowerCase(Locale.US);
            if (!grpcMode.equals("gun")) {
                throw new IllegalArgumentException(
                        "unsupported gRPC transport mode: " + grpcMode);
            }
            rejectAliasConflict(params, "gRPC service", "serviceName", "path");
            JSONObject value = new JSONObject().put("type", "grpc");
            String serviceName = nonEmpty(value(params, "serviceName", ""),
                    value(params, "path", ""));
            if (!empty(serviceName)) value.put("service_name", serviceName);
            return value;
        }
        if (network.equals("http") || network.equals("h2")) {
            rejectPresent(params, "HTTP", "serviceName", "ed", "eh",
                    "earlyDataHeaderName", "early_data_header_name", "mode", "extra");
            JSONObject value = new JSONObject().put("type", "http").put("path", path);
            if (!empty(host)) value.put("host", new JSONArray().put(host));
            JSONObject headers = headerObject(params, "");
            if (headers.length() > 0) value.put("headers", headers);
            return value;
        }
        if (network.equals("httpupgrade")) {
            rejectPresent(params, "HTTPUpgrade", "serviceName", "eh",
                    "earlyDataHeaderName", "early_data_header_name", "mode", "extra");
            JSONObject value = new JSONObject().put("type", "httpupgrade").put("path", path);
            long earlyData = params.containsKey("ed")
                    ? boundedUnsigned32Param(params.get("ed"),
                    "HTTPUpgrade early data", 0) : 0;
            if (earlyData > 0) value.put("max_early_data", earlyData);
            if (!empty(host)) value.put("host", host);
            JSONObject headers = headerObject(params, "");
            if (headers.length() > 0) value.put("headers", headers);
            return value;
        }
        if (network.equals("xhttp") || network.equals("splithttp")) {
            rejectPresent(params, "XHTTP", "headers", "serviceName", "ed", "eh",
                    "earlyDataHeaderName", "early_data_header_name");
            JSONObject value = new JSONObject().put("type", "xhttp").put("path", path);
            if (!empty(host)) value.put("host", host);
            String mode = value(params, "mode", "auto").toLowerCase(Locale.US);
            if (!mode.equals("auto") && !mode.equals("packet-up") && !mode.equals("stream-up")
                    && !mode.equals("stream-one")) {
                throw new IllegalArgumentException("unsupported XHTTP mode: " + mode);
            }
            value.put("mode", mode);
            String extra = value(params, "extra", "");
            if (!empty(extra)) {
                if (utf8Exceeds(extra, 64 * 1024)) {
                    throw new IllegalArgumentException("XHTTP extra exceeds 64 KiB");
                }
                JSONObject parsedExtra = JsonGuard.object(extra);
                validateXhttpExtra(parsedExtra);
                value.put("extra", parsedExtra);
            }
            return value;
        }
        if (kcpTransport) {
            rejectPresent(params, "mKCP", "path", "host", "headers", "ed", "eh",
                    "earlyDataHeaderName", "early_data_header_name", "serviceName",
                    "mode", "extra");
            rejectPresentEmpty(params, "mKCP numeric", "mtu", "tti",
                    "uplinkCapacity", "uplink_capacity", "downlinkCapacity",
                    "downlink_capacity", "cwndMultiplier", "cwnd_multiplier",
                    "maxSendingWindow", "max_sending_window");
            JSONObject value = new JSONObject().put("type", "mkcp");
            putPositiveInt(value, "mtu", valueAny(params, "mtu"), 21, 65535);
            putPositiveInt(value, "tti", valueAny(params, "tti"), 10, 1000);
            putPositiveInt(value, "uplink_capacity",
                    valueAny(params, "uplinkCapacity", "uplink_capacity"), 0, 4095);
            putPositiveInt(value, "downlink_capacity",
                    valueAny(params, "downlinkCapacity", "downlink_capacity"), 0, 4095);
            putUnsigned32(value, "cwnd_multiplier",
                    valueAny(params, "cwndMultiplier", "cwnd_multiplier"), 1);
            putUnsigned32(value, "max_sending_window",
                    valueAny(params, "maxSendingWindow", "max_sending_window"), 1);
            String header = valueAny(params, "headerType", "header_type", "header")
                    .trim().toLowerCase(Locale.US);
            if (header.equals("none")) header = "";
            if (header.equals("wechat-video")) header = "wechat";
            if (!header.isEmpty() && !header.equals("dns") && !header.equals("dtls")
                    && !header.equals("srtp") && !header.equals("utp")
                    && !header.equals("wechat") && !header.equals("wireguard")) {
                throw new IllegalArgumentException("unsupported mKCP headerType: " + header);
            }
            String seed = value(params, "seed", "");
            if (params.containsKey("seed") && exactEmpty(seed)) {
                throw new IllegalArgumentException("mKCP legacy seed is missing");
            }
            if (!header.isEmpty()) value.put("legacy_header", header);
            if (!seed.isEmpty()) value.put("legacy_seed", seed);
            validateNeutralMkcp(value);
            return value;
        }
        if (rawTransport) {
            rejectPresent(params, "raw TCP", "path", "host", "headers", "ed", "eh",
                    "earlyDataHeaderName", "early_data_header_name", "serviceName",
                    "mode", "extra");
            String header = valueAny(params, "headerType", "header_type", "header")
                    .trim().toLowerCase(Locale.US);
            if (!header.isEmpty() && !header.equals("none")) {
                throw new IllegalArgumentException("unsupported raw TCP headerType: " + header);
            }
            for (String key : new String[]{"seed", "mtu", "tti", "uplinkCapacity",
                    "uplink_capacity", "downlinkCapacity", "downlink_capacity",
                    "cwndMultiplier", "cwnd_multiplier", "maxSendingWindow",
                    "max_sending_window"}) {
                if (!empty(params.get(key))) {
                    throw new IllegalArgumentException(
                            "unsupported raw TCP transport parameter: " + key);
                }
            }
            return null;
        }
        throw new IllegalArgumentException("unsupported transport: " + network);
    }

    private static void rejectPresent(Map<String, String> params, String transport,
                                      String... keys) {
        for (String key : keys) {
            if (params.containsKey(key)) {
                throw new IllegalArgumentException(
                        "unsupported " + transport + " transport parameter: " + key);
            }
        }
    }

    private static void rejectPresentEmpty(Map<String, String> params, String label,
                                           String... keys) {
        for (String key : keys) {
            if (params.containsKey(key) && empty(params.get(key))) {
                throw new IllegalArgumentException("empty " + label + " parameter: " + key);
            }
        }
    }

    private static void rejectLegacyKcpParams(Map<String, String> params, String network) {
        String header = valueAny(params, "headerType", "header_type", "header")
                .trim().toLowerCase(Locale.US);
        if (!header.isEmpty() && !header.equals("none")) {
            throw new IllegalArgumentException(
                    "unsupported " + network + " transport headerType: " + header);
        }
        for (String key : new String[]{"seed", "mtu", "tti", "uplinkCapacity",
                "uplink_capacity", "downlinkCapacity", "downlink_capacity",
                "cwndMultiplier", "cwnd_multiplier", "maxSendingWindow",
                "max_sending_window"}) {
            if (!empty(params.get(key))) {
                throw new IllegalArgumentException(
                        "unsupported " + network + " transport parameter: " + key);
            }
        }
    }

    private static final int MAX_XHTTP_EXTRA_FIELDS = 32;
    private static final int MAX_XHTTP_EXTRA_VALUE_CHARS = 256;

    static void validateXhttpExtra(JSONObject extra) {
        if (extra == null) return;
        try {
            AtomicStore.jsonUtf8Size(extra, 64 * 1024);
        } catch (IllegalArgumentException boundedFailure) {
            throw new IllegalArgumentException("invalid or oversized XHTTP extra (64 KiB maximum)");
        }
        // The four fields below carry ranges this client depends on, so they
        // keep their exact checks. Everything else is bounded by shape instead
        // of by name: real subscriptions carry padding, sequence and session
        // options that an allow-list of names cannot keep up with, and
        // rejecting one unknown key discards the whole server.
        java.util.HashSet<String> ranged = new java.util.HashSet<>();
        Collections.addAll(ranged, "scMaxEachPostBytes", "scMinPostsIntervalMs",
                "xPaddingBytes", "noSSEHeader");
        int fields = 0;
        Iterator<String> keys = extra.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            Object value = extra.opt(key);
            if (value == null || value == JSONObject.NULL) {
                throw new IllegalArgumentException("unsupported XHTTP extra field: " + key);
            }
            if (++fields > MAX_XHTTP_EXTRA_FIELDS || key.length() > 64) {
                throw new IllegalArgumentException("unsupported XHTTP extra field: " + key);
            }
            if (!ranged.contains(key)) {
                // Nested structures would let a source reach past this field.
                if (value instanceof JSONObject || value instanceof org.json.JSONArray) {
                    throw new IllegalArgumentException(
                            "unsupported XHTTP extra field: " + key);
                }
                if (value instanceof String
                        && ((String) value).length() > MAX_XHTTP_EXTRA_VALUE_CHARS) {
                    throw new IllegalArgumentException("invalid XHTTP extra field: " + key);
                }
                continue;
            }
            if (key.equals("noSSEHeader")) {
                if (!(value instanceof Boolean)) {
                    throw new IllegalArgumentException("invalid XHTTP noSSEHeader");
                }
            } else if (key.equals("xPaddingBytes")) {
                validateInt32Range(value, 1, 1024 * 1024, key);
            } else if (key.equals("scMaxEachPostBytes")) {
                validateInt32Range(value, 1, 8 * 1024 * 1024, key);
            } else {
                validateInt32Range(value, 0, 60_000, key);
            }
        }
    }

    private static void validateInt32Range(Object value, int minimum, int maximum,
                                           String key) {
        if (!(value instanceof Number) && !(value instanceof String)) {
            throw new IllegalArgumentException("invalid XHTTP range field: " + key);
        }
        String encoded = String.valueOf(value).trim();
        if (encoded.isEmpty() || encoded.length() > 32
                || !encoded.matches("[0-9]+(?:-[0-9]+)?")) {
            throw new IllegalArgumentException("invalid XHTTP range field: " + key);
        }
        String[] bounds = encoded.split("-", -1);
        try {
            long from = Long.parseLong(bounds[0]);
            long to = bounds.length == 1 ? from : Long.parseLong(bounds[1]);
            if (from < minimum || to < from || to > maximum) {
                throw new IllegalArgumentException("XHTTP range is out of bounds: " + key);
            }
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("invalid XHTTP range field: " + key);
        }
    }

    private static JSONObject headerObject(Map<String, String> params, String defaultHost)
            throws Exception {
        JSONObject headers = new JSONObject();
        HashSet<String> normalizedNames = new HashSet<>();
        String encoded = value(params, "headers", "").trim();
        if (!encoded.isEmpty()) {
            if (encoded.getBytes(StandardCharsets.UTF_8).length > 16 * 1024) {
                throw new IllegalArgumentException("transport headers exceed 16 KiB");
            }
            JSONObject parsed = JsonGuard.object(encoded);
            Iterator<String> keys = parsed.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                Object raw = parsed.opt(key);
                String normalized = key.toLowerCase(Locale.US);
                if (!validHeaderName(key) || !normalizedNames.add(normalized)
                        || !validHeaderValue(raw)) {
                    throw new IllegalArgumentException("invalid transport header");
                }
                headers.put(key, raw);
            }
        }
        if (!empty(defaultHost)) {
            Object existingHost = caseInsensitiveHeader(headers, "host");
            if (existingHost == null) {
                headers.put("Host", defaultHost);
            } else if (!singleHeaderEquals(existingHost, defaultHost)) {
                throw new IllegalArgumentException("conflicting WebSocket Host header");
            }
        }
        return headers;
    }

    private static Object caseInsensitiveHeader(JSONObject headers, String expected) {
        Iterator<String> keys = headers.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (key.equalsIgnoreCase(expected)) return headers.opt(key);
        }
        return null;
    }

    private static boolean singleHeaderEquals(Object raw, String expected) {
        if (raw instanceof String) return raw.equals(expected);
        if (!(raw instanceof JSONArray)) return false;
        JSONArray values = (JSONArray) raw;
        return values.length() == 1 && expected.equals(values.opt(0));
    }

    private static void putPositiveInt(JSONObject target, String key, String raw,
                                       int minimum, int maximum) throws Exception {
        if (empty(raw)) return;
        int parsed = intValue(raw, Integer.MIN_VALUE);
        if (parsed < minimum || parsed > maximum) {
            throw new IllegalArgumentException("invalid " + key);
        }
        target.put(key, parsed);
    }

    private static void putUnsigned32(JSONObject target, String key, String raw,
                                      long minimum) throws Exception {
        if (empty(raw)) return;
        target.put(key, boundedUnsigned32Param(raw, key, minimum));
    }

    private static long boundedUnsigned32Param(String raw, String label,
                                               long minimum) {
        String normalized = raw == null ? "" : raw.trim();
        if (!normalized.matches("[0-9]+")) {
            throw new IllegalArgumentException("invalid " + label);
        }
        try {
            long parsed = Long.parseLong(normalized);
            if (parsed < minimum || parsed > 0xffff_ffffL) {
                throw new IllegalArgumentException("invalid " + label);
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("invalid " + label);
        }
    }

    private static Parsed parseStandard(String value) throws Exception {
        String name = fragmentName(value);
        String work = value;
        int hash = work.indexOf('#');
        if (hash >= 0) work = work.substring(0, hash);
        URI uri;
        try {
            uri = new URI(work.replace(" ", "%20"));
        } catch (Exception invalid) {
            throw new IllegalArgumentException("invalid proxy URI");
        }
        if (!empty(uri.getRawPath())) {
            throw new IllegalArgumentException("proxy URI path is not representable");
        }
        String host = uri.getHost();
        int port = uri.getPort();
        String user = uri.getRawUserInfo();
        if (host == null || port <= 0) {
            int scheme = work.indexOf("://");
            int at = work.indexOf('@', scheme + 3);
            int query = work.indexOf('?', at + 1);
            if (at < 0) throw new IllegalArgumentException("proxy endpoint is missing");
            HostPort endpoint = parseHostPort(work.substring(at + 1, query < 0 ? work.length() : query));
            host = endpoint.host;
            port = endpoint.port;
            user = work.substring(scheme + 3, at);
        }
        Map<String, String> params = parseQuery(uri.getRawQuery());
        rejectUnsupportedFunctionalParams(params);
        return new Parsed(decode(user), host, port, params, name, Collections.emptyList());
    }

    private static Parsed parseHysteria2Standard(String value) throws Exception {
        String name = fragmentName(value);
        String work = value;
        int hash = work.indexOf('#');
        if (hash >= 0) work = work.substring(0, hash);
        int scheme = work.indexOf("://");
        if (scheme < 0) throw new IllegalArgumentException("invalid Hysteria2 URI");
        int queryIndex = work.indexOf('?', scheme + 3);
        String authorityAndPath = work.substring(scheme + 3, queryIndex < 0 ? work.length() : queryIndex);
        int slash = authorityAndPath.indexOf('/');
        if (slash >= 0 && !"/".equals(authorityAndPath.substring(slash))) {
            throw new IllegalArgumentException("Hysteria2 URI path is not representable");
        }
        String authority = slash < 0 ? authorityAndPath : authorityAndPath.substring(0, slash);
        int at = authority.lastIndexOf('@');
        String rawUser = at < 0 ? "" : authority.substring(0, at);
        String endpoint = at < 0 ? authority : authority.substring(at + 1);
        if (endpoint.isEmpty()) throw new IllegalArgumentException("proxy endpoint is missing");

        String host;
        String portExpression = "";
        if (endpoint.startsWith("[")) {
            int close = endpoint.indexOf(']');
            if (close <= 0) throw new IllegalArgumentException("invalid IPv6 endpoint");
            host = endpoint.substring(1, close);
            if (close + 1 < endpoint.length()) {
                if (endpoint.charAt(close + 1) != ':') throw new IllegalArgumentException("invalid IPv6 endpoint");
                portExpression = endpoint.substring(close + 2);
                if (portExpression.isEmpty()) {
                    throw new IllegalArgumentException("invalid Hysteria2 port list");
                }
            }
        } else {
            int separator = endpoint.indexOf(':');
            if (separator >= 0) {
                if (separator == 0 || separator != endpoint.lastIndexOf(':')) {
                    throw new IllegalArgumentException(
                            "unbracketed Hysteria2 IPv6 endpoint");
                }
                host = endpoint.substring(0, separator);
                portExpression = endpoint.substring(separator + 1);
                if (portExpression.isEmpty()) {
                    throw new IllegalArgumentException("invalid Hysteria2 port list");
                }
            } else {
                host = endpoint;
            }
        }
        require(host, "Hysteria2 server");
        PortList ports = parseHysteria2Ports(portExpression);
        String query = queryIndex < 0 ? null : work.substring(queryIndex + 1);
        return new Parsed(decode(rawUser), decode(host), ports.firstPort,
                checkedParams(parseQuery(query)), name, ports.serverPorts);
    }

    private static Map<String, String> checkedParams(Map<String, String> params) {
        rejectUnsupportedFunctionalParams(params);
        return params;
    }

    private static void rejectUnsupportedFunctionalParams(Map<String, String> params) {
        for (String key : params.keySet()) {
            String normalized = key == null ? "" : key.replace("-", "_")
                    .toLowerCase(Locale.US);
            String compact = normalized.replace("_", "");
            if (compact.equals("detour") || compact.equals("proxysettings")
                    || compact.equals("sendthrough") || compact.equals("mux")
                    || compact.startsWith("bind") || compact.endsWith("strategy")
                    || compact.startsWith("dns") || compact.startsWith("routing")
                    || compact.equals("dialerproxy") || compact.equals("interfacename")) {
                throw new IllegalArgumentException("unsupported proxy parameter: " + normalized);
            }
        }
    }

    private static void rejectUnknownStreamParams(Map<String, String> params, String label,
                                                  String... protocolSpecific) {
        HashSet<String> allowed = new HashSet<>();
        Collections.addAll(allowed, STREAM_PARAMS);
        Collections.addAll(allowed, protocolSpecific);
        rejectUnknownParams(params, label, allowed);
    }

    private static void rejectUnknownParams(Map<String, String> params, String label,
                                            String... allowedValues) {
        HashSet<String> allowed = new HashSet<>();
        Collections.addAll(allowed, allowedValues);
        rejectUnknownParams(params, label, allowed);
    }

    private static void rejectUnknownParams(Map<String, String> params, String label,
                                            HashSet<String> allowed) {
        for (String key : params.keySet()) {
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException(
                        "unsupported " + label + " parameter: " + key);
            }
        }
    }

    private static PortList parseHysteria2Ports(String expression) {
        String value = expression == null ? "" : expression.trim();
        if (value.isEmpty()) return new PortList(443, Collections.emptyList());
        List<String> normalized = new ArrayList<>();
        BitSet selectedPorts = new BitSet(65536);
        int expandedPorts = 0;
        int firstPort = 0;
        boolean multiple = false;
        for (String raw : value.split(",", -1)) {
            String item = raw.trim();
            if (item.isEmpty()) throw new IllegalArgumentException("invalid Hysteria2 port list");
            int range = item.indexOf('-');
            if (range < 0) {
                int port = intValue(item, 0);
                requirePort(port);
                if (firstPort == 0) firstPort = port;
                if (selectedPorts.get(port)) {
                    throw new IllegalArgumentException("duplicate Hysteria2 port");
                }
                selectedPorts.set(port);
                if (++expandedPorts > MAX_HYSTERIA2_EXPANDED_PORTS) {
                    throw new IllegalArgumentException("Hysteria2 port list is too large");
                }
                // sing-quic's hopping parser requires an explicit range for
                // every list entry, including a singleton.
                normalized.add(port + ":" + port);
            } else {
                int start = intValue(item.substring(0, range), 0);
                int end = intValue(item.substring(range + 1), 0);
                requirePort(start);
                requirePort(end);
                if (start > end) throw new IllegalArgumentException("invalid Hysteria2 port range");
                if (firstPort == 0) firstPort = start;
                long width = (long) end - start + 1L;
                if ((long) expandedPorts + width > MAX_HYSTERIA2_EXPANDED_PORTS) {
                    throw new IllegalArgumentException("Hysteria2 port list is too large");
                }
                int duplicate = selectedPorts.nextSetBit(start);
                if (duplicate >= 0 && duplicate <= end) {
                    throw new IllegalArgumentException("duplicate Hysteria2 port");
                }
                selectedPorts.set(start, end + 1);
                expandedPorts += (int) width;
                normalized.add(start + ":" + end);
                multiple = true;
            }
        }
        if (normalized.size() > 1) multiple = true;
        return new PortList(firstPort, multiple ? normalized : Collections.emptyList());
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new TreeMap<>();
        if (query == null || query.isEmpty()) return result;
        for (String pair : query.split("&", -1)) {
            if (pair.isEmpty()) throw new IllegalArgumentException("empty proxy parameter");
            int separator = pair.indexOf('=');
            String key = separator < 0 ? pair : pair.substring(0, separator);
            String value = separator < 0 ? "" : pair.substring(separator + 1);
            String decodedKey = decode(key);
            if (decodedKey.isEmpty()) throw new IllegalArgumentException("empty proxy parameter name");
            if (result.containsKey(decodedKey)) {
                throw new IllegalArgumentException("duplicate proxy parameter: " + decodedKey);
            }
            result.put(decodedKey, decode(value));
        }
        return result;
    }

    private static HostPort parseHostPort(String value) {
        String work = value.trim();
        String host;
        String portValue;
        if (work.startsWith("[")) {
            int close = work.indexOf(']');
            if (close <= 0 || close + 2 > work.length() || work.charAt(close + 1) != ':') {
                throw new IllegalArgumentException("invalid IPv6 endpoint");
            }
            host = work.substring(1, close);
            portValue = work.substring(close + 2);
        } else {
            int separator = work.lastIndexOf(':');
            if (separator <= 0) throw new IllegalArgumentException("proxy port is missing");
            host = work.substring(0, separator);
            portValue = work.substring(separator + 1);
        }
        int port = intValue(portValue, 0);
        requirePort(port);
        return new HostPort(host, port);
    }

    private static String fragmentName(String value) {
        int hash = value.indexOf('#');
        return cleanName(hash < 0 ? "" : decode(value.substring(hash + 1)));
    }

    private static String cleanName(String value) {
        String result = value == null ? "" : value.replaceAll("[\\p{Cntrl}]", " ").trim()
                .replaceAll("\\s{2,}", " ");
        if (result.isEmpty()) result = I18n.t("Сервер", "Server");
        int points = result.codePointCount(0, result.length());
        if (points > 120) result = result.substring(
                0, result.offsetByCodePoints(0, 120));
        return result;
    }

    private static String decodeMaybeBase64(String value) {
        if (value.contains(":")) return decode(value);
        try {
            return decodeBase64Text(value);
        } catch (Exception ignored) {
            return decode(value);
        }
    }

    private static String decodeBase64Text(String value) {
        String normalized = value.trim().replace('-', '+').replace('_', '/');
        while ((normalized.length() & 3) != 0) normalized += "=";
        final byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("invalid base64 payload");
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(decoded)).toString();
        } catch (java.nio.charset.CharacterCodingException invalid) {
            throw new IllegalArgumentException("base64 payload is not valid UTF-8");
        }
    }

    private static String decode(String value) {
        if (value == null) return "";
        StringBuilder output = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); ) {
            if (value.charAt(index) != '%') {
                output.append(value.charAt(index++));
                continue;
            }
            ByteArrayOutputStream encoded = new ByteArrayOutputStream();
            while (index < value.length() && value.charAt(index) == '%') {
                if (index + 2 >= value.length()) {
                    throw new IllegalArgumentException("invalid percent encoding");
                }
                int high = Character.digit(value.charAt(index + 1), 16);
                int low = Character.digit(value.charAt(index + 2), 16);
                if (high < 0 || low < 0) {
                    throw new IllegalArgumentException("invalid percent encoding");
                }
                encoded.write((high << 4) | low);
                index += 3;
            }
            try {
                output.append(StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(encoded.toByteArray())));
            } catch (java.nio.charset.CharacterCodingException invalid) {
                throw new IllegalArgumentException("invalid percent encoding");
            }
        }
        return output.toString();
    }

    private static String value(Map<String, String> values, String key, String fallback) {
        String value = values.get(key);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static String valueAny(Map<String, String> values, String... keys) {
        String selected = null;
        String result = "";
        for (String key : keys) {
            if (!values.containsKey(key)) continue;
            if (selected != null) {
                throw new IllegalArgumentException(
                        "duplicate proxy parameter aliases: " + selected + "/" + key);
            }
            selected = key;
            String found = values.get(key);
            result = found == null ? "" : found;
        }
        return result;
    }

    private static boolean containsAny(Map<String, String> values, String... keys) {
        for (String key : keys) {
            if (values.containsKey(key)) return true;
        }
        return false;
    }

    private static int boundedIntegerParam(String value, String label,
                                           int minimum, int maximum) {
        String normalized = value == null ? "" : value.trim();
        if (!normalized.matches("[0-9]+")) {
            throw new IllegalArgumentException("invalid " + label);
        }
        try {
            long parsed = Long.parseLong(normalized);
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalArgumentException("invalid " + label);
            }
            return (int) parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("invalid " + label);
        }
    }

    private static int strictJsonInteger(JSONObject owner, String key, int fallback,
                                         int minimum, int maximum) {
        if (!owner.has(key)) return fallback;
        Object raw = owner.opt(key);
        long parsed;
        if (raw instanceof Byte || raw instanceof Short
                || raw instanceof Integer || raw instanceof Long) {
            parsed = ((Number) raw).longValue();
        } else if (raw instanceof String && ((String) raw).matches("0|[1-9][0-9]*")) {
            try {
                parsed = Long.parseLong((String) raw);
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("invalid VMess " + key);
            }
        } else {
            throw new IllegalArgumentException("invalid VMess " + key);
        }
        if (parsed < minimum || parsed > maximum) {
            throw new IllegalArgumentException("invalid VMess " + key);
        }
        return (int) parsed;
    }

    private static boolean strictBooleanParam(Map<String, String> params, String... keys) {
        String selectedKey = null;
        String selectedValue = null;
        for (String key : keys) {
            if (!params.containsKey(key)) continue;
            if (selectedKey != null) {
                throw new IllegalArgumentException(
                        "duplicate boolean proxy parameter: " + selectedKey + "/" + key);
            }
            selectedKey = key;
            selectedValue = params.get(key);
        }
        if (selectedKey == null) return false;
        String normalized = selectedValue == null ? ""
                : selectedValue.trim().toLowerCase(Locale.US);
        if (normalized.equals("1") || normalized.equals("true")
                || normalized.equals("yes") || normalized.equals("on")) return true;
        if (normalized.equals("0") || normalized.equals("false")
                || normalized.equals("no") || normalized.equals("off")) return false;
        throw new IllegalArgumentException("invalid boolean proxy parameter: " + selectedKey);
    }

    private static int parseBandwidthMbps(String value, String protocol, String label,
                                          int maximum) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.US);
        if (normalized.isEmpty()) return 0;
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("^([0-9]+)\\s*(?:mbps|m)?$").matcher(normalized);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                    "invalid " + protocol + " " + label + " bandwidth");
        }
        try {
            long parsed = Long.parseLong(matcher.group(1));
            if (parsed > maximum) {
                throw new IllegalArgumentException(
                        "invalid " + protocol + " " + label + " bandwidth");
            }
            return (int) parsed;
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException(
                    "invalid " + protocol + " " + label + " bandwidth");
        }
    }

    private static int intValue(Object value, int fallback) {
        try {
            return Integer.parseInt(String.valueOf(value));
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static void require(String value, String label) {
        if (empty(value)) throw new IllegalArgumentException(label + " is missing");
    }

    private static void requireOpaque(String value, String label) {
        if (exactEmpty(value)) throw new IllegalArgumentException(label + " is missing");
    }

    private static void requirePort(int value) {
        if (value <= 0 || value > 65535) throw new IllegalArgumentException("invalid proxy port");
    }

    private static boolean empty(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static boolean exactEmpty(String value) {
        return value == null || value.isEmpty();
    }

    private static void normalizeNeutralOutbound(JSONObject outbound) throws Exception {
        if (outbound == null || !(outbound.opt("type") instanceof String)) return;
        String protocol = outbound.optString("type", "").toLowerCase(Locale.US);
        if (protocol.equals("shadowsocks")) {
            Object rawMethod = outbound.opt("method");
            if (rawMethod instanceof String) {
                String method = canonicalShadowsocksMethod((String) rawMethod);
                outbound.put("method", method);
                Object rawPassword = outbound.opt("password");
                if (rawPassword instanceof String && isShadowsocks2022(method)) {
                    outbound.put("password", canonicalShadowsocks2022Password(
                            (String) rawPassword));
                }
            }
        }

        JSONObject tls = outbound.optJSONObject("tls");
        JSONObject utls = tls == null ? null : tls.optJSONObject("utls");
        if (utls != null && utls.opt("fingerprint") instanceof String) {
            utls.put("fingerprint", utls.optString("fingerprint", "")
                    .toLowerCase(Locale.US));
        }

        JSONObject transport = outbound.optJSONObject("transport");
        if (transport == null) return;
        Object rawTransportType = transport.opt("type");
        if (rawTransportType instanceof String) {
            transport.put("type", canonicalTransportType((String) rawTransportType));
        }
        String transportType = transport.optString("type", "").toLowerCase(Locale.US);
        if (transportType.equals("ws")) {
            String fallbackHost = tls == null
                    ? outbound.optString("server", "")
                    : tls.optString("server_name", outbound.optString("server", ""));
            normalizeWebSocketHost(transport, fallbackHost);
            return;
        }
        boolean httpUpgrade = transportType.equals("httpupgrade");
        boolean http = transportType.equals("http");
        if (!httpUpgrade && !http) return;
        String label = httpUpgrade ? "HTTPUpgrade" : "HTTP";
        JSONObject headers = transport.optJSONObject("headers");
        if (headers == null) return;
        String hostKey = null;
        Iterator<String> keys = headers.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!"host".equalsIgnoreCase(key)) continue;
            if (hostKey != null) {
                throw new IllegalArgumentException(
                        "duplicate " + label + " Host header");
            }
            hostKey = key;
        }
        if (hostKey == null) return;
        Object rawHost = headers.opt(hostKey);
        String headerHost;
        if (rawHost instanceof String) {
            headerHost = (String) rawHost;
        } else if (rawHost instanceof JSONArray
                && ((JSONArray) rawHost).length() == 1
                && ((JSONArray) rawHost).opt(0) instanceof String) {
            headerHost = ((JSONArray) rawHost).optString(0);
        } else {
            throw new IllegalArgumentException(
                    label + " Host header must contain one value");
        }
        if (empty(headerHost) || utf8Exceeds(headerHost, 1024)
                || containsWhitespaceOrControl(headerHost)) {
            throw new IllegalArgumentException("invalid " + label + " Host header");
        }
        if (transport.has("host")) {
            Object existing = transport.opt("host");
            String existingHost;
            if (httpUpgrade && existing instanceof String) {
                existingHost = (String) existing;
            } else if (http && existing instanceof JSONArray
                    && ((JSONArray) existing).length() == 1
                    && ((JSONArray) existing).opt(0) instanceof String) {
                existingHost = ((JSONArray) existing).optString(0);
            } else {
                throw new IllegalArgumentException("invalid " + label + " Host value");
            }
            if (!headerHost.equals(existingHost)) {
                throw new IllegalArgumentException("conflicting " + label + " Host values");
            }
        }
        transport.put("host", httpUpgrade ? headerHost : new JSONArray().put(headerHost));
        headers.remove(hostKey);
        if (headers.length() == 0) transport.remove("headers");
    }

    /**
     * Rejects addresses that can never carry a tunnel. Subscriptions gate on
     * the client User-Agent and answer an unrecognised one with entries whose
     * names spell out a message and whose address is the unspecified one, so
     * accepting them would report a server count made entirely of nodes that
     * cannot connect.
     */
    static final String UNREACHABLE_SERVER = "proxy server is unreachable";

    static boolean isUnreachableServer(String server) {
        String value = server == null ? "" : server.trim();
        if (value.startsWith("[") && value.endsWith("]") && value.length() > 2) {
            value = value.substring(1, value.length() - 1);
        }
        if (value.isEmpty()) return true;
        String lower = value.toLowerCase(Locale.US);
        int zone = lower.indexOf('%');
        if (zone >= 0) lower = lower.substring(0, zone);
        // Only the unspecified address is rejected. It is what the placeholder
        // entries use and it can never be dialled, while loopback is left alone
        // so a hand-written node pointing at a local proxy still works.
        return lower.equals("0.0.0.0") || lower.equals("::") || lower.equals("::0")
                || lower.equals("0:0:0:0:0:0:0:0");
    }

    static void validateNeutralOutbound(JSONObject outbound) {
        if (outbound == null) throw new IllegalArgumentException("neutral outbound is missing");
        AtomicStore.jsonUtf8Size(outbound, AtomicStore.MAX_JSON_BYTES);
        String protocol = neutralString(outbound, "type", true, false, 32);
        String server = neutralString(outbound, "server", true, false, 1024);
        if (isUnreachableServer(server)) {
            throw new IllegalArgumentException(UNREACHABLE_SERVER);
        }
        if (containsWhitespaceOrControl(server)) {
            throw new IllegalArgumentException("invalid neutral proxy server");
        }
        neutralInteger(outbound, "server_port", true, 1, 65535);

        switch (protocol) {
            case "vless":
                requireOnlyNeutralKeys(outbound, "VLESS outbound", "type", "server",
                        "server_port", "uuid", "encryption", "packet_encoding", "flow",
                        "tls", "transport");
                validateUserId(neutralOpaqueString(
                                outbound, "uuid", true, false, MAX_URI_BYTES),
                        "VLESS user ID");
                String encryption = neutralString(
                        outbound, "encryption", true, false, MAX_URI_BYTES);
                if (!xrayVlessEncryption(encryption)) {
                    throw new IllegalArgumentException("unsupported VLESS encryption");
                }
                if (outbound.has("packet_encoding")) {
                    String packetEncoding = neutralString(outbound, "packet_encoding",
                            true, true, 32).toLowerCase(Locale.US);
                    if (!packetEncoding.isEmpty() && !packetEncoding.equals("xudp")
                            && !packetEncoding.equals("packetaddr")) {
                        throw new IllegalArgumentException("unsupported neutral packet encoding");
                    }
                }
                if (outbound.has("flow")) {
                    String flow = neutralString(outbound, "flow", true, false, 256);
                    if (!flow.equals("xtls-rprx-vision")
                            && !flow.equals("xtls-rprx-vision-udp443")) {
                        throw new IllegalArgumentException("unsupported neutral VLESS flow");
                    }
                }
                validateOptionalTls(outbound);
                validateOptionalTransport(outbound);
                validateVlessVisionRequirements(outbound);
                break;
            case "vmess":
                requireOnlyNeutralKeys(outbound, "VMess outbound", "type", "server",
                        "server_port", "uuid", "alter_id", "security", "tls", "transport");
                validateUserId(neutralOpaqueString(
                                outbound, "uuid", true, false, MAX_URI_BYTES),
                        "VMess user ID");
                neutralInteger(outbound, "alter_id", true, 0, Integer.MAX_VALUE);
                String vmessSecurity = neutralString(
                        outbound, "security", true, false, 128);
                if (!vmessSecurity.equals(vmessSecurity.toLowerCase(Locale.US))
                        || !singBoxVmessSecurity(vmessSecurity)) {
                    throw new IllegalArgumentException("unsupported neutral VMess security");
                }
                validateOptionalTls(outbound);
                validateOptionalTransport(outbound);
                break;
            case "trojan":
                requireOnlyNeutralKeys(outbound, "Trojan outbound", "type", "server",
                        "server_port", "password", "tls", "transport");
                neutralOpaqueString(outbound, "password", true, false, MAX_URI_BYTES);
                validateOptionalTls(outbound);
                validateOptionalTransport(outbound);
                break;
            case "shadowsocks":
                requireOnlyNeutralKeys(outbound, "Shadowsocks outbound", "type", "server",
                        "server_port", "method", "password");
                String method = neutralString(outbound, "method", true, false, 128)
                        .toLowerCase(Locale.US);
                if (!singBoxShadowsocksMethod(method) && !xrayShadowsocksMethod(method)) {
                    throw new IllegalArgumentException("unsupported Shadowsocks method");
                }
                String shadowsocksPassword = neutralOpaqueString(
                        outbound, "password", true, method.equals("none"), MAX_URI_BYTES);
                if (isShadowsocks2022(method)
                        && !singBoxShadowsocks2022Password(method, shadowsocksPassword)
                        && !xrayShadowsocks2022Password(method, shadowsocksPassword)) {
                    throw new IllegalArgumentException("invalid Shadowsocks 2022 key");
                }
                break;
            case "hysteria":
                requireOnlyNeutralKeys(outbound, "Hysteria outbound", "type", "server",
                        "server_port", "tls", "auth_str", "up_mbps", "down_mbps", "obfs");
                validateRequiredTls(outbound);
                rejectQuicUtls(outbound);
                if (outbound.has("auth_str")) {
                    neutralOpaqueString(
                            outbound, "auth_str", true, false, MAX_URI_BYTES);
                }
                if (outbound.has("up_mbps")) {
                    neutralInteger(outbound, "up_mbps", true, 1, Integer.MAX_VALUE);
                }
                if (outbound.has("down_mbps")) {
                    neutralInteger(outbound, "down_mbps", true, 1, Integer.MAX_VALUE);
                }
                if (outbound.has("obfs")) {
                    neutralOpaqueString(outbound, "obfs", true, false, MAX_URI_BYTES);
                }
                break;
            case "hysteria2":
                requireOnlyNeutralKeys(outbound, "Hysteria2 outbound", "type", "server",
                        "server_port", "password", "tls", "server_ports", "hop_interval",
                        "up_mbps", "down_mbps", "obfs");
                neutralOpaqueString(outbound, "password", true, false, MAX_URI_BYTES);
                validateRequiredTls(outbound);
                rejectQuicUtls(outbound);
                validateHysteria2Ports(outbound);
                if (outbound.has("up_mbps")) {
                    neutralInteger(outbound, "up_mbps", true, 1, MAX_HYSTERIA2_MBPS);
                }
                if (outbound.has("down_mbps")) {
                    neutralInteger(outbound, "down_mbps", true, 1, MAX_HYSTERIA2_MBPS);
                }
                if (outbound.has("obfs")) validateHysteria2Obfs(outbound);
                break;
            case "tuic":
                requireOnlyNeutralKeys(outbound, "TUIC outbound", "type", "server",
                        "server_port", "uuid", "password", "congestion_control",
                        "udp_relay_mode", "tls");
                validateCanonicalUuid(neutralString(
                                outbound, "uuid", true, false, MAX_URI_BYTES),
                        "TUIC UUID");
                neutralOpaqueString(outbound, "password", true, false, MAX_URI_BYTES);
                String congestion = neutralString(outbound, "congestion_control",
                        true, false, 128).toLowerCase(Locale.US);
                if (!congestion.equals("bbr") && !congestion.equals("cubic")
                        && !congestion.equals("new_reno")) {
                    throw new IllegalArgumentException("unsupported TUIC congestion control");
                }
                String relay = neutralString(outbound, "udp_relay_mode",
                        true, false, 128).toLowerCase(Locale.US);
                if (!relay.equals("native") && !relay.equals("quic")) {
                    throw new IllegalArgumentException("unsupported TUIC UDP relay mode");
                }
                validateRequiredTls(outbound);
                rejectQuicUtls(outbound);
                break;
            default:
                throw new IllegalArgumentException("unsupported neutral proxy protocol");
        }
    }

    private static void validateOptionalTls(JSONObject outbound) {
        if (!outbound.has("tls")) return;
        validateNeutralTls(neutralObject(outbound, "tls", true));
    }

    private static void validateRequiredTls(JSONObject outbound) {
        validateNeutralTls(neutralObject(outbound, "tls", true));
    }

    private static void rejectQuicUtls(JSONObject outbound) {
        JSONObject tls = outbound.optJSONObject("tls");
        if (tls != null && tls.has("utls")) {
            throw new IllegalArgumentException(
                    "uTLS fingerprint is unsupported for QUIC proxy protocols");
        }
    }

    private static void validateNeutralTls(JSONObject tls) {
        requireOnlyNeutralKeys(tls, "TLS", "enabled", "server_name", "insecure",
                "alpn", "utls", "reality");
        if (!neutralBoolean(tls, "enabled", true)) {
            throw new IllegalArgumentException("neutral TLS must be enabled or omitted");
        }
        String serverName = neutralString(tls, "server_name", true, false, 1024);
        if (containsWhitespaceOrControl(serverName)) {
            throw new IllegalArgumentException("invalid neutral TLS server name");
        }
        neutralBoolean(tls, "insecure", true);
        if (tls.has("alpn")) {
            JSONArray alpn = neutralArray(tls, "alpn", true);
            if (alpn.length() <= 0 || alpn.length() > 16) {
                throw new IllegalArgumentException("invalid neutral TLS ALPN");
            }
            for (int i = 0; i < alpn.length(); i++) {
                Object item = alpn.opt(i);
                if (!(item instanceof String) || empty((String) item)
                        || utf8Exceeds((String) item, 255)
                        || containsControl((String) item)) {
                    throw new IllegalArgumentException("invalid neutral TLS ALPN");
                }
            }
        }
        if (tls.has("utls")) {
            JSONObject utls = neutralObject(tls, "utls", true);
            requireOnlyNeutralKeys(utls, "uTLS", "enabled", "fingerprint");
            if (!neutralBoolean(utls, "enabled", true)) {
                throw new IllegalArgumentException("neutral uTLS must be enabled or omitted");
            }
            String fingerprint = neutralString(
                    utls, "fingerprint", true, false, 128);
            boolean realityEnabled = tls.optJSONObject("reality") != null
                    && tls.optJSONObject("reality").optBoolean("enabled", false);
            if (!singBoxUtlsFingerprint(fingerprint)
                    && !xrayUtlsFingerprint(fingerprint, realityEnabled)) {
                throw new IllegalArgumentException("unsupported uTLS fingerprint");
            }
        }
        if (tls.has("reality")) {
            JSONObject reality = neutralObject(tls, "reality", true);
            requireOnlyNeutralKeys(reality, "Reality", "enabled", "public_key",
                    "short_id", "spider_x");
            if (!neutralBoolean(reality, "enabled", true)) {
                throw new IllegalArgumentException("neutral Reality must be enabled or omitted");
            }
            String publicKey = neutralString(
                    reality, "public_key", true, false, 1024);
            if (!validRealityPublicKey(publicKey)) {
                throw new IllegalArgumentException("invalid Reality public key");
            }
            String shortId = neutralString(reality, "short_id", true, true, 256);
            if (!validRealityShortId(shortId)) {
                throw new IllegalArgumentException("invalid Reality short ID");
            }
            if (reality.has("spider_x")) {
                String spiderX = neutralString(
                        reality, "spider_x", true, false, MAX_URI_BYTES);
                if (!validRealitySpiderX(spiderX)) {
                    throw new IllegalArgumentException("invalid Reality spiderX");
                }
            }
            if (!tls.has("utls")) {
                throw new IllegalArgumentException("neutral Reality requires uTLS fingerprint");
            }
        }
    }

    private static void validateOptionalTransport(JSONObject outbound) {
        if (!outbound.has("transport")) return;
        validateNeutralTransport(neutralObject(outbound, "transport", true));
    }

    private static void validateVlessVisionRequirements(JSONObject outbound) {
        String flow = outbound.optString("flow", "");
        if (!"xtls-rprx-vision".equals(flow)
                && !"xtls-rprx-vision-udp443".equals(flow)) return;
        if (!outbound.has("tls")) {
            throw new IllegalArgumentException(
                    "VLESS Vision flow requires TLS or Reality");
        }
        if (outbound.has("transport")) {
            throw new IllegalArgumentException(
                    "VLESS Vision flow requires raw TCP transport");
        }
    }

    private static void validateNeutralTransport(JSONObject transport) {
        String type = neutralString(transport, "type", true, false, 32);
        switch (type) {
            case "ws":
                requireOnlyNeutralKeys(transport, "WebSocket transport", "type", "path",
                        "headers", "max_early_data", "early_data_header_name",
                        WS_EARLY_DATA_MODE, WS_XRAY_PATH_SEMANTICS);
                String wsPath = neutralString(
                        transport, "path", true, false, MAX_URI_BYTES);
                if (containsControl(wsPath)) {
                    throw new IllegalArgumentException("invalid neutral WebSocket path");
                }
                if (!transport.has("headers")) {
                    throw new IllegalArgumentException(
                            "neutral WebSocket Host header is missing");
                }
                validateNeutralHeaders(transport, "headers");
                Object wsHost = caseInsensitiveHeader(
                        transport.optJSONObject("headers"), "host");
                if (!(wsHost instanceof String) || empty((String) wsHost)
                        || utf8Exceeds((String) wsHost, 1024)
                        || containsWhitespaceOrControl((String) wsHost)) {
                    throw new IllegalArgumentException(
                            "neutral WebSocket Host header must be singular");
                }
                boolean hasEarlyData = transport.has("max_early_data");
                boolean hasEarlyHeader = transport.has("early_data_header_name");
                boolean hasEarlyMode = transport.has(WS_EARLY_DATA_MODE);
                if ((hasEarlyHeader || hasEarlyMode) && !hasEarlyData) {
                    throw new IllegalArgumentException("incomplete neutral WebSocket early data");
                }
                if (hasEarlyData) {
                    neutralInteger(transport, "max_early_data", true, 1, 0xffff_ffffL);
                    if (hasEarlyHeader) {
                        String earlyHeader = neutralString(
                                transport, "early_data_header_name", true, false, 256);
                        if (!validHeaderName(earlyHeader)) {
                            throw new IllegalArgumentException(
                                    "invalid neutral WebSocket early-data header name");
                        }
                    }
                    if (hasEarlyMode) {
                        String mode = neutralString(transport, WS_EARLY_DATA_MODE,
                                true, false, 32);
                        if (!WS_EARLY_DATA_XRAY_PATH.equals(mode) || hasEarlyHeader) {
                            throw new IllegalArgumentException(
                                    "invalid neutral WebSocket early-data mode");
                        }
                    }
                }
                if (transport.has(WS_XRAY_PATH_SEMANTICS)
                        && !neutralBoolean(
                        transport, WS_XRAY_PATH_SEMANTICS, true)) {
                    throw new IllegalArgumentException(
                            "invalid neutral Xray WebSocket path provenance");
                }
                break;
            case "grpc":
                requireOnlyNeutralKeys(transport, "gRPC transport", "type", "service_name");
                if (transport.has("service_name")) {
                    String serviceName = neutralString(
                            transport, "service_name", true, false, MAX_URI_BYTES);
                    if (containsControl(serviceName)) {
                        throw new IllegalArgumentException("invalid neutral gRPC service name");
                    }
                }
                break;
            case "http":
                requireOnlyNeutralKeys(transport, "HTTP transport", "type", "path", "host",
                        "headers");
                String httpPath = neutralString(
                        transport, "path", true, false, MAX_URI_BYTES);
                if (containsControl(httpPath)) {
                    throw new IllegalArgumentException("invalid neutral HTTP path");
                }
                if (transport.has("host")) {
                    JSONArray hosts = neutralArray(transport, "host", true);
                    if (hosts.length() != 1 || !(hosts.opt(0) instanceof String)
                            || empty((String) hosts.opt(0))
                            || utf8Exceeds((String) hosts.opt(0), 1024)
                            || containsWhitespaceOrControl((String) hosts.opt(0))) {
                        throw new IllegalArgumentException("invalid neutral HTTP host");
                    }
                }
                if (transport.has("headers")) validateNeutralHeaders(transport, "headers");
                break;
            case "httpupgrade":
                requireOnlyNeutralKeys(transport, "HTTPUpgrade transport", "type", "path",
                        "host", "headers", "max_early_data");
                String upgradePath = neutralString(
                        transport, "path", true, false, MAX_URI_BYTES);
                if (containsControl(upgradePath)) {
                    throw new IllegalArgumentException("invalid neutral HTTPUpgrade path");
                }
                if (transport.has("host")) {
                    String host = neutralString(
                            transport, "host", true, false, 1024);
                    if (containsWhitespaceOrControl(host)) {
                        throw new IllegalArgumentException("invalid neutral HTTPUpgrade host");
                    }
                }
                if (transport.has("headers")) {
                    validateNeutralHeaders(transport, "headers");
                    JSONObject headers = transport.optJSONObject("headers");
                    Iterator<String> headerNames = headers.keys();
                    while (headerNames.hasNext()) {
                        if ("host".equalsIgnoreCase(headerNames.next())) {
                            throw new IllegalArgumentException(
                                    "HTTPUpgrade headers cannot contain Host");
                        }
                    }
                }
                if (transport.has("max_early_data")) {
                    neutralInteger(
                            transport, "max_early_data", true, 1, 0xffff_ffffL);
                }
                break;
            case "xhttp":
                requireOnlyNeutralKeys(transport, "XHTTP transport", "type", "path", "host",
                        "mode", "extra");
                String xhttpPath = neutralString(
                        transport, "path", true, false, MAX_URI_BYTES);
                if (containsControl(xhttpPath)) {
                    throw new IllegalArgumentException("invalid neutral XHTTP path");
                }
                if (transport.has("host")) {
                    String host = neutralString(
                            transport, "host", true, false, 1024);
                    if (containsWhitespaceOrControl(host)) {
                        throw new IllegalArgumentException("invalid neutral XHTTP host");
                    }
                }
                String mode = neutralString(transport, "mode", true, false, 32);
                if (!mode.equals("auto") && !mode.equals("packet-up")
                        && !mode.equals("stream-up") && !mode.equals("stream-one")) {
                    throw new IllegalArgumentException("unsupported neutral XHTTP mode");
                }
                if (transport.has("extra")) {
                    validateXhttpExtra(neutralObject(transport, "extra", true));
                }
                break;
            case "mkcp":
                validateNeutralMkcp(transport);
                break;
            default:
                throw new IllegalArgumentException("unsupported neutral transport");
        }
    }

    private static void validateNeutralMkcp(JSONObject transport) {
        requireOnlyNeutralKeys(transport, "mKCP transport", "type", "mtu", "tti",
                "uplink_capacity", "downlink_capacity", "cwnd_multiplier",
                "max_sending_window", "legacy_header", "legacy_seed");
        long mtu = transport.has("mtu")
                ? neutralInteger(transport, "mtu", true, 21, 65535) : 1350L;
        if (transport.has("downlink_capacity")) {
            neutralInteger(transport, "downlink_capacity", true, 0, 4095);
        }
        long tti = transport.has("tti")
                ? neutralInteger(transport, "tti", true, 10, 1000) : 50L;
        long uplink = transport.has("uplink_capacity")
                ? neutralInteger(transport, "uplink_capacity", true, 0, 4095) : 5L;
        long cwnd = transport.has("cwnd_multiplier")
                ? neutralInteger(transport, "cwnd_multiplier", true,
                1, 0xffff_ffffL) : 1L;
        long maxSendingWindow = transport.has("max_sending_window")
                ? neutralInteger(transport, "max_sending_window", true,
                1, 0xffff_ffffL)
                : 2L * 1024L * 1024L;
        if (maxSendingWindow < mtu) {
            throw new IllegalArgumentException(
                    "neutral mKCP max sending window must be at least MTU");
        }
        long sendInFlight = Math.max(8L,
                uplink * 1024L * 1024L / mtu / (1000L / tti));
        if (sendInFlight > 0xffff_ffffL / cwnd) {
            throw new IllegalArgumentException("neutral mKCP congestion window overflows");
        }
        String header = transport.has("legacy_header")
                ? neutralString(transport, "legacy_header", true, false, 64) : "";
        if (!header.isEmpty() && !header.equals("dns") && !header.equals("dtls")
                && !header.equals("srtp") && !header.equals("utp")
                && !header.equals("wechat") && !header.equals("wireguard")) {
            throw new IllegalArgumentException("unsupported neutral mKCP header");
        }
        if (transport.has("legacy_seed")) {
            neutralOpaqueString(
                    transport, "legacy_seed", true, false, MAX_URI_BYTES);
        }
    }

    private static void validateNeutralHeaders(JSONObject owner, String key) {
        JSONObject headers = neutralObject(owner, key, true);
        try {
            AtomicStore.jsonUtf8Size(headers, 16 * 1024);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("neutral transport headers exceed 16 KiB");
        }
        Iterator<String> keys = headers.keys();
        HashSet<String> normalizedNames = new HashSet<>();
        int count = 0;
        while (keys.hasNext()) {
            String header = keys.next();
            Object raw = headers.opt(header);
            if (++count > 128 || !validHeaderName(header)
                    || !normalizedNames.add(header.toLowerCase(Locale.US))
                    || !validHeaderValue(raw)) {
                throw new IllegalArgumentException("invalid neutral transport header");
            }
        }
    }

    static boolean validHeaderName(String value) {
        if (value == null || value.isEmpty() || value.length() > 256) return false;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            boolean token = current >= '0' && current <= '9'
                    || current >= 'A' && current <= 'Z'
                    || current >= 'a' && current <= 'z'
                    || "!#$%&'*+-.^_`|~".indexOf(current) >= 0;
            if (!token) return false;
        }
        return true;
    }

    private static boolean validHeaderValue(Object raw) {
        if (raw instanceof String) {
            return ((String) raw).length() <= 4096 && !containsControl((String) raw);
        }
        if (!(raw instanceof JSONArray)) return false;
        JSONArray values = (JSONArray) raw;
        if (values.length() <= 0 || values.length() > 32) return false;
        for (int index = 0; index < values.length(); index++) {
            Object item = values.opt(index);
            if (!(item instanceof String) || ((String) item).length() > 4096
                    || containsControl((String) item)) return false;
        }
        return true;
    }

    private static boolean containsControl(String value) {
        if (value == null) return false;
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) return true;
        }
        return false;
    }

    private static boolean containsWhitespaceOrControl(String value) {
        if (value == null) return false;
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (Character.isWhitespace(current) || Character.isISOControl(current)) return true;
        }
        return false;
    }

    private static void validateHysteria2Ports(JSONObject outbound) {
        if (!outbound.has("server_ports")) {
            if (outbound.has("hop_interval")) {
                throw new IllegalArgumentException("Hysteria2 hop interval requires port list");
            }
            return;
        }
        JSONArray ports = neutralArray(outbound, "server_ports", true);
        if (ports.length() <= 0 || ports.length() > MAX_HYSTERIA2_EXPANDED_PORTS) {
            throw new IllegalArgumentException("invalid neutral Hysteria2 port list");
        }
        BitSet selectedPorts = new BitSet(65536);
        int expandedPorts = 0;
        int first = -1;
        for (int i = 0; i < ports.length(); i++) {
            Object raw = ports.opt(i);
            if (!(raw instanceof String) || !((String) raw).matches("[0-9]+:[0-9]+")) {
                throw new IllegalArgumentException("invalid neutral Hysteria2 port list");
            }
            String[] range = ((String) raw).split(":", -1);
            int start = intValue(range[0], 0);
            int end = intValue(range[1], 0);
            requirePort(start);
            requirePort(end);
            if (start > end) throw new IllegalArgumentException("invalid neutral Hysteria2 port list");
            long width = (long) end - start + 1L;
            if ((long) expandedPorts + width > MAX_HYSTERIA2_EXPANDED_PORTS) {
                throw new IllegalArgumentException("neutral Hysteria2 port list is too large");
            }
            int duplicate = selectedPorts.nextSetBit(start);
            if (duplicate >= 0 && duplicate <= end) {
                throw new IllegalArgumentException("duplicate neutral Hysteria2 port");
            }
            selectedPorts.set(start, end + 1);
            expandedPorts += (int) width;
            if (first < 0) first = start;
        }
        if (first != (int) neutralInteger(outbound, "server_port", true, 1, 65535)) {
            throw new IllegalArgumentException("Hysteria2 port list does not match endpoint");
        }
        if (outbound.has("hop_interval")) {
            validatePositiveGoDuration(neutralString(
                    outbound, "hop_interval", true, false, 64));
        }
    }

    private static void validateUserId(String value, String label) {
        // Both pinned clients derive an RFC 4122 v5 UUID for a non-UUID user
        // ID. Xray limits that compatibility form to 30 UTF-8 bytes; sing-box
        // accepts longer values, so family selection handles that difference.
        if (exactEmpty(value) || utf8Exceeds(value, MAX_URI_BYTES)) {
            throw new IllegalArgumentException("invalid " + label);
        }
    }

    private static void validateCanonicalUuid(String value, String label) {
        if (value == null || !UUID.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid " + label);
        }
    }

    private static boolean xrayUserId(String value) {
        if (exactEmpty(value)) return false;
        if (UUID.matcher(value).matches()
                || value.matches("(?i)^[0-9a-f]{32}$")) return true;
        return !utf8Exceeds(value, 30);
    }

    private static void validatePositiveGoDuration(String value) {
        String duration = value == null ? "" : value;
        boolean negative = duration.startsWith("-");
        String unsigned = duration.startsWith("+") || negative
                ? duration.substring(1) : duration;
        if (unsigned.isEmpty()) {
            throw new IllegalArgumentException("invalid Hysteria2 hop interval");
        }
        // The pinned parser accepts signed bare zero as a special case.
        // sing-quic maps every successfully parsed zero duration (including
        // composite and sub-nanosecond forms) to its 30 second default.
        if (unsigned.equals("0")) return;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                "((?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+))(ns|us|µs|μs|ms|s|m|h|d)")
                .matcher(unsigned);
        int offset = 0;
        java.math.BigInteger total = java.math.BigInteger.ZERO;
        java.math.BigInteger maximum = java.math.BigInteger.valueOf(Long.MAX_VALUE);
        while (matcher.find()) {
            if (matcher.start() != offset) {
                throw new IllegalArgumentException("invalid Hysteria2 hop interval");
            }
            long multiplier;
            switch (matcher.group(2)) {
                case "ns": multiplier = 1L; break;
                case "us":
                case "µs":
                case "μs": multiplier = 1_000L; break;
                case "ms": multiplier = 1_000_000L; break;
                case "s": multiplier = 1_000_000_000L; break;
                case "m": multiplier = 60_000_000_000L; break;
                case "h": multiplier = 3_600_000_000_000L; break;
                case "d": multiplier = 86_400_000_000_000L; break;
                default: throw new IllegalArgumentException(
                        "invalid Hysteria2 hop interval");
            }
            try {
                java.math.BigInteger component = new java.math.BigDecimal(matcher.group(1))
                        .multiply(java.math.BigDecimal.valueOf(multiplier)).toBigInteger();
                total = total.add(component);
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("invalid Hysteria2 hop interval");
            }
            if (total.compareTo(maximum) > 0) {
                throw new IllegalArgumentException("invalid Hysteria2 hop interval");
            }
            offset = matcher.end();
        }
        if (offset != unsigned.length() || negative && total.signum() > 0) {
            throw new IllegalArgumentException("invalid Hysteria2 hop interval");
        }
    }

    private static boolean singBoxShadowsocksMethod(String method) {
        switch (method == null ? "" : method.toLowerCase(Locale.US)) {
            case "none":
            case "aes-128-gcm":
            case "aes-192-gcm":
            case "aes-256-gcm":
            case "chacha20-ietf-poly1305":
            case "xchacha20-ietf-poly1305":
            case "2022-blake3-aes-128-gcm":
            case "2022-blake3-aes-256-gcm":
            case "2022-blake3-chacha20-poly1305":
            case "aes-128-ctr":
            case "aes-192-ctr":
            case "aes-256-ctr":
            case "aes-128-cfb":
            case "aes-192-cfb":
            case "aes-256-cfb":
            case "rc4-md5":
            case "chacha20-ietf":
            case "xchacha20":
                return true;
            default:
                return false;
        }
    }

    static String canonicalShadowsocksMethod(String method) {
        String normalized = method == null ? "" : method.toLowerCase(Locale.US);
        switch (normalized) {
            case "plain":
            case "dummy":
                // Pinned sing-shadowsocks 0.2.8 resolves both aliases through
                // FetchMethod to NewNone. Store one neutral spelling so
                // selection, password rules and deduplication agree.
                return "none";
            case "aead_aes_128_gcm":
                return "aes-128-gcm";
            case "aead_aes_256_gcm":
                return "aes-256-gcm";
            case "aead_chacha20_poly1305":
            case "chacha20-poly1305":
                return "chacha20-ietf-poly1305";
            case "aead_xchacha20_poly1305":
            case "xchacha20-poly1305":
                return "xchacha20-ietf-poly1305";
            default:
                return normalized;
        }
    }

    static String canonicalTransportType(String transport) {
        String normalized = transport == null ? ""
                : transport.toLowerCase(Locale.US);
        return normalized.equals("websocket") ? "ws" : normalized;
    }

    private static boolean singBoxVmessSecurity(String security) {
        switch (security == null ? "" : security.toLowerCase(Locale.US)) {
            case "auto":
            case "none":
            case "zero":
            case "aes-128-cfb":
            case "aes-128-gcm":
            case "chacha20-poly1305":
                return true;
            default:
                return false;
        }
    }

    static boolean xrayVmessSecurity(String security) {
        String normalized = security == null ? ""
                : security.toLowerCase(Locale.US);
        return normalized.equals("auto") || normalized.equals("aes-128-gcm")
                || normalized.equals("chacha20-poly1305");
    }

    private static boolean isShadowsocks2022(String method) {
        return "2022-blake3-aes-128-gcm".equals(method)
                || "2022-blake3-aes-256-gcm".equals(method)
                || "2022-blake3-chacha20-poly1305".equals(method);
    }

    private static int shadowsocks2022KeyBytes(String method) {
        return "2022-blake3-aes-128-gcm".equals(method) ? 16
                : isShadowsocks2022(method) ? 32 : -1;
    }

    private static String canonicalShadowsocks2022Password(String password) {
        if (password == null || password.isEmpty()
                || utf8Exceeds(password, MAX_URI_BYTES)) {
            throw new IllegalArgumentException("invalid Shadowsocks 2022 key");
        }
        String[] components = password.split(":", -1);
        StringBuilder result = new StringBuilder(password.length() + components.length * 2);
        for (int index = 0; index < components.length; index++) {
            String component = components[index];
            if (component.isEmpty()) {
                throw new IllegalArgumentException("invalid Shadowsocks 2022 key");
            }
            StringBuilder padded = new StringBuilder(
                    component.replace('-', '+').replace('_', '/'));
            while ((padded.length() & 3) != 0) padded.append('=');
            final byte[] decoded;
            try {
                decoded = Base64.getDecoder().decode(padded.toString());
            } catch (IllegalArgumentException invalid) {
                throw new IllegalArgumentException("invalid Shadowsocks 2022 key");
            }
            if (decoded.length == 0) {
                throw new IllegalArgumentException("invalid Shadowsocks 2022 key");
            }
            if (index > 0) result.append(':');
            result.append(Base64.getEncoder().encodeToString(decoded));
        }
        if (utf8Exceeds(result.toString(), MAX_URI_BYTES)) {
            throw new IllegalArgumentException("invalid Shadowsocks 2022 key");
        }
        return result.toString();
    }

    private static int[] shadowsocks2022KeyLengths(String password) {
        if (password == null || password.isEmpty()) return null;
        String[] components = password.split(":", -1);
        int[] lengths = new int[components.length];
        try {
            for (int index = 0; index < components.length; index++) {
                if (components[index].isEmpty()) return null;
                byte[] decoded = Base64.getDecoder().decode(components[index]);
                if (!components[index].equals(
                        Base64.getEncoder().encodeToString(decoded))) return null;
                lengths[index] = decoded.length;
            }
            return lengths;
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }

    private static boolean singBoxShadowsocks2022Password(
            String method, String password) {
        int expected = shadowsocks2022KeyBytes(method);
        int[] lengths = shadowsocks2022KeyLengths(password);
        if (expected < 0 || lengths == null || lengths.length == 0
                || ("2022-blake3-chacha20-poly1305".equals(method)
                && lengths.length != 1)) return false;
        // sing-shadowsocks 0.2.8 accepts keys at least as long as the salt
        // length and derives oversized keys through SHA-256.
        for (int length : lengths) if (length < expected) return false;
        return true;
    }

    private static boolean xrayShadowsocks2022Password(
            String method, String password) {
        int expected = shadowsocks2022KeyBytes(method);
        int[] lengths = shadowsocks2022KeyLengths(password);
        if (expected < 0 || lengths == null || lengths.length == 0
                || ("2022-blake3-chacha20-poly1305".equals(method)
                && lengths.length != 1)) return false;
        for (int length : lengths) if (length < expected) return false;
        return true;
    }

    private static boolean xrayShadowsocksMethod(String method) {
        switch (method == null ? "" : method.toLowerCase(Locale.US)) {
            case "aes-128-gcm":
            case "aead_aes_128_gcm":
            case "aes-256-gcm":
            case "aead_aes_256_gcm":
            case "chacha20-ietf-poly1305":
            case "chacha20-poly1305":
            case "aead_chacha20_poly1305":
            case "xchacha20-ietf-poly1305":
            case "xchacha20-poly1305":
            case "aead_xchacha20_poly1305":
            case "2022-blake3-aes-128-gcm":
            case "2022-blake3-aes-256-gcm":
            case "2022-blake3-chacha20-poly1305":
                return true;
            default:
                return false;
        }
    }

    /** Exact uTLS names accepted by sing-box v1.13.14 with with_utls. */
    private static boolean singBoxUtlsFingerprint(String fingerprint) {
        switch (fingerprint == null ? "" : fingerprint.toLowerCase(Locale.US)) {
            case "":
            case "chrome":
            case "chrome_psk":
            case "chrome_psk_shuffle":
            case "chrome_padding_psk_shuffle":
            case "chrome_pq":
            case "chrome_pq_psk":
            case "firefox":
            case "edge":
            case "safari":
            case "360":
            case "qq":
            case "ios":
            case "android":
            case "random":
            case "randomized":
                return true;
            default:
                return false;
        }
    }

    /** Exact uTLS names accepted by Xray-core 50231eaff98c. */
    private static boolean xrayUtlsFingerprint(String fingerprint, boolean reality) {
        String value = fingerprint == null ? "" : fingerprint.toLowerCase(Locale.US);
        if (reality && (value.equals("unsafe") || value.equals("hellogolang"))) {
            return false;
        }
        switch (value) {
            case "":
            case "chrome":
            case "firefox":
            case "safari":
            case "ios":
            case "android":
            case "edge":
            case "360":
            case "qq":
            case "random":
            case "randomized":
            case "randomizednoalpn":
            case "unsafe":
            case "hellogolang":
            case "hellorandomized":
            case "hellorandomizedalpn":
            case "hellorandomizednoalpn":
            case "hellofirefox_auto":
            case "hellofirefox_55":
            case "hellofirefox_56":
            case "hellofirefox_63":
            case "hellofirefox_65":
            case "hellofirefox_99":
            case "hellofirefox_102":
            case "hellofirefox_105":
            case "hellofirefox_120":
            case "hellofirefox_148":
            case "hellochrome_auto":
            case "hellochrome_58":
            case "hellochrome_62":
            case "hellochrome_70":
            case "hellochrome_72":
            case "hellochrome_83":
            case "hellochrome_87":
            case "hellochrome_96":
            case "hellochrome_100":
            case "hellochrome_102":
            case "hellochrome_106_shuffle":
            case "hellochrome_120":
            case "hellochrome_131":
            case "hellochrome_133":
            case "helloios_auto":
            case "helloios_11_1":
            case "helloios_12_1":
            case "helloios_13":
            case "helloios_14":
            case "helloandroid_11_okhttp":
            case "helloedge_auto":
            case "helloedge_85":
            case "helloedge_106":
            case "hellosafari_auto":
            case "hellosafari_16_0":
            case "hellosafari_26_3":
            case "hello360_auto":
            case "hello360_7_5":
            case "hello360_11_0":
            case "helloqq_auto":
            case "helloqq_11_1":
            case "hellochrome_100_psk":
            case "hellochrome_112_psk_shuf":
            case "hellochrome_114_padding_psk_shuf":
            case "hellochrome_115_pq":
            case "hellochrome_115_pq_psk":
            case "hellochrome_120_pq":
                return true;
            default:
                return false;
        }
    }

    private static boolean validRealityPublicKey(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{43}")) return false;
        try {
            return Base64.getUrlDecoder().decode(value).length == 32;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static boolean validRealityShortId(String value) {
        if (value == null || value.length() > 16 || (value.length() & 1) != 0) {
            return false;
        }
        return value.matches("(?i)[0-9a-f]*");
    }

    private static boolean validRealitySpiderX(String value) {
        if (value == null || !value.startsWith("/") || containsControl(value)) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) != '%') continue;
            if (index + 2 >= value.length()
                    || Character.digit(value.charAt(index + 1), 16) < 0
                    || Character.digit(value.charAt(index + 2), 16) < 0) {
                return false;
            }
            index += 2;
        }
        return true;
    }

    /** Mirrors the VLESS outbound encryption parser in Xray-core 50231eaff98c. */
    private static boolean xrayVlessEncryption(String encryption) {
        if ("none".equals(encryption)) return true;
        String[] parts = encryption == null ? new String[0]
                : encryption.split("\\.", -1);
        if (parts.length < 4 || !"mlkem768x25519plus".equals(parts[0])) return false;
        if (!"native".equals(parts[1]) && !"xorpub".equals(parts[1])
                && !"random".equals(parts[1])) return false;
        if (!"1rtt".equals(parts[2]) && !"0rtt".equals(parts[2])) return false;

        boolean keySeen = false;
        int paddingIndex = 0;
        long maximumPadding = 0L;
        for (int index = 3; index < parts.length; index++) {
            String item = parts[index];
            // The conf layer treats short leading segments as a dot-separated
            // padding prefix. ClientInstance.Init later requires at least one
            // decoded key and ParsePadding validates every prefix triple.
            if (item.length() < 20) {
                if (keySeen || item.isEmpty()) return false;
                String[] triple = item.split("-", -1);
                if (triple.length != 3) return false;
                int chance;
                int from;
                int to;
                try {
                    // Keep untrusted padding probabilities, lengths and gaps
                    // inside a deliberately bounded signed range even though
                    // the arm64 Go core uses a wider int.
                    chance = Integer.parseInt(triple[0]);
                    from = Integer.parseInt(triple[1]);
                    to = Integer.parseInt(triple[2]);
                } catch (NumberFormatException invalid) {
                    return false;
                }
                if (paddingIndex == 0 && (chance < 100 || from < 35 || to < 35)) {
                    return false;
                }
                if ((paddingIndex & 1) == 0) {
                    maximumPadding += Math.max(from, to);
                    if (maximumPadding > 65_553L) return false;
                }
                paddingIndex++;
                continue;
            }
            keySeen = true;
            if (!item.matches("[A-Za-z0-9_-]+")) return false;
            StringBuilder padded = new StringBuilder(item);
            while ((padded.length() & 3) != 0) padded.append('=');
            try {
                int length = Base64.getUrlDecoder().decode(padded.toString()).length;
                if (length != 32 && length != 1184) return false;
            } catch (IllegalArgumentException invalid) {
                return false;
            }
        }
        return keySeen;
    }

    private static void validateHysteria2Obfs(JSONObject outbound) {
        JSONObject obfs = neutralObject(outbound, "obfs", true);
        requireOnlyNeutralKeys(obfs, "Hysteria2 obfs", "type", "password");
        String type = neutralString(obfs, "type", true, false, 32);
        if (!type.equals("salamander")) {
            throw new IllegalArgumentException("unsupported neutral Hysteria2 obfs");
        }
        neutralOpaqueString(obfs, "password", true, false, MAX_URI_BYTES);
    }

    private static void requireOnlyNeutralKeys(JSONObject value, String label,
                                               String... allowedValues) {
        java.util.HashSet<String> allowed = new java.util.HashSet<>();
        Collections.addAll(allowed, allowedValues);
        Iterator<String> keys = value.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException("unsupported " + label + " field: " + key);
            }
        }
    }

    private static String neutralString(JSONObject value, String key, boolean required,
                                        boolean allowEmpty, int maximumBytes) {
        if (!value.has(key)) {
            if (required) throw new IllegalArgumentException("neutral field is missing: " + key);
            return "";
        }
        Object raw = value.opt(key);
        if (!(raw instanceof String)) {
            throw new IllegalArgumentException("neutral field must be a string: " + key);
        }
        String result = (String) raw;
        if ((!allowEmpty && empty(result)) || utf8Exceeds(result, maximumBytes)) {
            throw new IllegalArgumentException("invalid neutral string field: " + key);
        }
        return result;
    }

    private static String neutralOpaqueString(JSONObject value, String key, boolean required,
                                              boolean allowEmpty, int maximumBytes) {
        if (!value.has(key)) {
            if (required) throw new IllegalArgumentException("neutral field is missing: " + key);
            return "";
        }
        Object raw = value.opt(key);
        if (!(raw instanceof String)) {
            throw new IllegalArgumentException("neutral field must be a string: " + key);
        }
        String result = (String) raw;
        if ((!allowEmpty && exactEmpty(result)) || utf8Exceeds(result, maximumBytes)) {
            throw new IllegalArgumentException("invalid neutral string field: " + key);
        }
        return result;
    }

    private static long neutralInteger(JSONObject value, String key, boolean required,
                                       long minimum, long maximum) {
        if (!value.has(key)) {
            if (required) throw new IllegalArgumentException("neutral field is missing: " + key);
            return Long.MIN_VALUE;
        }
        Object raw = value.opt(key);
        if (!(raw instanceof Number)) {
            throw new IllegalArgumentException("neutral field must be an integer: " + key);
        }
        String encoded = String.valueOf(raw);
        if (!encoded.matches("-?[0-9]+")) {
            throw new IllegalArgumentException("neutral field must be an integer: " + key);
        }
        try {
            long parsed = Long.parseLong(encoded);
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalArgumentException("neutral integer is out of range: " + key);
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("neutral field must be an integer: " + key);
        }
    }

    private static boolean neutralBoolean(JSONObject value, String key, boolean required) {
        if (!value.has(key)) {
            if (required) throw new IllegalArgumentException("neutral field is missing: " + key);
            return false;
        }
        Object raw = value.opt(key);
        if (!(raw instanceof Boolean)) {
            throw new IllegalArgumentException("neutral field must be boolean: " + key);
        }
        return (Boolean) raw;
    }

    private static JSONObject neutralObject(JSONObject value, String key, boolean required) {
        if (!value.has(key)) {
            if (required) throw new IllegalArgumentException("neutral object is missing: " + key);
            return null;
        }
        Object raw = value.opt(key);
        if (!(raw instanceof JSONObject)) {
            throw new IllegalArgumentException("neutral field must be an object: " + key);
        }
        return (JSONObject) raw;
    }

    private static JSONArray neutralArray(JSONObject value, String key, boolean required) {
        if (!value.has(key)) {
            if (required) throw new IllegalArgumentException("neutral array is missing: " + key);
            return null;
        }
        Object raw = value.opt(key);
        if (!(raw instanceof JSONArray)) {
            throw new IllegalArgumentException("neutral field must be an array: " + key);
        }
        return (JSONArray) raw;
    }

    private static void validateVmessSource(JSONObject source) {
        java.util.HashSet<String> allowed = new java.util.HashSet<>();
        Collections.addAll(allowed, "v", "ps", "add", "port", "id", "aid", "scy",
                "net", "type", "tls", "sni", "host", "path", "fp", "alpn", "pbk",
                "sid", "insecure", "allowInsecure", "mode", "extra", "headerType", "seed",
                "mtu", "tti", "uplinkCapacity", "downlinkCapacity", "cwndMultiplier",
                "maxSendingWindow", "ed", "eh", "earlyDataHeaderName", "headers");
        Iterator<String> keys = source.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException("unsupported VMess field: " + key);
            }
        }
        if (source.has("insecure") && source.has("allowInsecure")) {
            throw new IllegalArgumentException("duplicate VMess insecure fields");
        }
        if (source.has("headerType") && source.has("type")) {
            throw new IllegalArgumentException("duplicate VMess headerType fields");
        }
        if (source.has("eh") && source.has("earlyDataHeaderName")) {
            throw new IllegalArgumentException("duplicate VMess early-data header fields");
        }
        requireVmessStrings(source, "v", "ps", "add", "id", "scy", "net", "type",
                "tls", "sni", "host", "path", "fp", "alpn", "pbk", "sid",
                "mode", "extra", "headerType", "seed", "eh", "earlyDataHeaderName");
        requireVmessIntegers(source, "port", "aid", "mtu", "tti", "uplinkCapacity",
                "downlinkCapacity", "cwndMultiplier", "maxSendingWindow", "ed");
        requireVmessBooleans(source, "insecure", "allowInsecure");
        if (source.has("headers")) {
            Object raw = source.opt("headers");
            if (!(raw instanceof JSONObject) && !(raw instanceof String)) {
                throw new IllegalArgumentException("invalid VMess headers type");
            }
        }
    }

    private static void requireVmessStrings(JSONObject source, String... keys) {
        for (String key : keys) {
            if (source.has(key) && !(source.opt(key) instanceof String)) {
                throw new IllegalArgumentException("invalid VMess string field: " + key);
            }
        }
    }

    private static void requireVmessIntegers(JSONObject source, String... keys) {
        for (String key : keys) {
            if (!source.has(key)) continue;
            Object raw = source.opt(key);
            boolean integerNumber = raw instanceof Byte || raw instanceof Short
                    || raw instanceof Integer || raw instanceof Long;
            boolean integerString = raw instanceof String
                    && ((String) raw).matches("0|[1-9][0-9]*");
            if (!integerNumber && !integerString) {
                throw new IllegalArgumentException("invalid VMess integer field: " + key);
            }
        }
    }

    private static void requireVmessBooleans(JSONObject source, String... keys) {
        for (String key : keys) {
            if (!source.has(key)) continue;
            Object raw = source.opt(key);
            if (raw instanceof Boolean) continue;
            if (raw instanceof Byte || raw instanceof Short
                    || raw instanceof Integer || raw instanceof Long) {
                long number = ((Number) raw).longValue();
                if (number == 0L || number == 1L) continue;
            }
            if (raw instanceof String) {
                String normalized = ((String) raw).trim().toLowerCase(Locale.US);
                if (normalized.equals("0") || normalized.equals("1")
                        || normalized.equals("true") || normalized.equals("false")
                        || normalized.equals("yes") || normalized.equals("no")
                        || normalized.equals("on") || normalized.equals("off")) continue;
            }
            throw new IllegalArgumentException("invalid VMess boolean field: " + key);
        }
    }

    private static void rejectAliasConflict(Map<String, String> values, String label,
                                            String... keys) {
        String selected = null;
        for (String key : keys) {
            if (!values.containsKey(key)) continue;
            if (selected != null) {
                throw new IllegalArgumentException("duplicate " + label
                        + " aliases: " + selected + "/" + key);
            }
            selected = key;
        }
    }

    private static boolean utf8Exceeds(String value, int maximum) {
        if (value == null) return false;
        long bytes = 0L;
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (current <= 0x7f) bytes++;
            else if (current <= 0x7ff) bytes += 2;
            else if (Character.isHighSurrogate(current) && i + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(i + 1))) {
                bytes += 4;
                i++;
            } else bytes += 3;
            if (bytes > maximum) return true;
        }
        return false;
    }

    private static String nonEmpty(String value, String fallback) {
        return empty(value) ? fallback : value;
    }

    private static String opaqueNonEmpty(String value, String fallback) {
        return exactEmpty(value) ? fallback : value;
    }

    private static String sha256(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder output = new StringBuilder(64);
        for (byte item : digest) output.append(String.format(Locale.US, "%02x", item & 0xff));
        return output.toString();
    }

    private static String canonical(Object value) throws Exception {
        if (value == null || value == JSONObject.NULL) return "null";
        if (value instanceof JSONObject) {
            JSONObject object = (JSONObject) value;
            List<String> keys = new ArrayList<>();
            Iterator<String> iterator = object.keys();
            while (iterator.hasNext()) keys.add(iterator.next());
            Collections.sort(keys);
            StringBuilder output = new StringBuilder("{");
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) output.append(',');
                String key = keys.get(i);
                output.append(JSONObject.quote(key)).append(':').append(canonical(object.get(key)));
            }
            return output.append('}').toString();
        }
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            StringBuilder output = new StringBuilder("[");
            for (int i = 0; i < array.length(); i++) {
                if (i > 0) output.append(',');
                output.append(canonical(array.get(i)));
            }
            return output.append(']').toString();
        }
        if (value instanceof String) return JSONObject.quote((String) value);
        return String.valueOf(value);
    }

    static final class Node {
        final String uri;
        final String name;
        final JSONObject outbound;
        final String normalizedKey;

        Node(String uri, String name, JSONObject outbound, String normalizedKey) {
            this.uri = uri;
            this.name = name;
            this.outbound = outbound;
            this.normalizedKey = normalizedKey;
        }

        JSONObject toStoredJson() throws Exception {
            return new JSONObject().put("uri", uri).put("name", name)
                    .put("normalizedKey", normalizedKey)
                    .put("outbound", outbound);
        }

        boolean supports(CoreFamily family) {
            if (!incompatibilityReason(family).isEmpty()) return false;
            String protocol = outbound.optString("type", "");
            JSONObject transport = outbound.optJSONObject("transport");
            String network = transport == null ? "raw" : transport.optString("type", "raw");
            JSONObject tls = outbound.optJSONObject("tls");
            String flow = outbound.optString("flow", "");
            if (protocol.equals("vless")
                    && (flow.equals("xtls-rprx-vision")
                    || flow.equals("xtls-rprx-vision-udp443"))
                    && (tls == null || transport != null)) {
                return false;
            }
            if (family == CoreFamily.SING_BOX) {
                if (protocol.equals("shadowsocks") && !singBoxShadowsocksMethod(
                        outbound.optString("method", ""))) return false;
                JSONObject reality = tls == null ? null : tls.optJSONObject("reality");
                boolean spiderX = reality != null && !reality.optString("spider_x", "").isEmpty();
                return !network.equals("xhttp") && !network.equals("mkcp")
                        && !(network.equals("httpupgrade") && transport != null
                        && transport.has("max_early_data"))
                        && !spiderX
                        && (!protocol.equals("vless")
                        || "none".equalsIgnoreCase(outbound.optString("encryption", "none")));
            }
            if (!protocol.equals("vless") && !protocol.equals("vmess")
                    && !protocol.equals("trojan") && !protocol.equals("shadowsocks")) {
                return false;
            }
            if (protocol.equals("shadowsocks") && !xrayShadowsocksMethod(
                    outbound.optString("method", ""))) return false;
            if (network.equals("http")) return false;
            if (!network.equals("raw") && !network.equals("ws") && !network.equals("grpc")
                    && !network.equals("httpupgrade") && !network.equals("xhttp")
                    && !network.equals("mkcp")) {
                return false;
            }
            if ((network.equals("ws") || network.equals("httpupgrade"))
                    && !xrayHeadersRepresentable(transport)) return false;
            if (network.equals("ws") && transport != null
                    && transport.has("max_early_data")) {
                String earlyMode = transport.optString(WS_EARLY_DATA_MODE, "");
                String earlyHeader = transport.optString("early_data_header_name", "");
                boolean xrayEarlyData = WS_EARLY_DATA_XRAY_PATH.equals(earlyMode)
                        || WS_EARLY_DATA_XRAY_HEADER.equalsIgnoreCase(earlyHeader);
                if (!xrayEarlyData) return false;
            }
            boolean reality = tls != null && tls.optJSONObject("reality") != null
                    && tls.optJSONObject("reality").optBoolean("enabled", false);
            String packetEncoding = outbound.optString("packet_encoding", "");
            boolean packetEncodingSupported = !outbound.has("packet_encoding")
                    || packetEncoding.equalsIgnoreCase("xudp");
            String vmessSecurity = outbound.optString("security", "auto")
                    .toLowerCase(Locale.US);
            boolean vmessSecuritySupported = !protocol.equals("vmess")
                    || xrayVmessSecurity(vmessSecurity);
            return packetEncodingSupported && vmessSecuritySupported
                    && (!reality || network.equals("raw")
                    || network.equals("xhttp") || network.equals("grpc"));
        }

        String incompatibilityReason(CoreFamily family) {
            return ProtocolParser.incompatibilityReason(outbound, family);
        }

        private static boolean xrayHeadersRepresentable(JSONObject transport) {
            if (transport == null) return true;
            JSONObject headers = transport.optJSONObject("headers");
            if (headers == null) return true;
            Iterator<String> keys = headers.keys();
            while (keys.hasNext()) {
                Object raw = headers.opt(keys.next());
                if (raw instanceof JSONArray && ((JSONArray) raw).length() != 1) return false;
            }
            return true;
        }

    }

    private static final class Parsed {
        final String user;
        final String host;
        final int port;
        final Map<String, String> params;
        final String name;

        final List<String> serverPorts;

        Parsed(String user, String host, int port, Map<String, String> params, String name,
               List<String> serverPorts) {
            this.user = user;
            this.host = host;
            this.port = port;
            this.params = params;
            this.name = name;
            this.serverPorts = serverPorts == null ? Collections.emptyList() : serverPorts;
        }
    }

    private static final class ParsedSs {
        final JSONObject outbound;
        final String name;

        ParsedSs(JSONObject outbound, String name) {
            this.outbound = outbound;
            this.name = name;
        }
    }

    private static final class HostPort {
        final String host;
        final int port;

        HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private static final class PortList {
        final int firstPort;
        final List<String> serverPorts;

        PortList(int firstPort, List<String> serverPorts) {
            this.firstPort = firstPort;
            this.serverPorts = serverPorts;
        }
    }
}
