package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Locale;

/**
 * Sanitizes a native Xray outbound and extracts UI metadata. Protocol settings
 * are not remapped: Xray-core is the schema.
 */
final class XrayNativeOutbound {
    private static final String[] FORBIDDEN_KEYS = {
            "detour", "proxySettings", "sendThrough", "mux",
            "bind_interface", "bind_address", "inet4_bind_address", "inet6_bind_address",
            "routing_mark", "domain_strategy", "domainStrategy", "strategy", "dns"
    };
    private static final String[] SOCKOPT_FORBIDDEN = {
            "dialerProxy", "interface", "mark"
    };

    private XrayNativeOutbound() {
    }

    static boolean isTunnelProtocol(String protocol) {
        String value = protocol == null ? "" : protocol.trim();
        if (value.isEmpty() || value.length() > 64) return false;
        String lower = value.toLowerCase(Locale.US);
        return !lower.equals("freedom") && !lower.equals("blackhole")
                && !lower.equals("dns") && !lower.equals("loopback");
    }

    static JSONObject sanitize(JSONObject source) throws Exception {
        if (source == null) throw new IllegalArgumentException("Xray outbound is missing");
        AtomicStore.jsonUtf8Size(source, AtomicStore.MAX_JSON_BYTES);
        if (source.has("type")) {
            throw new IllegalArgumentException(
                    "Xray outbound requires exact protocol discriminator");
        }
        Object rawProtocol = source.opt("protocol");
        if (!(rawProtocol instanceof String)) {
            throw new IllegalArgumentException(
                    "structured discriminator must be a string: protocol");
        }
        String protocol = (String) rawProtocol;
        if (!isTunnelProtocol(protocol)) {
            throw new IllegalArgumentException(
                    "unsupported outbound discriminator: protocol");
        }
        for (String forbidden : FORBIDDEN_KEYS) {
            if (source.has(forbidden)) {
                throw new IllegalArgumentException("unsupported outbound field: " + forbidden);
            }
        }
        JSONObject copy = new JSONObject(source.toString());
        AtomicStore.jsonUtf8Size(copy, AtomicStore.MAX_JSON_BYTES);
        stripChainedSockopt(copy.optJSONObject("streamSettings"));
        HostPort endpoint = extractEndpoint(copy);
        if (ProtocolParser.isUnreachableServer(endpoint.host)) {
            throw new IllegalArgumentException(ProtocolParser.UNREACHABLE_SERVER);
        }
        if (endpoint.port <= 0 || endpoint.port > 65535) {
            throw new IllegalArgumentException("invalid proxy port");
        }
        return copy;
    }

    static JSONObject summary(JSONObject sanitized) throws Exception {
        HostPort endpoint = extractEndpoint(sanitized);
        JSONObject summary = new JSONObject()
                .put("type", sanitized.getString("protocol"))
                .put("server", endpoint.host)
                .put("server_port", endpoint.port);
        JSONObject stream = sanitized.optJSONObject("streamSettings");
        if (stream != null) {
            String network = ProtocolParser.canonicalTransportType(
                    stream.optString("network", ""));
            if (network.equals("tcp")) network = "raw";
            if (!network.isEmpty() && !network.equals("raw")) {
                summary.put("transport", new JSONObject().put("type", network));
            }
            String security = stream.optString("security", "").toLowerCase(Locale.US);
            if (security.equals("reality")) {
                summary.put("tls", new JSONObject().put("enabled", true)
                        .put("reality", new JSONObject().put("enabled", true)));
            } else if (security.equals("tls")) {
                summary.put("tls", new JSONObject().put("enabled", true));
            }
        }
        return summary;
    }

    static JSONObject runtimeOutbound(JSONObject sanitized, String tag) throws Exception {
        JSONObject copy = new JSONObject(sanitized.toString());
        stripChainedSockopt(copy.optJSONObject("streamSettings"));
        copy.put("tag", tag);
        return copy;
    }

    private static void stripChainedSockopt(JSONObject stream) {
        if (stream == null) return;
        JSONObject sockopt = stream.optJSONObject("sockopt");
        if (sockopt == null) return;
        for (String forbidden : SOCKOPT_FORBIDDEN) sockopt.remove(forbidden);
        if (sockopt.length() == 0) stream.remove("sockopt");
    }

    private static HostPort extractEndpoint(JSONObject outbound) {
        JSONObject settings = outbound.optJSONObject("settings");
        if (settings != null) {
            HostPort nested = firstServer(settings.optJSONArray("vnext"));
            if (nested == null) nested = firstServer(settings.optJSONArray("servers"));
            if (nested != null) return nested;
            String host = firstString(settings, "address", "server");
            int port = firstPort(settings, "port", "server_port");
            if (!host.isEmpty()) return new HostPort(host, port);
        }
        String host = firstString(outbound, "address", "server");
        int port = firstPort(outbound, "port", "server_port");
        return new HostPort(host, port);
    }

    private static HostPort firstServer(JSONArray values) {
        if (values == null || values.length() == 0) return null;
        JSONObject first = values.optJSONObject(0);
        if (first == null) return null;
        String host = firstString(first, "address", "server");
        int port = firstPort(first, "port", "server_port");
        if (host.isEmpty()) return null;
        return new HostPort(host, port);
    }

    private static String firstString(JSONObject owner, String... keys) {
        for (String key : keys) {
            Object raw = owner.opt(key);
            if (raw instanceof String) {
                String value = ((String) raw).trim();
                if (!value.isEmpty()) return value;
            }
        }
        return "";
    }

    private static int firstPort(JSONObject owner, String... keys) {
        for (String key : keys) {
            Object raw = owner.opt(key);
            if (raw instanceof Number) {
                int port = ((Number) raw).intValue();
                if (port > 0) return port;
            } else if (raw instanceof String) {
                try {
                    int port = Integer.parseInt(((String) raw).trim());
                    if (port > 0) return port;
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return 0;
    }

    private static final class HostPort {
        final String host;
        final int port;

        HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
}
