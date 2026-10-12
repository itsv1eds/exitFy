package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;

/** Explicit sing-box proxy objects, including the current WireGuard endpoint format. */
final class StructuredProxyImport {
    private StructuredProxyImport() { }

    static boolean matches(JSONObject value) {
        String type = value.optString("type", "");
        return type.equals("hysteria") || type.equals("hysteria2") || type.equals("tuic")
                || type.equals("socks") || type.equals("http") || type.equals("wireguard") || type.equals("anytls")
                || value.has("multiplex") && (type.equals("vless") || type.equals("vmess")
                || type.equals("trojan") || type.equals("shadowsocks"));
    }

    static ProtocolParser.Node parse(JSONObject source, String name) throws Exception {
        AtomicStore.jsonUtf8Size(source, AtomicStore.MAX_JSON_BYTES);
        if (source.has("protocol")) throw new IllegalArgumentException("conflicting outbound discriminator");
        JSONObject copy = new JSONObject(source.toString());
        for (String key : new String[]{"tag", "name", "remarks", "ps"}) copy.remove(key);
        String type = copy.getString("type");
        if (type.equals("wireguard")) return wireGuard(copy, name);
        if (type.equals("anytls") && !copy.has("password")) copy.put("password", "");
        if (type.equals("vless") && !copy.has("encryption")) copy.put("encryption", "none");
        if (type.equals("vmess")) {
            if (!copy.has("security")) copy.put("security", "auto");
            if (!copy.has("alter_id")) copy.put("alter_id", 0);
        }
        JSONObject tls = copy.optJSONObject("tls");
        if (tls != null) {
            if (Boolean.FALSE.equals(tls.opt("enabled")) && tls.length() == 1) copy.remove("tls");
            else {
                if (!tls.has("server_name")) tls.put("server_name", copy.optString("server", ""));
                if (!tls.has("insecure")) tls.put("insecure", false);
            }
        }
        if (type.equals("tuic")) {
            if (!copy.has("congestion_control") || "".equals(copy.opt("congestion_control"))) copy.put("congestion_control", "cubic");
            if (!copy.has("udp_relay_mode")) copy.put("udp_relay_mode", Boolean.TRUE.equals(copy.opt("udp_over_stream")) ? "" : "native");
        }
        if (type.equals("hysteria") || type.equals("hysteria2")) {
            for (String key : new String[]{"up_mbps", "down_mbps"}) {
                if (copy.opt(key) instanceof Number && "0".equals(String.valueOf(copy.opt(key)))) copy.remove(key);
            }
            if (copy.has("server_ports")) {
                Object raw = copy.get("server_ports");
                JSONArray ports = raw instanceof String ? new JSONArray().put(raw) : copy.getJSONArray("server_ports");
                JSONArray normalized = new JSONArray();
                for (int i = 0; i < ports.length(); i++) {
                    Object entry = ports.get(i);
                    if (!(entry instanceof String)) throw new IllegalArgumentException("invalid proxy port list");
                    String range = (String) entry;
                    if (range.matches("[0-9]+")) range += ":" + range;
                    normalized.put(range);
                }
                copy.put("server_ports", normalized);
                if (!copy.has("server_port") && normalized.length() > 0) {
                    copy.put("server_port", Integer.parseInt(normalized.getString(0).split(":", -1)[0]));
                }
            }
        }
        return ProtocolParser.fromOutbound("", name, copy);
    }

    private static ProtocolParser.Node wireGuard(JSONObject value, String name) throws Exception {
        only(value, "type", "server", "server_port", "private_key", "peer_public_key", "pre_shared_key",
                "local_address", "address", "mtu", "peers", "reserved", "system", "listen_port");
        if (value.has("system") && !Boolean.FALSE.equals(value.opt("system"))) throw new IllegalArgumentException("unsupported WireGuard system interface");
        if (value.has("listen_port") && number(value, "listen_port", 0, 0, 65535) != 0) throw new IllegalArgumentException("unsupported WireGuard listener");
        if (value.has("local_address") && value.has("address")) throw new IllegalArgumentException("conflicting WireGuard addresses");
        String addresses = list(value.opt(value.has("address") ? "address" : "local_address"));
        StringBuilder ini = new StringBuilder("[Interface]\nPrivateKey = ").append(string(value, "private_key", true))
                .append("\nAddress = ").append(addresses).append("\nMTU = ").append(number(value, "mtu", 1280, 576, 65535)).append('\n');
        JSONArray peers;
        if (!value.has("peers")) {
            peers = new JSONArray().put(new JSONObject().put("server", string(value, "server", true))
                    .put("server_port", number(value, "server_port", 0, 1, 65535))
                    .put("public_key", string(value, "peer_public_key", true))
                    .put("pre_shared_key", string(value, "pre_shared_key", false)));
        } else {
            if (value.has("peer_public_key") || value.has("pre_shared_key") || value.has("server") || value.has("server_port")) throw new IllegalArgumentException("conflicting WireGuard peers");
            peers = value.getJSONArray("peers");
        }
        if (peers.length() < 1 || peers.length() > 256) throw new IllegalArgumentException("invalid WireGuard peers");
        JSONArray reserved = value.has("reserved") ? reserved(value.get("reserved")) : null;
        for (int i = 0; i < peers.length(); i++) {
            JSONObject peer = peers.getJSONObject(i);
            only(peer, "server", "server_port", "address", "port", "public_key", "pre_shared_key", "allowed_ips", "persistent_keepalive_interval", "reserved");
            if (peer.has("address") && peer.has("server") || peer.has("port") && peer.has("server_port")) throw new IllegalArgumentException("conflicting WireGuard endpoint");
            String host = string(peer, peer.has("address") ? "address" : "server", true);
            if (peer.has("reserved")) {
                JSONArray current = reserved(peer.get("reserved"));
                if (i > 0 && reserved == null || reserved != null && !reserved.toString().equals(current.toString())) throw new IllegalArgumentException("unsupported per-peer WireGuard reserved bytes");
                reserved = current;
            } else if (i > 0 && reserved != null && !value.has("reserved")) throw new IllegalArgumentException("unsupported per-peer WireGuard reserved bytes");
            ini.append("[Peer]\nPublicKey = ").append(string(peer, "public_key", true))
                    .append("\nEndpoint = ").append(host.contains(":") ? "[" + host + "]" : host).append(':')
                    .append(number(peer, peer.has("port") ? "port" : "server_port", 0, 1, 65535))
                    .append("\nAllowedIPs = ").append(peer.has("allowed_ips") ? list(peer.get("allowed_ips")) : "0.0.0.0/0, ::/0")
                    .append("\nPersistentKeepalive = ").append(number(peer, "persistent_keepalive_interval", 0, 0, 65535)).append('\n');
            String shared = string(peer, "pre_shared_key", false);
            if (!shared.isEmpty()) ini.append("PresharedKey = ").append(shared).append('\n');
        }
        JSONObject awg = AwgConfigParser.parse(ini.toString()).outbound;
        JSONArray renderedPeers = new JSONArray();
        JSONArray validatedPeers = awg.getJSONArray("peers");
        for (int i = 0; i < validatedPeers.length(); i++) {
            JSONObject peer = validatedPeers.getJSONObject(i);
            JSONObject rendered = new JSONObject().put("publicKey", peer.get("public_key"))
                    .put("endpoint", peer.get("endpoint")).put("allowedIPs", peer.get("allowed_ips"))
                    .put("keepAlive", peer.get("persistent_keepalive_interval"));
            if (peer.has("preshared_key")) rendered.put("preSharedKey", peer.get("preshared_key"));
            renderedPeers.put(rendered);
        }
        JSONObject settings = new JSONObject().put("secretKey", awg.get("private_key")).put("address", awg.get("local_address"))
                .put("mtu", awg.get("mtu")).put("noKernelTun", true).put("peers", renderedPeers);
        if (reserved != null) settings.put("reserved", reserved);
        return ProtocolParser.fromXrayOutbound("", name, new JSONObject().put("protocol", "wireguard").put("settings", settings));
    }

    private static JSONArray reserved(Object raw) throws Exception {
        if (!(raw instanceof JSONArray) || ((JSONArray) raw).length() != 3) throw new IllegalArgumentException("invalid WireGuard reserved bytes");
        JSONArray result = new JSONArray();
        for (int i = 0; i < 3; i++) result.put(number(new JSONObject().put("byte", ((JSONArray) raw).get(i)), "byte", 0, 0, 255));
        return result;
    }

    private static String list(Object raw) throws Exception {
        if (raw instanceof String) return safe((String) raw);
        if (!(raw instanceof JSONArray) || ((JSONArray) raw).length() < 1 || ((JSONArray) raw).length() > 256) throw new IllegalArgumentException("invalid WireGuard address list");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < ((JSONArray) raw).length(); i++) {
            if (i > 0) result.append(", ");
            Object item = ((JSONArray) raw).get(i);
            if (!(item instanceof String)) throw new IllegalArgumentException("invalid WireGuard address list");
            result.append(safe((String) item));
        }
        return result.toString();
    }

    private static String safe(String value) {
        if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0 || value.indexOf('\0') >= 0 || value.length() > 16384) throw new IllegalArgumentException("invalid structured proxy value");
        return value;
    }

    private static String string(JSONObject value, String key, boolean required) throws Exception {
        if (!value.has(key) && !required) return "";
        Object raw = value.get(key);
        if (!(raw instanceof String) || required && ((String) raw).isEmpty()) throw new IllegalArgumentException("invalid structured proxy string");
        return safe((String) raw);
    }

    private static long number(JSONObject value, String key, long fallback, long minimum, long maximum) throws Exception {
        if (!value.has(key)) return fallback;
        Object raw = value.get(key);
        if (!(raw instanceof Number) || !String.valueOf(raw).matches("[0-9]+")) throw new IllegalArgumentException("invalid structured proxy integer");
        long result;
        try { result = Long.parseLong(String.valueOf(raw)); }
        catch (NumberFormatException overflow) { throw new IllegalArgumentException("invalid structured proxy integer"); }
        if (result < minimum || result > maximum) throw new IllegalArgumentException("invalid structured proxy integer");
        return result;
    }

    private static void only(JSONObject value, String... keys) {
        HashSet<String> allowed = new HashSet<>(Arrays.asList(keys));
        Iterator<String> it = value.keys();
        while (it.hasNext()) if (!allowed.contains(it.next())) throw new IllegalArgumentException("unsupported structured proxy field");
    }
}
