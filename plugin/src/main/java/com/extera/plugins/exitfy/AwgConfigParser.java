package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Converts a .conf into a private neutral outbound, without executing interface commands. */
final class AwgConfigParser {
    static final int MAX_CONFIG_CHARS = 64 * 1024;
    private static final String PARAMETERS = "jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5 "
            + "header_protection_key content_padding_addition rekey_after_time rekey_timeout "
            + "reject_after_time keepalive_timeout max_handshake_attempts";

    static boolean looksLike(String text) {
        if (text == null) return false;
        if (text.startsWith("\ufeff")) text = text.substring(1);
        return text.trim().matches("(?is)(?:[#;][^\\n]*\\n\\s*)*\\[Interface\\].*");
    }

    static ProtocolParser.Node parseLink(String uri) throws Exception {
        int scheme = uri.indexOf("://");
        int fragment = uri.indexOf('#', scheme + 3);
        String encoded = uri.substring(scheme + 3, fragment < 0 ? uri.length() : fragment);
        String name = fragment < 0 ? "" : URLDecoder.decode(
                uri.substring(fragment + 1).replace("+", "%2B"), "UTF-8");
        return parseEncoded(encoded, name);
    }

    static ProtocolParser.Node parseEncoded(String encoded, String name) throws Exception {
        if (encoded == null || encoded.isEmpty() || encoded.length() > MAX_CONFIG_CHARS * 4 / 3 + 8
                || !encoded.matches("[A-Za-z0-9+/_=-]+")) throw invalid("base64", "base64");
        byte[] bytes;
        try { bytes = Base64.getUrlDecoder().decode(encoded); }
        catch (IllegalArgumentException standard) {
            try { bytes = Base64.getDecoder().decode(encoded); }
            catch (IllegalArgumentException invalid) { throw invalid("base64", "base64"); }
        }
        if (bytes.length > MAX_CONFIG_CHARS) throw invalid("размер файла", "file size");
        String text = SubscriptionParser.decodeStrictUtf8(bytes);
        ProtocolParser.Node parsed = parse(text);
        if (name == null || name.trim().isEmpty()) {
            java.util.regex.Matcher comment = java.util.regex.Pattern.compile(
                    "(?im)^\\s*#\\s*Name\\s*=\\s*([^\\r\\n]{1,256})").matcher(text);
            name = comment.find() ? comment.group(1) : parsed.outbound.getString("server");
        }
        return ProtocolParser.fromOutbound("", name, parsed.outbound);
    }

    static ProtocolParser.Node parse(String text) throws Exception {
        if (text == null || text.length() > MAX_CONFIG_CHARS) throw invalid("размер файла", "file size");
        if (text.startsWith("\ufeff")) text = text.substring(1);
        Map<String, String> iface = new LinkedHashMap<>();
        java.util.List<Map<String, String>> peers = new java.util.ArrayList<>();
        Map<String, String> section = null;
        boolean interfaceSeen = false, deviceSeen = false;
        for (String raw : text.split("\\r?\\n")) {
            if (Thread.currentThread().isInterrupted()) throw new java.io.InterruptedIOException();
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue;
            if (line.equalsIgnoreCase("[Interface]")) {
                if (interfaceSeen || section != null) throw invalid("повторная секция Interface", "duplicate Interface section");
                interfaceSeen = true;
                section = iface; continue;
            }
            if (line.equalsIgnoreCase("[Device]")) {
                if (!interfaceSeen || deviceSeen || !peers.isEmpty()) throw invalid("секция Device", "Device section");
                deviceSeen = true;
                section = iface; continue;
            }
            if (line.equalsIgnoreCase("[Peer]")) {
                if (section == null || peers.size() >= 64) throw invalid("секция Peer", "Peer section");
                section = new LinkedHashMap<>(); peers.add(section); continue;
            }
            int separator = line.indexOf('=');
            if (section == null || separator < 1 || line.startsWith("[")) throw invalid("строка конфига", "configuration line");
            String key = normalizeKey(line.substring(0, separator).trim());
            String value = line.substring(separator + 1).trim();
            int comment = value.indexOf(" #");
            if (comment >= 0) value = value.substring(0, comment).trim();
            int valueLimit = key.equals("allowedips") || key.equals("address") || key.equals("dns")
                    || key.matches("i[1-5]") ? MAX_CONFIG_CHARS : 2048;
            if (value.length() > valueLimit) throw invalid("длина параметра", "parameter length");
            // Official exporters may leave optional entries blank. Keep required
            // keys strict and validate unknown directives below even when blank.
            boolean optional = section == iface
                    ? key.equals("dns") || key.equals("mtu") || key.equals("listenport")
                        || key.equals("table") || key.equals("fwmark") || key.equals("saveconfig")
                        || isParameter(key)
                    : key.equals("presharedkey") || key.equals("persistentkeepalive");
            if (value.isEmpty() && optional) continue;
            if (value.isEmpty()) throw invalid("пустой обязательный параметр", "empty required parameter");
            String previous = section.get(key);
            if (previous != null) {
                boolean list = section == iface ? key.equals("address") || key.equals("dns")
                        : key.equals("allowedips");
                if (list) {
                    value = previous + ", " + value;
                    if (value.length() > valueLimit) throw invalid("длина параметра", "parameter length");
                } else if (!previous.equals(value)) {
                    throw invalid("конфликт повторных параметров", "conflicting duplicate parameters");
                }
            }
            section.put(key, value);
        }
        if (peers.isEmpty()) throw invalid("нет Peer", "no Peer");
        JSONObject awg = new JSONObject();
        for (Map.Entry<String, String> entry : iface.entrySet()) {
            String key = entry.getKey();
            if (isParameter(key)) awg.put(key, entry.getValue());
            else if (!key.equals("privatekey") && !key.equals("address") && !key.equals("dns")
                    && !key.equals("mtu") && !key.equals("listenport") && !key.equals("table")
                    && !key.equals("fwmark") && !key.equals("saveconfig")) {
                throw invalid("неподдерживаемый параметр Interface", "unsupported Interface parameter");
            }
        }
        JSONArray peerValues = new JSONArray();
        String firstHost = ""; int firstPort = 0;
        for (Map<String, String> peer : peers) {
            for (String key : peer.keySet()) if (!key.equals("publickey") && !key.equals("presharedkey")
                    && !key.equals("endpoint") && !key.equals("allowedips")
                    && !key.equals("persistentkeepalive")) throw invalid("параметр Peer", "Peer parameter");
            String endpoint = required(peer, "endpoint");
            URI uri;
            try { uri = new URI("udp://" + endpoint); }
            catch (Exception error) { throw invalid("Endpoint", "Endpoint"); }
            if (uri.getHost() == null || uri.getPort() < 1 || uri.getPort() > 65535
                    || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                    || !uri.getRawPath().isEmpty()) throw invalid("Endpoint", "Endpoint");
            String host = uri.getHost();
            if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length()-1);
            if (firstHost.isEmpty()) { firstHost = host; firstPort = uri.getPort(); }
            JSONObject item = new JSONObject().put("public_key", required(peer, "publickey"))
                    .put("endpoint", endpoint).put("allowed_ips", prefixes(required(peer, "allowedips")))
                    .put("persistent_keepalive_interval", keepalive(peer.get("persistentkeepalive")));
            if (peer.containsKey("presharedkey")) item.put("preshared_key", peer.get("presharedkey"));
            peerValues.put(item);
        }
        JSONObject outbound = new JSONObject().put("type", "amneziawg")
                .put("server", firstHost).put("server_port", firstPort)
                .put("private_key", required(iface, "privatekey"))
                .put("local_address", prefixes(required(iface, "address")))
                .put("dns", list(iface.getOrDefault("dns", "1.1.1.1, 8.8.8.8")))
                .put("mtu", integer(iface.get("mtu"), 1280, 576, 9000))
                .put("listen_port", integer(iface.get("listenport"), 0, 0, 65535))
                .put("peers", peerValues).put("awg", awg);
        validateOutbound(outbound);
        return ProtocolParser.fromOutbound("", "AmneziaWG", outbound);
    }

    static void validateOutbound(JSONObject value) {
        try {
            only(value, "type server server_port private_key local_address dns mtu listen_port peers awg");
            key(value.getString("private_key"));
            range(value.getInt("mtu"), 576, 9000);
            range(value.optInt("listen_port", 0), 0, 65535);
            JSONArray addresses = value.getJSONArray("local_address");
            arrayLimit(addresses, 1, 16);
            for (int i=0; i<addresses.length(); i++) prefix(addresses.getString(i));
            JSONArray dns = value.getJSONArray("dns"); arrayLimit(dns, 0, 16);
            for (int i=0; i<dns.length(); i++) ip(dns.getString(i));
            JSONArray peers = value.getJSONArray("peers"); arrayLimit(peers, 1, 64);
            Set<String> publicKeys = new HashSet<>();
            for (int i=0; i<peers.length(); i++) {
                JSONObject peer = peers.getJSONObject(i);
                only(peer, "public_key preshared_key endpoint allowed_ips persistent_keepalive_interval");
                String publicKey = peer.getString("public_key"); key(publicKey);
                if (!publicKeys.add(publicKey)) throw new IllegalArgumentException();
                if (peer.has("preshared_key")) key(peer.getString("preshared_key"));
                URI endpoint = new URI("udp://" + peer.getString("endpoint"));
                if (endpoint.getHost()==null || endpoint.getPort()<1 || endpoint.getPort()>65535
                        || endpoint.getUserInfo()!=null || endpoint.getQuery()!=null || endpoint.getFragment()!=null
                        || !endpoint.getRawPath().isEmpty()) throw new IllegalArgumentException();
                JSONArray allowed = peer.getJSONArray("allowed_ips"); arrayLimit(allowed, 1, 256);
                for (int j=0; j<allowed.length(); j++) prefix(allowed.getString(j));
                keepalive(String.valueOf(peer.opt("persistent_keepalive_interval") == null
                        ? 0 : peer.get("persistent_keepalive_interval")));
            }
            JSONObject awg = value.optJSONObject("awg");
            if (awg != null) for (Iterator<String> it=awg.keys(); it.hasNext();) {
                String name = it.next(), parameter = awg.getString(name);
                if (!isParameter(name) || parameter.isEmpty()
                        || parameter.length() > (name.matches("i[1-5]") ? MAX_CONFIG_CHARS : 2048)
                        || parameter.indexOf('\n')>=0 || parameter.indexOf('\r')>=0
                        || parameter.indexOf('\0')>=0) throw new IllegalArgumentException();
                if (name.equals("header_protection_key")) key(parameter);
                else if (!name.startsWith("i")) {
                    String[] limits = parameter.split("-", -1);
                    if (limits.length>2) throw new IllegalArgumentException();
                    long previous=-1;
                    for (String limit:limits) { long number=Long.parseLong(limit);
                        if (number<0 || number>4294967295L || number<previous) throw new IllegalArgumentException();
                        previous=number; }
                }
            }
            validateParameterLimits(awg, value.getInt("mtu"));
        } catch (Exception error) { throw invalid("ключи, адреса или параметры AWG", "keys, addresses or AWG parameters"); }
    }

    private static void only(JSONObject value, String allowed) {
        for (Iterator<String> keys=value.keys(); keys.hasNext();) {
            if (!(" "+allowed+" ").contains(" "+keys.next()+" ")) throw new IllegalArgumentException();
        }
    }
    private static void key(String value) {
        byte[] decoded = Base64.getDecoder().decode(value);
        if (decoded.length != 32 || !Base64.getEncoder().encodeToString(decoded).equals(value)) {
            throw new IllegalArgumentException();
        }
    }

    private static void validateParameterLimits(JSONObject values, int mtu) throws Exception {
        if (values == null) return;
        long jc = 0, jmin = 0, jmax = 0;
        for (Iterator<String> keys = values.keys(); keys.hasNext();) {
            String name = keys.next(), value = values.getString(name);
            if (name.equals("header_protection_key")) continue;
            if (name.matches("i[1-5]")) { validateIPacket(value); continue; }
            String[] parts = value.split("-", -1);
            long minimum = Long.parseLong(parts[0]), maximum = Long.parseLong(parts[parts.length-1]);
            if (name.matches("jc|jmin|jmax|s[1-4]")) {
                if (minimum != maximum || maximum > 65000) throw new IllegalArgumentException();
                if (name.equals("jc")) { if (maximum > 128) throw new IllegalArgumentException(); jc = maximum; }
                if (name.equals("jmin")) jmin = maximum;
                if (name.equals("jmax")) jmax = maximum;
                if (name.equals("s4") && maximum + mtu + 80 > 65535) throw new IllegalArgumentException();
            }
            if (name.equals("content_padding_addition") && maximum > mtu) throw new IllegalArgumentException();
            if (name.equals("max_handshake_attempts") && maximum > 1024) throw new IllegalArgumentException();
        }
        if (jmin > jmax || jc * jmax > 1024 * 1024) throw new IllegalArgumentException();
    }

    private static void validateIPacket(String value) {
        java.util.regex.Matcher tags = java.util.regex.Pattern.compile("<([^<>]+)>").matcher(value);
        int previous = 0, total = 0, count = 0;
        while (tags.find()) {
            if (!value.substring(previous, tags.start()).trim().isEmpty()) throw new IllegalArgumentException();
            String[] fields = tags.group(1).trim().split("\\s+");
            if (fields.length < 1 || fields.length > 2) throw new IllegalArgumentException();
            String argument = fields.length == 2 ? fields[1] : "";
            switch (fields[0]) {
                case "b":
                    if (argument.startsWith("0x")) argument = argument.substring(2);
                    if (argument.isEmpty() || argument.length() % 2 != 0 || !argument.matches("[0-9a-fA-F]+")) throw new IllegalArgumentException();
                    total += argument.length()/2; break;
                case "t":
                    if (!argument.isEmpty()) throw new IllegalArgumentException(); total += 4; break;
                case "r": case "rc": case "rd": case "dz":
                    int number = Integer.parseInt(argument);
                    if (number < 0 || number > 65535) throw new IllegalArgumentException(); total += number; break;
                case "d": case "ds":
                    if (!argument.isEmpty()) throw new IllegalArgumentException(); break;
                default: throw new IllegalArgumentException();
            }
            if (++count > 256 || total > 65000) throw new IllegalArgumentException();
            previous = tags.end();
        }
        if (count == 0 || !value.substring(previous).trim().isEmpty()) throw new IllegalArgumentException();
    }
    private static InetAddress ip(String value) throws Exception {
        if (!value.matches("[0-9a-fA-F:.]+") || value.length()>45) throw new IllegalArgumentException();
        if (value.indexOf(':')<0 && !value.matches("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) throw new IllegalArgumentException();
        return InetAddress.getByName(value);
    }
    private static void prefix(String value) throws Exception {
        String[] parts=value.split("/", -1);
        if (parts.length!=2) throw new IllegalArgumentException();
        range(Integer.parseInt(parts[1]), 0, ip(parts[0]).getAddress().length*8);
    }
    private static void arrayLimit(JSONArray value, int min, int max) { range(value.length(), min, max); }
    private static void range(int value, int min, int max) { if (value<min || value>max) throw new IllegalArgumentException(); }
    private static int integer(String value, int fallback, int min, int max) {
        try { int result=value==null?fallback:Integer.parseInt(value); range(result,min,max); return result; }
        catch (Exception error) { throw invalid("числовой параметр", "numeric parameter"); }
    }
    private static Object keepalive(String value) {
        if (value == null) return 0;
        String[] parts = value.split("-", -1);
        if (parts.length < 1 || parts.length > 2) throw new IllegalArgumentException();
        int first = integer(parts[0], 0, 0, 65535);
        int last = integer(parts[parts.length-1], 0, first, 65535);
        return parts.length == 1 ? first : first + "-" + last;
    }
    private static JSONArray list(String value) {
        JSONArray result=new JSONArray(); for (String item:value.split(",")) result.put(item.trim()); return result;
    }
    private static JSONArray prefixes(String value) throws Exception {
        JSONArray result=new JSONArray();
        for (String raw:value.split(",")) {
            String item=raw.trim();
            if (item.indexOf('/')<0) item += "/" + (ip(item).getAddress().length*8);
            prefix(item); result.put(item);
        }
        return result;
    }
    private static String required(Map<String,String> values, String key) {
        String value=values.get(key); if(value==null || value.isEmpty()) throw invalid("обязательный параметр", "required parameter"); return value;
    }
    private static boolean isParameter(String key) { return (" "+PARAMETERS+" ").contains(" "+key+" "); }
    private static String normalizeKey(String key) {
        String lower=key.toLowerCase(Locale.ROOT);
        for (String parameter:PARAMETERS.split(" ")) if(parameter.replace("_", "").equals(lower.replace("_", ""))) return parameter;
        return lower;
    }
    private static IllegalArgumentException invalid(String ru, String en) {
        return new IllegalArgumentException(I18n.t("Конфиг AmneziaWG: ", "AmneziaWG configuration: ")
                + I18n.t(ru, en));
    }
}
