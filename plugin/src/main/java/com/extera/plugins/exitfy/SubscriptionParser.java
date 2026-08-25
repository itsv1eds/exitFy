package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.InetAddress;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SubscriptionParser {
    static final int MAX_SOURCE_NODES = 5_000;
    private static final int MAX_REASONS = 20;
    private static final int MAX_CLASH_LINE_CHARS = 64 * 1024;
    private static final int MAX_CLASH_FIELDS = 256;
    private static final int MAX_HIT_LINK_BYTES = 8 * 1024 * 1024;
    private static final int MAX_HIT_CONFIG_BYTES = 16 * 1024;
    private static final int MAX_HIT_SNI_BYTES = 1024;
    private static final int MAX_CBOR_DEPTH = 32;
    private static final int MAX_CBOR_CONTAINER_ITEMS = 10_000;
    private static final int MAX_CBOR_VALUES = 50_000;
    // The documented HitVPN VLESS record is tiny (UUID, 32-byte key, endpoint
    // and SNI). A per-blob cap prevents a valid 8 MiB wrapper from causing a
    // second multi-megabyte allocation inside the CBOR object graph.
    private static final int MAX_CBOR_BLOB_BYTES = MAX_HIT_CONFIG_BYTES;
    private static final Pattern PROXY_LINK = Pattern.compile(
            "(?i)(?:vless|vmess|trojan|ss|hy2|hysteria2|hysteria|tuic)://[^\\s\\\"'<>]+"
    );
    private static final Pattern HIT_LINK = Pattern.compile(
            "(?i)(?:https://hvpn\\.io/|https://hitray\\.io/|hitvpn://)[A-Za-z0-9_\\-=]+"
    );
    // Hysteria rate units are case-insensitive in real Clash subscriptions.
    // Keep b/B distinct (bits/bytes), normalize the prefix and suffix spelling,
    // then reject values the selected pinned sing-box integer-Mbps field cannot
    // represent exactly. Hysteria2 also supplies a conservative multiplication
    // cap for data originating in untrusted subscriptions.
    private static final Pattern CLASH_HYSTERIA_BANDWIDTH = Pattern.compile(
            "^([0-9]+)\\s*([KMGTkmgt]?)([Bb])(?i:ps)$"
    );
    private static final byte[] HIT_HASH_KEY = "IIkYdtWtkU".getBytes(StandardCharsets.US_ASCII);

    private SubscriptionParser() {
    }

    static List<ProtocolParser.Node> parseNodes(String body) {
        return parseDetailed(body).nodes;
    }

    static ParseResult parseDetailed(String body) {
        String text = body == null ? "" : body;
        if (utf8Exceeds(text, LimitedHttpClient.MAX_EXPANDED_BYTES)) {
            ArrayList<String> reasons = new ArrayList<>();
            reasons.add("source_too_large");
            return new ParseResult(new ArrayList<>(), 1, reasons);
        }
        try {
            text = normalizeDocumentBom(text);
        } catch (IllegalArgumentException invalidBom) {
            return rejectedDocument("invalid_document_bom");
        }
        if (Thread.currentThread().isInterrupted()) return interruptedResult();
        if (firstNonWhitespace(text) < 0) {
            return new ParseResult(new ArrayList<>(), 0, new ArrayList<>());
        }
        boolean knownLink = containsKnownLink(text);
        if (Thread.currentThread().isInterrupted()) return interruptedResult();
        if (!knownLink) {
            String decoded = tryBase64(text);
            if (Thread.currentThread().isInterrupted()) return interruptedResult();
            if (!decoded.isEmpty()) {
                try {
                    text = normalizeDocumentBom(decoded);
                } catch (IllegalArgumentException invalidBom) {
                    return rejectedDocument("invalid_document_bom");
                }
            }
        }
        try {
            text = normalizeLineEndings(text);
        } catch (ImportInterruptedException interrupted) {
            return interruptedResult();
        }
        if (Thread.currentThread().isInterrupted()) return interruptedResult();

        List<String> links = new ArrayList<>();
        List<ProtocolParser.Node> structuredNodes = new ArrayList<>();
        RejectionTracker rejections = new RejectionTracker();
        CandidateBudget budget = new CandidateBudget(rejections);
        int structuredStart = firstNonWhitespace(text);
        try {
            if (structuredStart >= 0
                    && (text.charAt(structuredStart) == '{' || text.charAt(structuredStart) == '[')) {
                collectJson(text, links, structuredNodes, rejections, budget);
            } else if (looksLikeClashProxyYaml(text)) {
                // Once an explicit Clash proxy section is recognized, it is the
                // sole trust boundary. URI-looking text in comments, names or
                // unrelated YAML fields must never become a runnable node.
                collectSimpleClashYaml(text, links, rejections, budget);
            } else {
                collectRegex(text, PROXY_LINK, links, budget);
                collectHitLinks(text, links, budget);
            }
        } catch (ImportInterruptedException interrupted) {
            links.clear();
            structuredNodes.clear();
            rejections.reject("import_interrupted");
        }

        LinkedHashMap<String, ProtocolParser.Node> exact = new LinkedHashMap<>();
        for (ProtocolParser.Node node : structuredNodes) addExactBounded(exact, node, rejections);
        for (String link : links) {
            try {
                if (isHitLink(link)) {
                    for (String decoded : decodeHitVpn(link, rejections)) {
                        addExactBounded(exact, ProtocolParser.parse(decoded), rejections);
                    }
                } else {
                    addExactBounded(exact, ProtocolParser.parse(link), rejections);
                }
            } catch (Exception error) {
                rejections.reject(reasonCode(error));
            }
        }
        return new ParseResult(new ArrayList<>(exact.values()), rejections.rejected,
                new ArrayList<>(rejections.reasons));
    }

    private static void addExactBounded(Map<String, ProtocolParser.Node> values,
                                        ProtocolParser.Node node, RejectionTracker rejections) {
        if (node == null || values.containsKey(node.normalizedKey)) return;
        if (values.size() >= MAX_SOURCE_NODES) {
            rejections.rejectLimit(1);
            return;
        }
        values.put(node.normalizedKey, node);
    }

    private static boolean containsKnownLink(String value) {
        for (String scheme : ProtocolParser.SCHEMES) {
            if (containsIgnoreCase(value, scheme)) return true;
        }
        return containsIgnoreCase(value, "https://hvpn.io/")
                || containsIgnoreCase(value, "https://hitray.io/")
                || containsIgnoreCase(value, "hitvpn://");
    }

    private static String normalizeDocumentBom(String value) {
        if (value == null || value.isEmpty()) return value == null ? "" : value;
        int content = firstNonWhitespace(value);
        if (content < 0 || value.charAt(content) != '\ufeff') return value;
        // U+FEFF is a document marker only at offset zero. Accept exactly one
        // marker and classify every other leading spelling as invalid before
        // link detection/base64/structured dispatch can fall through to regex.
        if (content != 0) throw new IllegalArgumentException("invalid document BOM");
        String normalized = value.substring(1);
        int next = firstNonWhitespace(normalized);
        if (next >= 0 && normalized.charAt(next) == '\ufeff') {
            throw new IllegalArgumentException("multiple document BOMs");
        }
        return normalized;
    }

    private static String normalizeLineEndings(String value) {
        if (value == null || value.indexOf('\r') < 0) return value == null ? "" : value;
        StringBuilder normalized = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            if ((index & 4095) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
            char current = value.charAt(index);
            if (current != '\r') {
                normalized.append(current);
                continue;
            }
            normalized.append('\n');
            if (index + 1 < value.length() && value.charAt(index + 1) == '\n') index++;
        }
        return normalized.toString();
    }

    private static ParseResult rejectedDocument(String reason) {
        ArrayList<String> reasons = new ArrayList<>();
        reasons.add(reason);
        return new ParseResult(new ArrayList<>(), 1, reasons);
    }

    private static void collectRegex(String text, Pattern pattern, List<String> output,
                                     CandidateBudget budget) {
        Matcher matcher = pattern.matcher(text);
        int scanned = 0;
        while (matcher.find()) {
            if (budget.reserve()) {
                if (pattern == PROXY_LINK && utf8RegionExceeds(
                        text, matcher.start(), matcher.end(), ProtocolParser.MAX_URI_BYTES)) {
                    budget.reject("uri_too_large");
                } else {
                    String candidate = pattern == PROXY_LINK
                            ? unwrapExtractedProxyCandidate(text, matcher.start(), matcher.end())
                            : matcher.group();
                    output.add(candidate);
                }
            }
            if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
        }
    }

    private static String unwrapExtractedProxyCandidate(String source, int start, int end) {
        String candidate = source.substring(start, end);
        if (start <= 0 || candidate.isEmpty()) return candidate;

        // URI punctuation is data unless the surrounding text proves that it
        // belongs to an outer wrapper.  In particular '.', ';' and ')' are
        // all legal at the end of a path/query/fragment and standalone
        // subscription lines must remain byte-for-byte intact.
        char opener = source.charAt(start - 1);
        char closer;
        if (opener == '(') closer = ')';
        else if (opener == '[') closer = ']';
        else if (opener == '{') closer = '}';
        else return candidate;

        int wrapperEnd = candidate.length() - 1;
        while (wrapperEnd >= 0 && ".,;:!?".indexOf(candidate.charAt(wrapperEnd)) >= 0) {
            wrapperEnd--;
        }
        if (wrapperEnd < 0 || candidate.charAt(wrapperEnd) != closer) return candidate;
        if (!balancedOuterWrapper(source, start - 1, start + wrapperEnd)) return candidate;
        return candidate.substring(0, wrapperEnd);
    }

    static boolean balancedOuterWrapper(String source, int openIndex, int closeIndex) {
        if (source == null || openIndex < 0 || closeIndex <= openIndex
                || closeIndex >= source.length()) return false;
        char opener = source.charAt(openIndex);
        char expected = matchingCloser(opener);
        if (expected == 0 || source.charAt(closeIndex) != expected) return false;
        if (opener == '\'' || opener == '"') {
            boolean escaped = false;
            for (int index = openIndex + 1; index <= closeIndex; index++) {
                char current = source.charAt(index);
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (current == '\\') {
                    escaped = true;
                    continue;
                }
                if (current == expected) return index == closeIndex;
            }
            return false;
        }
        char[] stack = new char[Math.min(64, closeIndex - openIndex + 1)];
        int depth = 0;
        stack[depth++] = expected;
        char quote = 0;
        boolean escaped = false;
        for (int index = openIndex + 1; index <= closeIndex; index++) {
            char current = source.charAt(index);
            if (quote != 0) {
                if (escaped) escaped = false;
                else if (current == '\\') escaped = true;
                else if (current == quote) quote = 0;
                continue;
            }
            if (current == '\'' || current == '"') {
                quote = current;
                continue;
            }
            char nestedCloser = matchingCloser(current);
            if (nestedCloser != 0 && current != '\'' && current != '"') {
                if (depth >= stack.length) return false;
                stack[depth++] = nestedCloser;
                continue;
            }
            if (current == ')' || current == ']' || current == '}' || current == '>') {
                if (depth <= 0 || stack[depth - 1] != current) return false;
                depth--;
                if (depth == 0) return index == closeIndex;
            }
        }
        return false;
    }

    private static char matchingCloser(char opener) {
        switch (opener) {
            case '(':
                return ')';
            case '[':
                return ']';
            case '{':
                return '}';
            case '<':
                return '>';
            case '\'':
            case '"':
                return opener;
            default:
                return 0;
        }
    }

    private static void collectHitLinks(String text, List<String> output,
                                        CandidateBudget budget) {
        collectRegex(text, HIT_LINK, output, budget);
    }

    private static void collectJson(String text, List<String> links,
                                    List<ProtocolParser.Node> nodes,
                                    RejectionTracker rejections, CandidateBudget budget) {
        try {
            int start = firstNonWhitespace(text);
            Object root = start >= 0 && text.charAt(start) == '{'
                    ? JsonGuard.object(text) : JsonGuard.array(text);
            if (root instanceof JSONObject) {
                JSONObject object = (JSONObject) root;
                if (object.has("outbounds")) {
                    Object rawOutbounds = object.opt("outbounds");
                    if (!(rawOutbounds instanceof JSONArray)) {
                        rejections.reject("invalid_json");
                        return;
                    }
                    collectExplicitOutbounds((JSONArray) rawOutbounds,
                            nodes, rejections, budget);
                } else if (isProxyOutbound(object)) {
                    collectExplicitOutbound(object, nodes, rejections, budget);
                } else {
                    // Remnawave exposes proxy values only through these
                    // documented fields. Arbitrary descriptions/metadata are
                    // never searched for runnable URI text.
                    walkJsonLinks(object.opt("links"), links, 0, false, budget);
                    walkJsonLinks(object.opt("ssConfLinks"), links, 0, true, budget);
                }
            } else {
                JSONArray values = (JSONArray) root;
                for (int i = 0; i < values.length(); i++) {
                    if ((i & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                        throw new ImportInterruptedException();
                    }
                    JSONObject object = values.optJSONObject(i);
                    if (object != null && isProxyOutbound(object)) {
                        collectExplicitOutbound(object, nodes, rejections, budget);
                    } else if (values.opt(i) instanceof String
                            || values.opt(i) instanceof JSONArray) {
                        walkJsonLinks(values.opt(i), links, 0, false, budget);
                    }
                }
            }
        } catch (StackOverflowError tooDeep) {
            rejections.reject("json_depth_exceeded");
        } catch (ImportInterruptedException interrupted) {
            links.clear();
            nodes.clear();
            rejections.reject("import_interrupted");
        } catch (IllegalArgumentException invalid) {
            rejections.reject(reasonCode(invalid));
        } catch (IllegalStateException interrupted) {
            links.clear();
            nodes.clear();
            rejections.reject("import_interrupted");
        } catch (Exception error) {
            rejections.reject("invalid_json");
        }
    }

    private static void collectExplicitOutbounds(JSONArray values,
                                                 List<ProtocolParser.Node> nodes,
                                                 RejectionTracker rejections,
                                                 CandidateBudget budget) {
        for (int i = 0; i < values.length(); i++) {
            if ((i & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
            JSONObject object = values.optJSONObject(i);
            if (object == null || !isProxyOutbound(object)) continue;
            collectExplicitOutbound(object, nodes, rejections, budget);
        }
    }

    private static void collectExplicitOutbound(JSONObject object,
                                                 List<ProtocolParser.Node> nodes,
                                                 RejectionTracker rejections,
                                                 CandidateBudget budget) {
        if (!budget.reserve()) return;
        try {
            validateOutboundShape(object);
            ImportHints hints = new ImportHints();
            String converted = jsonOutboundToUri(object, hints);
            if (converted.isEmpty()) throw new IllegalArgumentException("unrepresentable outbound");
            // Full structured configs have their own scalar/aggregate limits;
            // XHTTP extra is allowed up to 64 KiB and may legitimately make
            // the internal generated representation exceed the URI import cap.
            ProtocolParser.Node parsed = ProtocolParser.parseGeneratedBeforeCompatibility(converted);
            if (hints.xrayWebSocketPathSemantics) {
                JSONObject transport = parsed.outbound.optJSONObject("transport");
                if (transport == null || !"ws".equals(
                        transport.optString("type", ""))) {
                    throw new IllegalArgumentException(
                            "unrepresentable Xray WebSocket path semantics");
                }
                transport.put(ProtocolParser.WS_XRAY_PATH_SEMANTICS, true);
            }
            if (hints.xrayWebSocketPathEarlyData) {
                JSONObject transport = parsed.outbound.optJSONObject("transport");
                if (transport == null || !"ws".equals(transport.optString("type", ""))
                        || !transport.has("max_early_data")) {
                    throw new IllegalArgumentException("unrepresentable Xray WebSocket early data");
                }
                String earlyHeader = transport.optString("early_data_header_name", "");
                if (earlyHeader.isEmpty()) {
                    transport.put(ProtocolParser.WS_EARLY_DATA_MODE,
                            ProtocolParser.WS_EARLY_DATA_XRAY_PATH);
                } else if (ProtocolParser.WS_EARLY_DATA_XRAY_HEADER
                        .equalsIgnoreCase(earlyHeader)) {
                    // The standard header is an equivalent, core-neutral
                    // representation: sing-box consumes it directly and the
                    // Xray renderer restores ?ed=N. Keep only one provenance
                    // representation so the neutral validator stays strict.
                    transport.put("early_data_header_name",
                            ProtocolParser.WS_EARLY_DATA_XRAY_HEADER);
                } else {
                    throw new IllegalArgumentException(
                            "conflicting Xray WebSocket early-data header");
                }
            }
            if (hints.xrayHttpUpgradePathEarlyData) {
                JSONObject transport = parsed.outbound.optJSONObject("transport");
                if (transport == null
                        || !"httpupgrade".equals(transport.optString("type", ""))
                        || !transport.has("max_early_data")) {
                    throw new IllegalArgumentException(
                            "unrepresentable Xray HTTPUpgrade early data");
                }
            }
            nodes.add(ProtocolParser.fromOutbound("", parsed.name, parsed.outbound));
        } catch (Exception error) {
            rejections.reject(reasonCode(error));
        }
    }

    private static boolean isProxyOutbound(JSONObject object) {
        if (object == null) return false;
        for (String key : new String[]{"type", "protocol"}) {
            Object raw = object.opt(key);
            if (raw instanceof String && isSupportedOutboundType((String) raw)) return true;
        }
        return false;
    }

    private static void walkJsonLinks(Object value, List<String> output, int depth,
                                      boolean allowMap, CandidateBudget budget) {
        if (value == null || depth > 30) return;
        if (value instanceof String) {
            String text = ((String) value).trim();
            if ((ProtocolParser.supports(text) || isHitLink(text)) && budget.reserve()) {
                output.add(text);
            }
            return;
        }
        try {
            if (value instanceof JSONArray) {
                JSONArray array = (JSONArray) value;
                for (int i = 0; i < array.length(); i++) {
                    if ((i & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                        throw new ImportInterruptedException();
                    }
                    Object item = array.opt(i);
                    if (item instanceof String || item instanceof JSONArray) {
                        walkJsonLinks(item, output, depth + 1, false, budget);
                    }
                }
            } else if (allowMap && value instanceof JSONObject) {
                JSONObject object = (JSONObject) value;
                java.util.Iterator<String> keys = object.keys();
                int scanned = 0;
                while (keys.hasNext()) {
                    if ((scanned++ & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                        throw new ImportInterruptedException();
                    }
                    Object item = object.opt(keys.next());
                    if (item instanceof String || item instanceof JSONArray) {
                        walkJsonLinks(item, output, depth + 1, false, budget);
                    }
                }
            }
        } catch (ImportInterruptedException interrupted) {
            throw interrupted;
        } catch (Exception ignored) {
        }
    }

    private static String jsonOutboundToUri(JSONObject object, ImportHints hints) throws Exception {
        try {
            boolean xrayShape = isXrayOutboundShape(object);
            String type = xrayShape ? xrayOutboundType(object) : outboundType(object);
            if (!type.equals("vless") && !type.equals("vmess")
                    && !type.equals("trojan") && !type.equals("shadowsocks")) return "";
            String server = xrayShape ? "" : first(object, "server", "address");
            int port = xrayShape ? 0
                    : strictInteger(object, 0, 0, 65535, "server_port", "port");
            String credential = xrayShape ? ""
                    : (type.equals("trojan") || type.equals("shadowsocks")
                    ? first(object, "password") : first(object, "uuid", "id", "user"));
            String method = xrayShape ? "" : first(object, "method");
            int alterId = xrayShape ? 0 : strictInteger(
                    object, 0, 0, Integer.MAX_VALUE, "alter_id", "alterId");
            String cipher = xrayShape ? "" : first(object, "security", "encryption");
            String flow = xrayShape ? "" : first(object, "flow");

            JSONObject settings = optionalObject(object, "settings");
            boolean nestedSettings = settings != null && (settings.has("vnext")
                    || settings.has("servers"));
            boolean simplifiedSettings = settings != null && (xrayShape
                    ? hasAny(settings, "address", "port", "id", "password", "method",
                    "flow", "security", "encryption")
                    : hasAny(settings, "address", "server", "port", "server_port",
                    "id", "uuid", "user", "password", "method", "flow",
                    "security", "encryption"));
            if (nestedSettings && simplifiedSettings) {
                throw new IllegalArgumentException(
                        "conflicting nested and simplified Xray settings");
            }
            if (simplifiedSettings && hasTopLevelSimplifiedIdentity(object, type)) {
                throw new IllegalArgumentException(
                        "conflicting top-level and simplified Xray settings");
            }
            boolean packetEncodingPresent = !xrayShape && hasAny(
                    object, "packetEncoding", "packet_encoding");
            String packetEncoding = xrayShape ? ""
                    : first(object, "packetEncoding", "packet_encoding");
            if (settings != null && !xrayShape) {
                boolean settingsPacketEncodingPresent = hasAny(
                        settings, "packetEncoding", "packet_encoding");
                String settingsPacketEncoding = first(
                        settings, "packetEncoding", "packet_encoding");
                if (packetEncodingPresent && settingsPacketEncodingPresent) {
                    throw new IllegalArgumentException(
                            "duplicate structured packet encoding");
                }
                if (settingsPacketEncodingPresent) {
                    packetEncoding = settingsPacketEncoding;
                    packetEncodingPresent = true;
                }
            }
            if (packetEncodingPresent && !type.equals("vless")) return "";
            if (settings != null) {
                boolean validSettings;
                if (xrayShape && type.equals("vless")) {
                    validSettings = hasOnlyKeys(settings,
                            "vnext", "address", "port", "id", "flow", "encryption");
                } else if (xrayShape && type.equals("vmess")) {
                    validSettings = hasOnlyKeys(settings,
                            "vnext", "address", "port", "id", "security");
                } else if (xrayShape && type.equals("trojan")) {
                    validSettings = hasOnlyKeys(settings,
                            "servers", "address", "port", "password", "flow");
                } else if (xrayShape) {
                    validSettings = hasOnlyKeys(settings,
                            "servers", "address", "port", "password", "method");
                } else if (type.equals("vless")) {
                    validSettings = hasOnlyKeys(settings,
                            "vnext", "address", "server", "port", "server_port",
                            "id", "uuid", "user", "flow", "encryption",
                            "packetEncoding", "packet_encoding");
                } else if (type.equals("vmess")) {
                    validSettings = hasOnlyKeys(settings,
                            "vnext", "address", "server", "port", "server_port",
                            "id", "uuid", "user", "security", "encryption");
                } else if (type.equals("trojan")) {
                    validSettings = hasOnlyKeys(settings, "servers", "address", "server",
                            "port", "server_port", "password", "flow");
                } else {
                    validSettings = hasOnlyKeys(settings, "servers", "address", "server",
                            "port", "server_port", "password", "method");
                }
                if (!validSettings) return "";
                if (simplifiedSettings) {
                    server = xrayShape ? first(settings, "address")
                            : first(settings, "address", "server");
                    port = xrayShape ? strictXrayInteger(settings, 0, 0, 65535, "port")
                            : strictInteger(settings, 0, 0, 65535,
                            "port", "server_port");
                    if (type.equals("vless") || type.equals("vmess")) {
                        credential = xrayShape ? first(settings, "id")
                                : first(settings, "id", "uuid", "user");
                        if (type.equals("vless")) {
                            flow = first(settings, "flow");
                            cipher = first(settings, "encryption");
                        } else {
                            cipher = xrayShape ? first(settings, "security")
                                    : first(settings, "security", "encryption");
                        }
                    } else {
                        credential = first(settings, "password");
                        method = first(settings, "method");
                        if (type.equals("trojan")) flow = first(settings, "flow");
                    }
                }
            }
            if (type.equals("vless") || type.equals("vmess")) {
                JSONArray users = optionalArray(object, "users");
                JSONObject user = users == null ? null : requireExactFirst(users, "users");
                JSONArray vnext = settings == null ? null : optionalArray(settings, "vnext");
                if (vnext != null) {
                    JSONObject endpoint = requireExactFirst(vnext, "vnext");
                    if (!hasOnlyKeys(endpoint, "address", "port", "users")) {
                        return "";
                    }
                    server = first(endpoint, "address");
                    port = strictXrayInteger(endpoint, 0, 0, 65535, "port");
                    user = requireExactFirst(optionalArray(endpoint, "users"), "vnext users");
                }
                if (user != null) {
                    if (!xrayShape && hasAny(object, "uuid", "id", "user", "flow", "security",
                            "encryption", "alterId", "alter_id")) {
                        throw new IllegalArgumentException(
                                "conflicting top-level and users credentials");
                    }
                    boolean validUser;
                    if (xrayShape && type.equals("vless")) {
                        validUser = hasOnlyKeys(user, "id", "flow", "encryption");
                    } else if (xrayShape) {
                        validUser = hasOnlyKeys(user, "id", "security");
                    } else if (type.equals("vless")) {
                        validUser = hasOnlyKeys(
                                user, "id", "uuid", "user", "flow", "encryption");
                    } else {
                        validUser = hasOnlyKeys(user, "id", "uuid", "user", "alterId",
                                "alter_id", "security", "encryption");
                    }
                    if (!validUser) return "";
                    credential = xrayShape ? first(user, "id")
                            : first(user, "id", "uuid", "user");
                    flow = first(user, "flow");
                    if (!xrayShape) {
                        alterId = strictInteger(user, alterId, 0, Integer.MAX_VALUE,
                                "alterId", "alter_id");
                    }
                    cipher = xrayShape && type.equals("vmess")
                            ? first(user, "security") : first(user, "security", "encryption");
                }
            } else {
                JSONArray servers = settings == null ? null : optionalArray(settings, "servers");
                if (servers != null) {
                    JSONObject endpoint = requireExactFirst(servers, "servers");
                    if (type.equals("trojan") && endpoint.has("flow")) {
                        throw new IllegalArgumentException("unsupported Trojan flow");
                    }
                    boolean validEndpoint = type.equals("trojan")
                            ? hasOnlyKeys(endpoint, "address", "port", "password")
                            : hasOnlyKeys(endpoint, "address", "port", "password", "method");
                    if (!validEndpoint) return "";
                    server = first(endpoint, "address");
                    port = strictXrayInteger(endpoint, 0, 0, 65535, "port");
                    credential = first(endpoint, "password");
                    method = first(endpoint, "method");
                }
            }
            if (type.equals("shadowsocks")) {
                String canonicalMethod = ProtocolParser.canonicalShadowsocksMethod(method);
                if (xrayShape && canonicalMethod.startsWith("2022-")
                        && !method.equals(canonicalMethod)) {
                    throw new IllegalArgumentException(
                            "unsupported Xray Shadowsocks 2022 method");
                }
                method = canonicalMethod;
            }
            boolean emptyShadowsocksPassword = type.equals("shadowsocks")
                    && method.equals("none");
            if (server.isEmpty() || port <= 0 || port > 65535
                    || (credential.isEmpty() && !emptyShadowsocksPassword)) return "";
            requireScalarLimit(server, 1024, "proxy server");
            requireScalarLimit(credential, 8 * 1024, "proxy credential");
            requireScalarLimit(method, 256, "proxy method");
            requireScalarLimit(cipher, 256, "proxy cipher");
            requireScalarLimit(flow, 256, "proxy flow");
            requireScalarLimit(packetEncoding, 64, "packet encoding");
            if (type.equals("shadowsocks") && method.isEmpty()) return "";
            if (type.equals("trojan") && !flow.isEmpty()) {
                throw new IllegalArgumentException("unsupported Trojan flow");
            }
            if (xrayShape && type.equals("vless") && !flow.isEmpty()
                    && !flow.equals("xtls-rprx-vision")
                    && !flow.equals("xtls-rprx-vision-udp443")) {
                throw new IllegalArgumentException("unsupported Xray VLESS flow");
            }
            if (type.equals("vmess") && xrayShape && !cipher.isEmpty()
                    && !ProtocolParser.xrayVmessSecurity(cipher)) {
                // Pinned Xray treats legacy/unknown VMess security spellings as
                // AUTO. Importing the spelling as a sing-box-only cipher would
                // silently change an Xray-shaped configuration's behavior.
                throw new IllegalArgumentException(
                        "unsupported Xray VMess security");
            }

            Map<String, String> params = new LinkedHashMap<>();
            if (!flow.isEmpty()) params.put("flow", flow);
            if (packetEncodingPresent) {
                params.put("packetEncoding",
                        packetEncoding.isEmpty() ? "none" : packetEncoding);
            }
            if (type.equals("vless")) params.put("encryption", cipher.isEmpty() ? "none" : cipher);
            if (!extractStream(object, params, hints)) return "";
            validateGeneratedParams(params);
            if (type.equals("trojan") && !params.containsKey("security")) {
                params.put("security", "none");
            }
            String name = first(object, "tag", "name", "remarks", "ps");
            requireScalarLimit(name, 1024, "proxy name");

            if (type.equals("vmess")) {
                JSONObject vmess = new JSONObject()
                        .put("v", "2").put("ps", name).put("add", server).put("port", port)
                        .put("id", credential).put("aid", alterId)
                        .put("scy", cipher.isEmpty() ? "auto" : cipher)
                        .put("net", param(params, "type", "tcp"));
                copyParam(params, vmess, "security", "tls");
                copyParam(params, vmess, "sni");
                copyParam(params, vmess, "host");
                copyParam(params, vmess, "path");
                copyParam(params, vmess, "fp");
                copyParam(params, vmess, "alpn");
                copyParam(params, vmess, "mode");
                copyParam(params, vmess, "extra");
                copyParam(params, vmess, "headerType");
                copyParam(params, vmess, "seed");
                copyParam(params, vmess, "ed");
                copyParam(params, vmess, "eh");
                copyParam(params, vmess, "headers");
                copyParam(params, vmess, "mtu");
                copyParam(params, vmess, "tti");
                copyParam(params, vmess, "uplinkCapacity");
                copyParam(params, vmess, "downlinkCapacity");
                copyParam(params, vmess, "cwndMultiplier");
                copyParam(params, vmess, "maxSendingWindow");
                copyParam(params, vmess, "pbk");
                copyParam(params, vmess, "sid");
                copyParam(params, vmess, "insecure");
                return "vmess://" + Base64.getEncoder().withoutPadding().encodeToString(
                        vmess.toString().getBytes(StandardCharsets.UTF_8));
            }
            if (type.equals("shadowsocks")) {
                String network = param(params, "type", "tcp");
                if (!network.equals("tcp") && !network.equals("raw")) return "";
                for (String key : params.keySet()) if (!key.equals("type")) return "";
                String credentials = method + ":" + credential;
                String output = "ss://" + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        credentials.getBytes(StandardCharsets.UTF_8)) + "@"
                        + hostForUri(server) + ":" + port;
                return name.isEmpty() ? output : output + "#" + enc(name);
            }

            StringBuilder output = new StringBuilder(type).append("://")
                    .append(enc(credential)).append('@').append(hostForUri(server))
                    .append(':').append(port);
            if (!params.isEmpty()) {
                List<String> query = new ArrayList<>();
                for (Map.Entry<String, String> item : params.entrySet()) {
                    if (!item.getValue().isEmpty()) {
                        query.add(enc(item.getKey()) + "=" + enc(item.getValue()));
                    }
                }
                if (!query.isEmpty()) output.append('?').append(join(query, "&"));
            }
            if (!name.isEmpty()) output.append('#').append(enc(name));
            return output.toString();
        } catch (IllegalArgumentException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalArgumentException("unrepresentable outbound", error);
        }
    }

    private static boolean extractStream(JSONObject object, Map<String, String> params,
                                         ImportHints hints) {
        try {
            JSONObject tls = optionalObject(object, "tls");
            if (tls != null && !hasOnlyKeys(tls, "enabled", "server_name", "sni",
                    "insecure", "alpn", "utls", "reality")) return false;
            boolean tlsEnabled = tls != null && strictBoolean(tls, false, "enabled");
            if (tls != null && !tlsEnabled && hasFunctionalKeysBesides(tls, "enabled")) {
                return false;
            }
            if (tlsEnabled) {
                JSONObject reality = optionalObject(tls, "reality");
                boolean isReality = reality != null
                        && strictBoolean(reality, false, "enabled");
                if (reality != null && !isReality
                        && hasFunctionalKeysBesides(reality, "enabled")) return false;
                params.put("security", isReality ? "reality" : "tls");
                putParam(params, "sni", first(tls, "server_name", "sni"));
                if (strictBoolean(tls, false, "insecure")) params.put("insecure", "1");
                JSONArray alpn = optionalArray(tls, "alpn");
                if (alpn != null) putParam(params, "alpn", joinJsonStrings(alpn));
                JSONObject utls = optionalObject(tls, "utls");
                if (utls != null) {
                    if (!hasOnlyKeys(utls, "enabled", "fingerprint")) return false;
                    boolean utlsEnabled = strictBoolean(utls, false, "enabled");
                    if (!utlsEnabled) {
                        if (hasFunctionalKeysBesides(utls, "enabled")) return false;
                    } else if (first(utls, "fingerprint").isEmpty()) {
                        return false;
                    }
                    putParam(params, "fp", first(utls, "fingerprint"));
                }
                if (isReality) {
                    if (!hasOnlyKeys(reality, "enabled", "public_key", "publicKey",
                            "short_id", "shortId", "spider_x", "spiderX")) return false;
                    putParam(params, "pbk", first(reality, "public_key", "publicKey"));
                    putParam(params, "sid", first(reality, "short_id", "shortId"));
                    putParam(params, "spx", first(reality, "spider_x", "spiderX"));
                }
            }
            JSONObject transport = optionalObject(object, "transport");
            if (transport != null && !extractTransportSettings(
                    first(transport, "type", "network"), transport, params,
                    false, hints)) return false;

            JSONObject stream = optionalObject(object, "streamSettings");
            if (stream == null) return true;
            if (!hasOnlyKeys(stream, "network", "method", "security", "tlsSettings", "realitySettings",
                    "wsSettings", "grpcSettings", "httpSettings", "h2Settings",
                    "httpupgradeSettings", "xhttpSettings", "splithttpSettings",
                    "kcpSettings", "finalmask")) return false;
            String network = hasAny(stream, "network", "method")
                    ? ProtocolParser.canonicalTransportType(
                    first(stream, "network", "method")) : "raw";
            params.put("type", network);
            String security = stream.has("security")
                    ? first(stream, "security").toLowerCase(Locale.US) : "none";
            if (!security.equals("none") && !security.isEmpty()
                    && !security.equals("tls") && !security.equals("reality")) return false;
            if (!selectedStreamBlocksAreStrict(stream, network, security)) return false;
            if (!security.equals("none") && !security.isEmpty()) params.put("security", security);
            JSONObject secure = security.equals("reality")
                    ? optionalObject(stream, "realitySettings")
                    : (security.equals("tls") ? optionalObject(stream, "tlsSettings") : null);
            if (secure != null) {
                if (security.equals("tls")) {
                    // Only the pinned TLSConfig JSON tags represented by the
                    // neutral model are accepted. Snake-case/sing-box aliases
                    // are not Xray JSON and must not be reinterpreted.
                    if (!hasOnlyKeys(secure, "serverName", "allowInsecure",
                            "fingerprint", "alpn")) return false;
                    putParam(params, "sni", first(secure, "serverName"));
                    if (strictBoolean(secure, false, "allowInsecure")) {
                        params.put("insecure", "1");
                    }
                    putParam(params, "fp", first(secure, "fingerprint"));
                    if (secure.has("alpn")) {
                        Object rawAlpn = secure.opt("alpn");
                        if (rawAlpn instanceof JSONArray) {
                            putParam(params, "alpn",
                                    joinJsonStrings((JSONArray) rawAlpn));
                        } else if (rawAlpn instanceof String) {
                            String alpn = first(secure, "alpn");
                            if (alpn.isEmpty()) return false;
                            putParam(params, "alpn", alpn);
                        } else {
                            return false;
                        }
                    }
                } else {
                    // Client-side pinned REALITYConfig fields that ExitFy can
                    // preserve exactly. Server-only or unknown fields reject.
                    if (!hasOnlyKeys(secure, "serverName", "fingerprint",
                            "password", "publicKey", "shortId", "spiderX")) return false;
                    putParam(params, "sni", first(secure, "serverName"));
                    putParam(params, "fp", first(secure, "fingerprint"));
                    putParam(params, "pbk", first(secure, "publicKey", "password"));
                    putParam(params, "sid", first(secure, "shortId"));
                    putParam(params, "spx", first(secure, "spiderX"));
                }
            }

            JSONObject networkSettings = (network.equals("kcp") || network.equals("mkcp"))
                    ? optionalObject(stream, "kcpSettings")
                    : optionalObject(stream, network + "Settings");
            if ((networkSettings == null || !functional(networkSettings))
                    && network.equals("xhttp")) {
                networkSettings = optionalObject(stream, "splithttpSettings");
            }
            if ((networkSettings == null || !functional(networkSettings))
                    && network.equals("splithttp")) {
                networkSettings = optionalObject(stream, "xhttpSettings");
            }
            if (networkSettings != null && !extractTransportSettings(
                    network, networkSettings, params, true, hints)) return false;
            if (network.equals("kcp") || network.equals("mkcp")) {
                JSONObject finalmask = optionalObject(stream, "finalmask");
                if (finalmask != null && networkSettings != null && hasAny(networkSettings,
                        "header", "headerType", "legacy_header", "seed", "legacy_seed")) {
                    throw new IllegalArgumentException(
                            "conflicting mKCP settings and finalmask");
                }
                if (!extractFinalMask(finalmask, params)) return false;
            }
            return true;
        } catch (IllegalArgumentException error) {
            throw error;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean extractTransportSettings(String networkValue, JSONObject settings,
                                                     Map<String, String> params,
                                                     boolean xrayStream,
                                                     ImportHints hints) throws Exception {
        String network = ProtocolParser.canonicalTransportType(networkValue);
        if (network.equals("tcp") || network.equals("raw") || network.equals("none")
                || network.isEmpty()) {
            if (!hasOnlyKeys(settings, "type", "network")) return false;
        } else if (network.equals("ws")) {
            if (xrayStream) {
                if (!hasOnlyKeys(settings, "path", "host", "headers")) return false;
            } else {
                if (!hasOnlyKeys(settings, "type", "network", "path", "host", "headers",
                        "maxEarlyData", "max_early_data", "earlyDataHeaderName",
                        "early_data_header_name")) return false;
                long early = strictUnsigned32(settings, 0,
                        "maxEarlyData", "max_early_data");
                if (early > 0) params.put("ed", String.valueOf(early));
                putParam(params, "eh", first(settings, "earlyDataHeaderName",
                        "early_data_header_name"));
            }
        } else if (network.equals("grpc")) {
            if (xrayStream) {
                if (!hasOnlyKeys(settings, "serviceName")) return false;
            } else if (!hasOnlyKeys(settings, "type", "network", "path",
                    "serviceName", "service_name")) return false;
        } else if (network.equals("http") || network.equals("h2")) {
            if (!hasOnlyKeys(settings, "type", "network", "path", "host", "headers")) return false;
        } else if (network.equals("httpupgrade")) {
            if (xrayStream) {
                if (!hasOnlyKeys(settings, "path", "host", "headers")) {
                    return false;
                }
            } else if (!hasOnlyKeys(settings, "type", "network", "path", "host", "headers",
                    "maxEarlyData", "max_early_data")) {
                return false;
            }
            long early = strictUnsigned32(settings, 0,
                    "maxEarlyData", "max_early_data");
            if (early > 0) params.put("ed", String.valueOf(early));
        } else if (!network.equals("xhttp") && !network.equals("splithttp")
                && !network.equals("kcp") && !network.equals("mkcp")) {
            return false;
        }
        if (!network.isEmpty()) params.put("type", network);
        String path = (network.equals("http") || network.equals("h2"))
                ? singleString(settings, "path", true)
                : first(settings, "path", "serviceName", "service_name");
        if ((network.equals("ws") || network.equals("httpupgrade")) && xrayStream) {
            if (network.equals("ws") && hints != null && path != null
                    && (path.indexOf('?') >= 0 || path.indexOf('#') >= 0)) {
                hints.xrayWebSocketPathSemantics = true;
            }
            WebSocketPath normalized = normalizeXrayWebSocketPath(path);
            path = normalized.path;
            if (normalized.earlyData > 0) {
                String explicit = params.get("ed");
                if (explicit != null
                        && !explicit.equals(String.valueOf(normalized.earlyData))) {
                    throw new IllegalArgumentException("conflicting WebSocket early data");
                }
                params.put("ed", String.valueOf(normalized.earlyData));
                if (hints != null) {
                    if (network.equals("ws")) {
                        hints.xrayWebSocketPathEarlyData = true;
                    } else {
                        hints.xrayHttpUpgradePathEarlyData = true;
                    }
                }
            }
        }
        putParam(params, network.equals("grpc") ? "serviceName" : "path", path);
        Object rawHost = settings.opt("host");
        boolean explicitHost = rawHost != null && rawHost != JSONObject.NULL;
        String host = rawHost instanceof String ? first(settings, "host") : "";
        if (xrayStream && (network.equals("ws") || network.equals("httpupgrade"))
                && settings.has("host") && !(rawHost instanceof String)) {
            return false;
        }
        if (network.equals("ws") && xrayStream && rawHost instanceof String
                && host.isEmpty()) {
            throw new IllegalArgumentException("WebSocket Host is empty");
        }
        if (rawHost != null && rawHost != JSONObject.NULL
                && !(rawHost instanceof String) && !(rawHost instanceof JSONArray)) {
            return false;
        }
        JSONObject headers = optionalObject(settings, "headers");
        if (headers != null) {
            java.util.HashSet<String> normalizedHeaders = new java.util.HashSet<>();
            java.util.Iterator<String> headerKeys = headers.keys();
            while (headerKeys.hasNext()) {
                String header = headerKeys.next();
                Object raw = headers.opt(header);
                if (!ProtocolParser.validHeaderName(header)
                        || !normalizedHeaders.add(header.toLowerCase(Locale.US))
                        || (xrayStream && (network.equals("ws")
                        || network.equals("httpupgrade")) && !(raw instanceof String))
                        || (xrayStream && network.equals("httpupgrade")
                        && header.equalsIgnoreCase("host"))
                        || !validHeaderValue(raw)) return false;
            }
            enforceJsonSize(headers, 16 * 1024, "transport headers exceed 16 KiB");
            putParam(params, "headers", headers.toString());
        }
        if (headers != null) {
            Object headerHost = caseInsensitiveHeader(headers, "host");
            if (headerHost != null) explicitHost = true;
            String singularHost = singularHeaderValue(headerHost);
            if (!host.isEmpty() && headerHost != null && !host.equals(singularHost)) {
                return false;
            }
            if (host.isEmpty()) host = singularHost;
        }
        JSONArray hosts = settings.optJSONArray("host");
        if (hosts != null) {
            explicitHost = true;
            if (hosts.length() != 1 || !(hosts.opt(0) instanceof String)
                    || hosts.optString(0, "").isEmpty()) return false;
            String arrayHost = hosts.optString(0, "");
            if (!host.isEmpty() && !host.equals(arrayHost)) return false;
            if (host.isEmpty()) host = arrayHost;
        }
        if (network.equals("ws") && xrayStream && !explicitHost && host.isEmpty()) {
            // Pinned Xray falls back WebSocket Host to TLS ServerName, while
            // pinned sing-box falls back to the endpoint. Materialize Xray's
            // effective value so Auto cannot change the request on migration.
            String sni = params.get("sni");
            if (sni != null && !sni.isEmpty()) host = sni;
        }
        putParam(params, "host", host);
        String mode = first(settings, "mode");
        if (xrayStream && (network.equals("xhttp") || network.equals("splithttp"))
                && !mode.isEmpty() && !mode.equals("auto")
                && !mode.equals("packet-up") && !mode.equals("stream-up")
                && !mode.equals("stream-one")) {
            return false;
        }
        putParam(params, "mode", mode);
        Object extra = settings.opt("extra");
        if (extra instanceof JSONObject) {
            if (!validXhttpExtra((JSONObject) extra)) return false;
        } else if (extra != null && extra != JSONObject.NULL) {
            return false;
        }
        if (network.equals("xhttp") || network.equals("splithttp")) {
            if (settings.has("extra") && extra == JSONObject.NULL) return false;
            if (!hasOnlyKeys(settings, "host", "path", "mode", "extra", "type", "network",
                    "scMaxEachPostBytes", "scMinPostsIntervalMs",
                    "xPaddingBytes", "noSSEHeader")) return false;
            if (extra instanceof JSONObject && hasAny(settings,
                    "scMaxEachPostBytes", "scMinPostsIntervalMs",
                    "xPaddingBytes", "noSSEHeader")) {
                // Pinned Xray ignores these outer fields whenever `extra` is
                // present. Reject the hybrid shape instead of silently
                // changing which value becomes effective.
                return false;
            }
            JSONObject merged;
            if (extra instanceof JSONObject) {
                enforceJsonSize(extra, 64 * 1024, "XHTTP extra exceeds 64 KiB");
                merged = new JSONObject(extra.toString());
            } else {
                merged = new JSONObject();
            }
            java.util.Iterator<String> keys = settings.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                if (!key.equals("host") && !key.equals("path") && !key.equals("mode")
                        && !key.equals("extra") && !key.equals("type")
                        && !key.equals("network")) {
                    try {
                        merged.put(key, settings.opt(key));
                    } catch (Exception ignored) {
                        return false;
                    }
                }
            }
            if (merged.length() > 0) {
                enforceJsonSize(merged, 64 * 1024, "XHTTP extra exceeds 64 KiB");
                putParam(params, "extra", merged.toString());
            }
        } else if (network.equals("kcp") || network.equals("mkcp")) {
            if (xrayStream) {
                if (!hasOnlyKeys(settings, "mtu", "tti", "uplinkCapacity",
                        "downlinkCapacity", "cwndMultiplier", "maxSendingWindow",
                        "header", "seed")) return false;
            } else if (!hasOnlyKeys(settings, "type", "network", "mtu", "tti",
                    "uplinkCapacity", "uplink_capacity", "downlinkCapacity",
                    "downlink_capacity", "cwndMultiplier", "cwnd_multiplier",
                    "maxSendingWindow", "max_sending_window", "header", "headerType",
                    "legacy_header", "seed", "legacy_seed")) {
                return false;
            }
        }
        if (network.equals("kcp") || network.equals("mkcp")) {
            if (!xrayStream) {
                rejectStructuredAliases(settings, "mKCP header",
                        "header", "headerType", "legacy_header");
                rejectStructuredAliases(settings, "mKCP seed", "seed", "legacy_seed");
                rejectStructuredAliases(settings, "mKCP upload capacity",
                        "uplinkCapacity", "uplink_capacity");
                rejectStructuredAliases(settings, "mKCP download capacity",
                        "downlinkCapacity", "downlink_capacity");
                rejectStructuredAliases(settings, "mKCP congestion multiplier",
                        "cwndMultiplier", "cwnd_multiplier");
                rejectStructuredAliases(settings, "mKCP sending window",
                        "maxSendingWindow", "max_sending_window");
            }
        }
        JSONObject header = optionalObject(settings, "header");
        if (header != null) {
            if (!hasOnlyKeys(header, "type")) return false;
            putUniqueParam(params, "headerType", first(header, "type"));
        }
        if (!xrayStream) {
            putUniqueParam(params, "headerType",
                    first(settings, "legacy_header", "headerType"));
        }
        String legacySeed = xrayStream
                ? first(settings, "seed") : first(settings, "legacy_seed", "seed");
        if (hasAny(settings, xrayStream ? new String[]{"seed"}
                : new String[]{"legacy_seed", "seed"}) && legacySeed.isEmpty()) {
            throw new IllegalArgumentException("mKCP legacy seed is missing");
        }
        putUniqueParam(params, "seed", legacySeed);
        if (xrayStream) {
            copyXrayInteger(settings, params, "mtu", "mtu");
            copyXrayInteger(settings, params, "tti", "tti");
            copyXrayInteger(settings, params, "uplinkCapacity", "uplinkCapacity");
            copyXrayInteger(settings, params, "downlinkCapacity", "downlinkCapacity");
            copyXrayInteger(settings, params, "cwndMultiplier", "cwndMultiplier");
            copyXrayInteger(settings, params, "maxSendingWindow", "maxSendingWindow");
        } else {
            copyString(settings, params, "mtu", "mtu");
            copyString(settings, params, "tti", "tti");
            copyString(settings, params, "uplinkCapacity", "uplinkCapacity");
            copyString(settings, params, "downlinkCapacity", "downlinkCapacity");
            copyString(settings, params, "cwndMultiplier", "cwndMultiplier");
            copyString(settings, params, "maxSendingWindow", "maxSendingWindow");
        }
        if (!xrayStream) {
            copyString(settings, params, "uplink_capacity", "uplinkCapacity");
            copyString(settings, params, "downlink_capacity", "downlinkCapacity");
            copyString(settings, params, "cwnd_multiplier", "cwndMultiplier");
            copyString(settings, params, "max_sending_window", "maxSendingWindow");
        }
        return true;
    }

    private static boolean selectedStreamBlocksAreStrict(JSONObject stream,
                                                          String network,
                                                          String security) {
        String[] transports = {"wsSettings", "grpcSettings", "httpSettings", "h2Settings",
                "httpupgradeSettings", "xhttpSettings", "splithttpSettings",
                "kcpSettings"};
        java.util.HashSet<String> selected = new java.util.HashSet<>();
        if (network.equals("ws")) selected.add("wsSettings");
        else if (network.equals("grpc")) selected.add("grpcSettings");
        else if (network.equals("http")) selected.add("httpSettings");
        else if (network.equals("h2")) selected.add("h2Settings");
        else if (network.equals("httpupgrade")) selected.add("httpupgradeSettings");
        else if (network.equals("xhttp") || network.equals("splithttp")) {
            selected.add("xhttpSettings");
            selected.add("splithttpSettings");
            // These fields are pointer-valued aliases in pinned Xray. Their
            // simultaneous presence is ambiguous even when either object is
            // empty, so never choose one by content-based precedence.
            if (stream.has("xhttpSettings") && stream.has("splithttpSettings")) {
                return false;
            }
        } else if (network.equals("kcp") || network.equals("mkcp")) {
            selected.add("kcpSettings");
        } else if (!network.equals("tcp") && !network.equals("raw")
                && !network.equals("none") && !network.isEmpty()) {
            return false;
        }
        for (String block : transports) {
            if (stream.has(block) && !(stream.opt(block) instanceof JSONObject)) return false;
        }
        for (String block : new String[]{"tlsSettings", "realitySettings", "finalmask"}) {
            if (stream.has(block) && !(stream.opt(block) instanceof JSONObject)) return false;
        }
        for (String block : transports) {
            if (!selected.contains(block) && functional(stream.opt(block))) return false;
        }
        if (!security.equals("tls") && functional(stream.opt("tlsSettings"))) return false;
        if (!security.equals("reality") && functional(stream.opt("realitySettings"))) return false;
        if (!network.equals("kcp") && !network.equals("mkcp")
                && functional(stream.opt("finalmask"))) return false;
        return true;
    }

    private static boolean functional(Object value) {
        if (value == null || value == JSONObject.NULL) return false;
        if (value instanceof JSONObject) return ((JSONObject) value).length() > 0;
        if (value instanceof JSONArray) return ((JSONArray) value).length() > 0;
        if (value instanceof String) return !((String) value).trim().isEmpty();
        return true;
    }

    private static boolean validHeaderValue(Object raw) {
        if (raw instanceof String) return ((String) raw).length() <= 4096;
        if (!(raw instanceof JSONArray)) return false;
        JSONArray values = (JSONArray) raw;
        if (values.length() <= 0 || values.length() > 32) return false;
        for (int index = 0; index < values.length(); index++) {
            Object item = values.opt(index);
            if (!(item instanceof String) || ((String) item).length() > 4096) return false;
        }
        return true;
    }

    private static Object caseInsensitiveHeader(JSONObject headers, String expected) {
        java.util.Iterator<String> keys = headers.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (key.equalsIgnoreCase(expected)) return headers.opt(key);
        }
        return null;
    }

    private static String singularHeaderValue(Object raw) {
        if (raw == null || raw == JSONObject.NULL) return "";
        if (raw instanceof String) {
            String value = (String) raw;
            if (value.isEmpty()) {
                throw new IllegalArgumentException("WebSocket Host is empty");
            }
            return value;
        }
        if (raw instanceof JSONArray) {
            JSONArray values = (JSONArray) raw;
            if (values.length() == 1 && values.opt(0) instanceof String) {
                String value = (String) values.opt(0);
                if (value.isEmpty()) {
                    throw new IllegalArgumentException("WebSocket Host is empty");
                }
                return value;
            }
        }
        throw new IllegalArgumentException(
                "WebSocket Host must contain exactly one string");
    }

    private static String singleString(JSONObject owner, String key, boolean optional) {
        Object raw = owner.opt(key);
        if (raw == null || raw == JSONObject.NULL) {
            if (optional) return "";
            throw new IllegalArgumentException("missing transport " + key);
        }
        if (raw instanceof String) return (String) raw;
        if (raw instanceof JSONArray) {
            JSONArray values = (JSONArray) raw;
            if (values.length() != 1 || !(values.opt(0) instanceof String)) {
                throw new IllegalArgumentException("transport " + key + " is not singular");
            }
            return (String) values.opt(0);
        }
        throw new IllegalArgumentException("invalid transport " + key);
    }

    private static WebSocketPath normalizeXrayWebSocketPath(String rawPath) {
        String path = rawPath == null || rawPath.isEmpty() ? "/" : rawPath;
        int fragmentIndex = path.indexOf('#');
        String fragment = fragmentIndex < 0 ? "" : path.substring(fragmentIndex);
        String withoutFragment = fragmentIndex < 0 ? path : path.substring(0, fragmentIndex);
        int query = withoutFragment.indexOf('?');
        if (query < 0) return new WebSocketPath(path, 0);
        String base = withoutFragment.substring(0, query);
        List<XrayQueryItem> kept = new ArrayList<>();
        long earlyData = 0L;
        boolean found = false;
        String rawQuery = withoutFragment.substring(query + 1);
        for (String item : rawQuery.split("&", -1)) {
            // net/url.ParseQuery ignores empty query segments before Values.Encode.
            if (item.isEmpty()) continue;
            int separator = item.indexOf('=');
            String rawKey = separator < 0 ? item : item.substring(0, separator);
            byte[] key = decodeGoQueryComponent(rawKey);
            if (key.length == 2 && key[0] == 'e' && key[1] == 'd') {
                if (found || separator < 0) {
                    throw new IllegalArgumentException("invalid WebSocket early data");
                }
                found = true;
                byte[] decodedValue = decodeGoQueryComponent(item.substring(separator + 1));
                String value = new String(decodedValue, StandardCharsets.ISO_8859_1);
                try {
                    long parsed = Long.parseLong(value);
                    if (parsed < 0L || parsed > 0xffff_ffffL) {
                        throw new NumberFormatException();
                    }
                    earlyData = parsed;
                } catch (NumberFormatException invalid) {
                    throw new IllegalArgumentException("invalid WebSocket early data");
                }
            } else {
                byte[] value = decodeGoQueryComponent(
                        separator < 0 ? "" : item.substring(separator + 1));
                kept.add(new XrayQueryItem(key, value));
            }
        }
        if (!found) return new WebSocketPath(path, 0L);
        // Pinned Xray's Build path uses url.Values: Del("ed") followed by
        // Encode(). Canonicalize for every present ed key, including ed=0.
        // Sorting decoded byte strings and escaping their UTF-8 bytes mirrors
        // Go string ordering and net/url.QueryEscape, including odd raw input.
        kept.sort((left, right) -> compareUnsigned(left.key, right.key));
        StringBuilder canonical = new StringBuilder(rawQuery.length());
        for (XrayQueryItem item : kept) {
            if (canonical.length() > 0) canonical.append('&');
            appendGoQueryEscaped(canonical, item.key);
            canonical.append('=');
            appendGoQueryEscaped(canonical, item.value);
        }
        return new WebSocketPath(base
                + (canonical.length() == 0 ? "" : "?" + canonical)
                + fragment, earlyData);
    }

    private static byte[] decodeGoQueryComponent(String value) {
        byte[] encoded = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);
        byte[] decoded = new byte[encoded.length];
        int output = 0;
        for (int index = 0; index < encoded.length; index++) {
            int current = encoded[index] & 0xff;
            if (current == '+') {
                decoded[output++] = ' ';
                continue;
            }
            if (current != '%') {
                decoded[output++] = encoded[index];
                continue;
            }
            if (index + 2 >= encoded.length) {
                throw new IllegalArgumentException("invalid WebSocket query encoding");
            }
            int high = hexDigit(encoded[++index]);
            int low = hexDigit(encoded[++index]);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid WebSocket query encoding");
            }
            decoded[output++] = (byte) ((high << 4) | low);
        }
        return java.util.Arrays.copyOf(decoded, output);
    }

    private static int hexDigit(byte value) {
        int current = value & 0xff;
        if (current >= '0' && current <= '9') return current - '0';
        if (current >= 'a' && current <= 'f') return current - 'a' + 10;
        if (current >= 'A' && current <= 'F') return current - 'A' + 10;
        return -1;
    }

    private static int compareUnsigned(byte[] left, byte[] right) {
        int shared = Math.min(left.length, right.length);
        for (int index = 0; index < shared; index++) {
            int difference = (left[index] & 0xff) - (right[index] & 0xff);
            if (difference != 0) return difference;
        }
        return left.length - right.length;
    }

    private static void appendGoQueryEscaped(StringBuilder output, byte[] value) {
        final char[] hex = "0123456789ABCDEF".toCharArray();
        for (byte item : value) {
            int current = item & 0xff;
            if ((current >= 'a' && current <= 'z')
                    || (current >= 'A' && current <= 'Z')
                    || (current >= '0' && current <= '9')
                    || current == '-' || current == '_' || current == '.' || current == '~') {
                output.append((char) current);
            } else if (current == ' ') {
                output.append('+');
            } else {
                output.append('%').append(hex[current >>> 4]).append(hex[current & 0x0f]);
            }
        }
    }

    private static boolean validXhttpExtra(JSONObject value) {
        if (!hasOnlyKeys(value, "scMaxEachPostBytes", "scMinPostsIntervalMs",
                "xPaddingBytes", "noSSEHeader")) return false;
        java.util.Iterator<String> keys = value.keys();
        while (keys.hasNext()) {
            Object item = value.opt(keys.next());
            if (item == null || item == JSONObject.NULL || item instanceof JSONObject
                    || item instanceof JSONArray) return false;
        }
        return true;
    }

    private static void enforceJsonSize(Object value, int maximum, String message) {
        try {
            AtomicStore.jsonUtf8Size(value, maximum);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException(message);
        }
    }

    private static boolean extractFinalMask(JSONObject finalmask, Map<String, String> params) {
        if (finalmask == null) return true;
        JSONArray tcp = optionalArray(finalmask, "tcp");
        if (tcp != null && tcp.length() > 0) return false;
        JSONArray udp = optionalArray(finalmask, "udp");
        if (udp == null || udp.length() < 1 || udp.length() > 2
                || !hasOnlyKeys(finalmask, "tcp", "udp")) return false;
        String seed = "";
        String header = "";
        for (int index = 0; index < udp.length(); index++) {
            JSONObject mask = udp.optJSONObject(index);
            if (mask == null || !hasOnlyKeys(mask, "type", "settings")
                    || !"mkcp-legacy".equalsIgnoreCase(first(mask, "type"))) return false;
            JSONObject settings = optionalObject(mask, "settings");
            if (settings == null || !hasOnlyKeys(settings, "header", "value")) return false;
            String currentHeader = first(settings, "header");
            String currentSeed = first(settings, "value");
            if (currentHeader.isEmpty() == currentSeed.isEmpty()) return false;
            if (!currentSeed.isEmpty()) {
                if (!seed.isEmpty() || !header.isEmpty()) return false;
                seed = currentSeed;
            } else {
                if (!header.isEmpty()) return false;
                // With two masks the seed must be listed first: finalmask
                // applies the chain in reverse order to preserve legacy bytes.
                if (udp.length() == 2 && index != 1) return false;
                header = currentHeader;
            }
        }
        if (udp.length() == 2 && (seed.isEmpty() || header.isEmpty())) return false;
        putUniqueParam(params, "seed", seed);
        putUniqueParam(params, "headerType", header);
        return true;
    }

    private static boolean hasOnlyKeys(JSONObject value, String... allowedValues) {
        java.util.HashSet<String> allowed = new java.util.HashSet<>();
        java.util.Collections.addAll(allowed, allowedValues);
        java.util.Iterator<String> keys = value.keys();
        while (keys.hasNext()) if (!allowed.contains(keys.next())) return false;
        return true;
    }

    private static void validateOutboundShape(JSONObject object) {
        for (String forbidden : new String[]{"detour", "proxySettings", "sendThrough", "mux",
                "bind_interface", "bind_address", "inet4_bind_address", "inet6_bind_address",
                "routing_mark", "domain_strategy", "domainStrategy", "strategy", "dns"}) {
            if (object.has(forbidden)) {
                throw new IllegalArgumentException("unsupported outbound field: " + forbidden);
            }
        }
        boolean xray = isXrayOutboundShape(object);
        String type = xray ? xrayOutboundType(object) : outboundType(object);
        boolean valid;
        if (xray) {
            valid = hasOnlyKeys(object, "protocol", "tag", "settings", "streamSettings");
        } else if (type.equals("vless")) {
            valid = hasOnlyKeys(object, "type", "protocol", "tag", "name", "remarks", "ps",
                    "server", "address", "server_port", "port", "uuid", "id", "user",
                    "flow", "packet_encoding", "packetEncoding", "encryption", "tls",
                    "transport", "users", "settings");
        } else if (type.equals("vmess")) {
            valid = hasOnlyKeys(object, "type", "protocol", "tag", "name", "remarks", "ps",
                    "server", "address", "server_port", "port", "uuid", "id", "user",
                    "alter_id", "alterId", "security", "encryption", "tls", "transport",
                    "users", "settings");
        } else if (type.equals("trojan")) {
            valid = hasOnlyKeys(object, "type", "protocol", "tag", "name", "remarks", "ps",
                    "server", "address", "server_port", "port", "password", "tls",
                    "transport", "settings");
        } else {
            valid = hasOnlyKeys(object, "type", "protocol", "tag", "name", "remarks", "ps",
                    "server", "address", "server_port", "port", "password", "method",
                    "settings");
        }
        if (!valid) throw new IllegalArgumentException("unknown outbound field");
    }

    private static boolean isXrayOutboundShape(JSONObject object) {
        JSONObject settings = object == null ? null : object.optJSONObject("settings");
        return object != null && (object.has("protocol") || object.has("streamSettings")
                || (settings != null && (settings.has("vnext")
                || settings.has("servers"))));
    }

    private static String outboundType(JSONObject object) {
        String selected = "";
        String selectedKey = "";
        for (String key : new String[]{"type", "protocol"}) {
            if (!object.has(key)) continue;
            Object raw = object.opt(key);
            if (!(raw instanceof String)) {
                throw new IllegalArgumentException("structured discriminator must be a string: " + key);
            }
            String candidate = normalizeOutboundType((String) raw);
            if (candidate.isEmpty()) {
                throw new IllegalArgumentException("unsupported outbound discriminator: " + key);
            }
            if (!selected.isEmpty() && !selected.equals(candidate)) {
                throw new IllegalArgumentException("conflicting outbound discriminators: "
                        + selectedKey + "/" + key);
            }
            selected = candidate;
            selectedKey = key;
        }
        if (selected.isEmpty()) throw new IllegalArgumentException("missing outbound discriminator");
        return selected;
    }

    private static String xrayOutboundType(JSONObject object) {
        if (object == null || !object.has("protocol") || object.has("type")) {
            throw new IllegalArgumentException(
                    "Xray outbound requires exact protocol discriminator");
        }
        Object raw = object.opt("protocol");
        if (!(raw instanceof String)) {
            throw new IllegalArgumentException(
                    "structured discriminator must be a string: protocol");
        }
        String protocol = (String) raw;
        if (!protocol.equals("vless") && !protocol.equals("vmess")
                && !protocol.equals("trojan") && !protocol.equals("shadowsocks")) {
            throw new IllegalArgumentException(
                    "unsupported outbound discriminator: protocol");
        }
        return protocol;
    }

    private static boolean isSupportedOutboundType(String value) {
        return !normalizeOutboundType(value).isEmpty();
    }

    private static String normalizeOutboundType(String value) {
        String type = value == null ? "" : value.trim().toLowerCase(Locale.US);
        if (type.equals("ss")) return "shadowsocks";
        return type.equals("vless") || type.equals("vmess") || type.equals("trojan")
                || type.equals("shadowsocks") ? type : "";
    }

    static final String UNREACHABLE_ONLY = "unreachable_placeholders";

    private static String reasonCode(Exception error) {
        String value = error == null || error.getMessage() == null ? ""
                : error.getMessage().toLowerCase(Locale.US);
        if (value.contains(ProtocolParser.UNREACHABLE_SERVER)) return UNREACHABLE_ONLY;
        if (value.contains("16 kib") || value.contains("uri exceeds")) return "uri_too_large";
        if (value.contains("cbor value exceeds") || value.contains("hitvpn link exceeds")) {
            return "hit_config_too_large";
        }
        if (value.contains("duplicate cbor map key")) return "hit_cbor_duplicate";
        if (value.contains("json nesting")) return "json_depth_exceeded";
        if (value.contains("json string")) return "json_string_too_large";
        if (value.contains("json structure exceeds")) return "json_structure_too_large";
        if (value.contains("invalid unicode") || value.contains("mismatched")
                || value.contains("unterminated")) return "invalid_json";
        if (value.contains(ProtocolParser.XRAY_INSECURE_TLS_UNSUPPORTED)) {
            return ProtocolParser.XRAY_INSECURE_TLS_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.XRAY_VMESS_ALTER_ID_UNSUPPORTED)) {
            return ProtocolParser.XRAY_VMESS_ALTER_ID_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.XRAY_SHADOWSOCKS_METHOD_UNSUPPORTED)) {
            return ProtocolParser.XRAY_SHADOWSOCKS_METHOD_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.SING_BOX_SHADOWSOCKS_METHOD_UNSUPPORTED)) {
            return ProtocolParser.SING_BOX_SHADOWSOCKS_METHOD_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.SING_BOX_SHADOWSOCKS_PASSWORD_UNSUPPORTED)) {
            return ProtocolParser.SING_BOX_SHADOWSOCKS_PASSWORD_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.XRAY_SHADOWSOCKS_PASSWORD_UNSUPPORTED)) {
            return ProtocolParser.XRAY_SHADOWSOCKS_PASSWORD_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.SING_BOX_UTLS_FINGERPRINT_UNSUPPORTED)) {
            return ProtocolParser.SING_BOX_UTLS_FINGERPRINT_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.XRAY_UTLS_FINGERPRINT_UNSUPPORTED)) {
            return ProtocolParser.XRAY_UTLS_FINGERPRINT_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.XRAY_USER_ID_UNSUPPORTED)) {
            return ProtocolParser.XRAY_USER_ID_UNSUPPORTED;
        }
        if (value.contains(
                ProtocolParser.SING_BOX_HTTP_UPGRADE_EARLY_DATA_UNSUPPORTED)) {
            return ProtocolParser.SING_BOX_HTTP_UPGRADE_EARLY_DATA_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.SING_BOX_XRAY_WS_PATH_UNSUPPORTED)) {
            return ProtocolParser.SING_BOX_XRAY_WS_PATH_UNSUPPORTED;
        }
        if (value.contains(ProtocolParser.SING_BOX_VLESS_FLOW_UNSUPPORTED)) {
            return ProtocolParser.SING_BOX_VLESS_FLOW_UNSUPPORTED;
        }
        if (value.contains("vless encryption")) {
            return ProtocolParser.VLESS_ENCRYPTION_UNSUPPORTED;
        }
        if (value.contains("clash field") || value.contains("clash proxy type")) {
            return "clash_field_unsupported";
        }
        if (value.contains("trojan flow")) return "trojan_flow_unsupported";
        if (value.contains("vision flow requires tls")) return "vless_vision_tls_required";
        if (value.contains("vision flow requires raw tcp")) return "vless_vision_raw_required";
        if (value.contains("mux")) return "mux_unsupported";
        if (value.contains("detour") || value.contains("proxysettings")) return "detour_unsupported";
        if (value.contains("bind") || value.contains("sendthrough")) return "bind_unsupported";
        if (value.contains("domain") || value.contains("dns") || value.contains("strategy")) {
            return "dns_strategy_unsupported";
        }
        if (value.contains("security")) return "security_unsupported";
        if (value.contains("transport") || value.contains("mkcp") || value.contains("xhttp")) {
            return "transport_unsupported";
        }
        return "invalid_or_unrepresentable";
    }

    private static void validateGeneratedParams(Map<String, String> params) {
        for (Map.Entry<String, String> item : params.entrySet()) {
            int maximum = item.getKey().equals("extra") ? 64 * 1024
                    : (item.getKey().equals("headers") ? 16 * 1024 : 8 * 1024);
            requireScalarLimit(item.getValue(), maximum,
                    "transport parameter " + item.getKey());
        }
    }

    private static void requireScalarLimit(String value, int maximumBytes, String label) {
        if (value == null) return;
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
            if (bytes > maximumBytes) {
                throw new IllegalArgumentException(label + " exceeds limit");
            }
        }
    }

    private static JSONObject requireExactFirst(JSONArray values, String label) {
        if (values == null || values.length() != 1 || !(values.opt(0) instanceof JSONObject)) {
            throw new IllegalArgumentException(
                    "structured " + label + " must contain exactly one object");
        }
        return values.optJSONObject(0);
    }

    private static boolean hasAny(JSONObject owner, String... keys) {
        for (String key : keys) if (owner.has(key)) return true;
        return false;
    }

    private static void putParam(Map<String, String> target, String key, String value) {
        if (value != null && !value.isEmpty()) target.put(key, value);
    }

    private static void putUniqueParam(Map<String, String> target, String key, String value) {
        if (value == null || value.isEmpty()) return;
        if (target.containsKey(key)) {
            throw new IllegalArgumentException("duplicate structured field: " + key);
        }
        target.put(key, value);
    }

    private static void rejectStructuredAliases(JSONObject source, String label,
                                                String... keys) {
        String selected = "";
        for (String key : keys) {
            if (!source.has(key)) continue;
            if (!selected.isEmpty()) {
                throw new IllegalArgumentException(
                        "duplicate " + label + " aliases: " + selected + "/" + key);
            }
            selected = key;
        }
    }

    private static void copyString(JSONObject source, Map<String, String> target,
                                   String sourceKey, String targetKey) {
        if (!source.has(sourceKey)) return;
        if (target.containsKey(targetKey)) {
            throw new IllegalArgumentException("duplicate structured field: " + targetKey);
        }
        Object raw = source.opt(sourceKey);
        if (!(raw instanceof String) && !(raw instanceof Number)) {
            throw new IllegalArgumentException("invalid structured scalar: " + sourceKey);
        }
        String normalized = String.valueOf(raw).trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("empty structured scalar: " + sourceKey);
        }
        putParam(target, targetKey, normalized);
    }

    private static void copyXrayInteger(JSONObject source, Map<String, String> target,
                                        String sourceKey, String targetKey) {
        if (!source.has(sourceKey)) return;
        if (target.containsKey(targetKey)) {
            throw new IllegalArgumentException("duplicate structured field: " + targetKey);
        }
        Object raw = source.opt(sourceKey);
        if (!(raw instanceof Byte) && !(raw instanceof Short)
                && !(raw instanceof Integer) && !(raw instanceof Long)) {
            throw new IllegalArgumentException(
                    "invalid Xray integer field: " + sourceKey);
        }
        putParam(target, targetKey, String.valueOf(((Number) raw).longValue()));
    }

    private static void copyParam(Map<String, String> source, JSONObject target, String key)
            throws Exception {
        copyParam(source, target, key, key);
    }

    private static void copyParam(Map<String, String> source, JSONObject target,
                                  String sourceKey, String targetKey) throws Exception {
        String value = source.get(sourceKey);
        if (value != null && !value.isEmpty()) target.put(targetKey, value);
    }

    private static void putJsonString(JSONObject target, String key, String value)
            throws Exception {
        if (value != null && !value.isEmpty()) target.put(key, value);
    }

    private static String param(Map<String, String> source, String key, String fallback) {
        String value = source.get(key);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static String joinJsonStrings(JSONArray values) {
        List<String> output = new ArrayList<>();
        for (int i = 0; i < values.length(); i++) {
            Object raw = values.opt(i);
            if (!(raw instanceof String)) {
                throw new IllegalArgumentException("JSON string array contains non-string value");
            }
            String value = (String) raw;
            if (value.isEmpty() || value.indexOf(',') >= 0
                    || containsControl(value) || utf8Exceeds(value, 255)) {
                throw new IllegalArgumentException("invalid structured ALPN value");
            }
            output.add(value);
        }
        return join(output, ",");
    }

    private static void collectSimpleClashYaml(String text, List<String> output,
                                               RejectionTracker rejections,
                                               CandidateBudget budget) {
        if (countRootClashProxySections(text) != 1) {
            rejections.reject("clash_root_invalid");
            return;
        }
        int outputStart = output.size();
        Map<String, String> current = null;
        int currentIndent = -1;
        int proxyItemIndent = -1;
        List<String> sectionNames = new ArrayList<>();
        List<Integer> sectionIndents = new ArrayList<>();
        boolean inProxies = false;
        int proxiesIndent = -1;
        int start = 0;
        int scanned = 0;
        while (start <= text.length()) {
            int end = text.indexOf('\n', start);
            if (end < 0) end = text.length();
            int contentEnd = end > start && text.charAt(end - 1) == '\r' ? end - 1 : end;
            if (contentEnd - start > MAX_CLASH_LINE_CHARS) {
                rejections.reject("clash_line_too_large");
                if (inProxies) {
                    output.subList(outputStart, output.size()).clear();
                    return;
                }
                if (end == text.length()) break;
                start = end + 1;
                if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                    throw new ImportInterruptedException();
                }
                continue;
            }
            String rawLine = text.substring(start, contentEnd);
            if (start == 0 && !rawLine.isEmpty() && rawLine.charAt(0) == '\ufeff') {
                rawLine = rawLine.substring(1);
            }
            String noComment = stripYamlComment(rawLine);
            if (noComment.trim().isEmpty()) {
                if (end == text.length()) break;
                start = end + 1;
                if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                    throw new ImportInterruptedException();
                }
                continue;
            }
            int indent = leadingSpaces(noComment);
            String line = noComment.trim();
            if (!inProxies) {
                if (hasClashProxyIntent(noComment, true)) {
                    if (!isRootClashProxySection(noComment)) {
                        rejections.reject("clash_root_invalid");
                        return;
                    }
                    inProxies = true;
                    proxiesIndent = 0;
                }
                if (end == text.length()) break;
                start = end + 1;
                if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                    throw new ImportInterruptedException();
                }
                continue;
            }
            boolean listItem = line.startsWith("- ");
            if (indent < proxiesIndent || indent == proxiesIndent && !listItem) {
                if (current != null) addClashEntry(current, output, rejections, budget);
                current = null;
                break;
            }
            if (listItem) {
                if (proxyItemIndent < 0) proxyItemIndent = indent;
                if (indent != proxyItemIndent) {
                    if (current != null) {
                        current.put("__invalid_list_item__", "1");
                    } else {
                        rejections.reject("clash_item_indent_invalid");
                    }
                } else {
                    if (current != null) addClashEntry(current, output, rejections, budget);
                    current = new LinkedHashMap<>();
                    currentIndent = indent;
                    sectionNames.clear();
                    sectionIndents.clear();
                    parseYamlKeyValue(line.substring(2), current, "");
                }
            } else if (proxyItemIndent < 0) {
                rejections.reject("clash_sequence_invalid");
                return;
            } else if (current != null && indent > currentIndent) {
                while (!sectionIndents.isEmpty()
                        && indent <= sectionIndents.get(sectionIndents.size() - 1)) {
                    int last = sectionIndents.size() - 1;
                    sectionIndents.remove(last);
                    sectionNames.remove(last);
                }
                if (line.endsWith(":")) {
                    String section = line.substring(0, line.length() - 1).trim();
                    String parent = yamlSectionPath(sectionNames);
                    String path = parent.isEmpty() ? section : parent + "." + section;
                    String marker = "__section__" + path;
                    if (current.containsKey(marker)) {
                        current.put("__duplicate_field__", path);
                    } else if (current.size() >= MAX_CLASH_FIELDS) {
                        current.put("__field_limit__", "1");
                    } else {
                        current.put(marker, "1");
                    }
                    if (sectionNames.size() >= MAX_CLASH_FIELDS) {
                        current.put("__field_limit__", "1");
                    } else {
                        sectionNames.add(section);
                        sectionIndents.add(indent);
                    }
                } else {
                    parseYamlKeyValue(line, current, yamlSectionPath(sectionNames));
                }
            }
            if (end == text.length()) break;
            start = end + 1;
            if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
        }
        if (current != null) addClashEntry(current, output, rejections, budget);
    }

    private static int countRootClashProxySections(String text) {
        int count = 0;
        int start = 0;
        int scanned = 0;
        while (start <= text.length()) {
            int end = text.indexOf('\n', start);
            if (end < 0) end = text.length();
            int contentEnd = end > start && text.charAt(end - 1) == '\r' ? end - 1 : end;
            if (clashProxyIntentSeparator(
                    text, start, contentEnd, true, start == 0) >= 0) {
                if (++count > 1) return count;
            }
            if (end == text.length()) break;
            start = end + 1;
            if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
        }
        return count;
    }

    private static boolean isRootClashProxySection(String line) {
        int separator = clashProxyKeySeparator(line, true);
        return separator >= 0 && line.substring(separator + 1).trim().isEmpty();
    }

    private static boolean hasClashProxyKey(String line, boolean requireRoot) {
        return clashProxyKeySeparator(line, requireRoot) >= 0;
    }

    private static boolean hasClashProxyIntent(String line, boolean requireRoot) {
        return line != null && clashProxyIntentSeparator(
                line, 0, line.length(), requireRoot, false) >= 0;
    }

    private static int clashProxyKeySeparator(String line, boolean requireRoot) {
        if (line == null) return -1;
        return clashProxyKeySeparator(line, 0, line.length(), requireRoot, false);
    }

    private static int clashProxyKeySeparator(String source, int start, int end,
                                               boolean requireRoot,
                                               boolean allowDocumentBom) {
        if (source == null || start < 0 || end < start || end > source.length()) return -1;
        int cursor = start;
        if (allowDocumentBom && cursor < end && source.charAt(cursor) == '\ufeff') cursor++;
        int indentationStart = cursor;
        while (cursor < end && Character.isWhitespace(source.charAt(cursor))) cursor++;
        if (requireRoot && cursor != indentationStart) return -1;
        int keyStart = cursor;
        int separator = boundedYamlKeySeparator(source, keyStart, end);
        if (separator <= keyStart) return -1;
        String rawKey = source.substring(keyStart, separator).trim();
        try {
            return unquoteYaml(rawKey).equalsIgnoreCase("proxies")
                    ? separator : -1;
        } catch (IllegalArgumentException invalid) {
            return -1;
        }
    }

    private static int clashProxyIntentSeparator(String source, int start, int end,
                                                  boolean requireRoot,
                                                  boolean allowDocumentBom) {
        int exact = clashProxyKeySeparator(
                source, start, end, requireRoot, allowDocumentBom);
        if (exact >= 0) return exact;
        if (source == null || start < 0 || end < start || end > source.length()) return -1;
        int cursor = start;
        if (allowDocumentBom && cursor < end && source.charAt(cursor) == '\ufeff') cursor++;
        int indentationStart = cursor;
        while (cursor < end && Character.isWhitespace(source.charAt(cursor))) cursor++;
        if (requireRoot && cursor != indentationStart) return -1;

        // Explicit YAML key syntax (`? proxies`) is outside the supported
        // subset, but must still enter the Clash parser and fail closed.
        if (cursor < end && source.charAt(cursor) == '?') {
            int valueStart = cursor + 1;
            int valueEnd = Math.min(end, valueStart + 256);
            if (proxyScalarAfterNodeProperties(
                    source.substring(valueStart, valueEnd))) return valueStart;
        }

        int separator = boundedYamlKeySeparator(source, cursor, end);
        if (separator <= cursor) return -1;
        String rawKey = source.substring(cursor, separator).trim();
        if (rawKey.startsWith("*")
                || proxyScalarAfterNodeProperties(rawKey)) return separator;

        // An anchored/tagged scalar value can later be used as an alias key:
        // `root: &k proxies` followed by `*k:`. Conservatively classify the
        // document now instead of regex-promoting URI-looking metadata.
        int valueStart = separator + 1;
        while (valueStart < end && Character.isWhitespace(source.charAt(valueStart))) {
            valueStart++;
        }
        if (valueStart < end && (source.charAt(valueStart) == '&'
                || source.charAt(valueStart) == '!')) {
            int valueEnd = Math.min(end, valueStart + 256);
            if (proxyScalarAfterNodeProperties(
                    source.substring(valueStart, valueEnd))) return separator;
        }
        return -1;
    }

    private static boolean proxyScalarAfterNodeProperties(String source) {
        String remaining = source == null ? "" : stripYamlComment(source).trim();
        while (!remaining.isEmpty() && (remaining.charAt(0) == '&'
                || remaining.charAt(0) == '!')) {
            int end;
            if (remaining.startsWith("!<")) {
                end = remaining.indexOf('>');
                if (end < 2) return false;
                end++;
            } else {
                end = 0;
                while (end < remaining.length()
                        && !Character.isWhitespace(remaining.charAt(end))) end++;
            }
            if (end >= remaining.length()) return false;
            remaining = remaining.substring(end).trim();
        }
        try {
            return unquoteYaml(remaining).equalsIgnoreCase("proxies");
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static int boundedYamlKeySeparator(String source, int keyStart, int end) {
        char quote = 0;
        boolean escaped = false;
        int separator = -1;
        int cursor = keyStart;
        // A YAML key spelling larger than this cannot decode to `proxies`.
        // The cap also avoids allocating an oversized substring while the
        // source-wide scan still sees a key after arbitrarily long indentation.
        int keyLimit = Math.min(end, keyStart + 256);
        for (; cursor < keyLimit; cursor++) {
            char current = source.charAt(cursor);
            if (quote == '\'') {
                if (current == '\'' && cursor + 1 < keyLimit
                        && source.charAt(cursor + 1) == '\'') {
                    cursor++;
                } else if (current == '\'') {
                    quote = 0;
                }
                continue;
            }
            if (quote == '"') {
                if (escaped) {
                    escaped = false;
                } else if (current == '\\') {
                    escaped = true;
                } else if (current == '"') {
                    quote = 0;
                }
                continue;
            }
            if (current == '\'' || current == '"') {
                quote = current;
            } else if (current == ':') {
                separator = cursor;
                break;
            }
        }
        return quote == 0 ? separator : -1;
    }

    private static void parseYamlKeyValue(String line, Map<String, String> output, String section) {
        int separator = line.indexOf(':');
        if (separator <= 0) return;
        String key = line.substring(0, separator).trim();
        String storedKey = section.isEmpty() ? key : section + "." + key;
        if (storedKey.equals("ws-opts.headers.Host")) storedKey = "headers.Host";
        if (output.size() >= MAX_CLASH_FIELDS && !output.containsKey(storedKey)) {
            output.put("__field_limit__", "1");
            return;
        }
        if (output.containsKey(storedKey)) {
            output.put("__duplicate_field__", storedKey);
            return;
        }
        try {
            String rawValue = line.substring(separator + 1).trim();
            if (rawValue.matches("[|>][0-9+\\-]*")) {
                throw new IllegalArgumentException("unsupported Clash block scalar");
            }
            boolean quoted = !rawValue.isEmpty()
                    && (rawValue.charAt(0) == '"' || rawValue.charAt(0) == '\'');
            if (!quoted && (rawValue.equals("~")
                    || rawValue.equalsIgnoreCase("null"))) {
                // YAML null is not a string. Treating it as the literal
                // credential/host/option text silently changes the document.
                throw new IllegalArgumentException("unsupported Clash YAML null scalar");
            }
            if (!quoted && rawValue.matches("[+-]?0[0-9]+")) {
                // go-yaml/v3 resolves this spelling as an octal integer while
                // Integer.parseInt below is decimal. Reject the ambiguous
                // scalar instead of silently connecting to another port.
                throw new IllegalArgumentException(
                        "unsupported Clash YAML leading-zero integer");
            }
            if (!rawValue.isEmpty() && rawValue.charAt(0) != '"'
                    && rawValue.charAt(0) != '\''
                    && "&*![{".indexOf(rawValue.charAt(0)) >= 0) {
                throw new IllegalArgumentException("unsupported Clash YAML scalar semantics");
            }
            output.put(storedKey, unquoteYaml(rawValue));
        } catch (IllegalArgumentException invalid) {
            output.put("__invalid_scalar__", storedKey);
        }
    }

    private static String yamlSectionPath(List<String> sectionNames) {
        StringBuilder path = new StringBuilder();
        for (String section : sectionNames) {
            if (path.length() > 0) path.append('.');
            path.append(section);
        }
        return path.toString();
    }

    private static void addClashEntry(Map<String, String> source, List<String> output,
                                      RejectionTracker rejections, CandidateBudget budget) {
        if (!budget.reserve()) return;
        String type = value(source, "type").toLowerCase(Locale.US);
        String server = value(source, "server");
        String name = rawValue(source, "name");
        try {
            if (source.containsKey("__duplicate_field__")) {
                throw new IllegalArgumentException("duplicate Clash field");
            }
            if (source.containsKey("__invalid_scalar__")) {
                throw new IllegalArgumentException("invalid quoted Clash scalar");
            }
            if (source.containsKey("__invalid_list_item__")) {
                throw new IllegalArgumentException("invalid nested Clash list item");
            }
            String declaredPort = value(source, "port");
            boolean hysteria2PortsOnly = (type.equals("hysteria2") || type.equals("hy2"))
                    && declaredPort.isEmpty() && !value(source, "ports").isEmpty();
            // Mihomo's Hysteria2 `ports` replaces the singular `port`. The
            // generated URI below carries the full expression and
            // ProtocolParser derives the actual first endpoint from it.
            int port = hysteria2PortsOnly ? 443
                    : strictInteger(declaredPort, "Clash port", 1, 65535, false);
            validateClashFields(source);
            if (server.isEmpty()) {
                throw new IllegalArgumentException("invalid Clash endpoint");
            }
            if (type.equals("vless") || type.equals("trojan")) {
                String credential = type.equals("vless")
                        ? rawValue(source, "uuid") : rawValue(source, "password");
                if (credential.isEmpty()) throw new IllegalArgumentException("missing Clash credential");
                List<String> query = clashStreamQuery(source);
                if (type.equals("vless") && !rawValue(source, "encryption").isEmpty()) {
                    query.add("encryption=" + enc(rawValue(source, "encryption")));
                }
                StringBuilder uri = new StringBuilder(type).append("://").append(enc(credential))
                        .append('@').append(hostForUri(server)).append(':').append(port);
                if (!query.isEmpty()) uri.append('?').append(join(query, "&"));
                if (!name.isEmpty()) uri.append('#').append(enc(name));
                output.add(uri.toString());
            } else if (type.equals("ss") || type.equals("shadowsocks")) {
                String method = ProtocolParser.canonicalShadowsocksMethod(
                        value(source, "cipher"));
                String password = rawValue(source, "password");
                if (method.isEmpty()
                        || (password.isEmpty() && !method.equals("none"))) {
                    throw new IllegalArgumentException("missing Clash Shadowsocks credential");
                }
                String credentials = Base64.getUrlEncoder().withoutPadding().encodeToString((method + ":" + password)
                        .getBytes(StandardCharsets.UTF_8));
                output.add("ss://" + credentials + "@" + hostForUri(server) + ":" + port
                        + (name.isEmpty() ? "" : "#" + enc(name)));
            } else if (type.equals("vmess")) {
                String uuid = rawValue(source, "uuid");
                if (uuid.isEmpty()) throw new IllegalArgumentException("missing Clash VMess UUID");
                String alterId = value(source, "alterId");
                if (alterId.isEmpty()) alterId = value(source, "alter-id");
                String publicKey = rawValue(source, "reality-opts.public-key");
                String shortId = rawValue(source, "reality-opts.short-id");
                String sni = value(source, "servername");
                if (sni.isEmpty()) sni = value(source, "sni");
                String network = value(source, "network").isEmpty()
                        ? "tcp" : value(source, "network");
                String security = !publicKey.isEmpty() ? "reality"
                        : (strictBoolean(value(source, "tls"), "tls") ? "tls" : "");
                int parsedAlterId = alterId.isEmpty() ? 0
                        : strictInteger(alterId, "VMess alterId", 0, Integer.MAX_VALUE, false);
                JSONObject vmess = new JSONObject()
                        .put("v", "2").put("ps", name).put("add", server).put("port", port)
                        .put("id", uuid).put("aid", parsedAlterId)
                        .put("scy", value(source, "cipher").isEmpty() ? "auto" : value(source, "cipher"))
                        .put("net", network);
                putJsonString(vmess, "tls", security);
                putJsonString(vmess, "sni", sni);
                if (strictBoolean(value(source, "skip-cert-verify"), "skip-cert-verify")) {
                    vmess.put("insecure", "1");
                }
                putJsonString(vmess, "pbk", publicKey);
                putJsonString(vmess, "sid", shortId);
                if ("grpc".equalsIgnoreCase(network)) {
                    putJsonString(vmess, "path", rawValue(
                            source, "grpc-opts.grpc-service-name"));
                } else if ("ws".equalsIgnoreCase(network)) {
                    putJsonString(vmess, "path", rawValue(source, "ws-opts.path"));
                    putJsonString(vmess, "host", rawValue(source, "headers.Host"));
                }
                output.add("vmess://" + Base64.getEncoder().encodeToString(
                        vmess.toString().getBytes(StandardCharsets.UTF_8)));
            } else if (type.equals("hysteria")) {
                String auth = rawValue(source, "auth-str");
                if (auth.isEmpty()) auth = rawValue(source, "auth");
                if ((source.containsKey("auth-str") || source.containsKey("auth"))
                        && auth.isEmpty()) {
                    throw new IllegalArgumentException("missing Clash Hysteria auth");
                }
                List<String> query = clashTlsQuery(source);
                int up = clashHysteriaBandwidthMbps(value(source, "up"),
                        "Hysteria", "upload", Integer.MAX_VALUE);
                int down = clashHysteriaBandwidthMbps(value(source, "down"),
                        "Hysteria", "download", Integer.MAX_VALUE);
                String obfs = rawValue(source, "obfs");
                if (source.containsKey("obfs") && obfs.isEmpty()) {
                    throw new IllegalArgumentException("missing Clash Hysteria obfs password");
                }
                if (up > 0) query.add("upmbps=" + up);
                if (down > 0) query.add("downmbps=" + down);
                if (!obfs.isEmpty()) {
                    query.add("obfs=xplus");
                    query.add("obfsParam=" + enc(obfs));
                }
                StringBuilder uri = new StringBuilder("hysteria://").append(enc(auth))
                        .append('@').append(hostForUri(server)).append(':').append(port);
                if (!query.isEmpty()) uri.append('?').append(join(query, "&"));
                if (!name.isEmpty()) uri.append('#').append(enc(name));
                output.add(uri.toString());
            } else if (type.equals("hysteria2") || type.equals("hy2") || type.equals("tuic")) {
                String credential;
                if (type.equals("tuic")) {
                    String uuid = rawValue(source, "uuid");
                    String password = rawValue(source, "password");
                    if (uuid.isEmpty() || password.isEmpty()) {
                        throw new IllegalArgumentException("missing Clash TUIC credential");
                    }
                    credential = uuid + ":" + password;
                } else {
                    credential = rawValue(source, "password");
                }
                if (credential.isEmpty()) {
                    throw new IllegalArgumentException("missing Clash QUIC credential");
                }
                List<String> query = clashTlsQuery(source);
                if (!type.equals("tuic")) {
                    int up = clashHysteriaBandwidthMbps(value(source, "up"),
                            "Hysteria2", "upload", ProtocolParser.MAX_HYSTERIA2_MBPS);
                    int down = clashHysteriaBandwidthMbps(value(source, "down"),
                            "Hysteria2", "download", ProtocolParser.MAX_HYSTERIA2_MBPS);
                    if (up > 0) query.add("upmbps=" + up);
                    if (down > 0) query.add("downmbps=" + down);
                    String obfs = value(source, "obfs");
                    String obfsPassword = rawValue(source, "obfs-password");
                    if (source.containsKey("obfs-password") && obfsPassword.isEmpty()) {
                        throw new IllegalArgumentException(
                                "missing Clash Hysteria2 obfs password");
                    }
                    if (!obfs.isEmpty()) query.add("obfs=" + enc(obfs));
                    if (!obfsPassword.isEmpty()) query.add("obfs-password=" + enc(obfsPassword));
                    String hopInterval = value(source, "hop-interval");
                    if (!hopInterval.isEmpty()) query.add("hop_interval=" + enc(clashDuration(hopInterval)));
                } else {
                    String congestion = value(source, "congestion-controller");
                    if (congestion.isEmpty()) congestion = value(source, "congestion_control");
                    String relay = value(source, "udp-relay-mode");
                    if (relay.isEmpty()) relay = value(source, "udp_relay_mode");
                    if (!congestion.isEmpty()) {
                        query.add("congestion_control=" + enc(congestion));
                    }
                    if (!relay.isEmpty()) query.add("udp_relay_mode=" + enc(relay));
                }
                String scheme = type.equals("hy2") ? "hysteria2" : type;
                String portExpression = String.valueOf(port);
                if (!type.equals("tuic")) {
                    String ports = value(source, "ports");
                    if (!ports.isEmpty()) portExpression = ports;
                }
                StringBuilder uri = new StringBuilder(scheme).append("://").append(enc(credential))
                        .append('@').append(hostForUri(server)).append(':').append(portExpression);
                if (!query.isEmpty()) uri.append('?').append(join(query, "&"));
                if (!name.isEmpty()) uri.append('#').append(enc(name));
                output.add(uri.toString());
            } else {
                throw new IllegalArgumentException("unsupported Clash proxy type");
            }
        } catch (Exception error) {
            rejections.reject(reasonCode(error));
        }
    }

    private static void validateClashFields(Map<String, String> source) {
        java.util.HashSet<String> allowed = new java.util.HashSet<>();
        java.util.Collections.addAll(allowed, "name", "type", "server", "port");
        String type = value(source, "type").toLowerCase(Locale.US);
        rejectClashAliasPair(source, "servername", "sni");
        boolean stream = type.equals("vless") || type.equals("vmess")
                || type.equals("trojan");
        if (type.equals("vless")) {
            java.util.Collections.addAll(allowed, "uuid", "flow", "encryption");
        } else if (type.equals("vmess")) {
            rejectClashAliasPair(source, "alterId", "alter-id");
            java.util.Collections.addAll(allowed, "uuid", "alterId", "alter-id", "cipher");
        } else if (type.equals("trojan")) {
            java.util.Collections.addAll(allowed, "password", "flow");
        } else if (type.equals("ss") || type.equals("shadowsocks")) {
            java.util.Collections.addAll(allowed, "cipher", "password");
        } else if (type.equals("hysteria")) {
            rejectClashAliasPair(source, "auth", "auth-str");
            java.util.Collections.addAll(allowed, "auth", "auth-str", "up", "down", "obfs");
        } else if (type.equals("hysteria2") || type.equals("hy2")) {
            java.util.Collections.addAll(allowed, "password", "obfs", "obfs-password",
                    "hop-interval", "ports", "up", "down");
        } else if (type.equals("tuic")) {
            rejectClashAliasPair(source, "congestion-controller", "congestion_control");
            rejectClashAliasPair(source, "udp-relay-mode", "udp_relay_mode");
            java.util.Collections.addAll(allowed, "uuid", "password", "congestion-controller",
                    "congestion_control", "udp-relay-mode", "udp_relay_mode");
        }
        if (stream) {
            java.util.Collections.addAll(allowed, "network", "tls", "servername", "sni",
                    "skip-cert-verify", "reality-opts.public-key", "reality-opts.short-id");
            // The lightweight YAML reader records an actual mapping key as a
            // section marker. Only mappings represented by the neutral model
            // may be ignored as structure. Treat every other `key:` (for
            // example `tls:`, `network:` or `mux:`) as an unsupported field so
            // YAML nulls cannot silently turn into defaults.
            allowed.add("__section__reality-opts");
            if (type.equals("trojan") && source.containsKey("tls")
                    && !strictBoolean(value(source, "tls"), "tls")) {
                throw new IllegalArgumentException(
                        "intrinsic-TLS Clash Trojan cannot disable TLS");
            }
            String network = value(source, "network").toLowerCase(Locale.US);
            if (network.equals("ws")) {
                java.util.Collections.addAll(allowed, "ws-opts.path", "headers.Host");
                java.util.Collections.addAll(allowed, "__section__ws-opts",
                        "__section__ws-opts.headers");
            } else if (network.equals("grpc")) {
                allowed.add("grpc-opts.grpc-service-name");
                allowed.add("__section__grpc-opts");
            }
        } else if (type.equals("hysteria") || type.equals("hysteria2")
                || type.equals("hy2") || type.equals("tuic")) {
            java.util.Collections.addAll(allowed, "tls", "servername", "sni",
                    "skip-cert-verify");
            if (source.containsKey("tls")
                    && !strictBoolean(value(source, "tls"), "tls")) {
                throw new IllegalArgumentException(
                        "forced-TLS Clash proxy cannot disable TLS");
            }
        }
        if (stream) {
            String publicKey = rawValue(source, "reality-opts.public-key");
            String shortId = rawValue(source, "reality-opts.short-id");
            if (!shortId.isEmpty() && publicKey.isEmpty()) {
                throw new IllegalArgumentException(
                        "unsupported Clash field: Reality short-id without public-key");
            }
            boolean secured = type.equals("trojan") || !publicKey.isEmpty()
                    || strictBoolean(value(source, "tls"), "tls");
            if (!secured && (!value(source, "servername").isEmpty()
                    || !value(source, "sni").isEmpty()
                    || strictBoolean(value(source, "skip-cert-verify"),
                    "skip-cert-verify")
                    || !value(source, "flow").isEmpty())) {
                throw new IllegalArgumentException(
                        "unsupported Clash field: TLS option without TLS or Reality");
            }
        }
        for (String key : source.keySet()) {
            if (!allowed.contains(key)) {
                throw new IllegalArgumentException("unsupported Clash field: " + key);
            }
        }
    }

    private static void rejectClashAliasPair(Map<String, String> source,
                                             String first, String second) {
        if (source.containsKey(first) && source.containsKey(second)) {
            throw new IllegalArgumentException("duplicate Clash aliases");
        }
    }

    private static boolean looksLikeClashProxyYaml(String text) {
        if (hasExplicitYamlFlowDocument(text) || hasNestedYamlFlowProxyKey(text)
                || hasUnsupportedYamlExplicitKey(text)) return true;
        int start = 0;
        int scanned = 0;
        while (start <= text.length()) {
            int end = text.indexOf('\n', start);
            if (end < 0) end = text.length();
            int contentEnd = end > start && text.charAt(end - 1) == '\r' ? end - 1 : end;
            if (start == 0 && contentEnd - start > 1
                    && text.charAt(start) == '\ufeff' && text.charAt(start + 1) == '\ufeff') {
                // Multiple document BOMs are invalid. Enter the Clash parser
                // so it fails closed instead of promoting URI-looking metadata.
                return true;
            }
            if (clashProxyIntentSeparator(
                    text, start, contentEnd, false, start == 0) >= 0) {
                return true;
            }
            if (end == text.length()) break;
            start = end + 1;
            if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
        }
        return false;
    }

    private static boolean hasExplicitYamlFlowDocument(String text) {
        if (text == null || text.isEmpty()) return false;
        int start = 0;
        // The first non-comment node is a document root even without `---`.
        boolean expectsDocumentRoot = true;
        int scanned = 0;
        while (start < text.length()) {
            int end = start;
            while (end < text.length() && text.charAt(end) != '\n'
                    && text.charAt(end) != '\r') end++;
            int content = start;
            while (content < end
                    && (text.charAt(content) == ' ' || text.charAt(content) == '\t')) {
                content++;
            }
            if (content < end && text.charAt(content) != '#') {
                if (startsYamlDirective(text, content, end)) {
                    expectsDocumentRoot = true;
                } else if (isYamlDocumentMarker(text, content, end)) {
                    expectsDocumentRoot = true;
                    content += 3;
                    while (content < end
                            && (text.charAt(content) == ' '
                            || text.charAt(content) == '\t')) {
                        content++;
                    }
                    if (content < end && text.charAt(content) != '#') {
                        int prefix = yamlFlowRootAfterNodeProperties(text, content, end);
                        if (prefix == YAML_FLOW_FOUND || prefix == YAML_FLOW_UNSUPPORTED) {
                            return true;
                        }
                        expectsDocumentRoot = prefix == YAML_FLOW_PROPERTIES_ONLY;
                    }
                } else if (expectsDocumentRoot) {
                    int prefix = yamlFlowRootAfterNodeProperties(text, content, end);
                    if (prefix == YAML_FLOW_FOUND || prefix == YAML_FLOW_UNSUPPORTED) {
                        return true;
                    }
                    // Keep scanning: a later YAML document marker may start a
                    // flow document even when the first document is block YAML.
                    expectsDocumentRoot = prefix == YAML_FLOW_PROPERTIES_ONLY;
                }
            }
            if (end == text.length()) break;
            start = end + 1;
            if (text.charAt(end) == '\r' && start < text.length()
                    && text.charAt(start) == '\n') start++;
            if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
        }
        return false;
    }

    private static final int YAML_FLOW_OTHER = 0;
    private static final int YAML_FLOW_FOUND = 1;
    private static final int YAML_FLOW_PROPERTIES_ONLY = 2;
    private static final int YAML_FLOW_UNSUPPORTED = 3;

    private static int yamlFlowRootAfterNodeProperties(
            String text, int start, int end) {
        int cursor = start;
        int properties = 0;
        int propertyBytes = 0;
        while (cursor < end) {
            while (cursor < end && (text.charAt(cursor) == ' '
                    || text.charAt(cursor) == '\t')) cursor++;
            if (cursor >= end || text.charAt(cursor) == '#') {
                return properties > 0 ? YAML_FLOW_PROPERTIES_ONLY : YAML_FLOW_OTHER;
            }
            char current = text.charAt(cursor);
            if (current == '{' || current == '[') return YAML_FLOW_FOUND;
            if (current != '&' && current != '!') return YAML_FLOW_OTHER;
            if (++properties > 8 || propertyBytes > 1024) return YAML_FLOW_UNSUPPORTED;
            int propertyStart = cursor++;
            if (current == '!' && cursor < end && text.charAt(cursor) == '<') {
                int closeLimit = Math.min(end, cursor + 257);
                int close = -1;
                for (int index = cursor + 1; index < closeLimit; index++) {
                    if (text.charAt(index) == '>') {
                        close = index;
                        break;
                    }
                }
                if (close < 0) return YAML_FLOW_UNSUPPORTED;
                cursor = close + 1;
            } else {
                if (current == '!' && cursor < end && text.charAt(cursor) == '!') {
                    cursor++;
                }
                int tokenStart = cursor;
                while (cursor < end && !Character.isWhitespace(text.charAt(cursor))
                        && "{}[]#,&".indexOf(text.charAt(cursor)) < 0
                        && (current == '!' || text.charAt(cursor) != '!')) {
                    cursor++;
                }
                if (cursor == tokenStart || cursor - tokenStart > 256) {
                    return YAML_FLOW_UNSUPPORTED;
                }
            }
            propertyBytes += cursor - propertyStart;
        }
        return properties > 0 ? YAML_FLOW_PROPERTIES_ONLY : YAML_FLOW_OTHER;
    }

    private static boolean hasNestedYamlFlowProxyKey(String text) {
        if (text == null || text.isEmpty()) return false;
        int flowDepth = 0;
        boolean comment = false;
        // A quote starts a quoted scalar only when the current flow collection
        // is waiting for a key/value node. YAML plain scalars may legally
        // contain quote characters, including after whitespace; treating those
        // as delimiters can skip a later structural `proxies` key.
        boolean[] expectsNode = new boolean[65];
        for (int index = 0; index < text.length(); index++) {
            if ((index & 4095) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
            char current = text.charAt(index);
            if (comment) {
                if (current == '\n' || current == '\r') comment = false;
                continue;
            }
            if (current == '#' && (index == 0
                    || Character.isWhitespace(text.charAt(index - 1)))) {
                comment = true;
                continue;
            }
            if (flowDepth <= 0) {
                if (current == '{' || current == '[') {
                    flowDepth = 1;
                    expectsNode[flowDepth] = true;
                }
                // Outside a flow collection, a quote may be data inside a
                // block plain scalar. Do not let it hide a later flow mapping.
                continue;
            }
            if ((current == '\'' || current == '"') && expectsNode[flowDepth]) {
                int end = yamlFlowQuotedScalarEnd(text, index);
                if (end < 0) return true;
                if (yamlFlowQuotedScalarIsProxies(text, index, end)
                        && yamlFlowColonAfter(text, end + 1)) return true;
                expectsNode[flowDepth] = false;
                index = end;
                continue;
            }
            if (Character.isWhitespace(current)) {
                continue;
            }
            if (current == '{' || current == '[') {
                if (flowDepth >= 64) return true;
                expectsNode[flowDepth] = false;
                expectsNode[++flowDepth] = true;
                continue;
            }
            if (current == '}' || current == ']') {
                flowDepth--;
                if (flowDepth > 0) expectsNode[flowDepth] = false;
                continue;
            }
            if (current == ',') {
                expectsNode[flowDepth] = true;
                continue;
            }
            if (current == '?' && expectsNode[flowDepth]
                    && index + 1 < text.length()
                    && Character.isWhitespace(text.charAt(index + 1))) {
                // Explicit flow mapping keys may place the colon after a
                // comment/newline. This subset does not execute them; enter
                // the Clash boundary and fail closed.
                return true;
            }
            if (expectsNode[flowDepth] && (current == '&' || current == '!')) {
                // Nested tags and anchors can change the scalar which becomes
                // a mapping key. The lightweight parser does not resolve them.
                return true;
            }
            if (expectsNode[flowDepth] && current == '*') {
                int nameEnd = yamlFlowNodeNameEnd(text, index + 1);
                if (nameEnd > index + 1 && nameEnd - index <= 257
                        && yamlFlowColonAfter(text, nameEnd)) {
                    // Alias keys are not representable by the lightweight
                    // parser. The referenced scalar may resolve to `proxies`.
                    return true;
                }
                expectsNode[flowDepth] = false;
                continue;
            }
            if (expectsNode[flowDepth] && index + 7 <= text.length()
                    && yamlFlowPlainProxiesAt(text, index)) {
                int after = index + 7;
                while (after < text.length()
                        && Character.isWhitespace(text.charAt(after))) after++;
                if (after < text.length() && text.charAt(after) == ':') return true;
            }
            if (current == ':' && yamlFlowColonIsSeparator(text, index)) {
                expectsNode[flowDepth] = true;
            } else {
                expectsNode[flowDepth] = false;
            }
        }
        return false;
    }

    private static boolean yamlFlowColonIsSeparator(String text, int index) {
        int next = index + 1;
        if (next >= text.length()) return true;
        char value = text.charAt(next);
        return Character.isWhitespace(value)
                || "{[}]},'\"&*!".indexOf(value) >= 0;
    }

    private static boolean hasUnsupportedYamlExplicitKey(String text) {
        int start = 0;
        int scanned = 0;
        while (start <= text.length()) {
            int end = text.indexOf('\n', start);
            if (end < 0) end = text.length();
            int contentEnd = end > start && text.charAt(end - 1) == '\r'
                    ? end - 1 : end;
            int content = start;
            while (content < contentEnd
                    && (text.charAt(content) == ' ' || text.charAt(content) == '\t')) {
                content++;
            }
            if (content < contentEnd && text.charAt(content) == '?'
                    && (content + 1 == contentEnd
                    || Character.isWhitespace(text.charAt(content + 1)))) return true;
            if (end == text.length()) break;
            start = end + 1;
            if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
        }
        return false;
    }

    private static int yamlFlowQuotedScalarEnd(String text, int start) {
        char quote = text.charAt(start);
        for (int index = start + 1; index < text.length(); index++) {
            char current = text.charAt(index);
            if (quote == '\'' && current == '\'' && index + 1 < text.length()
                    && text.charAt(index + 1) == '\'') {
                index++;
            } else if (quote == '"' && current == '\\') {
                if (++index >= text.length()) return -1;
            } else if (current == quote) {
                return index;
            }
        }
        return -1;
    }

    private static boolean yamlFlowQuotedScalarIsProxies(
            String text, int start, int end) {
        // Seven YAML \UXXXXXXXX escapes plus the surrounding quotes occupy
        // 72 raw characters while decoding to the seven-code-point key.
        if (end - start + 1 > 72) return false;
        try {
            return unquoteYaml(text.substring(start, end + 1))
                    .equalsIgnoreCase("proxies");
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static int yamlFlowNodeNameEnd(String text, int start) {
        int end = start;
        while (end < text.length()) {
            char current = text.charAt(end);
            if (Character.isWhitespace(current)
                    || ",[]{}:?&*!".indexOf(current) >= 0) break;
            end++;
        }
        return end;
    }

    private static int yamlFlowSkipWhitespace(String text, int start) {
        int result = start;
        while (result < text.length() && Character.isWhitespace(text.charAt(result))) {
            result++;
        }
        return result;
    }

    private static boolean yamlFlowColonAfter(String text, int start) {
        int after = yamlFlowSkipWhitespace(text, start);
        return after < text.length() && text.charAt(after) == ':';
    }

    private static boolean yamlFlowPlainProxiesAt(String text, int start) {
        if (start < 0 || start + 7 > text.length()
                || !text.regionMatches(true, start, "proxies", 0, 7)) return false;
        int after = start + 7;
        if (after >= text.length()) return true;
        char boundary = text.charAt(after);
        return !Character.isLetterOrDigit(boundary) && boundary != '_'
                && boundary != '-';
    }

    private static boolean startsYamlDirective(String text, int start, int end) {
        return yamlTokenAt(text, start, end, "%YAML")
                || yamlTokenAt(text, start, end, "%TAG");
    }

    private static boolean isYamlDocumentMarker(String text, int start, int end) {
        if (end - start < 3 || !text.regionMatches(start, "---", 0, 3)) return false;
        if (start + 3 == end) return true;
        char next = text.charAt(start + 3);
        return next == ' ' || next == '\t' || next == '#' || next == '{' || next == '[';
    }

    private static boolean yamlTokenAt(String text, int start, int end, String token) {
        if (end - start < token.length()
                || !text.regionMatches(start, token, 0, token.length())) return false;
        if (start + token.length() == end) return true;
        char next = text.charAt(start + token.length());
        return next == ' ' || next == '\t';
    }

    private static List<String> clashStreamQuery(Map<String, String> source) {
        List<String> query = clashTlsQuery(source);
        String network = value(source, "network");
        if (!network.isEmpty()) query.add("type=" + enc(network));
        String path = rawValue(source, "ws-opts.path");
        if (!path.isEmpty()) query.add("path=" + enc(path));
        String grpcService = rawValue(source, "grpc-opts.grpc-service-name");
        if (!grpcService.isEmpty()) query.add("serviceName=" + enc(grpcService));
        String host = rawValue(source, "headers.Host");
        if (!host.isEmpty()) query.add("host=" + enc(host));
        String flow = value(source, "flow");
        if (!flow.isEmpty()) query.add("flow=" + enc(flow));
        return query;
    }

    private static List<String> clashTlsQuery(Map<String, String> source) {
        List<String> query = new ArrayList<>();
        if (strictBoolean(value(source, "tls"), "tls")) query.add("security=tls");
        String sni = value(source, "servername");
        if (sni.isEmpty()) sni = value(source, "sni");
        if (!sni.isEmpty()) query.add("sni=" + enc(sni));
        if (strictBoolean(value(source, "skip-cert-verify"), "skip-cert-verify")) {
            query.add("insecure=1");
        }
        String publicKey = rawValue(source, "reality-opts.public-key");
        if (!publicKey.isEmpty()) {
            query.remove("security=tls");
            query.add("security=reality");
            query.add("pbk=" + enc(publicKey));
        }
        String shortId = rawValue(source, "reality-opts.short-id");
        if (!shortId.isEmpty()) query.add("sid=" + enc(shortId));
        return query;
    }

    private static String clashDuration(String value) {
        String duration = value == null ? "" : value.trim();
        return duration.matches("[0-9]+(?:\\.[0-9]+)?") ? duration + "s" : duration;
    }

    private static int clashHysteriaBandwidthMbps(String value, String protocol,
                                                  String label, int maximumMbps) {
        String source = value == null ? "" : value;
        if (source.isEmpty()) return 0;
        String errorLabel = "Clash " + protocol + " " + label + " bandwidth";
        if (source.matches("[0-9]+")) {
            return strictInteger(source, errorLabel, 0, maximumMbps, false);
        }

        Matcher matcher = CLASH_HYSTERIA_BANDWIDTH.matcher(source);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("invalid " + errorLabel);
        }
        final long amount;
        try {
            amount = Long.parseLong(matcher.group(1));
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("invalid " + errorLabel);
        }

        long bitsMultiplier;
        switch (matcher.group(2).toUpperCase(Locale.US)) {
            case "T":
                bitsMultiplier = 1_000_000_000_000L;
                break;
            case "G":
                bitsMultiplier = 1_000_000_000L;
                break;
            case "M":
                bitsMultiplier = 1_000_000L;
                break;
            case "K":
                bitsMultiplier = 1_000L;
                break;
            default:
                bitsMultiplier = 1L;
                break;
        }
        if ("B".equals(matcher.group(3))) bitsMultiplier *= 8L;

        long maximumBits = (long) maximumMbps * 1_000_000L;
        if (amount > maximumBits / bitsMultiplier) {
            throw new IllegalArgumentException("invalid " + errorLabel);
        }
        long bits = amount * bitsMultiplier;
        if (bits % 1_000_000L != 0L) {
            throw new IllegalArgumentException("unrepresentable " + errorLabel);
        }
        return (int) (bits / 1_000_000L);
    }

    private static List<String> decodeHitVpn(String link, RejectionTracker rejections) throws Exception {
        String encoded;
        if (link.regionMatches(true, 0, "https://hvpn.io/", 0, "https://hvpn.io/".length())) {
            encoded = link.substring("https://hvpn.io/".length());
        } else if (link.regionMatches(true, 0, "https://hitray.io/", 0,
                "https://hitray.io/".length())) {
            encoded = link.substring("https://hitray.io/".length());
        } else if (link.regionMatches(true, 0, "hitvpn://", 0, "hitvpn://".length())) {
            encoded = link.substring("hitvpn://".length());
        }
        else return new ArrayList<>();

        if (encoded.length() > (MAX_HIT_LINK_BYTES * 4L / 3L) + 16L) {
            throw new IllegalArgumentException("HitVPN link exceeds limit");
        }
        byte[] wrapped = decodeUrlBase64(encoded);
        if (wrapped.length > MAX_HIT_LINK_BYTES) throw new IllegalArgumentException("HitVPN link exceeds limit");
        if (wrapped.length < 32 || wrapped[0] != 1) throw new IllegalArgumentException("invalid HitVPN link");
        byte[] salt = slice(wrapped, 1, 5);
        byte[] expectedHash = slice(wrapped, 5, 9);
        byte[] payload = slice(wrapped, 9, wrapped.length);
        if (littleEndianInt(salt) != 0) xorHitPayload(salt, payload);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
        for (int i = 0; i < 4; i++) if (digest[i] != expectedHash[i]) {
            throw new IllegalArgumentException("HitVPN digest mismatch");
        }
        Object rootValue = new MiniCbor(payload).read();
        if (!(rootValue instanceof Map)) throw new IllegalArgumentException("invalid HitVPN CBOR");
        Map<?, ?> root = (Map<?, ?>) rootValue;
        int vid = asInt(root.get(1L));
        List<String> output = new ArrayList<>();
        Object configsValue = root.get(4L);
        if (!(configsValue instanceof List)) return output;
        for (Object itemValue : (List<?>) configsValue) {
            if (!(itemValue instanceof Map)) continue;
            Map<?, ?> item = (Map<?, ?>) itemValue;
            if (asInt(item.get(1L)) != 2 || !(item.get(2L) instanceof byte[])) continue;
            byte[] config = (byte[]) item.get(2L);
            if (config.length == 0 || config.length > MAX_HIT_CONFIG_BYTES) {
                rejections.reject("hit_config_too_large");
                continue;
            }
            String uri = decodeHitVless(config, vid);
            if (uri.isEmpty()) continue;
            if (output.size() >= MAX_SOURCE_NODES) {
                rejections.rejectLimit(1);
            } else {
                output.add(uri);
            }
        }
        return output;
    }

    private static String decodeHitVless(byte[] bytes, int vid) throws Exception {
        Object value = new MiniCbor(bytes).read();
        if (!(value instanceof Map)) return "";
        Map<?, ?> map = (Map<?, ?>) value;
        if (map.size() != 7) return "";
        for (Object key : map.keySet()) {
            if (!(key instanceof Number) || asLong(key) < 1L || asLong(key) > 7L) return "";
        }
        byte[] uuidBytes = bytes(map.get(1L));
        byte[] publicKey = bytes(map.get(2L));
        long rawIp = asLong(map.get(3L));
        int port = asInt(map.get(4L));
        int network = asInt(map.get(5L));
        int security = asInt(map.get(6L));
        Object rawSni = map.get(7L);
        if (!(rawSni instanceof String)) return "";
        String sni = (String) rawSni;
        if (uuidBytes.length != 16 || publicKey.length != 32
                || rawIp < 0L || rawIp > 0xffff_ffffL
                || port <= 0 || port > 65535 || network != 0
                || (security != 0 && security != 1)
                || utf8Exceeds(sni, MAX_HIT_SNI_BYTES) || containsControlOrSpace(sni)
                || (security == 1 && sni.trim().isEmpty())) return "";
        byte[] ip = new byte[]{(byte) (rawIp >>> 24), (byte) (rawIp >>> 16),
                (byte) (rawIp >>> 8), (byte) rawIp};
        String address = InetAddress.getByAddress(ip).getHostAddress();
        String uuid = String.format(Locale.US,
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                uuidBytes[0] & 255, uuidBytes[1] & 255, uuidBytes[2] & 255, uuidBytes[3] & 255,
                uuidBytes[4] & 255, uuidBytes[5] & 255, uuidBytes[6] & 255, uuidBytes[7] & 255,
                uuidBytes[8] & 255, uuidBytes[9] & 255, uuidBytes[10] & 255, uuidBytes[11] & 255,
                uuidBytes[12] & 255, uuidBytes[13] & 255, uuidBytes[14] & 255, uuidBytes[15] & 255);
        String publicKeyText = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey);
        return "vless://" + uuid + "@" + address + ":" + port
                + "?type=" + (network == 1 ? "udp" : "tcp")
                + "&security=" + (security == 0 ? "none" : "reality")
                + "&pbk=" + enc(publicKeyText) + "&sni=" + enc(sni)
                + "&fp=random&sid=42&spx=%2F&flow=xtls-rprx-vision#HitVPN-" + vid;
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

    private static boolean utf8RegionExceeds(String value, int start, int end, int maximum) {
        if (value == null) return false;
        long bytes = 0L;
        int boundedStart = Math.max(0, start);
        int boundedEnd = Math.min(value.length(), Math.max(boundedStart, end));
        for (int index = boundedStart; index < boundedEnd; index++) {
            if ((index & 4095) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
            char current = value.charAt(index);
            if (current <= 0x7f) bytes++;
            else if (current <= 0x7ff) bytes += 2;
            else if (Character.isHighSurrogate(current) && index + 1 < boundedEnd
                    && Character.isLowSurrogate(value.charAt(index + 1))) {
                bytes += 4;
                index++;
            } else bytes += 3;
            if (bytes > maximum) return true;
        }
        return false;
    }

    private static boolean containsControlOrSpace(String value) {
        if (value == null) return false;
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (Character.isWhitespace(current) || Character.isISOControl(current)) return true;
        }
        return false;
    }

    private static boolean containsControl(String value) {
        if (value == null) return false;
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) return true;
        }
        return false;
    }

    private static void xorHitPayload(byte[] salt, byte[] payload) throws Exception {
        MessageDigest seed = MessageDigest.getInstance("SHA-256");
        seed.update(HIT_HASH_KEY);
        seed.update(salt);
        byte[] current = digestSnapshot(seed);
        int index = 0;
        for (int i = 0; i < payload.length; i++) {
            if (index >= current.length) {
                seed.update(current, 0, 8);
                current = digestSnapshot(seed);
                index = 0;
            }
            payload[i] ^= current[index++];
        }
    }

    private static byte[] digestSnapshot(MessageDigest seed) throws Exception {
        try {
            return ((MessageDigest) seed.clone()).digest();
        } catch (CloneNotSupportedException error) {
            throw new IllegalStateException("SHA-256 state cloning is unavailable", error);
        }
    }

    private static String tryBase64(String value) {
        try {
            byte[] decoded = decodeUrlBase64(value, LimitedHttpClient.MAX_EXPANDED_BYTES);
            return decodeStrictUtf8(decoded);
        } catch (Exception ignored) {
            return "";
        }
    }

    static String decodeStrictUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value == null ? new byte[0] : value))
                    .toString();
        } catch (java.nio.charset.CharacterCodingException invalid) {
            throw new IllegalArgumentException("invalid UTF-8 text");
        }
    }

    private static byte[] decodeUrlBase64(String value) {
        return decodeUrlBase64(value, MAX_HIT_LINK_BYTES);
    }

    private static byte[] decodeUrlBase64(String value, int maximumBytes) {
        if (value == null || maximumBytes < 0) {
            throw new IllegalArgumentException("invalid base64 input");
        }
        int outputLength = decodedBase64Length(value, maximumBytes);
        byte[] output = new byte[outputLength];
        int outputOffset = 0;
        int[] block = new int[4];
        int count = 0;
        boolean finished = false;
        for (int index = 0; index < value.length(); index++) {
            if ((index & 4095) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
            char current = value.charAt(index);
            if (Character.isWhitespace(current)) continue;
            if (finished) throw new IllegalArgumentException("trailing base64 data");
            block[count++] = base64Value(current);
            if (count != 4) continue;
            int padding = block[3] == -2 ? 1 : 0;
            if (block[2] == -2) padding++;
            if (block[0] < 0 || block[1] < 0 || block[2] == -2 && block[3] != -2
                    || block[2] < -2 || block[3] < -2) {
                throw new IllegalArgumentException("invalid base64 padding");
            }
            outputOffset = writeDecoded(output, outputOffset,
                    (block[0] << 2) | (block[1] >> 4));
            if (padding < 2) {
                outputOffset = writeDecoded(output, outputOffset,
                        ((block[1] & 15) << 4) | (block[2] >> 2));
            }
            if (padding == 0) {
                outputOffset = writeDecoded(output, outputOffset,
                        ((block[2] & 3) << 6) | block[3]);
            }
            finished = padding > 0;
            count = 0;
        }
        if (!finished && count > 0) {
            if (count == 1 || block[0] < 0 || block[1] < 0) {
                throw new IllegalArgumentException("invalid base64 length");
            }
            outputOffset = writeDecoded(output, outputOffset,
                    (block[0] << 2) | (block[1] >> 4));
            if (count == 3) {
                if (block[2] < 0) throw new IllegalArgumentException("invalid base64 data");
                outputOffset = writeDecoded(output, outputOffset,
                        ((block[1] & 15) << 4) | (block[2] >> 2));
            }
        }
        if (outputOffset != output.length) {
            throw new IllegalArgumentException("invalid decoded base64 length");
        }
        return output;
    }

    private static int decodedBase64Length(String value, int maximumBytes) {
        long symbols = 0L;
        char last = 0;
        char beforeLast = 0;
        for (int index = 0; index < value.length(); index++) {
            if ((index & 4095) == 0 && Thread.currentThread().isInterrupted()) {
                throw new ImportInterruptedException();
            }
            char current = value.charAt(index);
            if (Character.isWhitespace(current)) continue;
            base64Value(current);
            beforeLast = last;
            last = current;
            symbols++;
            if (symbols > ((long) maximumBytes + 2L) / 3L * 4L + 4L) {
                throw new IllegalArgumentException("decoded base64 exceeds limit");
            }
        }
        if (symbols == 0L) return 0;
        int remainder = (int) (symbols & 3L);
        if (remainder == 1) throw new IllegalArgumentException("invalid base64 length");
        int padding = last == '=' ? (beforeLast == '=' ? 2 : 1) : 0;
        if (padding > 0 && remainder != 0) {
            throw new IllegalArgumentException("invalid base64 padding");
        }
        long decoded = symbols / 4L * 3L - padding;
        if (padding == 0) {
            if (remainder == 2) decoded += 1L;
            else if (remainder == 3) decoded += 2L;
        }
        if (decoded < 0L || decoded > maximumBytes || decoded > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("decoded base64 exceeds limit");
        }
        return (int) decoded;
    }

    private static int base64Value(char value) {
        if (value >= 'A' && value <= 'Z') return value - 'A';
        if (value >= 'a' && value <= 'z') return value - 'a' + 26;
        if (value >= '0' && value <= '9') return value - '0' + 52;
        if (value == '+' || value == '-') return 62;
        if (value == '/' || value == '_') return 63;
        if (value == '=') return -2;
        throw new IllegalArgumentException("invalid base64 character");
    }

    private static int writeDecoded(byte[] output, int offset, int value) {
        if (offset >= output.length) {
            throw new IllegalArgumentException("decoded base64 exceeds expected length");
        }
        output[offset] = (byte) (value & 255);
        return offset + 1;
    }

    private static boolean isHitLink(String value) {
        String source = value == null ? "" : value;
        return source.regionMatches(true, 0, "https://hvpn.io/", 0, "https://hvpn.io/".length())
                || source.regionMatches(true, 0, "https://hitray.io/", 0,
                "https://hitray.io/".length())
                || source.regionMatches(true, 0, "hitvpn://", 0, "hitvpn://".length());
    }

    private static boolean containsIgnoreCase(String source, String expected) {
        if (source == null || expected == null || expected.isEmpty()
                || source.length() < expected.length()) return false;
        int end = source.length() - expected.length();
        for (int i = 0; i <= end; i++) {
            if ((i & 4095) == 0 && Thread.currentThread().isInterrupted()) return false;
            if (source.regionMatches(true, i, expected, 0, expected.length())) return true;
        }
        return false;
    }

    private static int firstNonWhitespace(String value) {
        if (value == null) return -1;
        for (int index = 0; index < value.length(); index++) {
            if (!Character.isWhitespace(value.charAt(index))) return index;
        }
        return -1;
    }

    private static String first(JSONObject object, String... keys) {
        String selected = "";
        String selectedKey = "";
        for (String key : keys) {
            if (!object.has(key)) continue;
            if (!selectedKey.isEmpty()) {
                throw new IllegalArgumentException(
                        "duplicate structured aliases: " + selectedKey + "/" + key);
            }
            selectedKey = key;
            Object raw = object.opt(key);
            if (!(raw instanceof String)) {
                throw new IllegalArgumentException("structured field must be a string: " + key);
            }
            // Structured strings are already delimited by JSON. Whitespace is
            // data for credentials, paths, header values and display names;
            // silently trimming here changes the imported configuration.
            String candidate = (String) raw;
            if (utf8Exceeds(candidate, ProtocolParser.MAX_URI_BYTES)) {
                throw new IllegalArgumentException("proxy scalar exceeds limit");
            }
            selected = candidate;
        }
        return selected;
    }

    private static JSONObject optionalObject(JSONObject owner, String key) {
        if (owner == null || !owner.has(key)) return null;
        Object raw = owner.opt(key);
        if (!(raw instanceof JSONObject)) {
            throw new IllegalArgumentException("structured field must be an object: " + key);
        }
        return (JSONObject) raw;
    }

    private static JSONArray optionalArray(JSONObject owner, String key) {
        if (owner == null || !owner.has(key)) return null;
        Object raw = owner.opt(key);
        if (!(raw instanceof JSONArray)) {
            throw new IllegalArgumentException("structured field must be an array: " + key);
        }
        return (JSONArray) raw;
    }

    private static int strictInteger(JSONObject owner, int fallback, int minimum,
                                     int maximum, String... keys) {
        Object selected = null;
        String selectedKey = "";
        for (String key : keys) {
            if (!owner.has(key)) continue;
            if (selected != null) {
                throw new IllegalArgumentException(
                        "duplicate structured integer: " + selectedKey + "/" + key);
            }
            selected = owner.opt(key);
            selectedKey = key;
        }
        if (selected == null) return fallback;
        long parsed;
        if (selected instanceof Byte || selected instanceof Short
                || selected instanceof Integer || selected instanceof Long) {
            parsed = ((Number) selected).longValue();
        } else if (selected instanceof String
                && ((String) selected).matches("0|[1-9][0-9]*")) {
            try {
                parsed = Long.parseLong((String) selected);
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException("invalid structured integer: " + selectedKey);
            }
        } else {
            throw new IllegalArgumentException("invalid structured integer: " + selectedKey);
        }
        if (parsed < minimum || parsed > maximum) {
            throw new IllegalArgumentException("invalid structured integer: " + selectedKey);
        }
        return (int) parsed;
    }

    private static int strictXrayInteger(JSONObject owner, int fallback, int minimum,
                                         int maximum, String key) {
        if (!owner.has(key)) return fallback;
        Object raw = owner.opt(key);
        if (!(raw instanceof Byte) && !(raw instanceof Short)
                && !(raw instanceof Integer) && !(raw instanceof Long)) {
            throw new IllegalArgumentException("invalid Xray integer: " + key);
        }
        long parsed = ((Number) raw).longValue();
        if (parsed < minimum || parsed > maximum) {
            throw new IllegalArgumentException("invalid Xray integer: " + key);
        }
        return (int) parsed;
    }

    private static long strictUnsigned32(JSONObject owner, long fallback,
                                         String... keys) {
        Object selected = null;
        String selectedKey = "";
        for (String key : keys) {
            if (!owner.has(key)) continue;
            if (selected != null) {
                throw new IllegalArgumentException(
                        "duplicate structured integer: " + selectedKey + "/" + key);
            }
            selected = owner.opt(key);
            selectedKey = key;
        }
        if (selected == null) return fallback;
        long parsed;
        if (selected instanceof Byte || selected instanceof Short
                || selected instanceof Integer || selected instanceof Long) {
            parsed = ((Number) selected).longValue();
        } else if (selected instanceof String
                && ((String) selected).matches("0|[1-9][0-9]*")) {
            try {
                parsed = Long.parseLong((String) selected);
            } catch (NumberFormatException invalid) {
                throw new IllegalArgumentException(
                        "invalid structured integer: " + selectedKey);
            }
        } else {
            throw new IllegalArgumentException("invalid structured integer: " + selectedKey);
        }
        if (parsed < 0 || parsed > 0xffff_ffffL) {
            throw new IllegalArgumentException("invalid structured integer: " + selectedKey);
        }
        return parsed;
    }

    private static boolean strictBoolean(JSONObject owner, boolean fallback, String key) {
        return strictBooleanAliases(owner, fallback, key);
    }

    private static boolean strictBooleanAliases(JSONObject owner, boolean fallback,
                                                String... keys) {
        Object selected = null;
        String selectedKey = "";
        for (String key : keys) {
            if (!owner.has(key)) continue;
            if (selected != null) {
                throw new IllegalArgumentException(
                        "duplicate structured boolean: " + selectedKey + "/" + key);
            }
            selected = owner.opt(key);
            selectedKey = key;
        }
        if (selected == null) return fallback;
        if (!(selected instanceof Boolean)) {
            throw new IllegalArgumentException("invalid structured boolean: " + selectedKey);
        }
        return (Boolean) selected;
    }

    private static boolean hasFunctionalKeysBesides(JSONObject owner, String... ignoredKeys) {
        java.util.HashSet<String> ignored = new java.util.HashSet<>();
        java.util.Collections.addAll(ignored, ignoredKeys);
        java.util.Iterator<String> keys = owner.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!ignored.contains(key) && functional(owner.opt(key))) return true;
        }
        return false;
    }

    private static String value(Map<String, String> source, String key) {
        String value = source.get(key);
        return value == null ? "" : value.trim();
    }

    private static String rawValue(Map<String, String> source, String key) {
        String value = source.get(key);
        return value == null ? "" : value;
    }

    private static boolean hasTopLevelSimplifiedIdentity(JSONObject object, String type) {
        if (hasAny(object, "server", "address", "server_port", "port")) return true;
        if (type.equals("vless")) {
            return hasAny(object, "uuid", "id", "user", "flow", "encryption", "users");
        }
        if (type.equals("vmess")) {
            return hasAny(object, "uuid", "id", "user", "alter_id", "alterId",
                    "security", "encryption", "users");
        }
        if (type.equals("trojan")) return hasAny(object, "password", "flow");
        return hasAny(object, "password", "method");
    }

    private static String enc(String value) {
        try {
            return URLEncoder.encode(value == null ? "" : value, "UTF-8").replace("+", "%20");
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String hostForUri(String host) {
        return host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
    }

    private static String join(List<String> values, String separator) {
        StringBuilder output = new StringBuilder();
        for (String value : values) {
            if (output.length() > 0) output.append(separator);
            output.append(value);
        }
        return output.toString();
    }

    private static int strictInteger(String value, String label, int minimum,
                                     int maximum, boolean optional) {
        String clean = value == null ? "" : value.trim();
        if (clean.isEmpty() && optional) return minimum;
        if (!clean.matches("[0-9]+")) {
            throw new IllegalArgumentException("invalid " + label);
        }
        try {
            long parsed = Long.parseLong(clean);
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalArgumentException("invalid " + label);
            }
            return (int) parsed;
        } catch (NumberFormatException ignored) {
            throw new IllegalArgumentException("invalid " + label);
        }
    }

    private static boolean strictBoolean(String value, String label) {
        String lower = value == null ? "" : value.trim().toLowerCase(Locale.US);
        if (lower.isEmpty() || lower.equals("false") || lower.equals("0")
                || lower.equals("no") || lower.equals("off")) return false;
        if (lower.equals("true") || lower.equals("1")
                || lower.equals("yes") || lower.equals("on")) return true;
        throw new IllegalArgumentException("invalid Clash boolean: " + label);
    }

    private static String stripYamlComment(String line) {
        int separator = line.indexOf(':');
        int scalarStart = separator < 0 ? 0 : separator + 1;
        while (scalarStart < line.length()
                && Character.isWhitespace(line.charAt(scalarStart))) scalarStart++;
        boolean single = scalarStart < line.length() && line.charAt(scalarStart) == '\'';
        boolean quoted = scalarStart < line.length() && line.charAt(scalarStart) == '"';
        int start = single || quoted ? scalarStart + 1 : scalarStart;
        for (int i = start; i < line.length(); i++) {
            char c = line.charAt(i);
            if (single) {
                if (c == '\'') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '\'') {
                        i++;
                    } else {
                        single = false;
                    }
                }
            } else if (quoted) {
                if (c == '\\' && i + 1 < line.length()) {
                    i++;
                } else if (c == '"') {
                    quoted = false;
                }
            } else if (c == '#' && (i == 0
                    || Character.isWhitespace(line.charAt(i - 1)))) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static int leadingSpaces(String value) {
        int result = 0;
        while (result < value.length() && Character.isWhitespace(value.charAt(result))) result++;
        return result;
    }

    private static String unquoteYaml(String value) {
        if (value.isEmpty()) return value;
        char first = value.charAt(0);
        if (first != '"' && first != '\'') return value;
        if (value.length() < 2 || value.charAt(value.length() - 1) != first) {
            throw new IllegalArgumentException("invalid quoted Clash scalar");
        }
        StringBuilder decoded = new StringBuilder(value.length() - 2);
        int end = value.length() - 1;
        if (first == '\'') {
            for (int i = 1; i < end; i++) {
                char c = value.charAt(i);
                if (c != '\'') {
                    decoded.append(c);
                } else if (i + 1 < end && value.charAt(i + 1) == '\'') {
                    decoded.append('\'');
                    i++;
                } else {
                    throw new IllegalArgumentException("invalid quoted Clash scalar");
                }
            }
            return decoded.toString();
        }
        for (int i = 1; i < end; i++) {
            char c = value.charAt(i);
            if (c == '"') {
                throw new IllegalArgumentException("invalid quoted Clash scalar");
            }
            if (c != '\\') {
                decoded.append(c);
                continue;
            }
            if (++i >= end) {
                throw new IllegalArgumentException("invalid quoted Clash scalar");
            }
            char escaped = value.charAt(i);
            switch (escaped) {
                case '0': decoded.append('\0'); break;
                case 'a': decoded.append('\u0007'); break;
                case 'b': decoded.append('\b'); break;
                case 't': decoded.append('\t'); break;
                case 'n': decoded.append('\n'); break;
                case 'v': decoded.append('\u000b'); break;
                case 'f': decoded.append('\f'); break;
                case 'r': decoded.append('\r'); break;
                case 'e': decoded.append('\u001b'); break;
                case ' ': decoded.append(' '); break;
                case '"': decoded.append('"'); break;
                case '/': decoded.append('/'); break;
                case '\\': decoded.append('\\'); break;
                case 'N': decoded.append('\u0085'); break;
                case '_': decoded.append('\u00a0'); break;
                case 'L': decoded.append('\u2028'); break;
                case 'P': decoded.append('\u2029'); break;
                case 'x':
                    i = appendYamlHexEscape(value, i, end, 2, decoded);
                    break;
                case 'u':
                    i = appendYamlHexEscape(value, i, end, 4, decoded);
                    break;
                case 'U':
                    i = appendYamlHexEscape(value, i, end, 8, decoded);
                    break;
                default:
                    throw new IllegalArgumentException("invalid quoted Clash scalar");
            }
        }
        return decoded.toString();
    }

    private static int appendYamlHexEscape(String value, int marker, int end,
                                           int digits, StringBuilder output) {
        if (marker + digits >= end) {
            throw new IllegalArgumentException("invalid quoted Clash scalar");
        }
        int codePoint = 0;
        for (int offset = 1; offset <= digits; offset++) {
            int digit = Character.digit(value.charAt(marker + offset), 16);
            if (digit < 0) {
                throw new IllegalArgumentException("invalid quoted Clash scalar");
            }
            if (codePoint > (0x10ffff - digit) / 16) {
                throw new IllegalArgumentException("invalid quoted Clash scalar");
            }
            codePoint = codePoint * 16 + digit;
        }
        if (!Character.isValidCodePoint(codePoint)
                || codePoint >= Character.MIN_SURROGATE
                && codePoint <= Character.MAX_SURROGATE) {
            throw new IllegalArgumentException("invalid quoted Clash scalar");
        }
        output.appendCodePoint(codePoint);
        return marker + digits;
    }

    private static int littleEndianInt(byte[] value) {
        return ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static byte[] slice(byte[] value, int start, int end) {
        byte[] output = new byte[Math.max(0, end - start)];
        System.arraycopy(value, start, output, 0, output.length);
        return output;
    }

    private static byte[] bytes(Object value) {
        return value instanceof byte[] ? (byte[]) value : new byte[0];
    }

    private static int asInt(Object value) {
        return (int) asLong(value);
    }

    private static long asLong(Object value) {
        return value instanceof Number ? ((Number) value).longValue() : 0L;
    }

    private static final class ImportHints {
        boolean xrayWebSocketPathEarlyData;
        boolean xrayHttpUpgradePathEarlyData;
        boolean xrayWebSocketPathSemantics;
    }

    private static final class WebSocketPath {
        final String path;
        final long earlyData;

        WebSocketPath(String path, long earlyData) {
            this.path = path;
            this.earlyData = earlyData;
        }
    }

    private static final class XrayQueryItem {
        final byte[] key;
        final byte[] value;

        XrayQueryItem(byte[] key, byte[] value) {
            this.key = key;
            this.value = value;
        }
    }

    private static final class ImportInterruptedException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static ParseResult interruptedResult() {
        ArrayList<String> reasons = new ArrayList<>();
        reasons.add("import_interrupted");
        return new ParseResult(new ArrayList<>(), 1, reasons);
    }

    static final class ParseResult {
        final List<ProtocolParser.Node> nodes;
        final int rejected;
        final List<String> reasons;

        ParseResult(List<ProtocolParser.Node> nodes, int rejected, List<String> reasons) {
            this.nodes = nodes;
            this.rejected = rejected;
            this.reasons = reasons;
        }
    }

    private static final class RejectionTracker {
        int rejected;
        final LinkedHashSet<String> reasons = new LinkedHashSet<>();

        void reject(String reason) {
            rejected++;
            if (reasons.size() < MAX_REASONS) {
                reasons.add(reason == null || reason.isEmpty()
                        ? "invalid_or_unrepresentable" : reason);
            }
        }

        void rejectLimit(int count) {
            if (count <= 0) return;
            rejected += count;
            if (reasons.size() < MAX_REASONS) reasons.add("source_node_limit");
        }
    }

    private static final class CandidateBudget {
        private final RejectionTracker rejections;
        private int accepted;

        CandidateBudget(RejectionTracker rejections) {
            this.rejections = rejections;
        }

        boolean reserve() {
            if (accepted >= MAX_SOURCE_NODES) {
                rejections.rejectLimit(1);
                return false;
            }
            accepted++;
            return true;
        }

        void reject(String reason) {
            rejections.reject(reason);
        }
    }

    private static final class MiniCbor {
        private final byte[] data;
        private int position;
        private int valuesRead;

        MiniCbor(byte[] data) {
            this.data = data;
        }

        Object read() {
            Object value = read(0);
            if (position != data.length) {
                throw new IllegalArgumentException("trailing CBOR data");
            }
            return value;
        }

        private Object read(int depth) {
            if (depth > MAX_CBOR_DEPTH) throw new IllegalArgumentException("CBOR nesting exceeds limit");
            if (++valuesRead > MAX_CBOR_VALUES) throw new IllegalArgumentException("CBOR value count exceeds limit");
            int initial = takeByte();
            int major = initial >>> 5;
            int additional = initial & 31;
            if (major == 0) return readUnsigned(additional);
            if (major == 1) return -1L - readUnsigned(additional);
            if (major == 2) return take(checkedLength(readUnsigned(additional), MAX_CBOR_BLOB_BYTES));
            if (major == 3) return decodeStrictUtf8(
                    take(checkedLength(readUnsigned(additional), MAX_CBOR_BLOB_BYTES)));
            if (major == 4) {
                int size = checkedContainerSize(readUnsigned(additional), false);
                List<Object> output = new ArrayList<>(Math.min(size, 256));
                for (int i = 0; i < size; i++) output.add(read(depth + 1));
                return output;
            }
            if (major == 5) {
                int size = checkedContainerSize(readUnsigned(additional), true);
                Map<Object, Object> output = new LinkedHashMap<>();
                for (int i = 0; i < size; i++) {
                    Object key = read(depth + 1);
                    Object value = read(depth + 1);
                    if (output.containsKey(key)) {
                        throw new IllegalArgumentException("duplicate CBOR map key");
                    }
                    output.put(key, value);
                }
                return output;
            }
            if (major == 6) {
                readUnsigned(additional);
                return read(depth + 1);
            }
            if (major == 7) {
                if (additional == 20) return false;
                if (additional == 21) return true;
                if (additional == 22) return null;
            }
            throw new IllegalArgumentException("unsupported CBOR value");
        }

        private long readUnsigned(int additional) {
            if (additional < 24) return additional;
            if (additional == 24) return takeByte();
            if (additional == 25) return number(2);
            if (additional == 26) return number(4);
            if (additional == 27) return number(8);
            throw new IllegalArgumentException("unsupported CBOR integer");
        }

        private long number(int size) {
            byte[] value = take(size);
            long result = 0;
            for (byte item : value) result = (result << 8) | (item & 255L);
            return result;
        }

        private int checkedContainerSize(long value, boolean map) {
            if (value < 0L || value > MAX_CBOR_CONTAINER_ITEMS) {
                throw new IllegalArgumentException("CBOR container exceeds limit");
            }
            long minimumBytes = value * (map ? 2L : 1L);
            if (minimumBytes > data.length - position) {
                throw new IllegalArgumentException("truncated CBOR container");
            }
            return (int) value;
        }

        private static int checkedLength(long value, int maximum) {
            if (value < 0L || value > maximum || value > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("CBOR value exceeds limit");
            }
            return (int) value;
        }

        private int takeByte() {
            if (position >= data.length) throw new IllegalArgumentException("truncated CBOR");
            return data[position++] & 255;
        }

        private byte[] take(int size) {
            if (size < 0 || size > data.length - position) throw new IllegalArgumentException("truncated CBOR");
            byte[] output = new byte[size];
            System.arraycopy(data, position, output, 0, size);
            position += size;
            return output;
        }
    }
}
