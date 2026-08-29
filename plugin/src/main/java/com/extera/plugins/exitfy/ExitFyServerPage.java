package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Immutable, bounded projection of the nested JSON returned by {@code list_nodes}. */
final class ExitFyServerPage {
    static final int MAX_NODES = SubscriptionManager.MAX_PAGE_SIZE;
    static final ExitFyServerPage INVALID = new ExitFyServerPage(
            false, Collections.emptyList(), Collections.emptyList(),
            -1, 0, MAX_NODES, 0, 0, false, false,
            "", "", "all");

    final boolean valid;
    final List<Node> nodes;
    final List<CustomSource> customSources;
    final int providerId;
    final int offset;
    final int limit;
    final int total;
    final int unfilteredTotal;
    final boolean hasPrevious;
    final boolean hasNext;
    final String selectedKey;
    final String query;
    final String protocol;

    private ExitFyServerPage(boolean valid, List<Node> nodes,
                             List<CustomSource> customSources,
                             int providerId, int offset, int limit,
                             int total, int unfilteredTotal,
                             boolean hasPrevious, boolean hasNext,
                             String selectedKey, String query,
                             String protocol) {
        this.valid = valid;
        this.nodes = Collections.unmodifiableList(new ArrayList<>(nodes));
        this.customSources = Collections.unmodifiableList(
                new ArrayList<>(customSources));
        this.providerId = providerId;
        this.offset = offset;
        this.limit = limit;
        this.total = total;
        this.unfilteredTotal = unfilteredTotal;
        this.hasPrevious = hasPrevious;
        this.hasNext = hasNext;
        this.selectedKey = selectedKey;
        this.query = query;
        this.protocol = protocol;
    }

    static ExitFyServerPage parse(ExitFyCommandResult result) {
        return result == null || !result.ok ? INVALID : parse(result.data);
    }

    static ExitFyServerPage parse(String data) {
        if (data == null || data.trim().isEmpty()) return INVALID;
        try {
            if (JsonGuard.exceedsUtf8Limit(
                    data, ExitFyCommandResult.MAX_DATA_UTF8_BYTES)) {
                return INVALID;
            }
            JSONObject value = JsonGuard.object(
                    data, JsonGuard.MAX_STRING_BYTES,
                    ExitFyCommandResult.MAX_DATA_UTF8_BYTES);
            JSONArray rawNodes = requireArray(value, "nodes");
            JSONArray rawSources = requireArray(value, "customSources");
            if (rawNodes.length() > MAX_NODES
                    || rawSources.length() > SubscriptionManager.MAX_CUSTOM_URLS) {
                return INVALID;
            }

            int providerId = requireInt(value, "providerId", 0,
                    SettingsModel.CUSTOM_PROVIDER_ID);
            int offset = requireInt(value, "offset", 0,
                    SubscriptionManager.MAX_TOTAL_NODES);
            int limit = requireInt(value, "limit", 1, MAX_NODES);
            int total = requireInt(value, "total", 0,
                    SubscriptionManager.MAX_TOTAL_NODES);
            int unfilteredTotal = requireInt(value, "unfilteredTotal", 0,
                    SubscriptionManager.MAX_TOTAL_NODES);
            boolean hasPrevious = requireBoolean(value, "hasPrevious");
            boolean hasNext = requireBoolean(value, "hasNext");
            if (total > unfilteredTotal || offset > total
                    || rawNodes.length() != Math.min(limit, total - offset)
                    || hasPrevious != (offset > 0)
                    || hasNext != (offset + rawNodes.length() < total)) {
                return INVALID;
            }

            String selectedKey = requireNodeKey(value, "selectedKey", true);
            String query = safeText(requireString(value, "query"), 128);
            query = SubscriptionManager.requireUiQuery(query);
            String protocol = SubscriptionManager.requireUiProtocol(
                    requireString(value, "protocol"));

            List<Node> nodes = new ArrayList<>(rawNodes.length());
            Set<String> nodeKeys = new HashSet<>();
            for (int index = 0; index < rawNodes.length(); index++) {
                JSONObject object = rawNodes.optJSONObject(index);
                if (object == null) return INVALID;
                Node node = parseNode(object);
                if (!nodeKeys.add(node.key)) return INVALID;
                nodes.add(node);
            }

            List<CustomSource> sources = new ArrayList<>(rawSources.length());
            Set<String> sourceIds = new HashSet<>();
            for (int index = 0; index < rawSources.length(); index++) {
                JSONObject object = rawSources.optJSONObject(index);
                if (object == null) return INVALID;
                CustomSource source = new CustomSource(
                        requireIdentity(object, "id", 192, false),
                        ExitFyDashboardState.safeLabel(
                                requireString(object, "title"), 160, ""),
                        object.optInt("nodeCount", 0));
                if (!sourceIds.add(source.id)) return INVALID;
                sources.add(source);
            }

            return new ExitFyServerPage(true, nodes, sources,
                    providerId, offset, limit, total, unfilteredTotal,
                    hasPrevious, hasNext, selectedKey,
                    query, protocol);
        } catch (Exception | StackOverflowError ignored) {
            return INVALID;
        }
    }

    private static Node parseNode(JSONObject value) throws Exception {
        String key = requireNodeKey(value, "key", false);
        String name = ExitFyDashboardState.safeLabel(
                requireString(value, "name"), 256, "");
        String group = ExitFyDashboardState.safeLabel(
                requireString(value, "group"), 160, "");
        boolean manual = requireBoolean(value, "manual");
        String protocol = requireToken(value, "protocol", 32, false);
        String transport = requireToken(value, "transport", 32, true);
        String security = requireToken(value, "security", 32, true);
        long latency = Math.max(-1L, requireLong(value, "latency"));
        String pingStatus = requireToken(value, "pingStatus", 48, false);
        return new Node(key, name, group, manual, protocol, transport, security,
                latency, pingStatus);
    }

    private static JSONArray requireArray(JSONObject value, String key) throws Exception {
        Object raw = value.get(key);
        if (!(raw instanceof JSONArray)) throw invalidField(key);
        return (JSONArray) raw;
    }

    private static String requireString(JSONObject value, String key) throws Exception {
        Object raw = value.get(key);
        if (!(raw instanceof String)) throw invalidField(key);
        return (String) raw;
    }

    private static boolean requireBoolean(JSONObject value, String key) throws Exception {
        Object raw = value.get(key);
        if (!(raw instanceof Boolean)) throw invalidField(key);
        return (Boolean) raw;
    }

    private static int requireInt(JSONObject value, String key,
                                  int minimum, int maximum) throws Exception {
        long parsed = requireLong(value, key);
        if (parsed < minimum || parsed > maximum) throw invalidField(key);
        return (int) parsed;
    }

    private static long requireLong(JSONObject value, String key) throws Exception {
        Object raw = value.get(key);
        if (!(raw instanceof Number)) throw invalidField(key);
        try {
            return new BigDecimal(raw.toString()).longValueExact();
        } catch (ArithmeticException | NumberFormatException error) {
            throw invalidField(key);
        }
    }

    private static String requireIdentity(JSONObject value, String key,
                                          int maximumCodePoints,
                                          boolean allowEmpty) throws Exception {
        String raw = requireString(value, key);
        String normalized = safeText(raw, maximumCodePoints);
        if ((!allowEmpty && normalized.isEmpty()) || !normalized.equals(raw.trim())) {
            throw invalidField(key);
        }
        return normalized;
    }

    private static String requireNodeKey(JSONObject value, String key,
                                         boolean allowEmpty) throws Exception {
        String parsed = requireIdentity(value, key, 64, allowEmpty);
        if (allowEmpty && parsed.isEmpty()) return parsed;
        if (parsed.length() != 64) throw invalidField(key);
        for (int index = 0; index < parsed.length(); index++) {
            char item = parsed.charAt(index);
            if (!((item >= '0' && item <= '9')
                    || (item >= 'a' && item <= 'f'))) {
                throw invalidField(key);
            }
        }
        return parsed;
    }

    private static String requireToken(JSONObject value, String key,
                                       int maximumCodePoints,
                                       boolean allowEmpty) throws Exception {
        String token = safeText(requireString(value, key), maximumCodePoints)
                .toLowerCase(Locale.ROOT);
        if ((!allowEmpty && token.isEmpty()) || !isToken(token)) {
            throw invalidField(key);
        }
        return token;
    }

    private static boolean isToken(String value) {
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (!(item >= 'a' && item <= 'z') && !(item >= '0' && item <= '9')
                    && item != '_' && item != '-') {
                return false;
            }
        }
        return true;
    }

    private static String safeText(String value, int maximumCodePoints) {
        if (value == null || maximumCodePoints <= 0) return "";
        StringBuilder output = new StringBuilder(
                Math.min(value.length(), maximumCodePoints));
        int count = 0;
        for (int offset = 0;
             offset < value.length() && count < maximumCodePoints; ) {
            int point = value.codePointAt(offset);
            offset += Character.charCount(point);
            if (Character.isISOControl(point) || point == 0x2028 || point == 0x2029
                    || point == 0x061c || point == 0x200e || point == 0x200f
                    || (point >= 0x202a && point <= 0x202e)
                    || (point >= 0x2066 && point <= 0x2069)) {
                continue;
            }
            output.appendCodePoint(point);
            count++;
        }
        return output.toString().trim();
    }

    private static IllegalArgumentException invalidField(String key) {
        return new IllegalArgumentException("invalid server page field: " + key);
    }

    static final class Node {
        final String key;
        final String name;
        final String group;
        final boolean manual;
        final String protocol;
        final String transport;
        final String security;
        final long latency;
        final String pingStatus;

        private Node(String key, String name, String group, boolean manual,
                     String protocol, String transport, String security,
                     long latency, String pingStatus) {
            this.key = key;
            this.name = name;
            this.group = group;
            this.manual = manual;
            this.protocol = protocol;
            this.transport = transport;
            this.security = security;
            this.latency = latency;
            this.pingStatus = pingStatus;
        }
    }

    static final class CustomSource {
        final String id;
        final String title;
        final int nodeCount;

        private CustomSource(String id, String title, int nodeCount) {
            this.id = id;
            this.title = title;
            this.nodeCount = nodeCount;
        }
    }
}
