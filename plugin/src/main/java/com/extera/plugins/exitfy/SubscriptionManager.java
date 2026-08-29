package com.extera.plugins.exitfy;

import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.Closeable;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SubscriptionManager implements Closeable {
    private static final String SUBSCRIPTION_USER_AGENT = "v2rayN/6.23";
    // Ordered: the long-standing agent first, so a provider that already
    // answers it keeps returning exactly what it returns today.
    private static final String[] SUBSCRIPTION_USER_AGENTS = {
            SUBSCRIPTION_USER_AGENT, "clash-verge/1.0",
    };
    private static final String STORE_FILE = "subscriptions.json";
    private static final long CACHE_TTL_MS = 6L * 60L * 60L * 1000L;
    static final int MAX_TOTAL_NODES = 10_000;
    // Listing and probing are bounded separately: people asked to see a whole
    // source at once, while probing that many servers is a different cost.
    static final int MAX_PAGE_SIZE = 200;
    static final int DEFAULT_PAGE_SIZE = 50;
    static final int MAX_PING_KEYS = 50;
    static final int MAX_UI_QUERY_CODE_POINTS = 128;
    static final int MAX_UI_QUERY_UTF8_BYTES = 512;
    static final int MAX_CUSTOM_URLS = 256;
    private static final int CUSTOM_PROVIDER_ID = SettingsModel.CUSTOM_PROVIDER_ID;
    private static final int MAX_PROVIDER_ID = CUSTOM_PROVIDER_ID;
    private static final int PROVIDER_LAYOUT_VERSION = 3;
    private static final int LEGACY_V2_CUSTOM_ID = 2;
    private static final int MAX_PROFILE_HEADER_CHARS = 16 * 1024;
    private static final Pattern HTTP_URL = Pattern.compile("(?i)https?://[^\\s\\\"'<>]+", Pattern.MULTILINE);
    private static final Pattern FILE_NAME = Pattern.compile(
            "(?i)filename\\*?=(?:UTF-8''|\\\")?([^\\\";]+)"
    );
    static boolean validPageRequest(int offset, int limit) {
        return offset >= 0 && offset <= MAX_TOTAL_NODES
                && limit > 0 && limit <= MAX_PAGE_SIZE;
    }
    private static final String[] PROVIDER_NAMES = {"Shrimp", "Elix", "Sworkle"};
    private static final Set<String> UI_PROTOCOLS = Collections.unmodifiableSet(
            new LinkedHashSet<>(java.util.Arrays.asList(
                    "all", "vless", "vmess", "trojan", "shadowsocks",
                    "hysteria", "hysteria2", "tuic")));
    // Ordered like the catalog.
    private static final String[] REFERRALS = {
            "https://t.me/invisibleshrimpbot?start=exitfy",
            "https://t.me/elixrobot?start=utm_exteragram",
            "https://t.me/sworklevpnbot?start=ref_2XJEM5CS"
    };

    private final AtomicStore store;
    private final AtomicStore.WriterLease writerLease;
    private final LimitedHttpClient http;
    private final OperationObserver operationObserver;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean persistencePoisoned = new AtomicBoolean();
    private final AtomicLong lifecycleEpoch = new AtomicLong(1L);
    private final Map<String, Long> latencyCache = new ConcurrentHashMap<>();
    private final Map<String, String> pingStatusCache = new ConcurrentHashMap<>();
    private final Map<Integer, List<ProtocolParser.Node>> nodeCache = new HashMap<>();
    private JSONObject data;
    private volatile ViewSnapshot viewSnapshot = ViewSnapshot.empty();
    private volatile boolean cancelPendingOnClose;
    // In-memory mutation epoch. Refresh and import parse outside this monitor;
    // an older parse must never overwrite a newer add/remove/clear action.
    private long mutationRevision;

    private String migratedHwid = "";

    /** Seeds the device identifier once, before any request is made. */
    synchronized void adoptMigratedHwid(String value) {
        migratedHwid = value == null ? "" : value.trim();
    }

    SubscriptionManager(AtomicStore store, LimitedHttpClient http) {
        this(store, http, OperationObserver.NO_OP);
    }

    SubscriptionManager(AtomicStore store, LimitedHttpClient http,
                        OperationObserver operationObserver) {
        ProviderCatalog.verify();
        this.store = store;
        this.writerLease = store.claimWriter(STORE_FILE);
        this.http = http;
        this.operationObserver = operationObserver == null
                ? OperationObserver.NO_OP : operationObserver;
        JSONObject loaded;
        try {
            loaded = store.readJsonIfExists(STORE_FILE);
        } catch (Exception error) {
            writerLease.close();
            throw new IllegalStateException("subscription state is unreadable", error);
        }
        this.data = loaded == null ? new JSONObject() : loaded;
        try {
            boolean changed = ensureShape();
            changed |= boundLoadedNodesLocked();
            if (changed) {
                persist();
            }
        } catch (Exception error) {
            writerLease.close();
            throw new IllegalStateException("subscription state initialization failed", error);
        }
        synchronized (this) {
            publishViewSnapshotLocked();
        }
    }

    synchronized List<ProtocolParser.Node> nodes(int providerId) {
        int bounded = boundedProvider(providerId);
        List<ProtocolParser.Node> cached = nodeCache.get(bounded);
        if (cached != null) return new ArrayList<>(cached);
        LinkedHashMap<String, ProtocolParser.Node> exact = new LinkedHashMap<>();
        JSONArray sources = provider(bounded).optJSONArray("sources");
        Set<String> hidden = bounded == CUSTOM_PROVIDER_ID
                ? hiddenSourceIdsLocked() : Collections.emptySet();
        if (sources != null) {
            for (int i = 0; i < sources.length(); i++) {
                JSONObject source = sources.optJSONObject(i);
                if (source != null && !hidden.contains(source.optString("id", ""))) {
                    collectStored(source.optJSONArray("nodes"), exact);
                }
                if (exact.size() >= MAX_TOTAL_NODES) break;
            }
        }
        if (bounded == CUSTOM_PROVIDER_ID && exact.size() < MAX_TOTAL_NODES) {
            collectStored(data.optJSONArray("manual"), exact);
        }
        List<ProtocolParser.Node> result = new ArrayList<>(exact.values());
        // Retain full credentials/outbound JSON for at most the provider in
        // current use. UI reads the compact immutable snapshot instead.
        nodeCache.clear();
        nodeCache.put(bounded, result);
        return new ArrayList<>(result);
    }

    void warmCache() {
        // Runtime load must remain cheap and must not retain every parsed URI,
        // outbound JSON object, and credential for all providers. The compact
        // view snapshot is built during construction; full nodes are parsed
        // lazily only for the provider which is actually used.
    }

    int nodeCountFast(int providerId) {
        return viewSnapshot.uiNodes(boundedProvider(providerId)).size();
    }

    synchronized boolean isStale(int providerId) {
        List<String> urls = sourceUrlsLocked(providerId);
        if (urls.isEmpty()) return nodes(providerId).isEmpty();
        long now = System.currentTimeMillis();
        for (String url : urls) {
            JSONObject source = sourceForUrlLocked(providerId, url, false);
            long updatedAt = source == null ? 0L : source.optLong("updatedAt", 0L);
            if (source == null || staleTimestamp(now, updatedAt)) {
                return true;
            }
        }
        return false;
    }

    static boolean staleTimestamp(long now, long updatedAt) {
        return updatedAt <= 0L || updatedAt > now || now - updatedAt >= CACHE_TTL_MS;
    }

    int customUrlCount() {
        return viewSnapshot.customSources.size();
    }

    boolean hasCustomConfiguration() {
        ViewSnapshot snapshot = viewSnapshot;
        return !snapshot.customSources.isEmpty()
                || !snapshot.uiNodes(CUSTOM_PROVIDER_ID).isEmpty();
    }

    String referral(int providerId) {
        return providerId >= 0 && providerId < REFERRALS.length
                && ProviderCatalog.isEnabled(providerId) ? REFERRALS[providerId] : "";
    }

    List<ProtocolParser.Node> refresh(int providerId, SettingsModel settings) throws Exception {
        return refresh(providerId, settings, Long.MAX_VALUE);
    }

    List<ProtocolParser.Node> refresh(int providerId, SettingsModel settings,
                                      long absoluteDeadlineNanos) throws Exception {
        return refresh(providerId, settings, absoluteDeadlineNanos,
                RefreshCancellation.NO_OP);
    }

    List<ProtocolParser.Node> refresh(int providerId, SettingsModel settings,
                                      long absoluteDeadlineNanos,
                                      RefreshCancellation cancellation) throws Exception {
        RefreshCancellation signal = cancellation == null
                ? RefreshCancellation.NO_OP : cancellation;
        long operationEpoch = beginOperation();
        LimitedHttpClient.RequestScope requestScope = http.beginRequestScope();
        List<String> urls;
        long membershipRevision;
        synchronized (this) {
            ensureOperationActive(operationEpoch);
            urls = sourceUrlsLocked(providerId);
            membershipRevision = mutationRevision;
        }
        if (urls.isEmpty()) {
            List<ProtocolParser.Node> existing = nodes(providerId);
            if (!existing.isEmpty()) return existing;
            throw new IllegalStateException(I18n.t(
                    "Нет URL подписки для выбранного источника",
                    "No subscription URL for the selected source"));
        }

        Exception lastError = null;
        int succeeded = 0;
        refreshLoop:
        for (String url : urls) {
            if (refreshCancelled(absoluteDeadlineNanos, signal)
                    || !operationActive(operationEpoch)) break;
            synchronized (this) {
                ensureOperationActive(operationEpoch);
                ensureRefreshActive(absoluteDeadlineNanos, signal);
                // Do not send device/HWID headers to a URL which the user
                // removed while an earlier request was in flight.
                if (membershipRevision != mutationRevision
                        || !sourceUrlsLocked(providerId).contains(url)) {
                    lastError = new IllegalStateException(
                            "subscription source membership changed");
                    break;
                }
            }
            try {
                FetchResult fetched = fetch(providerId, url, settings, requestScope);
                if (refreshCancelled(absoluteDeadlineNanos, signal)
                        || !operationActive(operationEpoch)) break;
                synchronized (this) {
                    ensureOperationActive(operationEpoch);
                    ensureRefreshActive(absoluteDeadlineNanos, signal);
                    if (membershipRevision != mutationRevision
                            || !sourceUrlsLocked(providerId).contains(url)) {
                        lastError = new IllegalStateException(
                                "subscription source membership changed");
                        break refreshLoop;
                    }
                    JSONObject source = sourceForUrlLocked(providerId, url, true);
                    String oldTitle = source.optString("title", "");
                    long oldUpdatedAt = source.optLong("updatedAt", 0L);
                    JSONArray oldNodes = source.optJSONArray("nodes");
                    String oldCustomTitle = customTitleLocked(url);
                    JSONObject mutationOwner = data;
                    try {
                        source.put("title", fetched.title);
                        source.put("updatedAt", System.currentTimeMillis());
                        source.put("nodes", storeNodes(fetched.nodes));
                        if (boundedProvider(providerId) == CUSTOM_PROVIDER_ID) {
                            updateCustomTitleLocked(url, fetched.title);
                        }
                        // Keep the aggregate bounded after every source, not
                        // only after all 256 possible sources were applied.
                        AtomicStore.jsonUtf8Size(data, AtomicStore.MAX_JSON_BYTES);
                        invalidateNodeCachesLocked(boundedProvider(providerId));
                        clearProbeResultsLocked();
                        // Each successful URL is its own atomic durable commit.
                        // A later timeout/error therefore preserves the partial
                        // success without exposing half-mutated in-memory data.
                        ensureRefreshActive(absoluteDeadlineNanos, signal);
                        persist(operationEpoch, SnapshotMode.FULL,
                                () -> !refreshCancelled(absoluteDeadlineNanos, signal));
                    } catch (Exception mutationError) {
                        // persist() reloads durable state on I/O failure. If
                        // validation failed before persistence, restore only
                        // the touched source without cloning the full 8 MiB
                        // store into another large String/JSONObject graph.
                        if (data == mutationOwner) {
                            source.put("title", oldTitle).put("updatedAt", oldUpdatedAt)
                                    .put("nodes", oldNodes == null ? new JSONArray() : oldNodes);
                            if (boundedProvider(providerId) == CUSTOM_PROVIDER_ID) {
                                updateCustomTitleLocked(url, oldCustomTitle);
                            }
                        }
                        invalidateNodeCachesLocked(boundedProvider(providerId));
                        throw mutationError;
                    }
                }
                succeeded++;
            } catch (Exception error) {
                lastError = error;
                if (refreshCancelled(absoluteDeadlineNanos, signal)
                        || !operationActive(operationEpoch)) break;
            }
        }

        ensureRefreshActive(absoluteDeadlineNanos, signal);

        if (succeeded == 0) {
            if (lastError != null) throw lastError;
            throw new IllegalStateException(I18n.t(
                    "В подписке нет поддерживаемых серверов",
                    "The subscription has no supported servers"));
        }

        synchronized (this) {
            ensureOperationActive(operationEpoch);
            ensureRefreshActive(absoluteDeadlineNanos, signal);
            if (membershipRevision != mutationRevision) {
                throw new IllegalStateException("subscription source membership changed");
            }
            // Use current membership, never the stale network snapshot: a URL
            // added during refresh must not be pruned by the old operation.
            pruneSourcesLocked(providerId,
                    new LinkedHashSet<>(sourceUrlsLocked(providerId)));
            invalidateNodeCachesLocked(boundedProvider(providerId));
            clearProbeResultsLocked();
            persist(operationEpoch, SnapshotMode.FULL,
                    () -> !refreshCancelled(absoluteDeadlineNanos, signal));
        }
        List<ProtocolParser.Node> result = nodes(providerId);
        if (result.size() > MAX_TOTAL_NODES) {
            throw new IllegalStateException("provider node set exceeds 10000 nodes");
        }
        return result;
    }

    private static boolean refreshCancelled(long absoluteDeadlineNanos,
                                            RefreshCancellation cancellation) {
        return Thread.currentThread().isInterrupted()
                || (cancellation != null && cancellation.cancelled())
                || (absoluteDeadlineNanos != Long.MAX_VALUE
                && System.nanoTime() >= absoluteDeadlineNanos);
    }

    private static void ensureRefreshActive(long absoluteDeadlineNanos,
                                            RefreshCancellation cancellation) {
        if (refreshCancelled(absoluteDeadlineNanos, cancellation)) {
            throw new IllegalStateException("subscription refresh cancelled");
        }
    }

    private FetchResult fetch(int providerId, String originalUrl, SettingsModel settings,
                              LimitedHttpClient.RequestScope requestScope) throws Exception {
        Exception last = null;
        for (String candidate : subscriptionCandidateUrls(originalUrl)) {
            try {
                SubscriptionParser.ParseResult parsed = null;
                LimitedHttpClient.Response response = null;
                // Some providers answer an unrecognised client with a list of
                // unusable placeholder entries instead of servers. Retrying
                // under a second widely accepted agent recovers those without
                // changing what every other provider already returns.
                for (String agent : SUBSCRIPTION_USER_AGENTS) {
                    response = http.get(candidate,
                            requestHeaders(settings, agent), requestScope);
                    if (response.status < 200 || response.status >= 300) {
                        throw new IllegalStateException("HTTP " + response.status);
                    }
                    parsed = SubscriptionParser.parseDetailed(
                            SubscriptionParser.decodeStrictUtf8(response.body));
                    if (!parsed.nodes.isEmpty()) break;
                }
                if (parsed == null || parsed.nodes.isEmpty()) {
                    // A source that answers an unrecognised client sends entries
                    // whose names carry a notice and whose address cannot be
                    // reached. Saying "no supported servers" there points the
                    // user at their own configuration instead of the refusal.
                    boolean refused = parsed != null && parsed.rejected > 0
                            && parsed.reasons.contains(SubscriptionParser.UNREACHABLE_ONLY);
                    if (!refused) {
                        String cause = parsed == null ? ""
                                : RejectionReason.summarize(parsed.reasons);
                        throw new IllegalStateException(I18n.t(
                                "Подписка не содержит поддерживаемых серверов",
                                "Subscription contains no supported servers")
                                + (cause.isEmpty() ? "" : ": " + cause));
                    }
                    // The source stated its reason in the names of the dead
                    // entries. Repeating it verbatim tells the user far more
                    // than any wording of ours, so it is shown when present.
                    String notice = joinNotices(parsed.notices);
                    throw new IllegalStateException(notice.isEmpty()
                            ? I18n.t(
                            "Источник не отдаёт серверы этому приложению",
                            "This source refuses to serve this app")
                            : I18n.t("Ответ источника: ", "The source answered: ") + notice);
                }
                int bounded = boundedProvider(providerId);
                String title = bounded < ProviderCatalog.size()
                        ? PROVIDER_NAMES[bounded] : responseTitle(response, originalUrl);
                return new FetchResult(parsed.nodes, title);
            } catch (Exception error) {
                last = error;
            }
        }
        if (last != null) throw last;
        throw new IllegalStateException("subscription fetch failed");
    }

    static List<String> subscriptionCandidateUrls(String value) {
        String target = value == null ? "" : value.trim();
        if (target.isEmpty()) return new ArrayList<>();
        List<String> result = new ArrayList<>();
        // Device and HWID headers may only be sent to the URL explicitly
        // configured by the user/provider, never to rewritten mirrors.
        result.add(target);
        return result;
    }

    ImportResult importText(String text) throws Exception {
        long operationEpoch = beginOperation();
        String value = text == null ? "" : text;
        Set<String> knownAtStart;
        long membershipAtStart;
        synchronized (this) {
            ensureOperationActive(operationEpoch);
            knownAtStart = customUrlSetLocked();
            membershipAtStart = mutationRevision;
        }
        operationObserver.onImportParseStarted();
        ensureOperationActive(operationEpoch);
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(value);
        List<String> extractedUrls = explicitSubscriptionUrls(value, knownAtStart);
        ensureOperationActive(operationEpoch);
        synchronized (this) {
            ensureOperationActive(operationEpoch);
            if (membershipAtStart != mutationRevision) {
                throw new IllegalStateException("subscription source membership changed");
            }
            JSONObject transactionOwner = data;
            JSONArray oldManual = data.optJSONArray("manual");
            JSONArray oldCustomUrls = data.optJSONArray("customUrls");
            try {
                // addManualNodesLocked replaces manual with a newly built
                // array. Custom URL import only appends, so a shallow array copy is
                // sufficient to keep the old field reference as a rollback point.
                data.put("customUrls", shallowArray(oldCustomUrls));
                int addedNodes = addManualNodesLocked(parsed.nodes);
                int urls = 0;
                Set<String> knownUrls = customUrlSetLocked();
                for (String url : extractedUrls) {
                    if (addCustomUrlLocked(url, knownUrls)) urls++;
                }
                persist(operationEpoch);
                if (addedNodes > 0 || urls > 0) mutationRevision++;
                invalidateNodeCachesLocked(CUSTOM_PROVIDER_ID);
                clearProbeResultsLocked();
                return new ImportResult(addedNodes, urls);
            } catch (Exception error) {
                // persist() may already have reloaded durable data on I/O failure.
                // Otherwise restore only fields touched by this transaction.
                if (data == transactionOwner) {
                    data.put("manual", oldManual == null ? new JSONArray() : oldManual);
                    data.put("customUrls",
                            oldCustomUrls == null ? new JSONArray() : oldCustomUrls);
                }
                throw error;
            }
        }
    }

    private static JSONArray shallowArray(JSONArray source) {
        JSONArray copy = new JSONArray();
        for (int i = 0; source != null && i < source.length(); i++) {
            copy.put(source.opt(i));
        }
        return copy;
    }

    synchronized int addManualUri(String value) throws Exception {
        ensureWritable();
        SubscriptionParser.ParseResult parsed = SubscriptionParser.parseDetailed(
                value == null ? "" : value.trim());
        if (parsed.nodes.isEmpty()) {
            // The parser knows exactly what it refused; saying only "invalid
            // key" left people guessing at a key another client accepts.
            String cause = RejectionReason.summarize(parsed.reasons);
            throw new IllegalArgumentException(cause.isEmpty()
                    ? I18n.t("Некорректный ключ", "Invalid key")
                    : I18n.t("Некорректный ключ: ", "Invalid key: ") + cause);
        }
        int added = addManualNodesLocked(parsed.nodes);
        invalidateNodeCachesLocked(CUSTOM_PROVIDER_ID);
        clearProbeResultsLocked();
        persist();
        if (added > 0) mutationRevision++;
        return added;
    }

    synchronized boolean addCustomUrl(String value) throws Exception {
        ensureWritable();
        boolean added = addCustomUrlLocked(value, customUrlSetLocked());
        if (added) {
            persist();
            mutationRevision++;
        }
        return added;
    }

    synchronized boolean removeCustomUrl(String id) throws Exception {
        ensureWritable();
        JSONArray current = data.optJSONArray("customUrls");
        JSONArray next = new JSONArray();
        String removedUrl = "";
        for (int i = 0; current != null && i < current.length(); i++) {
            JSONObject item = current.optJSONObject(i);
            if (item == null) continue;
            if (removedUrl.isEmpty() && id != null && id.equals(item.optString("id", ""))) {
                removedUrl = item.optString("url", "");
            } else {
                next.put(item);
            }
        }
        if (removedUrl.isEmpty()) return false;
        data.put("customUrls", next);
        pruneSourcesLocked(CUSTOM_PROVIDER_ID,
                new LinkedHashSet<>(sourceUrlsLocked(CUSTOM_PROVIDER_ID)));
        invalidateNodeCachesLocked(CUSTOM_PROVIDER_ID);
        clearProbeResultsLocked();
        persist();
        mutationRevision++;
        return true;
    }

    /**
     * Moves one saved subscription within the list. Order decides which
     * servers a page shows first, so it is the user's to arrange.
     */
    synchronized boolean moveCustomUrl(String id, int delta) throws Exception {
        ensureWritable();
        if (id == null || id.isEmpty() || delta == 0) return false;
        JSONArray current = data.optJSONArray("customUrls");
        int length = current == null ? 0 : current.length();
        int from = -1;
        for (int i = 0; i < length; i++) {
            JSONObject item = current.optJSONObject(i);
            if (item != null && id.equals(item.optString("id", ""))) {
                from = i;
                break;
            }
        }
        if (from < 0) return false;
        int to = from + (delta > 0 ? 1 : -1);
        if (to < 0 || to >= length) return false;
        List<JSONObject> items = new ArrayList<>();
        for (int i = 0; i < length; i++) items.add(current.optJSONObject(i));
        JSONObject moved = items.remove(from);
        items.add(to, moved);
        JSONArray next = new JSONArray();
        for (JSONObject item : items) next.put(item);
        data.put("customUrls", next);
        reorderSourcesLocked(items);
        invalidateNodeCachesLocked(CUSTOM_PROVIDER_ID);
        persist();
        mutationRevision++;
        return true;
    }

    /**
     * Hides a subscription's servers without deleting it. Sources go quiet for
     * a while and come back; losing the URL to stop seeing them is a poor
     * trade, and re-adding it loses whatever else was saved with it.
     */
    synchronized boolean setCustomUrlHidden(String id, boolean hidden) throws Exception {
        ensureWritable();
        if (id == null || id.isEmpty()) return false;
        JSONArray current = data.optJSONArray("customUrls");
        for (int i = 0; current != null && i < current.length(); i++) {
            JSONObject item = current.optJSONObject(i);
            if (item == null || !id.equals(item.optString("id", ""))) continue;
            if (item.optBoolean("hidden", false) == hidden) return false;
            item.put("hidden", hidden);
            invalidateNodeCachesLocked(CUSTOM_PROVIDER_ID);
            clearProbeResultsLocked();
            persist();
            mutationRevision++;
            return true;
        }
        return false;
    }

    private void reorderSourcesLocked(List<JSONObject> orderedUrls) throws Exception {
        JSONArray sources = provider(CUSTOM_PROVIDER_ID).optJSONArray("sources");
        if (sources == null) return;
        LinkedHashMap<String, JSONObject> byId = new LinkedHashMap<>();
        for (int i = 0; i < sources.length(); i++) {
            JSONObject source = sources.optJSONObject(i);
            if (source != null) byId.put(source.optString("id", ""), source);
        }
        JSONArray next = new JSONArray();
        for (JSONObject item : orderedUrls) {
            if (item == null) continue;
            String sourceKey = sourceId(sourceStorageKey(
                    CUSTOM_PROVIDER_ID, item.optString("url", "")));
            JSONObject source = byId.remove(sourceKey);
            if (source != null) next.put(source);
        }
        for (JSONObject leftover : byId.values()) next.put(leftover);
        provider(CUSTOM_PROVIDER_ID).put("sources", next);
    }

    private Set<String> hiddenSourceIdsLocked() {
        LinkedHashSet<String> hidden = new LinkedHashSet<>();
        JSONArray custom = data.optJSONArray("customUrls");
        for (int i = 0; custom != null && i < custom.length(); i++) {
            JSONObject item = custom.optJSONObject(i);
            if (item == null || !item.optBoolean("hidden", false)) continue;
            hidden.add(sourceId(sourceStorageKey(
                    CUSTOM_PROVIDER_ID, item.optString("url", ""))));
        }
        return hidden;
    }

    synchronized void clearNodesKeepSubscriptions() throws Exception {
        ensureWritable();
        long operationEpoch = beginOperation();
        data.put("manual", new JSONArray());
        for (int providerId = 0; providerId <= MAX_PROVIDER_ID; providerId++) {
            JSONArray sources = provider(providerId).optJSONArray("sources");
            for (int i = 0; sources != null && i < sources.length(); i++) {
                JSONObject source = sources.optJSONObject(i);
                if (source != null) source.put("updatedAt", 0L).put("nodes", new JSONArray());
            }
        }
        data.put("activeKeys", new JSONObject());
        clearProbeResultsLocked();
        invalidateAllNodeCachesLocked();
        persist(operationEpoch);
        // Refresh snapshots this revision before leaving the monitor for HTTP.
        // A clear keeps URLs but invalidates every result fetched before it.
        mutationRevision++;
    }

    synchronized boolean removeManualNode(String key) throws Exception {
        ensureWritable();
        JSONArray manual = data.optJSONArray("manual");
        JSONArray next = new JSONArray();
        boolean removed = false;
        for (int i = 0; manual != null && i < manual.length(); i++) {
            JSONObject item = manual.optJSONObject(i);
            if (item == null) continue;
            try {
                ProtocolParser.Node node = ProtocolParser.fromStoredJson(item);
                if (!removed && node.normalizedKey.equals(key)) {
                    removed = true;
                    continue;
                }
            } catch (Exception ignored) {
            }
            next.put(item);
        }
        if (!removed) return false;
        data.put("manual", next);
        String customKey = String.valueOf(CUSTOM_PROVIDER_ID);
        String selected = data.optJSONObject("activeKeys").optString(customKey, "");
        if (selected.equals(key)) data.optJSONObject("activeKeys").remove(customKey);
        invalidateNodeCachesLocked(CUSTOM_PROVIDER_ID);
        latencyCache.remove(key);
        pingStatusCache.remove(key);
        persist();
        mutationRevision++;
        return true;
    }

    JSONObject uiState(int providerId) {
        return uiState(providerId, 0, DEFAULT_PAGE_SIZE);
    }

    JSONObject uiState(int providerId, int requestedOffset, int requestedLimit) {
        return uiState(providerId, requestedOffset, requestedLimit,
                "", "all");
    }

    JSONObject uiState(int providerId, int requestedOffset, int requestedLimit,
                       String requestedQuery, String requestedProtocol) {
        int bounded = boundedProvider(providerId);
        ViewSnapshot snapshot = viewSnapshot;
        JSONObject result = new JSONObject();
        JSONArray output = new JSONArray();
        int requested = Math.max(0, requestedOffset);
        int limit = Math.max(1, Math.min(MAX_PAGE_SIZE, requestedLimit));
        try {
            String query = requireUiQuery(requestedQuery);
            String protocol = requireUiProtocol(requestedProtocol);
            List<UiNode> unfiltered = snapshot.uiNodes(bounded);
            List<UiNode> values = new ArrayList<>();
            for (UiNode value : unfiltered) {
                if (!"all".equals(protocol) && !protocol.equals(value.protocol)) continue;
                if (!query.isEmpty() && !value.searchText.contains(query)) continue;
                values.add(value);
            }
            int total = values.size();
            int offset = Math.min(requested, total);
            int end = offset + Math.min(limit, total - offset);
            for (int i = offset; i < end; i++) {
                UiNode value = values.get(i);
                long latency = cachedLatency(latencyCache, value.key);
                String pingStatus = pingStatusCache.getOrDefault(
                        value.key, "idle");
                if (cancelPendingOnClose && "pending".equals(pingStatus)) {
                    pingStatus = "cancelled";
                }
                output.put(value.toJson(latency, pingStatus));
            }
            JSONArray custom = new JSONArray();
            if (bounded == CUSTOM_PROVIDER_ID) {
                for (SourceSummary item : snapshot.customSources) {
                    custom.put(new JSONObject()
                            .put("id", item.id)
                            .put("title", item.title)
                            .put("nodeCount", item.nodeCount)
                            .put("hidden", item.hidden));
                }
            }
            result.put("providerId", bounded);
            result.put("nodes", output);
            result.put("customSources", custom);
            result.put("offset", offset);
            result.put("limit", limit);
            result.put("total", total);
            result.put("unfilteredTotal", unfiltered.size());
            result.put("hasPrevious", offset > 0);
            result.put("hasNext", end < total);
            result.put("selectedKey", snapshot.selectedKey(bounded));
            result.put("query", query);
            result.put("protocol", protocol);
        } catch (Exception ignored) {
        }
        return result;
    }

    JSONObject uiNodeInfo(int providerId, String key) {
        if (key == null || key.isEmpty()) return new JSONObject();
        ViewSnapshot snapshot = viewSnapshot;
        for (UiNode value : snapshot.uiNodes(boundedProvider(providerId))) {
            if (!key.equals(value.key)) continue;
            long latency = cachedLatency(latencyCache, value.key);
            String status = pingStatusCache.getOrDefault(value.key, "idle");
            if (cancelPendingOnClose && "pending".equals(status)) status = "cancelled";
            return value.toJson(latency, status);
        }
        return new JSONObject();
    }

    JSONObject selectedUiNodeInfo(int providerId) {
        ViewSnapshot snapshot = viewSnapshot;
        int bounded = boundedProvider(providerId);
        String selectedKey = snapshot.selectedKey(bounded);
        if (selectedKey.isEmpty()) return new JSONObject();
        for (UiNode value : snapshot.uiNodes(bounded)) {
            if (!selectedKey.equals(value.key)) continue;
            long latency = cachedLatency(latencyCache, value.key);
            String status = pingStatusCache.getOrDefault(value.key, "idle");
            if (cancelPendingOnClose && "pending".equals(status)) status = "cancelled";
            return value.toJson(latency, status);
        }
        return new JSONObject();
    }

    static long cachedLatency(Map<String, Long> cache, String key) {
        Long value = cache == null ? null : cache.get(key);
        return value == null ? -1L : value;
    }

    static String requireUiQuery(String value) {
        String query = value == null ? "" : value.trim();
        if (query.codePointCount(0, query.length()) > MAX_UI_QUERY_CODE_POINTS
                || query.getBytes(StandardCharsets.UTF_8).length > MAX_UI_QUERY_UTF8_BYTES) {
            throw new IllegalArgumentException(I18n.t(
                    "Поисковый запрос слишком длинный", "Search query is too long"));
        }
        return query.toLowerCase(Locale.ROOT);
    }

    static String requireUiProtocol(String value) {
        String protocol = value == null ? "all" : value.trim().toLowerCase(Locale.ROOT);
        if (protocol.isEmpty()) protocol = "all";
        if (!UI_PROTOCOLS.contains(protocol)) {
            throw new IllegalArgumentException(I18n.t(
                    "Неизвестный фильтр протокола", "Unknown protocol filter"));
        }
        return protocol;
    }

    private void invalidateNodeCachesLocked(int providerId) {
        int bounded = boundedProvider(providerId);
        nodeCache.remove(bounded);
    }

    private void invalidateAllNodeCachesLocked() {
        nodeCache.clear();
    }

    private void appendUiNodes(List<UiNode> output, JSONArray source, String group, boolean manual,
                               Set<String> seen) throws Exception {
        if (source == null) return;
        for (int i = 0; i < source.length() && output.size() < MAX_TOTAL_NODES; i++) {
            JSONObject item = source.optJSONObject(i);
            if (item == null) continue;
            try {
                ProtocolParser.Node node = ProtocolParser.fromStoredJson(item);
                if (!seen.add(node.normalizedKey)) continue;
                output.add(new UiNode(node.normalizedKey, node.name,
                        group == null || group.isEmpty() ? I18n.t("Подписка", "Subscription") : group,
                        manual, protocolLabel(node), transportLabel(node), securityLabel(node)));
            } catch (Exception ignored) {
            }
        }
    }

    /** Publish only fully committed data; readers never observe a transaction in flight. */
    private void publishViewSnapshotLocked() {
        Map<Integer, List<UiNode>> providers = new HashMap<>();
        Map<Integer, String> selected = new HashMap<>();
        JSONObject activeKeys = data.optJSONObject("activeKeys");
        for (int providerId = 0; providerId <= MAX_PROVIDER_ID; providerId++) {
            List<UiNode> values = new ArrayList<>();
            Set<String> seen = new LinkedHashSet<>();
            try {
                JSONArray sources = provider(providerId).optJSONArray("sources");
                // The list the UI renders comes from here, not from nodes():
                // filtering only there left hidden sources fully visible.
                Set<String> hidden = providerId == CUSTOM_PROVIDER_ID
                        ? hiddenSourceIdsLocked() : Collections.emptySet();
                for (int i = 0; sources != null && i < sources.length(); i++) {
                    JSONObject source = sources.optJSONObject(i);
                    if (source == null || hidden.contains(source.optString("id", ""))) {
                        continue;
                    }
                    appendUiNodes(values, source.optJSONArray("nodes"),
                            source.optString("title", ""), false, seen);
                    if (values.size() >= MAX_TOTAL_NODES) break;
                }
                if (providerId == CUSTOM_PROVIDER_ID && values.size() < MAX_TOTAL_NODES) {
                    appendUiNodes(values, data.optJSONArray("manual"), "manual", true, seen);
                }
            } catch (Exception ignored) {
            }
            List<UiNode> immutableValues = Collections.unmodifiableList(new ArrayList<>(values));
            providers.put(providerId, immutableValues);
            String selectedKey = activeKeys == null ? ""
                    : activeKeys.optString(String.valueOf(providerId), "");
            selected.put(providerId, containsUiKey(immutableValues, selectedKey)
                    ? selectedKey : "");
        }

        List<SourceSummary> customSources = new ArrayList<>();
        JSONArray urls = data.optJSONArray("customUrls");
        for (int i = 0; urls != null && i < urls.length(); i++) {
            JSONObject item = urls.optJSONObject(i);
            if (item == null) continue;
            // A source that contributes nothing looks identical to a working
            // one otherwise, which reads as the plugin ignoring it.
            String sourceUrl = item.optString("url", "");
            JSONObject stored = sourceForUrlLocked(CUSTOM_PROVIDER_ID, sourceUrl, false);
            JSONArray storedNodes = stored == null ? null : stored.optJSONArray("nodes");
            customSources.add(new SourceSummary(item.optString("id", ""),
                    item.optString("title", hostTitle(sourceUrl)),
                    storedNodes == null ? 0 : storedNodes.length(),
                    item.optBoolean("hidden", false)));
        }
        viewSnapshot = new ViewSnapshot(providers, selected,
                Collections.unmodifiableList(customSources));
        operationObserver.onSnapshotPublished("full");
    }

    private void publishSelectionSnapshotLocked() {
        ViewSnapshot current = viewSnapshot;
        Map<Integer, String> selected = new HashMap<>();
        JSONObject activeKeys = data.optJSONObject("activeKeys");
        for (int providerId = 0; providerId <= MAX_PROVIDER_ID; providerId++) {
            String selectedKey = activeKeys == null ? ""
                    : activeKeys.optString(String.valueOf(providerId), "");
            selected.put(providerId, containsUiKey(
                    current.uiNodes(providerId), selectedKey) ? selectedKey : "");
        }
        viewSnapshot = new ViewSnapshot(current.providers, selected, current.customSources);
        operationObserver.onSnapshotPublished("selection");
    }

    private static boolean containsUiKey(List<UiNode> values, String key) {
        if (key == null || key.isEmpty() || values == null) return false;
        for (UiNode value : values) if (key.equals(value.key)) return true;
        return false;
    }

    synchronized List<ProtocolParser.Node> nodesByKeys(int providerId, List<String> keys) {
        if (keys == null || keys.isEmpty()) return new ArrayList<>();
        if (keys.size() > MAX_PING_KEYS) {
            throw new IllegalArgumentException("at most " + MAX_PING_KEYS
                    + " node keys are allowed");
        }
        LinkedHashSet<String> requested = new LinkedHashSet<>();
        for (String key : keys) {
            if (key == null || key.isEmpty() || !requested.add(key)) {
                throw new IllegalArgumentException("node keys must be non-empty and unique");
            }
        }
        Map<String, ProtocolParser.Node> available = new LinkedHashMap<>();
        for (ProtocolParser.Node node : nodes(providerId)) available.put(node.normalizedKey, node);
        List<ProtocolParser.Node> result = new ArrayList<>();
        for (String key : requested) {
            ProtocolParser.Node node = available.get(key);
            if (node == null) throw new IllegalArgumentException("node key is not in the current provider");
            result.add(node);
        }
        return result;
    }

    void setProbeResult(String key, String status, long latencyMillis) {
        if (key == null || key.isEmpty()) return;
        pingStatusCache.put(key, status == null || status.isEmpty() ? "failed" : status);
        latencyCache.put(key, latencyMillis >= 0L ? latencyMillis : -1L);
    }

    void markProbePending(List<ProtocolParser.Node> nodes) {
        if (nodes == null) return;
        for (ProtocolParser.Node node : nodes) {
            pingStatusCache.put(node.normalizedKey, "pending");
            latencyCache.remove(node.normalizedKey);
        }
    }

    void cancelPendingProbes(List<ProtocolParser.Node> nodes) {
        if (nodes == null) return;
        for (ProtocolParser.Node node : nodes) {
            if (pingStatusCache.replace(node.normalizedKey, "pending", "cancelled")) {
                latencyCache.put(node.normalizedKey, -1L);
            }
        }
    }

    void cancelPendingProbesNonBlocking() {
        for (Map.Entry<String, String> item : pingStatusCache.entrySet()) {
            if ("pending".equals(item.getValue())
                    && pingStatusCache.replace(item.getKey(), "pending", "cancelled")) {
                latencyCache.put(item.getKey(), -1L);
            }
        }
    }

    void clearProbeResults() {
        clearProbeResultsLocked();
    }

    private void clearProbeResultsLocked() {
        latencyCache.clear();
        pingStatusCache.clear();
    }

    synchronized ProtocolParser.Node selected(int providerId) {
        List<ProtocolParser.Node> values = nodes(providerId);
        if (values.isEmpty()) return null;
        String selectedKey = data.optJSONObject("activeKeys").optString(String.valueOf(boundedProvider(providerId)), "");
        for (ProtocolParser.Node node : values) if (node.normalizedKey.equals(selectedKey)) return node;
        setSelected(providerId, values.get(0));
        return values.get(0);
    }

    synchronized boolean setSelectedKey(int providerId, String key) {
        if (key == null || key.isEmpty()) return false;
        for (ProtocolParser.Node node : nodes(providerId)) {
            if (node.normalizedKey.equals(key)) {
                return setSelected(providerId, node);
            }
        }
        return false;
    }

    synchronized boolean setSelected(int providerId, ProtocolParser.Node node) {
        if (node == null) return false;
        if (persistencePoisoned.get()) return false;
        try {
            data.optJSONObject("activeKeys").put(String.valueOf(boundedProvider(providerId)), node.normalizedKey);
            persist(SnapshotMode.SELECTION);
            return true;
        } catch (Exception error) {
            return false;
        }
    }

    private static String joinNotices(List<String> notices) {
        if (notices == null || notices.isEmpty()) return "";
        StringBuilder output = new StringBuilder();
        for (String notice : notices) {
            if (notice == null || notice.trim().isEmpty()) continue;
            if (output.length() > 0) output.append(' ');
            output.append(notice.trim());
            if (output.length() > 400) break;
        }
        return ErrorSanitizer.clean(output.toString());
    }

    private Map<String, String> requestHeaders(SettingsModel settings) {
        return requestHeaders(settings, SUBSCRIPTION_USER_AGENT);
    }

    private Map<String, String> requestHeaders(SettingsModel settings, String userAgent) {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", userAgent);
        headers.put("X-Device-Locale", I18n.isRussian() ? "ru" : "en");
        headers.put("X-Device-model", safeHeaderValue(deviceModel(), "Android"));
        headers.put("X-Device-OS", "Android");
        headers.put("X-Ver-OS", safeHeaderValue(Build.VERSION.RELEASE, "Android"));
        headers.put("X-HWID", safeHeaderValue(hwid(settings), "unknown"));
        return headers;
    }

    static String safeHeaderValue(String value, String fallback) {
        String source = value == null ? "" : value;
        StringBuilder output = new StringBuilder(Math.min(source.length(), 256));
        int codePoints = 0;
        int utf8Bytes = 0;
        for (int offset = 0; offset < source.length() && codePoints < 256; ) {
            int point = source.codePointAt(offset);
            offset += Character.charCount(point);
            if (Character.isISOControl(point) || point == '\r' || point == '\n') continue;
            int bytes = point <= 0x7f ? 1 : point <= 0x7ff ? 2
                    : point <= 0xffff ? 3 : 4;
            if (utf8Bytes + bytes > 1024) break;
            output.appendCodePoint(point);
            utf8Bytes += bytes;
            codePoints++;
        }
        String result = output.toString().trim();
        return result.isEmpty() ? fallback : result;
    }

    private synchronized String hwid(SettingsModel settings) {
        if (settings != null && !settings.customHwid.isEmpty()) return settings.customHwid;
        JSONObject meta = data.optJSONObject("meta");
        String value = meta.optString("hwid", "");
        if (!value.isEmpty()) return value;
        if (!migratedHwid.isEmpty()) {
            try {
                if (!persistencePoisoned.get()) {
                    meta.put("hwid", migratedHwid);
                    persist(SnapshotMode.NONE);
                }
            } catch (Exception ignored) {
            }
            return migratedHwid;
        }
        byte[] bytes = new byte[8];
        new SecureRandom().nextBytes(bytes);
        StringBuilder output = new StringBuilder(16);
        for (byte item : bytes) output.append(String.format(Locale.US, "%02x", item & 255));
        try {
            if (persistencePoisoned.get()) return output.toString();
            meta.put("hwid", output.toString());
            persist(SnapshotMode.NONE);
        } catch (Exception ignored) {
        }
        return output.toString();
    }

    synchronized String defaultHwid() {
        return hwid(null);
    }

    private static String deviceModel() {
        String manufacturer = Build.MANUFACTURER == null ? "" : Build.MANUFACTURER.trim();
        String model = Build.MODEL == null ? "" : Build.MODEL.trim();
        if (!manufacturer.isEmpty() && model.toLowerCase(Locale.US)
                .startsWith(manufacturer.toLowerCase(Locale.US))) return model;
        return (manufacturer + " " + model).trim();
    }

    private synchronized JSONObject provider(int id) {
        JSONObject providers = data.optJSONObject("providers");
        String key = String.valueOf(boundedProvider(id));
        JSONObject value = providers.optJSONObject(key);
        if (value == null) {
            value = new JSONObject();
            try {
                value.put("sources", new JSONArray());
                providers.put(key, value);
            } catch (Exception ignored) {
            }
        }
        if (value.optJSONArray("sources") == null) {
            try {
                value.put("sources", new JSONArray());
            } catch (Exception ignored) {
            }
        }
        return value;
    }

    private List<String> sourceUrlsLocked(int providerId) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        int bounded = boundedProvider(providerId);
        if (bounded < ProviderCatalog.size()) {
            if (ProviderCatalog.isEnabled(bounded)) {
                urls.add(ProviderCatalog.endpoint(bounded));
            }
            return new ArrayList<>(urls);
        }
        JSONArray custom = data.optJSONArray("customUrls");
        for (int i = 0; custom != null && i < custom.length(); i++) {
            JSONObject item = custom.optJSONObject(i);
            String url = item == null ? "" : item.optString("url", "").trim();
            if (!url.isEmpty() && urls.size() < MAX_CUSTOM_URLS) urls.add(url);
        }
        return new ArrayList<>(urls);
    }

    private JSONObject sourceForUrlLocked(int providerId, String url, boolean create) {
        int bounded = boundedProvider(providerId);
        JSONArray sources = provider(bounded).optJSONArray("sources");
        String storedUrl = sourceStorageKey(bounded, url);
        String id = sourceId(storedUrl);
        for (int i = 0; sources != null && i < sources.length(); i++) {
            JSONObject source = sources.optJSONObject(i);
            if (source != null && (id.equals(source.optString("id", ""))
                    || storedUrl.equals(source.optString("url", "")))) return source;
        }
        if (!create) return null;
        JSONObject result = new JSONObject();
        try {
            result.put("id", id).put("url", storedUrl)
                    .put("title", defaultSourceTitle(bounded, url))
                    .put("updatedAt", 0L).put("nodes", new JSONArray());
            if (bounded < ProviderCatalog.size()) {
                result.put("catalogRevision", ProviderCatalog.revision(bounded));
            }
            sources.put(result);
        } catch (Exception ignored) {
        }
        return result;
    }

    private void pruneSourcesLocked(int providerId, Set<String> validUrls) throws Exception {
        JSONArray sources = provider(providerId).optJSONArray("sources");
        LinkedHashSet<String> storedUrls = new LinkedHashSet<>();
        if (validUrls != null) for (String url : validUrls) {
            storedUrls.add(sourceStorageKey(providerId, url));
        }
        JSONArray next = new JSONArray();
        for (int i = 0; sources != null && i < sources.length(); i++) {
            JSONObject source = sources.optJSONObject(i);
            if (source == null) continue;
            String url = source.optString("url", "");
            if (storedUrls.contains(url)) next.put(source);
        }
        provider(providerId).put("sources", next);
    }

    private int addManualNodesLocked(List<ProtocolParser.Node> parsed) throws Exception {
        JSONArray oldStored = data.optJSONArray("manual");
        LinkedHashMap<String, ProtocolParser.Node> manual = new LinkedHashMap<>();
        collectStored(oldStored, manual);
        int before = manual.size();
        if (parsed != null) for (ProtocolParser.Node node : parsed) {
            if (node == null || manual.containsKey(node.normalizedKey)) continue;
            if (manual.size() >= SubscriptionParser.MAX_SOURCE_NODES) {
                continue;
            }
            manual.put(node.normalizedKey, node);
        }
        data.put("manual", storeNodes(new ArrayList<>(manual.values())));
        try {
            AtomicStore.jsonUtf8Size(data, AtomicStore.MAX_JSON_BYTES);
        } catch (Exception error) {
            data.put("manual", oldStored == null ? new JSONArray() : oldStored);
            throw error;
        }
        return manual.size() - before;
    }

    private boolean addCustomUrlLocked(String value, Set<String> knownUrls) throws Exception {
        String url = value == null ? "" : value.trim();
        if (url.length() > 4096) throw new IllegalArgumentException(I18n.t("URL слишком длинный", "URL is too long"));
        URI parsed = new URI(url);
        String scheme = parsed.getScheme() == null ? "" : parsed.getScheme().toLowerCase(Locale.US);
        if (!("http".equals(scheme) || "https".equals(scheme)) || parsed.getHost() == null) {
            throw new IllegalArgumentException(I18n.t("Некорректный URL подписки", "Invalid subscription URL"));
        }
        if (invalidExplicitPort(parsed)) {
            throw new IllegalArgumentException(I18n.t(
                    "Некорректный порт подписки", "Invalid subscription URL port"));
        }
        Set<String> known = knownUrls == null ? customUrlSetLocked() : knownUrls;
        if (known.contains(url)) return false;
        if (known.size() >= MAX_CUSTOM_URLS) {
            throw new IllegalStateException(I18n.t(
                    "Слишком много URL подписок", "Too many subscription URLs"));
        }
        JSONArray custom = data.optJSONArray("customUrls");
        int addedIndex = custom.length();
        custom.put(new JSONObject().put("id", sourceId(url)).put("url", url).put("title", hostTitle(url)));
        known.add(url);
        try {
            AtomicStore.jsonUtf8Size(data, AtomicStore.MAX_JSON_BYTES);
        } catch (Exception error) {
            custom.remove(addedIndex);
            known.remove(url);
            throw error;
        }
        return true;
    }

    private static boolean invalidExplicitPort(URI value) {
        String authority = value == null ? null : value.getRawAuthority();
        if (authority == null || authority.isEmpty()) return false;
        int userInfo = authority.lastIndexOf('@');
        if (userInfo >= 0) authority = authority.substring(userInfo + 1);
        int separator;
        if (authority.startsWith("[")) {
            int bracket = authority.indexOf(']');
            if (bracket < 0 || bracket + 1 >= authority.length()) return false;
            if (authority.charAt(bracket + 1) != ':') return true;
            separator = bracket + 1;
        } else {
            separator = authority.lastIndexOf(':');
            if (separator < 0) return false;
        }
        String port = authority.substring(separator + 1);
        if (!port.matches("[0-9]+")) return true;
        try {
            long parsed = Long.parseLong(port);
            return parsed < 1L || parsed > 65_535L;
        } catch (NumberFormatException invalid) {
            return true;
        }
    }

    private Set<String> customUrlSetLocked() {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        JSONArray custom = data.optJSONArray("customUrls");
        for (int i = 0; custom != null && i < custom.length(); i++) {
            JSONObject item = custom.optJSONObject(i);
            String url = item == null ? "" : item.optString("url", "").trim();
            if (!url.isEmpty()) result.add(url);
        }
        return result;
    }

    private void updateCustomTitleLocked(String url, String title) throws Exception {
        JSONArray custom = data.optJSONArray("customUrls");
        for (int i = 0; custom != null && i < custom.length(); i++) {
            JSONObject item = custom.optJSONObject(i);
            if (item != null && url.equals(item.optString("url", ""))) {
                item.put("title", title);
                return;
            }
        }
    }

    private String customTitleLocked(String url) {
        JSONArray custom = data.optJSONArray("customUrls");
        for (int i = 0; custom != null && i < custom.length(); i++) {
            JSONObject item = custom.optJSONObject(i);
            if (item != null && url.equals(item.optString("url", ""))) {
                return item.optString("title", hostTitle(url));
            }
        }
        return hostTitle(url);
    }

    private void collectStored(JSONArray source, Map<String, ProtocolParser.Node> output) {
        if (source == null) return;
        for (int i = 0; i < source.length() && output.size() < MAX_TOTAL_NODES; i++) {
            JSONObject item = source.optJSONObject(i);
            if (item == null) continue;
            try {
                ProtocolParser.Node node = ProtocolParser.fromStoredJson(item);
                output.putIfAbsent(node.normalizedKey, node);
            } catch (Exception ignored) {
            }
        }
    }

    private JSONArray storeNodes(List<ProtocolParser.Node> nodes) throws Exception {
        JSONArray output = new JSONArray();
        int serializedBytes = 2; // '[' + ']'
        for (ProtocolParser.Node node : nodes) {
            if (output.length() >= SubscriptionParser.MAX_SOURCE_NODES) break;
            JSONObject stored = node.toStoredJson();
            int itemBytes = AtomicStore.jsonUtf8Size(stored, AtomicStore.MAX_JSON_BYTES);
            long next = (long) serializedBytes + (output.length() == 0 ? 0 : 1) + itemBytes;
            if (next > AtomicStore.MAX_JSON_BYTES) {
                throw new IllegalArgumentException("serialized node source exceeds 8 MiB");
            }
            serializedBytes = (int) next;
            output.put(stored);
        }
        return output;
    }

    private synchronized boolean ensureShape() {
        boolean changed = false;
        try {
            if (data.optJSONArray("manual") == null) {
                data.put("manual", new JSONArray());
                changed = true;
            }
            if (data.optJSONObject("providers") == null) {
                data.put("providers", new JSONObject());
                changed = true;
            }
            if (data.optJSONObject("activeKeys") == null) {
                data.put("activeKeys", new JSONObject());
                changed = true;
            }
            if (data.optJSONObject("meta") == null) {
                data.put("meta", new JSONObject());
                changed = true;
            }

            JSONArray oldCustom = data.optJSONArray("customUrls");
            JSONArray normalizedCustom = new JSONArray();
            LinkedHashSet<String> normalizedUrls = new LinkedHashSet<>();
            if (oldCustom != null) {
                for (int i = 0; i < oldCustom.length(); i++) {
                    JSONObject object = oldCustom.optJSONObject(i);
                    String url = object == null ? oldCustom.optString(i, "") : object.optString("url", "");
                    url = url.trim();
                    if (url.isEmpty()) {
                        changed = true;
                        continue;
                    }
                    if (normalizedCustom.length() >= MAX_CUSTOM_URLS) {
                        changed = true;
                        continue;
                    }
                    if (!normalizedUrls.add(url)) {
                        changed = true;
                        continue;
                    }
                    String id = object == null ? sourceId(url) : object.optString("id", sourceId(url));
                    String title = object == null ? hostTitle(url) : object.optString("title", hostTitle(url));
                    normalizedCustom.put(new JSONObject().put("id", id).put("url", url).put("title", title));
                    if (object == null) changed = true;
                }
            } else {
                changed = true;
            }
            data.put("customUrls", normalizedCustom);

            changed |= migrateProviderLayoutLocked();
            changed |= sanitizeBuiltinSourcesLocked();

            for (int id = 0; id <= MAX_PROVIDER_ID; id++) {
                JSONObject existingProvider = data.optJSONObject("providers")
                        .optJSONObject(String.valueOf(id));
                boolean missingShape = existingProvider == null
                        || existingProvider.optJSONArray("sources") == null;
                JSONObject current = provider(id);
                if (missingShape) changed = true;
                List<String> validUrls = sourceUrlsLocked(id);
                for (String url : validUrls) {
                    if (sourceForUrlLocked(id, url, false) == null) {
                        sourceForUrlLocked(id, url, true);
                        changed = true;
                    }
                }
                int beforePrune = current.optJSONArray("sources").length();
                pruneSourcesLocked(id, new LinkedHashSet<>(validUrls));
                if (current.optJSONArray("sources").length() != beforePrune) changed = true;
            }
        } catch (Exception error) {
        }
        return changed;
    }

    private boolean sanitizeBuiltinSourcesLocked() throws Exception {
        JSONObject providers = data.optJSONObject("providers");
        JSONObject activeKeys = data.optJSONObject("activeKeys");
        boolean changed = false;
        for (int providerId = 0; providerId < ProviderCatalog.size(); providerId++) {
            JSONObject current = providers.optJSONObject(String.valueOf(providerId));
            if (current == null) {
                current = provider(providerId);
                changed = true;
            }
            JSONArray sources = current.optJSONArray("sources");
            if (sources == null) continue;
            String providerKey = String.valueOf(providerId);
            if (!ProviderCatalog.isEnabled(providerId)) {
                if (sources.length() != 0) {
                    current.put("sources", new JSONArray());
                    changed = true;
                }
                if (activeKeys.has(providerKey)) {
                    activeKeys.remove(providerKey);
                    changed = true;
                }
                continue;
            }
            JSONObject retained = null;
            for (int index = 0; index < sources.length(); index++) {
                JSONObject candidate = sources.optJSONObject(index);
                if (candidate != null) {
                    retained = candidate;
                    break;
                }
            }
            JSONArray sanitized = new JSONArray();
            boolean providerChanged = false;
            if (retained != null) {
                String key = ProviderCatalog.storageKey(providerId);
                String id = sourceId(key);
                String title = PROVIDER_NAMES[providerId];
                String revision = ProviderCatalog.revision(providerId);
                boolean catalogChanged = !revision.equals(
                        retained.optString("catalogRevision", ""));
                if (!key.equals(retained.optString("url", ""))
                        || !id.equals(retained.optString("id", ""))
                        || !title.equals(retained.optString("title", ""))
                        || catalogChanged
                        || sources.length() != 1) {
                    providerChanged = true;
                }
                retained.put("id", id).put("url", key).put("title", title)
                        .put("catalogRevision", revision);
                if (catalogChanged) {
                    retained.put("updatedAt", 0L).put("nodes", new JSONArray());
                    if (activeKeys.has(providerKey)) activeKeys.remove(providerKey);
                }
                sanitized.put(retained);
            } else {
                if (sources.length() != 0) providerChanged = true;
                if (activeKeys.has(providerKey)) {
                    activeKeys.remove(providerKey);
                    changed = true;
                }
            }
            if (providerChanged) {
                current.put("sources", sanitized);
                changed = true;
            }
        }
        return changed;
    }

    private static String sourceStorageKey(int providerId, String networkUrl) {
        int bounded = boundedProvider(providerId);
        return bounded < ProviderCatalog.size()
                ? ProviderCatalog.storageKey(bounded) : networkUrl;
    }

    /**
     * Moves stored data whenever the catalog order changes, so a saved
     * subscription keeps belonging to the provider it was added under instead
     * of silently reappearing under whichever provider now owns that index.
     */
    private boolean migrateProviderLayoutLocked() throws Exception {
        JSONObject providers = data.optJSONObject("providers");
        JSONObject activeKeys = data.optJSONObject("activeKeys");
        JSONObject meta = data.optJSONObject("meta");
        int layout = meta.optInt("providerLayout", 0);
        if (layout >= PROVIDER_LAYOUT_VERSION) return false;

        if (layout < 2) {
            // v1 kept Custom at index 3; v2 moved it onto index 2.
            remapProviderSlots(providers, activeKeys,
                    new int[][]{{3, LEGACY_V2_CUSTOM_ID}});
        }
        // v3 leads with Shrimp, puts Elix second, inserts Sworkle third and
        // moves Custom to the slot after it.
        remapProviderSlots(providers, activeKeys,
                new int[][]{{0, 1}, {1, 0},
                        {LEGACY_V2_CUSTOM_ID, CUSTOM_PROVIDER_ID}});
        meta.put("providerLayout", PROVIDER_LAYOUT_VERSION);
        return true;
    }

    private static void remapProviderSlots(JSONObject providers,
                                           JSONObject activeKeys, int[][] moves)
            throws Exception {
        JSONObject movedProviders = new JSONObject();
        JSONObject movedKeys = new JSONObject();
        for (int[] move : moves) {
            String from = String.valueOf(move[0]);
            String to = String.valueOf(move[1]);
            JSONObject provider = providers.optJSONObject(from);
            if (provider != null) movedProviders.put(to, provider);
            String selection = activeKeys.optString(from, "");
            if (!selection.isEmpty()) movedKeys.put(to, selection);
        }
        // Every source slot is cleared before anything lands, so a swap cannot
        // overwrite the half that has not been read yet.
        for (int[] move : moves) {
            providers.remove(String.valueOf(move[0]));
            activeKeys.remove(String.valueOf(move[0]));
            providers.remove(String.valueOf(move[1]));
            activeKeys.remove(String.valueOf(move[1]));
        }
        for (java.util.Iterator<String> keys = movedProviders.keys(); keys.hasNext(); ) {
            String key = keys.next();
            providers.put(key, movedProviders.get(key));
        }
        for (java.util.Iterator<String> keys = movedKeys.keys(); keys.hasNext(); ) {
            String key = keys.next();
            activeKeys.put(key, movedKeys.get(key));
        }
    }

    private void persist() throws Exception {
        persist(SnapshotMode.FULL);
    }

    private void persist(SnapshotMode mode) throws Exception {
        persist(beginOperation(), mode, null);
    }

    private void persist(long operationEpoch) throws Exception {
        persist(operationEpoch, SnapshotMode.FULL, null);
    }

    private synchronized void persist(long operationEpoch, SnapshotMode mode,
                                      AtomicStore.CommitGuard additionalGuard) throws Exception {
        operationObserver.onBeforePersist();
        ensureOperationActive(operationEpoch);
        try {
            SnapshotMode effectiveMode = mode == null ? SnapshotMode.FULL : mode;
            if (effectiveMode == SnapshotMode.FULL) {
                operationObserver.onNodeLimitValidation();
                validateNodeLimitsLocked();
            }
            boolean committed = store.writeJson(STORE_FILE, data, writerLease,
                    () -> operationActive(operationEpoch)
                            && (additionalGuard == null || additionalGuard.canCommit()));
            if (!committed) throw new IllegalStateException("subscription state was not committed");
            if (effectiveMode == SnapshotMode.FULL) publishViewSnapshotLocked();
            else if (effectiveMode == SnapshotMode.SELECTION) publishSelectionSnapshotLocked();
        } catch (AtomicStore.StaleWriteException stale) {
            throw stale;
        } catch (Exception error) {
            if (operationActive(operationEpoch)) {
                if (!Thread.currentThread().isInterrupted()) {
                    try {
                        JSONObject recovered = store.readJsonStrict(STORE_FILE);
                        data = recovered;
                        ensureShape();
                        invalidateAllNodeCachesLocked();
                        clearProbeResultsLocked();
                        publishViewSnapshotLocked();
                    } catch (Exception recoveryError) {
                        // A new interrupt has the same transaction-level
                        // rollback path as an already interrupted writer. A
                        // genuine non-interrupt read/I/O failure is ambiguous:
                        // revoke this manager's writer before any later
                        // mutation can accidentally publish its live object.
                        if (!Thread.currentThread().isInterrupted()) {
                            persistencePoisoned.set(true);
                            writerLease.close();
                        }
                        error.addSuppressed(recoveryError);
                    }
                }
            }
            throw error;
        }
    }

    private long beginOperation() {
        long epoch = lifecycleEpoch.get();
        ensureOperationActive(epoch);
        return epoch;
    }

    private boolean operationActive(long epoch) {
        return !closed.get() && !persistencePoisoned.get()
                && lifecycleEpoch.get() == epoch && writerLease.isActive();
    }

    private void ensureWritable() {
        if (persistencePoisoned.get()) {
            throw new IllegalStateException("subscription persistence requires reload");
        }
    }

    private void ensureOperationActive(long epoch) {
        if (!operationActive(epoch)) {
            throw new IllegalStateException("subscription manager is closed or superseded");
        }
    }

    private void validateNodeLimitsLocked() throws Exception {
        int aggregate = 0;
        for (int providerId = 0; providerId <= MAX_PROVIDER_ID; providerId++) {
            LinkedHashSet<String> keys = new LinkedHashSet<>();
            JSONArray sources = provider(providerId).optJSONArray("sources");
            for (int i = 0; sources != null && i < sources.length(); i++) {
                JSONObject source = sources.optJSONObject(i);
                JSONArray nodes = source == null ? null : source.optJSONArray("nodes");
                addStoredKeys(nodes, keys, true);
            }
            if (providerId == CUSTOM_PROVIDER_ID) {
                addStoredKeys(data.optJSONArray("manual"), keys, true);
            }
            if (keys.size() > MAX_TOTAL_NODES) {
                throw new IllegalStateException("provider node set exceeds 10000 nodes");
            }
            aggregate += keys.size();
            if (aggregate > MAX_TOTAL_NODES) {
                throw new IllegalStateException("aggregate node set exceeds 10000 nodes");
            }
        }
    }

    /**
     * Bounds a previously persisted store before its compact all-provider UI
     * snapshot is published.  Nodes duplicated across sources of one provider
     * are represented once in that snapshot, so the same per-provider
     * deduplication defines the aggregate limit.  A node present in two
     * providers counts twice because it creates two stored/UI entries.
     */
    private boolean boundLoadedNodesLocked() throws Exception {
        boolean changed = false;
        int aggregate = 0;
        for (int providerId = 0; providerId <= MAX_PROVIDER_ID; providerId++) {
            LinkedHashSet<String> providerKeys = new LinkedHashSet<>();
            JSONArray sources = provider(providerId).optJSONArray("sources");
            for (int sourceIndex = 0; sources != null && sourceIndex < sources.length(); sourceIndex++) {
                JSONObject source = sources.optJSONObject(sourceIndex);
                if (source == null) continue;
                JSONArray original = source.optJSONArray("nodes");
                JSONArray bounded = new JSONArray();
                for (int nodeIndex = 0; original != null && nodeIndex < original.length(); nodeIndex++) {
                    JSONObject stored = original.optJSONObject(nodeIndex);
                    if (stored == null) {
                        changed = true;
                        continue;
                    }
                    String key;
                    try {
                        key = ProtocolParser.fromStoredJson(stored).normalizedKey;
                    } catch (Exception invalid) {
                        changed = true;
                        continue;
                    }
                    if (providerKeys.contains(key)) {
                        changed = true;
                        continue;
                    }
                    if (bounded.length() >= SubscriptionParser.MAX_SOURCE_NODES
                            || aggregate >= MAX_TOTAL_NODES) {
                        changed = true;
                        continue;
                    }
                    providerKeys.add(key);
                    aggregate++;
                    bounded.put(stored);
                }
                if (original == null || bounded.length() != original.length()) {
                    source.put("nodes", bounded);
                    changed = true;
                }
            }
            if (providerId == CUSTOM_PROVIDER_ID) {
                JSONArray original = data.optJSONArray("manual");
                JSONArray bounded = new JSONArray();
                for (int nodeIndex = 0; original != null && nodeIndex < original.length(); nodeIndex++) {
                    JSONObject stored = original.optJSONObject(nodeIndex);
                    if (stored == null) {
                        changed = true;
                        continue;
                    }
                    String key;
                    try {
                        key = ProtocolParser.fromStoredJson(stored).normalizedKey;
                    } catch (Exception invalid) {
                        changed = true;
                        continue;
                    }
                    if (providerKeys.contains(key)) {
                        changed = true;
                        continue;
                    }
                    if (bounded.length() >= SubscriptionParser.MAX_SOURCE_NODES
                            || aggregate >= MAX_TOTAL_NODES) {
                        changed = true;
                        continue;
                    }
                    providerKeys.add(key);
                    aggregate++;
                    bounded.put(stored);
                }
                if (original == null || bounded.length() != original.length()) {
                    data.put("manual", bounded);
                    changed = true;
                }
            }
        }
        return changed;
    }

    private static void addStoredKeys(JSONArray source, Set<String> output, boolean sourceLimit)
            throws Exception {
        if (source == null) return;
        if (sourceLimit && source.length() > SubscriptionParser.MAX_SOURCE_NODES) {
            throw new IllegalStateException("source exceeds 5000 nodes");
        }
        for (int i = 0; i < source.length(); i++) {
            JSONObject item = source.optJSONObject(i);
            if (item == null) continue;
            try {
                output.add(ProtocolParser.fromStoredJson(item).normalizedKey);
            } catch (Exception ignored) {
            }
            if (output.size() > MAX_TOTAL_NODES) return;
        }
    }

    @Override
    public void close() {
        // Close is an O(1) revocation: it never waits for the manager monitor,
        // parser, fsync, or another AtomicStore instance. Staged writes perform
        // the same epoch/lease check immediately before their atomic move.
        if (closed.compareAndSet(false, true)) {
            cancelPendingOnClose = true;
            lifecycleEpoch.incrementAndGet();
            writerLease.close();
        }
    }

    static String responseTitle(LimitedHttpClient.Response response, String url) {
        String title = cleanTitle(boundedHeader(response.header("profile-title")));
        if (title.isEmpty()) {
            String disposition = boundedHeader(response.header("content-disposition"));
            Matcher matcher = FILE_NAME.matcher(disposition == null ? "" : disposition);
            if (matcher.find()) title = cleanTitle(matcher.group(1));
        }
        if (title.isEmpty()) {
            title = hostTitle(boundedHeader(response.header("profile-web-page-url")));
        }
        if (title.isEmpty()) title = hostTitle(url);
        return title;
    }

    private static String boundedHeader(String value) {
        return value == null || value.length() > MAX_PROFILE_HEADER_CHARS ? "" : value;
    }

    private static String decodeBase64Title(String encoded) {
        if (encoded.isEmpty()) return "";
        for (Base64.Decoder decoder
                : new Base64.Decoder[]{Base64.getDecoder(), Base64.getUrlDecoder()}) {
            try {
                return SubscriptionParser.decodeStrictUtf8(decoder.decode(encoded));
            } catch (Exception ignored) {
            }
        }
        return "";
    }

    private static String cleanTitle(String value) {
        String result = value == null ? "" : value.trim();
        if (result.length() > MAX_PROFILE_HEADER_CHARS) return "";
        if (result.isEmpty()) return "";
        // The base64 prefix is examined before any URL decoding: standard
        // base64 uses '+', which percent-decoding turns into a space and so
        // destroys the payload before it can be read.
        if (result.toLowerCase(Locale.US).startsWith("base64:")) {
            String encoded = result.substring(7).trim();
            String decoded = decodeBase64Title(encoded);
            if (decoded.isEmpty()) {
                // A source may percent-encode the payload as well.
                try {
                    decoded = decodeBase64Title(
                            URLDecoder.decode(encoded, "UTF-8").trim());
                } catch (Exception ignored) {
                }
            }
            if (!decoded.isEmpty()) result = decoded;
        } else {
            try {
                result = URLDecoder.decode(result, "UTF-8");
            } catch (Exception ignored) {
            }
        }
        result = result.replace('\r', ' ').replace('\n', ' ').trim();
        int points = result.codePointCount(0, result.length());
        if (points > 120) result = result.substring(
                0, result.offsetByCodePoints(0, 120));
        return result;
    }

    private static String defaultSourceTitle(int providerId, String url) {
        return providerId >= 0 && providerId < PROVIDER_NAMES.length
                ? PROVIDER_NAMES[providerId] : hostTitle(url);
    }

    private static String hostTitle(String url) {
        try {
            URI parsed = new URI(url == null ? "" : url.trim());
            String host = parsed.getHost();
            return host == null ? "" : host;
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String sourceId(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            StringBuilder output = new StringBuilder(24);
            for (int i = 0; i < 12; i++) output.append(String.format(Locale.US, "%02x", digest[i] & 255));
            return output.toString();
        } catch (Exception ignored) {
            return Integer.toHexString(value == null ? 0 : value.hashCode());
        }
    }

    private static List<String> explicitSubscriptionUrls(String value,
                                                         Set<String> existing) {
        List<String> result = new ArrayList<>();
        LinkedHashSet<String> observed = new LinkedHashSet<>();
        if (existing != null) observed.addAll(existing);
        String source = value == null ? "" : value;
        int start = 0;
        int scanned = 0;
        while (start <= source.length()) {
            int end = source.indexOf('\n', start);
            if (end < 0) end = source.length();
            int contentEnd = end > start && source.charAt(end - 1) == '\r' ? end - 1 : end;
            int length = contentEnd - start;
            if (length <= 4096) {
                String candidate = explicitUrlLine(source.substring(start, contentEnd));
                String lower = candidate.toLowerCase(Locale.US);
                if (!candidate.isEmpty() && HTTP_URL.matcher(candidate).matches()
                        && !lower.startsWith("https://hvpn.io/")
                        && !lower.startsWith("https://hitray.io/")
                        && !observed.contains(candidate)) {
                    if (observed.size() >= MAX_CUSTOM_URLS) {
                        // Ignore entries beyond the bounded custom URL set.
                    } else {
                        observed.add(candidate);
                        result.add(candidate);
                    }
                }
            }
            if (end == source.length()) break;
            start = end + 1;
            if ((++scanned & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                throw new IllegalStateException("subscription import interrupted");
            }
        }
        return result;
    }

    private static String explicitUrlLine(String value) {
        String line = value == null ? "" : value.trim();
        if (line.isEmpty()) return "";
        // A whole URL line is exact data: trailing '.', ';', ')' and similar
        // characters may be a functional path/query component.
        if (HTTP_URL.matcher(line).matches()) return line;
        if (line.length() < 3) return "";
        char open = line.charAt(0);
        char close;
        switch (open) {
            case '(':
                close = ')';
                break;
            case '[':
                close = ']';
                break;
            case '{':
                close = '}';
                break;
            case '<':
                close = '>';
                break;
            case '"':
            case '\'':
                close = open;
                break;
            default:
                return "";
        }
        int closing = line.lastIndexOf(close);
        if (closing <= 1) return "";
        if (!SubscriptionParser.balancedOuterWrapper(line, 0, closing)) return "";
        String suffix = line.substring(closing + 1).trim();
        for (int index = 0; index < suffix.length(); index++) {
            if (".,;:".indexOf(suffix.charAt(index)) < 0) return "";
        }
        String inner = line.substring(1, closing).trim();
        return HTTP_URL.matcher(inner).matches() ? inner : "";
    }

    private static int boundedProvider(int id) {
        return Math.max(0, Math.min(id, MAX_PROVIDER_ID));
    }

    static final class ImportResult {
        final int nodes;
        final int urls;

        ImportResult(int nodes, int urls) {
            this.nodes = nodes;
            this.urls = urls;
        }
    }

    interface OperationObserver {
        OperationObserver NO_OP = new OperationObserver() { };

        default void onImportParseStarted() {
        }

        default void onBeforePersist() {
        }

        default void onSnapshotPublished(String kind) {
        }

        default void onNodeLimitValidation() {
        }
    }

    interface RefreshCancellation {
        RefreshCancellation NO_OP = () -> false;

        boolean cancelled();
    }

    private enum SnapshotMode {
        FULL,
        SELECTION,
        NONE
    }

    private static final class ViewSnapshot {
        final Map<Integer, List<UiNode>> providers;
        final Map<Integer, String> selected;
        final List<SourceSummary> customSources;

        ViewSnapshot(Map<Integer, List<UiNode>> providers,
                     Map<Integer, String> selected,
                     List<SourceSummary> customSources) {
            this.providers = Collections.unmodifiableMap(new HashMap<>(providers));
            this.selected = Collections.unmodifiableMap(new HashMap<>(selected));
            this.customSources = customSources;
        }

        static ViewSnapshot empty() {
            Map<Integer, List<UiNode>> providers = new HashMap<>();
            Map<Integer, String> selected = new HashMap<>();
            for (int providerId = 0; providerId <= MAX_PROVIDER_ID; providerId++) {
                providers.put(providerId, Collections.emptyList());
                selected.put(providerId, "");
            }
            return new ViewSnapshot(providers, selected, Collections.emptyList());
        }

        List<UiNode> uiNodes(int providerId) {
            List<UiNode> values = providers.get(providerId);
            return values == null ? Collections.emptyList() : values;
        }

        String selectedKey(int providerId) {
            String value = selected.get(providerId);
            return value == null ? "" : value;
        }
    }

    private static final class SourceSummary {
        final String id;
        final String title;
        final int nodeCount;
        final boolean hidden;

        SourceSummary(String id, String title, int nodeCount, boolean hidden) {
            this.id = id == null ? "" : id;
            this.title = title == null ? "" : title;
            this.nodeCount = Math.max(0, nodeCount);
            this.hidden = hidden;
        }
    }

    private static final class FetchResult {
        final List<ProtocolParser.Node> nodes;
        final String title;

        FetchResult(List<ProtocolParser.Node> nodes, String title) {
            this.nodes = nodes;
            this.title = title;
        }
    }

    private static final class UiNode {
        final String key;
        final String name;
        final String group;
        final boolean manual;
        final String protocol;
        final String transport;
        final String security;
        final String searchText;

        UiNode(String key, String name, String group, boolean manual,
               String protocol, String transport, String security) {
            this.key = key == null ? "" : key;
            this.name = name == null ? "" : name;
            this.group = group == null ? "" : group;
            this.manual = manual;
            this.protocol = protocol == null ? "" : protocol;
            this.transport = transport == null ? "" : transport;
            this.security = security == null ? "" : security;
            this.searchText = (this.name + "\n" + this.group)
                    .toLowerCase(Locale.ROOT);
        }

        JSONObject toJson(long latency, String pingStatus) {
            JSONObject value = new JSONObject();
            try {
                value.put("key", key);
                value.put("name", name);
                value.put("group", group);
                value.put("manual", manual);
                value.put("protocol", protocol);
                value.put("transport", transport);
                value.put("security", security);
                value.put("latency", latency);
                value.put("pingStatus", pingStatus == null ? "idle" : pingStatus);
            } catch (Exception ignored) {
            }
            return value;
        }
    }

    private static String protocolLabel(ProtocolParser.Node node) {
        return node == null ? "" : node.outbound.optString("type", "")
                .trim().toLowerCase(Locale.ROOT);
    }

    private static String transportLabel(ProtocolParser.Node node) {
        if (node == null) return "";
        JSONObject transport = node.outbound.optJSONObject("transport");
        if (transport == null) {
            String protocol = protocolLabel(node);
            return "hysteria".equals(protocol) || "hysteria2".equals(protocol)
                    || "tuic".equals(protocol) ? "quic" : "tcp";
        }
        String value = transport.optString("type", "tcp")
                .trim().toLowerCase(Locale.ROOT);
        return value.isEmpty() || "raw".equals(value) ? "tcp" : value;
    }

    private static String securityLabel(ProtocolParser.Node node) {
        if (node == null) return "";
        JSONObject tls = node.outbound.optJSONObject("tls");
        if (tls != null) {
            if (tls.optJSONObject("reality") != null) return "reality";
            return "tls";
        }
        String value = node.outbound.optString("security", "")
                .trim().toLowerCase(Locale.ROOT);
        if (!value.isEmpty() && !"none".equals(value) && !"auto".equals(value)) {
            return value;
        }
        return "";
    }

}
