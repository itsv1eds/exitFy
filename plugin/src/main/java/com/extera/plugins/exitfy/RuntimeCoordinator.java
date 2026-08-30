package com.extera.plugins.exitfy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;

import com.exteragram.messenger.plugins.PluginsController;

import org.json.JSONObject;
import org.json.JSONArray;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.NotificationCenter;

import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

final class RuntimeCoordinator implements NotificationCenter.NotificationCenterDelegate {
    static final int MAX_COMMAND_TOKEN_UTF8_BYTES = LimitedHttpClient.MAX_EXPANDED_BYTES;
    private static final int CORE_MASK_SING_BOX = 1;
    private static final int CORE_MASK_XRAY = 1 << 1;
    private static final int CORE_MASK_ALL = CORE_MASK_SING_BOX | CORE_MASK_XRAY;
    // JSON escaping can double an otherwise valid import made entirely of
    // quotes, backslashes or line separators. Keep the decoded token boundary
    // at 8 MiB, but give the internal Python -> DEX envelope bounded room for
    // that representation plus its small command wrapper.
    static final int MAX_COMMAND_JSON_UTF8_BYTES = MAX_COMMAND_TOKEN_UTF8_BYTES * 2 + 1024;

    private final String pluginId;
    private final DirectSettingsHook directSettingsHook = new DirectSettingsHook();
    private final LimitedHttpClient subscriptionHttp = new LimitedHttpClient();
    private final LimitedHttpClient coreHttp = new LimitedHttpClient();
    private final SubscriptionManager subscriptions;
    private final CoreUpdater singBoxUpdater;
    private final CoreUpdater xrayUpdater;
    private final NativeCoreRuntime nativeCore;
    private final ProxySession proxySession;
    private final ConnectionStateMachine stateMachine = new ConnectionStateMachine();
    private final ScheduledThreadPoolExecutor coordinator;
    private final ThreadPoolExecutor coreExecutor;
    private final ExecutorService subscriptionExecutor;
    private final ScheduledThreadPoolExecutor subscriptionDeadlineExecutor;
    private final ThreadPoolExecutor importExecutor;
    private final ScheduledThreadPoolExecutor pingExecutor;
    private final ThreadPoolExecutor pingWorkers;
    private final ThreadPoolExecutor dnsExecutor;
    private final SocksHttpProbe socksProbe = new SocksHttpProbe();
    private final Object lifecycleLock = new Object();
    private final Object pingControl = new Object();
    private final Object settingsRequestLock = new Object();
    private final Object dashboardRefreshLock = new Object();
    private final Object subscriptionRefreshControl = new Object();
    private final Object corePreparationLock = new Object();
    private final AtomicLong generation = new AtomicLong();
    private final AtomicLong settingsRevision = new AtomicLong();
    private final RuntimeRevisionGate revisionGate = new RuntimeRevisionGate(generation, settingsRevision);
    private final AppliedSettingsGate appliedSettings = new AppliedSettingsGate();
    private final KeyedRevisionGate settingPersistenceRevisions = new KeyedRevisionGate();
    private final ReconnectBackoff reconnectBackoff = new ReconnectBackoff();
    private final CoreInstallBackoff coreInstallBackoff = new CoreInstallBackoff();
    private final CoreInstallBackoff singBoxRepairBackoff = new CoreInstallBackoff();
    private final CoreInstallBackoff xrayRepairBackoff = new CoreInstallBackoff();
    private final CorePreparationGate corePreparations = new CorePreparationGate();
    private final CoreInstallSession coreInstallSession = new CoreInstallSession();
    private final ManualRefreshIntentGate manualRefreshIntent = new ManualRefreshIntentGate();
    private final AtomicLong pingGeneration = new AtomicLong();
    private final AtomicLong activeProxyPingTasks = new AtomicLong();
    private final AtomicBoolean coreOperationRunning = new AtomicBoolean();
    private final AtomicInteger verifiedCoreReadinessMask = new AtomicInteger();
    private final AtomicLong settingsProbeRestoreGeneration = new AtomicLong();
    private final ReconnectRequestGate reconnectRequests = new ReconnectRequestGate();
    private final ImportRequestGate importRequests = new ImportRequestGate();
    private final RefreshCompletionGate subscriptionRefreshes = new RefreshCompletionGate();
    private final ConnectivityManager connectivity;
    private final ConnectivityManager.NetworkCallback networkCallback;

    private volatile SettingsModel settings = SettingsModel.defaults();
    private volatile SettingsModel requestedSettings = SettingsModel.defaults();
    private volatile boolean loaded;
    private volatile ProtocolParser.Node activeNode;
    private volatile String connectionIssue = "";
    private volatile int localPort;
    private volatile long reconnectAt;
    private volatile ScheduledFuture<?> reconnectFuture;
    private volatile CoreFamily requiredCore;
    private volatile boolean restartRequired;
    private volatile boolean coreSelectionBlocked;
    private volatile ScheduledFuture<?> corePreparationRetry;
    private final AtomicBoolean corePreparationInFlight = new AtomicBoolean();
    // Guarded by corePreparationLock.
    private int coreMaintenancePendingMask;
    private int coreOperationCoverageMask;
    private ScheduledFuture<?> singBoxRepairRetry;
    private ScheduledFuture<?> xrayRepairRetry;
    private long singBoxRepairGeneration;
    private long xrayRepairGeneration;
    private volatile Future<?> pingFuture;
    private volatile SocksHttpProbe.Session pingSocksSession;
    private volatile Future<?> pingRestoreFuture;
    private volatile Future<?> settingsProbeRestoreFuture;
    // Guarded by pingControl.
    private long pingRestoreSequence;
    private volatile Future<?> subscriptionRefreshFuture;
    private volatile Future<?> importFuture;
    private volatile boolean importRunning;
    private volatile boolean initialCoreInspectionComplete;
    private volatile ScheduledFuture<?> subscriptionRefreshTimeout;
    private volatile RefreshCompletionGate.Ticket subscriptionRefreshTicket;
    // Guarded by subscriptionRefreshControl.
    private RefreshCompletionGate.Ticket manualSubscriptionRefreshTicket;
    private long manualSubscriptionRefreshAttempt;
    private volatile PingKind pingKind = PingKind.NONE;
    private volatile String pingState = "idle";
    private volatile String pingType = SettingsModel.PING_TCP;
    private volatile int pingTotal;
    private volatile int pingCompleted;
    private volatile List<ProtocolParser.Node> pingNodes = new ArrayList<>();
    private volatile boolean probePausing;
    private volatile ProxySession.StateGuard probeResumeGuard;
    private volatile boolean settingsProbeRestorePending;
    // Guarded by dashboardRefreshLock so frequent ping callbacks cannot flood
    // the UI thread with fragment refreshes.
    private ScheduledFuture<?> dashboardRefreshFuture;
    private long lastDashboardRefreshNanos;

    static RuntimeCoordinator create(BootstrapConfig bootstrap) throws Exception {
        Context context = ApplicationLoader.applicationContext;
        if (context == null) throw new IllegalStateException("application context is unavailable");
        File root = new File(bootstrap.dataDir, "runtime-v5");
        return new RuntimeCoordinator(bootstrap, new AtomicStore(root));
    }

    private RuntimeCoordinator(BootstrapConfig bootstrap, AtomicStore store) throws Exception {
        this.pluginId = bootstrap.pluginId;
        this.subscriptions = new SubscriptionManager(store, subscriptionHttp);
        this.subscriptions.adoptMigratedHwid(bootstrap.migratedHwid);
        this.singBoxUpdater = new CoreUpdater(
                store, coreHttp, bootstrap.nativeAbi, CoreFamily.SING_BOX);
        this.xrayUpdater = new CoreUpdater(
                store, coreHttp, bootstrap.nativeAbi, CoreFamily.XRAY);
        this.nativeCore = new NativeCoreRuntime(singBoxUpdater, xrayUpdater);
        this.proxySession = new ProxySession(store);
        this.coordinator = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "exitfy-coordinator");
            thread.setDaemon(true);
            return thread;
        });
        coordinator.setRemoveOnCancelPolicy(true);
        this.coreExecutor = RuntimeExecutors.bounded(1, 1, "exitfy-core-update");
        ScheduledThreadPoolExecutor refreshExecutor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "exitfy-subscriptions");
            thread.setDaemon(true);
            return thread;
        });
        refreshExecutor.setRemoveOnCancelPolicy(true);
        this.subscriptionExecutor = refreshExecutor;
        this.subscriptionDeadlineExecutor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "exitfy-subscription-deadline");
            thread.setDaemon(true);
            return thread;
        });
        subscriptionDeadlineExecutor.setRemoveOnCancelPolicy(true);
        subscriptionDeadlineExecutor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.importExecutor = RuntimeExecutors.bounded(1, 1, "exitfy-import");
        this.pingExecutor = RuntimeExecutors.replacing("exitfy-ping");
        this.pingWorkers = RuntimeExecutors.bounded(4, 64, "exitfy-ping-worker");
        this.dnsExecutor = RuntimeExecutors.bounded(4, 8, "exitfy-dns-worker");
        connectivity = (ConnectivityManager) ApplicationLoader.applicationContext
                .getSystemService(Context.CONNECTIVITY_SERVICE);
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                if (!safeExecute(() -> {
                    resetCorePreparationBackoff();
                    resetCoreRepairBackoff();
                    requestReconnect("network_available");
                })) {
                    requestReconnect("network_available");
                }
            }

            @Override
            public void onLost(Network network) {
                requestReconnect("network_lost");
            }
        };
    }

    void load() {
        if (loaded) return;
        loaded = true;
        directSettingsHook.install();
        try {
            if (connectivity != null) connectivity.registerDefaultNetworkCallback(networkCallback);
        } catch (Throwable error) {
        }
        try {
            AndroidUtilities.runOnUIThread(() -> {
                if (loaded) NotificationCenter.getGlobalInstance().addObserver(
                        this, NotificationCenter.proxySettingsChanged);
            });
        } catch (Throwable error) {
        }
        safeExecute(() -> {
            proxySession.recoverIfNeeded();
            subscriptions.warmCache();
            invalidateSettings();
        });
        requestInitialCoreInspection();
        safeScheduleWithFixedDelay(this::scheduledCoreCheck,
                24L * 60L * 60L, 24L * 60L * 60L, TimeUnit.SECONDS);
        safeScheduleWithFixedDelay(this::healthTick, 60, 60, TimeUnit.SECONDS);
        safeScheduleWithFixedDelay(this::runScheduledLatencyCheck, 300, 300, TimeUnit.SECONDS);
    }

    void updateSettings(String json) {
        SettingsModel parsed = SettingsModel.fromJson(json);
        SettingsModel next = normalizeProviderSettings(parsed);
        boolean providerCorrected = parsed.providerId != next.providerId;
        boolean enabledCorrected = parsed.enabled != next.enabled;
        SettingsUpdate update;
        synchronized (settingsRequestLock) {
            update = requestSettingsLocked(next);
        }
        finishSettingsUpdate(update);
        if (update.unchanged) {
            if (providerCorrected) {
                persistPluginSetting("provider_id", next.providerId, update.revision);
            }
            if (enabledCorrected) {
                persistPluginSetting("enabled", next.enabled, update.revision);
            }
            return;
        }
        if (providerCorrected) {
            persistPluginSetting("provider_id", next.providerId, update.revision);
        }
        if (enabledCorrected) {
            persistPluginSetting("enabled", next.enabled, update.revision);
        }
    }

    private SettingsModel normalizeProviderSettings(SettingsModel value) {
        boolean[] available = new boolean[ProviderCatalog.size()];
        for (int provider = 0; provider < available.length; provider++) {
            available[provider] = ProviderCatalog.isEnabled(provider);
        }
        ProviderSelectionDecision decision = RuntimePolicy.normalizeProviderSelection(
                value.providerId, available, subscriptions.hasCustomConfiguration(), value.enabled);
        boolean enabled = value.enabled && !decision.disable;
        if (decision.providerId == value.providerId && enabled == value.enabled) return value;
        // Carry every field: rebuilding with the short constructor silently
        // reset the settings this method does not name.
        return new SettingsModel(enabled, decision.providerId, value.customHwid,
                value.schemaVersion, value.pingType, value.dualCore, value.failover);
    }

    private String setSettingFromUi(String key, Object rawValue) {
        SettingsModel requested;
        SettingsModel normalized;
        SettingsUpdate update;
        synchronized (settingsRequestLock) {
            // Derive and publish the replacement under one lock. Previously a
            // host settings callback could replace requestedSettings between
            // this read and updateSettings(), causing one dashboard click to
            // restore stale values for every other setting. Capturing the
            // revision here also prevents a late persistence callback from
            // being authorized by an unrelated newer settings request.
            requested = requestedSettings.withSetting(key, rawValue);
            normalized = normalizeProviderSettings(requested);
            update = requestSettingsLocked(normalized);
        }
        finishSettingsUpdate(update);
        persistPluginSetting(key, normalized.settingValue(key), update.revision);
        if (requested.providerId != normalized.providerId && !"provider_id".equals(key)) {
            persistPluginSetting("provider_id", normalized.providerId, update.revision);
        }
        if (requested.enabled != normalized.enabled && !"enabled".equals(key)) {
            persistPluginSetting("enabled", normalized.enabled, update.revision);
        }
        return response(true, I18n.t(
                "Настройка применена", "Setting applied"), "").toString();
    }

    /** settingsRequestLock must be held by the caller. */
    private SettingsUpdate requestSettingsLocked(SettingsModel next) {
        if (sameSettings(requestedSettings, next)) {
            return new SettingsUpdate(next, revisionGate.settingsRevision(), false, true);
        }
        SettingsModel previousRequested = requestedSettings;
        boolean connectionSettingsChanged;
        long requestedRevision;
        synchronized (subscriptionRefreshControl) {
            connectionSettingsChanged = RuntimePolicy.connectionSettingsChanged(settings, next);
            requestedRevision = revisionGate.requestSettingsChange();
            recordChangedSettingRevisions(previousRequested, next, requestedRevision);
            requestedSettings = next;
            if (!next.enabled) manualRefreshIntent.clear();
            cancelSubscriptionRefreshLocked();
        }
        return new SettingsUpdate(next, requestedRevision,
                connectionSettingsChanged, false);
    }

    private void recordChangedSettingRevisions(SettingsModel previous, SettingsModel next,
                                               long revision) {
        if (previous.enabled != next.enabled) {
            settingPersistenceRevisions.record("enabled", revision);
        }
        if (previous.providerId != next.providerId) {
            settingPersistenceRevisions.record("provider_id", revision);
        }
        if (!previous.customHwid.equals(next.customHwid)) {
            settingPersistenceRevisions.record("custom_hwid", revision);
        }
        if (!previous.pingType.equals(next.pingType)) {
            settingPersistenceRevisions.record("ping_type", revision);
        }
        if (previous.dualCore != next.dualCore) {
            settingPersistenceRevisions.record("dual_core", revision);
        }
        if (previous.failover != next.failover) {
            settingPersistenceRevisions.record("failover", revision);
        }
        if (previous.refreshOnOpen != next.refreshOnOpen) {
            settingPersistenceRevisions.record("refresh_on_open", revision);
        }
        if (previous.autoCheckMinutes != next.autoCheckMinutes) {
            settingPersistenceRevisions.record("auto_check_minutes", revision);
        }
        if (previous.callsViaProxy != next.callsViaProxy) {
            settingPersistenceRevisions.record("calls_via_proxy", revision);
        }
    }

    private void finishSettingsUpdate(SettingsUpdate update) {
        if (update == null || update.unchanged) return;
        // Revoke a pending install before the serialized apply can be delayed
        // behind reconnect or native work. A due retry must observe an empty
        // gate as soon as disable/provider replacement is accepted.
        if (update.connectionSettingsChanged) cancelCorePreparation(true);
        boolean proxyRestoreContext = cancelPing(false);
        if (!update.connectionSettingsChanged && proxyRestoreContext) {
            scheduleSettingsProbeRestore(update.revision);
        }
        safeExecute(() -> applySettings(update.settings, update.revision));
    }

    private void applySettings(SettingsModel next, long requestedRevision) {
        if (!loaded || !revisionGate.settingsRequestIsCurrent(requestedRevision)) return;
        // A manual refresh command may already be queued ahead of this apply.
        // It can start after updateSettings()' eager cancellation while still
        // carrying the old provider/HWID, so revoke again at the ordering boundary.
        cancelSubscriptionRefresh();
        SettingsModel previous = settings;
        settings = next;
        // Mapping the second core is irreversible for the process, so the
        // experiment only ever turns on here; turning it back off takes effect
        // after exteraGram restarts.
        NativeCoreRuntime.setDualCoreEnabled(next.dualCore);
        appliedSettings.markApplied(requestedRevision);
        if (previous.providerId != next.providerId) {
            restartRequired = false;
            coreSelectionBlocked = false;
            cancelCorePreparation(true);
            resetCoreRepairBackoff();
        }
        boolean lifecycleChange = RuntimePolicy.settingsNeedLifecycleReconcile(
                previous, next, stateMachine.get(), settingsProbeRestorePending);
        if (!lifecycleChange) {
            invalidateSettings();
            schedulePendingManualRefresh();
            return;
        }
        RuntimeOperationToken operation = revisionGate.token(
                revisionGate.advanceLifecycle(), requestedRevision);
        cancelReconnect();
        if (!next.enabled) {
            cancelCorePreparation(true);
            stopInternal();
        } else {
            stopInternal();
            startInternal(operation);
        }
        invalidateSettings();
        schedulePendingManualRefresh();
    }

    String execute(String commandJson) {
        try {
            JSONObject request = JsonGuard.object(commandJson == null ? "{}" : commandJson,
                    MAX_COMMAND_TOKEN_UTF8_BYTES, MAX_COMMAND_JSON_UTF8_BYTES);
            String command = request.optString("command", "");
            if (mutatesNodeSelection(command)) cancelPing(true);
            if ("call_relay_map".equals(command)) {
                CallRelay relay = callRelay;
                if (relay == null || !settings.callsViaProxy
                        || stateMachine.get() != RuntimeState.RUNNING) {
                    return response(false, I18n.t(
                            "Звонки через exitFy недоступны без подключения",
                            "Calls through exitFy need an active connection"), "").toString();
                }
                int mapped = relay.mapEndpoint(
                        request.optString("ip", ""), request.optInt("port", 0));
                return response(true, "", new JSONObject()
                        .put("port", mapped).toString()).toString();
            }
            if ("core_versions".equals(command)) {
                // Kept off the dashboard on purpose: which engine runs is not
                // something the main screen asks anyone to think about. People
                // who want the number open the advanced screen.
                return response(true, "", new JSONObject()
                        .put("xray", CoreVersionLabel.describe(
                                nativeCore.coreVersion(CoreFamily.XRAY)))
                        .put("singBox", CoreVersionLabel.describe(
                                nativeCore.coreVersion(CoreFamily.SING_BOX)))
                        .toString()).toString();
            }
            if ("provider_referral".equals(command)) {
                String referral = subscriptions.referral(settings.providerId);
                return referral.isEmpty()
                        ? response(false, I18n.t("Для пользовательского источника нет реферальной ссылки",
                        "The custom source has no referral link"), "").toString()
                        : response(true, "", referral).toString();
            }
            if ("set_setting".equals(command)) {
                String key = request.optString("key", "");
                if (!request.has("value") || request.isNull("value")) {
                    throw new IllegalArgumentException(I18n.t(
                            "Не указано значение настройки", "Missing setting value"));
                }
                Object value = request.get("value");
                return executeSerialized(() -> setSettingFromUi(key, value));
            }
            if ("install_cores".equals(command)) {
                if (!loaded) return runtimeStoppingResponse();
                if (request.length() != 1) {
                    throw new IllegalArgumentException(I18n.t(
                            "Команда установки не принимает параметры",
                            "The install command does not accept parameters"));
                }
                if (!coreInstallRequired() && !coreInstallSession.isActive()) {
                    return response(true, I18n.t(
                            "Ядра уже установлены",
                            "The cores are already installed"), "").toString();
                }
                CoreInstallSession.Request installRequest = coreInstallSession.request();
                if (!loaded) {
                    coreInstallSession.cancel();
                    return runtimeStoppingResponse();
                }
                requestDashboardRefresh();
                attemptExplicitCoreInstall();
                String data = new JSONObject()
                        .put("generation", installRequest.generation)
                        .toString();
                return response(true, installRequest.created
                        ? I18n.t("Установка запущена", "Installation started")
                        : I18n.t("Установка уже выполняется",
                        "Installation is already running"), data).toString();
            }
            if ("list_nodes".equals(command)) {
                int offset = request.optInt("offset", 0);
                int limit = request.optInt("limit", SubscriptionManager.DEFAULT_PAGE_SIZE);
                if (!SubscriptionManager.validPageRequest(offset, limit)) {
                    return response(false, I18n.t(
                            "Недопустимый размер страницы",
                            "Invalid page size"), "").toString();
                }
                String query = SubscriptionManager.requireUiQuery(
                        request.optString("query", ""));
                String protocol = SubscriptionManager.requireUiProtocol(
                        request.optString("protocol", "all"));
                return response(true, "", subscriptions.uiState(
                        settings.providerId, offset, limit, query, protocol)
                        .toString()).toString();
            }
            if ("add_node".equals(command)) {
                String uri = request.optString("uri", "");
                return executeSerialized(() -> {
                    int added = subscriptions.addManualUri(uri);
                    switchToCustomProviderFromJava();
                    if (settings.enabled) {
                        requestReconnect("manual_node_added");
                    }
                    invalidateSettings();
                    return response(true, I18n.t("Добавлено узлов: ", "Nodes added: ") + added, "").toString();
                });
            }
            if ("add_subscription".equals(command)) {
                String url = request.optString("url", "");
                return executeSerialized(() -> {
                    boolean added = subscriptions.addCustomUrl(url);
                    switchToCustomProviderFromJava();
                    if (added) {
                        requestSubscriptionRefresh(false,
                                revisionGate.currentToken(), true);
                    }
                    invalidateSettings();
                    return response(true, added
                            ? I18n.t("Подписка добавлена", "Subscription added")
                            : I18n.t("Подписка уже сохранена", "Subscription is already saved"), "").toString();
                });
            }
            if ("move_subscription".equals(command)) {
                String id = request.optString("id", "");
                int delta = request.optInt("delta", 0);
                return executeSerialized(() -> {
                    boolean moved = subscriptions.moveCustomUrl(id, delta);
                    if (moved) invalidateSettings();
                    return response(moved, moved
                            ? I18n.t("Порядок изменён", "Order updated")
                            : I18n.t("Не удалось переместить", "Could not move it"),
                            "").toString();
                });
            }
            if ("hide_subscription".equals(command)) {
                String id = request.optString("id", "");
                boolean hidden = request.optBoolean("hidden", false);
                return executeSerialized(() -> {
                    boolean changed = subscriptions.setCustomUrlHidden(id, hidden);
                    if (changed) {
                        if (settings.enabled) requestReconnect("subscription_hidden");
                        invalidateSettings();
                    }
                    return response(changed, changed
                            ? (hidden ? I18n.t("Подписка скрыта", "Subscription hidden")
                            : I18n.t("Подписка показана", "Subscription shown"))
                            : I18n.t("Ничего не изменилось", "Nothing changed"),
                            "").toString();
                });
            }
            if ("delete_subscription".equals(command)) {
                String id = request.optString("id", "");
                return executeSerialized(() -> {
                    boolean removed = subscriptions.removeCustomUrl(id);
                    if (removed && settings.enabled
                            && settings.providerId == SettingsModel.CUSTOM_PROVIDER_ID) {
                        requestReconnect("subscription_deleted");
                    }
                    invalidateSettings();
                    return response(removed, removed
                            ? I18n.t("Подписка удалена", "Subscription deleted")
                            : I18n.t("Подписка не найдена", "Subscription not found"), "").toString();
                });
            }
            if ("delete_manual_node".equals(command)) {
                String key = request.optString("key", "");
                return executeSerialized(() -> {
                    ProtocolParser.Node selectedBeforeRemoval =
                            subscriptions.selected(settings.providerId);
                    boolean removedSelection = selectedBeforeRemoval != null
                            && key.equals(selectedBeforeRemoval.normalizedKey);
                    boolean removed = subscriptions.removeManualNode(key);
                    if (removed && settings.enabled && (removedSelection
                            || activeNode != null && key.equals(activeNode.normalizedKey))) {
                        cancelCorePreparation(true);
                        requestReconnect("manual_node_deleted");
                    }
                    invalidateSettings();
                    return response(removed, removed
                            ? I18n.t("Сервер удалён", "Node deleted")
                            : I18n.t("Сервер не найден", "Node not found"), "").toString();
                });
            }
            if ("select_node".equals(command)) {
                String key = request.optString("key", "");
                return executeSerialized(() -> {
                    boolean selected = subscriptions.setSelectedKey(settings.providerId, key);
                    if (selected) {
                        resetCoreRepairBackoff();
                        if (settings.enabled) {
                            cancelCorePreparation(true);
                            requestReconnect("node_selected");
                        }
                    }
                    invalidateSettings();
                    return response(selected, selected
                            ? I18n.t("Сервер выбран", "Node selected")
                            : I18n.t("Сервер не найден", "Node not found"), "").toString();
                });
            }
            if ("clear_nodes".equals(command)) {
                return executeSerialized(() -> {
                    subscriptions.clearNodesKeepSubscriptions();
                    if (settings.enabled) disableFromJava("nodes_cleared");
                    activeNode = null;
                    invalidateSettings();
                    return response(true, I18n.t("Серверы очищены", "Servers cleared"), "").toString();
                });
            }
            if ("ping_nodes".equals(command)) {
                String expectedPingType = request.optString(
                        "expected_ping_type", settings.pingType);
                if (!(SettingsModel.PING_PROXY_GET.equals(expectedPingType)
                        || SettingsModel.PING_TCP.equals(expectedPingType))) {
                    throw new IllegalArgumentException(I18n.t(
                            "Некорректный способ проверки",
                            "Invalid latency-check method"));
                }
                if (!expectedPingType.equals(settings.pingType)) {
                    return response(false, I18n.t(
                            "Способ проверки изменился; повторите действие",
                            "The latency-check method changed; try again"), "").toString();
                }
                List<String> keys = parseNodeKeys(request.optJSONArray("keys"));
                List<ProtocolParser.Node> nodes = subscriptions.nodesByKeys(settings.providerId, keys);
                startManualPing(nodes, settings.pingType);
                return response(true, SettingsModel.PING_PROXY_GET.equals(settings.pingType)
                        ? I18n.t("Подключение временно приостановлено для полной проверки",
                        "The connection is temporarily paused for the full-path check")
                        : I18n.t("TCP-проверка запущена", "TCP check started"), "").toString();
            }
            if ("cancel_ping".equals(command)) {
                cancelPing(true);
                return response(true, I18n.t("Проверка отменена", "Check cancelled"), "").toString();
            }
            if ("import_text".equals(command)) {
                String text = request.optString("text", "");
                if (JsonGuard.exceedsUtf8Limit(text, LimitedHttpClient.MAX_EXPANDED_BYTES)) {
                    return response(false, I18n.t("Импорт превышает 8 МиБ", "Import exceeds 8 MiB"), "").toString();
                }
                ImportSubmission submission = requestImportText(text);
                if (submission == ImportSubmission.BUSY) {
                    return response(false, I18n.t("Предыдущий импорт ещё выполняется",
                            "A previous import is still running"), "").toString();
                }
                if (submission != ImportSubmission.ACCEPTED) {
                    return response(false, I18n.t("Runtime останавливается",
                            "Runtime is stopping"), "").toString();
                }
                return response(true, I18n.t("Импорт запущен", "Import started"), "").toString();
            }
            if ("refresh_subscriptions".equals(command)) {
                ManualRefreshSubmission submission = queueManualSubscriptionRefresh();
                if (submission == ManualRefreshSubmission.STOPPING) {
                    return response(false, I18n.t("Runtime останавливается",
                            "Runtime is stopping"), "").toString();
                }
                if (submission == ManualRefreshSubmission.DISABLING) {
                    return response(false, I18n.t(
                            "Обновление отменено: exitFy выключается",
                            "Refresh cancelled because exitFy is being disabled"), "").toString();
                }
                boolean queued = submission == ManualRefreshSubmission.QUEUED;
                return response(true, queued
                        ? I18n.t("Обновление поставлено в очередь",
                        "Refresh queued until settings are applied")
                        : I18n.t("Обновление запущено", "Refresh started"), "").toString();
            }
            if ("reconnect".equals(command)) {
                if (!loaded || !settings.enabled) {
                    return response(false, I18n.t(
                            "Сначала включите exitFy",
                            "Enable exitFy before reconnecting"), "").toString();
                }
                requestReconnect("manual");
                return response(true, I18n.t("Переподключение запланировано", "Reconnect scheduled"), "").toString();
            }
            return response(false, I18n.t("Неизвестная команда", "Unknown command"), "").toString();
        } catch (Exception error) {
            return response(false, ErrorSanitizer.clean(error.getMessage() == null
                    ? I18n.t("Некорректная команда", "Invalid command") : error.getMessage()), "").toString();
        }
    }

    private String executeSerialized(Callable<String> command) throws Exception {
        SerializedCommand serialized = new SerializedCommand(command);
        Future<String> future = coordinator.submit(serialized);
        try {
            return future.get(3, TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            if (serialized.cancelIfQueued()) {
                future.cancel(false);
                throw new IllegalStateException(I18n.t(
                        "Очередь exitFy занята; повторите команду",
                        "exitFy queue is busy; retry the command"));
            }
            // The mutation is already running. Reporting a timeout would let
            // the caller retry while the first mutation commits in the
            // background, so return its one authoritative result instead.
            return awaitRunningCommand(future);
        } catch (InterruptedException interrupted) {
            if (serialized.cancelIfQueued()) {
                future.cancel(false);
                Thread.currentThread().interrupt();
                throw interrupted;
            }
            String result = awaitRunningCommand(future);
            Thread.currentThread().interrupt();
            return result;
        }
    }

    private static String awaitRunningCommand(Future<String> future) throws Exception {
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    return future.get();
                } catch (InterruptedException ignored) {
                    interrupted = true;
                } catch (java.util.concurrent.ExecutionException execution) {
                    Throwable cause = execution.getCause();
                    if (cause instanceof Exception) throw (Exception) cause;
                    throw new IllegalStateException(cause == null ? "command failed" : cause.getMessage(), cause);
                }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    static final class SerializedCommand implements Callable<String> {
        private final Callable<String> command;
        private CommandState state = CommandState.QUEUED;

        SerializedCommand(Callable<String> command) {
            this.command = command;
        }

        @Override
        public String call() throws Exception {
            synchronized (this) {
                if (state != CommandState.QUEUED) {
                    throw new java.util.concurrent.CancellationException("command was cancelled");
                }
                state = CommandState.RUNNING;
            }
            try {
                return command.call();
            } finally {
                synchronized (this) {
                    state = CommandState.DONE;
                    notifyAll();
                }
            }
        }

        synchronized boolean cancelIfQueued() {
            if (state != CommandState.QUEUED) return false;
            state = CommandState.CANCELLED;
            return true;
        }

        synchronized boolean isRunning() {
            return state == CommandState.RUNNING;
        }
    }

    private enum CommandState {
        QUEUED,
        RUNNING,
        CANCELLED,
        DONE
    }

    private static final class SettingsUpdate {
        final SettingsModel settings;
        final long revision;
        final boolean connectionSettingsChanged;
        final boolean unchanged;

        SettingsUpdate(SettingsModel settings, long revision,
                       boolean connectionSettingsChanged, boolean unchanged) {
            this.settings = settings;
            this.revision = revision;
            this.connectionSettingsChanged = connectionSettingsChanged;
            this.unchanged = unchanged;
        }
    }

    private static boolean mutatesNodeSelection(String command) {
        return "add_node".equals(command) || "add_subscription".equals(command)
                || "delete_subscription".equals(command) || "delete_manual_node".equals(command)
                || "select_node".equals(command) || "clear_nodes".equals(command)
                || "hide_subscription".equals(command)
                || "import_text".equals(command) || "refresh_subscriptions".equals(command);
    }

    String getUiState() {
        JSONObject value = new JSONObject();
        try {
            RuntimeState state = stateMachine.get();
            SettingsModel current = settings;
            value.put("runtimeAvailable", loaded);
            value.put("state", state.name());
            value.put("enabled", current.enabled);
            value.put("providerId", current.providerId);
            JSONArray providerAvailability = new JSONArray();
            for (int provider = 0; provider < ProviderCatalog.size(); provider++) {
                providerAvailability.put(ProviderCatalog.isEnabled(provider));
            }
            providerAvailability.put(true);
            value.put("providerAvailability", providerAvailability);
            value.put("pingType", current.pingType);
            value.put("dualCore", current.dualCore);
            value.put("failover", current.failover);
            value.put("refreshOnOpen", current.refreshOnOpen);
            value.put("autoCheckMinutes", current.autoCheckMinutes);
            value.put("callsViaProxy", current.callsViaProxy);
            value.put("dualCoreActive", NativeCoreRuntime.dualCoreEnabled());
            // Never expose a custom identifier in a screen-state snapshot
            // which can outlive the editor dialog.
            value.put("customHwidSet", !current.customHwid.isEmpty());
            // This is the plugin-generated default identifier, not a custom
            // value or a hardware-derived device identifier.
            value.put("defaultHwid", subscriptions.defaultHwid());
            value.put("connectionIssue", connectionIssue);
            value.put("serverCount", subscriptions.nodeCountFast(current.providerId));
            value.put("activeNodeInfo", activeNode == null
                    ? subscriptions.selectedUiNodeInfo(current.providerId)
                    : subscriptions.uiNodeInfo(current.providerId, activeNode.normalizedKey));
            // Keep the pre-existing restart handoff contract intact. Restart
            // actions/notifications are intentionally deferred to a separate
            // release even though this iteration removes every core control.
            CoreFamily loadedFamily = nativeCore.loadedFamily();
            // With the experiment on, the other family is mapped on demand,
            // so a mismatch is not a restart the user has to perform.
            value.put("restartRequired", (restartRequired
                    || CoreProcessState.requiresRestart(loadedFamily, requiredCore))
                    && !NativeCoreRuntime.canMapAnotherFamily());
            value.put("customUrlCount", subscriptions.customUrlCount());
            CoreInstallSession.Snapshot coreInstall = coreInstallSession.snapshot();
            value.put("coreInstall", new JSONObject()
                    .put("required", coreInstallRequired())
                    .put("state", coreInstall.state.id)
                    .put("progress", coreInstall.progress)
                    .put("stage", coreInstall.stage.id)
                    .put("generation", coreInstall.generation));
            RefreshCompletionGate.Ticket refreshTicket = subscriptionRefreshTicket;
            boolean refreshing = refreshTicket != null
                    && subscriptionRefreshes.isPending(refreshTicket);
            value.put("operations", new JSONObject()
                    .put("subscriptionRefresh", refreshing ? "running" : "idle")
                    .put("import", importRunning ? "running" : "idle"));
            value.put("ping", new JSONObject()
                    .put("state", pingState)
                    .put("type", pingType)
                    .put("total", pingTotal)
                    .put("completed", pingCompleted));
        } catch (Exception ignored) {
        }
        return value.toString();
    }

    void onAppResume() {
        if (!loaded) return;
        safeExecute(() -> {
            checkRuntimeAndProxy("app_resume");
            refreshSubscriptionsOnOpen();
        });
    }

    /**
     * Reloads the selected source when the app comes back, for people who
     * would otherwise refresh by hand every time. Off unless asked for: it is
     * a network request the user did not initiate.
     */
    private void refreshSubscriptionsOnOpen() {
        if (!settings.refreshOnOpen || !loaded) return;
        try {
            if (!subscriptions.isStale(settings.providerId)) return;
            requestSubscriptionRefresh(false, revisionGate.currentToken(), false);
        } catch (Exception ignored) {
        }
    }

    /**
     * Measures the current page of servers on a schedule. Always TCP: the
     * full-path check has to take Telegram's proxy away for the duration, and
     * doing that to a working connection on a timer is not something anyone
     * asked for.
     */
    private void runScheduledLatencyCheck() {
        try {
            int minutes = settings.autoCheckMinutes;
            if (minutes <= 0 || !loaded) return;
            long now = System.currentTimeMillis();
            if (now - lastAutoCheckAt < minutes * 60_000L) return;
            if (!"idle".equals(pingState) && !"completed".equals(pingState)) return;
            List<ProtocolParser.Node> nodes = subscriptions.nodes(settings.providerId);
            if (nodes.isEmpty()) return;
            List<ProtocolParser.Node> batch = nodes.size() <= SubscriptionManager.MAX_PING_KEYS
                    ? nodes : new ArrayList<>(nodes.subList(0, SubscriptionManager.MAX_PING_KEYS));
            lastAutoCheckAt = now;
            startManualPing(batch, SettingsModel.PING_TCP);
        } catch (Exception ignored) {
        }
    }

    @Override
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id != NotificationCenter.proxySettingsChanged || !loaded || probePausing) return;
        safeExecute(() -> {
            if (!loaded || !settings.enabled || stateMachine.get() != RuntimeState.RUNNING) return;
            ProxySession.Ownership ownership = proxySession.ownership();
            if (ownership == ProxySession.Ownership.EXTERNALLY_CHANGED) {
                disableFromJava(RuntimePolicy.TELEGRAM_PROXY_CHANGED);
            } else if (ownership == ProxySession.Ownership.INACTIVE) {
                requestReconnect("telegram_proxy_missing");
            } else if (ownership == ProxySession.Ownership.UNKNOWN) {
                scheduleOwnershipRetry("telegram_proxy_unknown");
            }
        });
    }

    private void requestReconnect(String reason) {
        if (!loaded) return;
        boolean scheduleRunner = reconnectRequests.offer(reason, ReconnectBackoff.resetsForReason(reason));
        if (scheduleRunner && !safeExecute(this::drainReconnectRequests)) {
            reconnectRequests.clear();
        }
    }

    private void drainReconnectRequests() {
        while (loaded) {
            ReconnectRequestGate.Request request = reconnectRequests.beginNext();
            if (request == null) {
                reconnectRequests.clear();
                return;
            }
            try {
                handleReconnectRequest(request.reason);
            } catch (Throwable error) {
            } finally {
                if (!reconnectRequests.complete(request)) return;
            }
        }
        reconnectRequests.clear();
    }

    private void handleReconnectRequest(String reason) {
        if (!loaded || !settings.enabled) return;
        if (ReconnectBackoff.resetsForReason(reason)) {
            restartRequired = false;
            coreSelectionBlocked = false;
        } else if (restartRequired || coreSelectionBlocked) {
            return;
        }
        if (stateMachine.get() == RuntimeState.RUNNING) {
            ProxySession.Ownership ownership = proxySession.ownership();
            if (ownership == ProxySession.Ownership.EXTERNALLY_CHANGED) {
                disableFromJava(RuntimePolicy.TELEGRAM_PROXY_CHANGED);
                return;
            }
            if (ownership == ProxySession.Ownership.UNKNOWN) {
                scheduleOwnershipRetry(reason);
                return;
            }
        }
        cancelSubscriptionRefresh();
        RuntimeOperationToken operation = revisionGate.token(
                revisionGate.advanceLifecycle(), revisionGate.settingsRevision());
        stopInternal();
        scheduleReconnect(operation, nextReconnectDelay(ReconnectBackoff.resetsForReason(reason)));
    }

    private void scheduleOwnershipRetry(String reason) {
        if (!loaded || !settings.enabled) return;
        safeSchedule(() -> requestReconnect(reason), 1L, TimeUnit.SECONDS);
    }

    private void checkRuntimeAndProxy(String reason) {
        if (!loaded || !settings.enabled) return;
        if (stateMachine.get() == RuntimeState.RUNNING) {
            ProxySession.Ownership ownership = proxySession.ownership();
            if (ownership == ProxySession.Ownership.EXTERNALLY_CHANGED) {
                disableFromJava(RuntimePolicy.TELEGRAM_PROXY_CHANGED);
                return;
            }
            if (ownership == ProxySession.Ownership.OWNED && servicesHealthy()) {
                proxySession.reapplyIfOwned();
                return;
            }
        }
        requestReconnect(reason);
    }

    private boolean servicesHealthy() {
        return localPort > 0 && nativeCore.isRunning() && isLoopbackListening(localPort);
    }

    private void disableFromJava(String reason) {
        if (!settings.enabled) return;
        SettingsModel previous = settings;
        SettingsModel disabled = new SettingsModel(false, previous.providerId,
                previous.customHwid, previous.schemaVersion, previous.pingType,
                previous.dualCore, previous.failover,
                previous.refreshOnOpen, previous.autoCheckMinutes,
                previous.callsViaProxy);
        long persistRevision;
        synchronized (settingsRequestLock) {
            synchronized (subscriptionRefreshControl) {
                requestedSettings = disabled;
                persistRevision = revisionGate.requestSettingsChange();
                manualRefreshIntent.clear();
                cancelSubscriptionRefreshLocked();
            }
        }
        settings = disabled;
        appliedSettings.markApplied(persistRevision);
        revisionGate.advanceLifecycle();
        cancelReconnect();
        cancelCorePreparation(true);
        stopInternal(RuntimePolicy.preserveCurrentTelegramProxy(reason));
        persistPluginSetting("enabled", false, persistRevision);
    }

    private void switchToCustomProviderFromJava() {
        if (settings.providerId == SettingsModel.CUSTOM_PROVIDER_ID) return;
        SettingsModel previous = settings;
        SettingsModel custom = new SettingsModel(previous.enabled, SettingsModel.CUSTOM_PROVIDER_ID,
                previous.customHwid, previous.schemaVersion, previous.pingType,
                previous.dualCore, previous.failover,
                previous.refreshOnOpen, previous.autoCheckMinutes,
                previous.callsViaProxy);
        long persistRevision;
        synchronized (settingsRequestLock) {
            synchronized (subscriptionRefreshControl) {
                requestedSettings = custom;
                persistRevision = revisionGate.requestSettingsChange();
                cancelSubscriptionRefreshLocked();
            }
        }
        settings = custom;
        appliedSettings.markApplied(persistRevision);
        cancelCorePreparation(true);
        persistPluginSetting("provider_id", SettingsModel.CUSTOM_PROVIDER_ID, persistRevision);
        schedulePendingManualRefresh();
    }

    private void persistPluginSetting(String key, Object value, long expectedRevision) {
        try {
            settingPersistenceRevisions.record(key, expectedRevision);
            PluginSettingDispatcher.dispatch(expectedRevision,
                    () -> settingPersistenceRevisions.current(key),
                    () -> loaded,
                    PluginsController::runOnPluginsQueue,
                    () -> {
                        try {
                            PluginsController.getInstance().setPluginSetting(pluginId, key, value);
                        } catch (Throwable error) {
                        }
                    });
        } catch (Throwable error) {
        }
    }

    private void startInternal(RuntimeOperationToken operation) {
        synchronized (lifecycleLock) {
            ProxySession.StateGuard guard = probeResumeGuard;
            boolean started = startInternalLocked(
                    operation, false, guard, Long.MAX_VALUE);
            maybeClearProbeResumeGuard(guard,
                    RuntimePolicy.shouldClearProbeResumeGuard(
                            loaded, settings.enabled, started));
        }
    }

    private boolean startInternalLocked(RuntimeOperationToken operation, boolean skipRefresh,
                                        ProxySession.StateGuard expectedProxyState,
                                        long absoluteDeadline) {
        if (!revisionGate.isCurrent(operation, loaded, settings.enabled)) return false;
        try {
            if (!proxySession.recoverIfNeeded()) {
                throw proxySession.recoveryPendingException();
            }
            restartRequired = false;
            coreSelectionBlocked = false;
            connectionIssue = "";
            transition(RuntimeState.STARTING);
            int port = findFreeLoopbackPort();
            ProxySession.Credentials credentials = ProxySession.newCredentials();
            ProtocolParser.Node selected = subscriptions.selected(settings.providerId);
            if (!skipRefresh && subscriptions.isStale(settings.providerId)) {
                requestSubscriptionRefresh(selected == null, operation, false);
                if (selected == null) {
                    invalidateSettings();
                    return false;
                }
            }
            if (selected == null) throw new IllegalStateException(I18n.t(
                    "Нет доступных proxy-серверов", "No proxy servers available"));
            CoreFamily family = resolveCore(selected);
            requiredCore = family;
            CoreFamily loadedFamily = nativeCore.loadedFamily();
            restartRequired = CoreProcessState.requiresRestart(loadedFamily, family);
            boolean usableOnDisk = isCoreUsable(family);
            if (!usableOnDisk) {
                requestCorePreparation(family, selected.normalizedKey);
                if (RuntimePolicy.shouldWaitForCorePreparation(
                        loadedFamily, usableOnDisk)) {
                    fail(new IllegalStateException(I18n.t(
                            "Компоненты подключения устанавливаются в фоне",
                            "Connection components are being installed in the background")));
                    return false;
                }
            }
            JSONObject config = family == CoreFamily.SING_BOX
                    ? ProtocolParser.buildConfig(selected, port,
                    credentials.username, credentials.password)
                    : XrayConfigRenderer.build(selected, port,
                    credentials.username, credentials.password);
            if (!revisionGate.isCurrent(operation, loaded, settings.enabled)) return false;
            NativeCoreRuntime.StartResult result;
            if (absoluteDeadline == Long.MAX_VALUE) {
                result = nativeCore.start(family, config.toString());
            } else {
                long remaining = remainingMillis(absoluteDeadline);
                // Keep enough of the page deadline for the guarded Telegram
                // proxy activation after StartCore returns.
                if (remaining <= 2_100L) return false;
                result = nativeCore.start(family, config.toString(), remaining - 2_000L);
            }
            if (result.restartRequired) {
                restartRequired = true;
            }
            if (result.missingCore) {
                requestCorePreparation(family, selected.normalizedKey);
                fail(new IllegalStateException(result.error));
                return false;
            }
            String error = result.ok ? "" : result.error;
            if (!revisionGate.isCurrent(operation, loaded, settings.enabled)) {
                stopServicesOnly(absoluteDeadline);
                return false;
            }
            if (!error.isEmpty()) throw new IllegalStateException(error);
            // A same-family core already mapped in this process can start
            // without touching its on-disk file. Only a first native open is
            // evidence that the local candidate passed pinned SHA/ELF checks.
            if (loadedFamily == null) markCoreReadinessVerified(family);
            long proxyTimeout = boundedWait(absoluteDeadline, 2_000L);
            if (proxyTimeout <= 0L) {
                stopServicesOnly(absoluteDeadline);
                return false;
            }
            proxySession.activate(port, credentials, proxyTimeout, expectedProxyState);
            // updateSettings(), reconnect, or unload may advance generation
            // while the UI operation is RUNNING.  A late callback must undo
            // its owned proxy and must never publish RUNNING.
            if (!revisionGate.isCurrent(operation, loaded, settings.enabled)) {
                stopServicesOnly(absoluteDeadline);
                proxySession.restore(boundedWait(absoluteDeadline, 2_000L));
                return false;
            }
            boolean published;
            synchronized (settingsRequestLock) {
                published = revisionGate.isCurrent(operation, loaded, settings.enabled);
                if (published) {
                    activeNode = selected;
                    connectionIssue = "";
                    localPort = port;
                    openCallRelay(port, credentials);
                    restartRequired = false;
                    coreSelectionBlocked = false;
                    reconnectBackoff.reset();
                    failoverFailures = 0;
                    failoverFailedKey = "";
                    reconnectAt = 0;
                    transition(RuntimeState.RUNNING);
                }
            }
            if (!published) {
                stopServicesOnly(absoluteDeadline);
                proxySession.restore(boundedWait(absoluteDeadline, 2_000L));
                return false;
            }
            // A reconnect/network flap may have cancelled a user-requested
            // subscription refresh. Resume that intent only after a real
            // RUNNING publication; retrying at onLost/backoff admission would
            // immediately consume it on the unavailable network.
            if (isCoreUsable(family)) {
                handleCoreRepairResult(family, true);
                clearCorePreparation(family, selected.normalizedKey);
            }
            schedulePendingManualRefresh();
            return true;
        } catch (ProxySession.RecoveryPendingException recoveryPending) {
            stopServicesOnly(absoluteDeadline);
            if (!revisionGate.isCurrent(operation, loaded, settings.enabled)) return false;
            fail(recoveryPending);
            scheduleReconnect(operation, nextReconnectDelay());
            return false;
        } catch (ProxySession.ExternalProxyChangeException externalChange) {
            // A proxy selected while Proxy GET had temporarily restored
            // Telegram belongs to the user.  Preserve it, invalidate this
            // generation, and let the coordinator perform the regular
            // disable flow outside the ping deadline/lock.
            stopServicesOnly(absoluteDeadline);
            if (revisionGate.isCurrent(operation, loaded, settings.enabled)) {
                safeExecute(() -> disableFromJava(RuntimePolicy.TELEGRAM_PROXY_CHANGED));
            }
            return false;
        } catch (Exception error) {
            boolean current = revisionGate.isCurrent(operation, loaded, settings.enabled);
            stopServicesOnly(absoluteDeadline);
            proxySession.restore(boundedWait(absoluteDeadline, 2_000L));
            if (!current || !revisionGate.isCurrent(operation, loaded, settings.enabled)) return false;
            fail(error);
            // Only a server that failed to carry the connection is rotated.
            // A subscription that would not refresh is a different failure and
            // must not move anyone off the server they chose.
            rotateServerAfterFailure();
            if (!restartRequired && !coreSelectionBlocked) {
                scheduleReconnect(operation, nextReconnectDelay());
            }
            return false;
        }
    }

    private CoreSelector.Coverage providerCoverage() {
        try {
            return CoreSelector.coverage(subscriptions.nodes(settings.providerId));
        } catch (Exception ignored) {
            return CoreSelector.Coverage.EMPTY;
        }
    }

    private CoreFamily resolveCore(ProtocolParser.Node node) {
        try {
            return CoreSelector.select(node, nativeCore.loadedFamily(),
                    isCoreUsable(CoreFamily.SING_BOX),
                    isCoreUsable(CoreFamily.XRAY),
                    providerCoverage());
        } catch (IllegalArgumentException incompatible) {
            coreSelectionBlocked = true;
            throw incompatible;
        }
    }

    private void stopInternal() {
        stopInternal(false);
    }

    private void stopInternal(boolean preserveCurrentTelegramProxy) {
        synchronized (lifecycleLock) {
            stopInternalLocked(preserveCurrentTelegramProxy);
        }
    }

    private void stopInternalLocked(boolean preserveCurrentTelegramProxy) {
        RuntimeState current = stateMachine.get();
        if (current == RuntimeState.STOPPED) {
            finishProxySession(preserveCurrentTelegramProxy);
            stopServicesOnly();
            localPort = 0;
            closeCallRelay();
            if (!loaded || !settings.enabled) probeResumeGuard = null;
            return;
        }
        try {
            stateMachine.transition(RuntimeState.STOPPING);
        } catch (Exception ignored) {
        }
        invalidateSettings();
        finishProxySession(preserveCurrentTelegramProxy);
        stopServicesOnly();
        activeNode = null;
        connectionIssue = "";
        localPort = 0;
        closeCallRelay();
        try {
            stateMachine.transition(RuntimeState.STOPPED);
        } catch (Exception ignored) {
        }
        if (!loaded || !settings.enabled) probeResumeGuard = null;
        invalidateSettings();
    }

    private void finishProxySession(boolean preserveCurrentTelegramProxy) {
        if (preserveCurrentTelegramProxy) proxySession.releasePreservingCurrent();
        else if (!settings.enabled) proxySession.restoreForDisable();
        else proxySession.restore();
    }

    private void stopServicesOnly() {
        stopServicesOnly(Long.MAX_VALUE);
    }

    private void stopServicesOnly(long absoluteDeadline) {
        try {
            long timeout = boundedWait(absoluteDeadline, 3_000L);
            nativeCore.stop(timeout);
        } catch (Throwable ignored) {
        }
    }

    private static final int FAILOVER_ATTEMPTS = 2;
    private String failoverFailedKey = "";
    private int failoverFailures;

    /**
     * Moves to the next server of the current source once the selected one has
     * failed repeatedly. Off unless asked for: people who pick a server on
     * purpose do not want it changed under them, and switching also changes
     * the exit country.
     */
    private void rotateServerAfterFailure() {
        if (!settings.failover || !settings.enabled || !loaded) return;
        if (restartRequired || coreSelectionBlocked) return;
        try {
            ProtocolParser.Node active = subscriptions.selected(settings.providerId);
            if (active == null) return;
            if (!active.normalizedKey.equals(failoverFailedKey)) {
                failoverFailedKey = active.normalizedKey;
                failoverFailures = 0;
            }
            if (++failoverFailures < FAILOVER_ATTEMPTS) return;
            List<ProtocolParser.Node> candidates = subscriptions.nodes(settings.providerId);
            String next = RuntimePolicy.nextServerAfterFailure(
                    candidates, active.normalizedKey);
            if (next.isEmpty()) return;
            failoverFailures = 0;
            failoverFailedKey = next;
            if (subscriptions.setSelectedKey(settings.providerId, next)) {
                connectionIssue = I18n.t(
                        "Сервер не отвечал, выбран следующий",
                        "The server did not respond; the next one was selected");
                resetCoreRepairBackoff();
                cancelCorePreparation(true);
                requestReconnect("node_selected");
            }
        } catch (Exception ignored) {
        }
    }

    private volatile long lastAutoCheckAt;
    private volatile CallRelay callRelay;

    /**
     * The relay lives exactly as long as the connection it borrows: its
     * mappings point at a local proxy port that stops existing when the core
     * stops.
     */
    private void openCallRelay(int port, ProxySession.Credentials credentials) {
        closeCallRelay();
        if (!settings.callsViaProxy) return;
        callRelay = new CallRelay("127.0.0.1", port,
                credentials.username, credentials.password);
    }

    private void closeCallRelay() {
        CallRelay current = callRelay;
        callRelay = null;
        if (current != null) current.close();
    }

    private void fail(Exception error) {
        String message = ErrorSanitizer.clean(error == null ? ""
                : error.getMessage());
        connectionIssue = message.isEmpty()
                ? I18n.t("Не удалось запустить подключение",
                "Could not start the connection")
                : message;
        try {
            if (stateMachine.get() != RuntimeState.ERROR) stateMachine.transition(RuntimeState.ERROR);
        } catch (Exception ignored) {
        }
        invalidateSettings();
    }

    private long nextReconnectDelay() {
        return nextReconnectDelay(false);
    }

    private long nextReconnectDelay(boolean reset) {
        return reconnectBackoff.nextDelaySeconds(reset);
    }

    private void scheduleReconnect(RuntimeOperationToken operation, long seconds) {
        if (!loaded || !settings.enabled
                || RuntimePolicy.reconnectBlocked(nativeCore.isQuarantined())
                || restartRequired || coreSelectionBlocked) return;
        cancelReconnect();
        reconnectAt = System.currentTimeMillis() + seconds * 1000L;
        reconnectFuture = safeSchedule(() -> {
            reconnectAt = 0L;
            if (!revisionGate.isCurrent(operation, loaded, settings.enabled)) return;
            stopInternal();
            startInternal(operation);
        }, seconds, TimeUnit.SECONDS);
        if (reconnectFuture == null) reconnectAt = 0L;
        invalidateSettings();
    }

    private void cancelReconnect() {
        ScheduledFuture<?> value = reconnectFuture;
        reconnectFuture = null;
        reconnectAt = 0L;
        if (value != null) value.cancel(false);
    }

    private void startManualPing(List<ProtocolParser.Node> nodes, String requestedType) {
        if (nodes == null || nodes.isEmpty()) {
            throw new IllegalArgumentException(I18n.t(
                    "На текущей странице нет серверов", "The current page has no nodes"));
        }
        PingTaskSnapshot replaced;
        SocksHttpProbe.Session newSession = null;
        RuntimeException submissionFailure = null;
        synchronized (pingControl) {
            replaced = detachPingLocked();
            long token = pingGeneration.incrementAndGet();
            RuntimeOperationToken runtimeOperation = revisionGate.currentToken();
            String nextType = SettingsModel.PING_TCP.equals(requestedType)
                    ? SettingsModel.PING_TCP : SettingsModel.PING_PROXY_GET;
            PingKind kind = SettingsModel.PING_TCP.equals(nextType)
                    ? PingKind.TCP : PingKind.PROXY_GET;
            boolean proxyRestoreContext = proxyRestoreContextLocked(replaced.kind);
            cancelReplacedFutureLocked(replaced);
            cancelProbeStatusesLocked(replaced);
            if (RuntimePolicy.replacementNeedsGuardedRestore(
                    kind.name(), proxyRestoreContext) && loaded) {
                queuePingRestoreLocked(runtimeOperation);
            }
            newSession = kind == PingKind.PROXY_GET ? socksProbe.beginSession() : null;
            final SocksHttpProbe.Session taskSession = newSession;
            List<ProtocolParser.Node> taskNodes = new ArrayList<>(nodes);
            pingNodes = taskNodes;
            pingTotal = nodes.size();
            pingCompleted = 0;
            pingType = nextType;
            pingKind = kind;
            pingSocksSession = taskSession;
            pingState = "running";
            subscriptions.markProbePending(taskNodes);
            try {
                pingFuture = pingExecutor.submit(() -> {
                    if (kind == PingKind.TCP) runTcpPing(token, taskNodes);
                    else runProxyPing(token, taskNodes, runtimeOperation, taskSession);
                });
            } catch (RuntimeException rejected) {
                pingKind = PingKind.NONE;
                pingSocksSession = null;
                pingState = "cancelled";
                subscriptions.cancelPendingProbes(taskNodes);
                submissionFailure = rejected;
            }
        }
        closeReplacedSession(replaced);
        if (submissionFailure != null) {
            socksProbe.closeSession(newSession);
            throw submissionFailure;
        }
        invalidateSettings();
    }

    private boolean cancelPing(boolean restoreConnection) {
        PingTaskSnapshot replaced;
        boolean proxyRestoreContext;
        synchronized (pingControl) {
            replaced = detachPingLocked();
            pingGeneration.incrementAndGet();
            proxyRestoreContext = proxyRestoreContextLocked(replaced.kind);
            cancelReplacedFutureLocked(replaced);
            cancelProbeStatusesLocked(replaced);
            if ("running".equals(pingState)) {
                pingState = "cancelled";
            }
            if (restoreConnection && loaded && proxyRestoreContext) {
                queuePingRestoreLocked(revisionGate.currentToken());
            }
        }
        closeReplacedSession(replaced);
        // A cancelled Proxy GET may already have restored the user's proxy.
        // Keep its exact guard until a guarded restart succeeds (or the
        // runtime is disabled/unloaded), including when another ping starts
        // before the old task has left the single-thread executor.
        ProxySession.StateGuard cancelledGuard = probeResumeGuard;
        maybeClearProbeResumeGuard(cancelledGuard,
                RuntimePolicy.shouldClearProbeResumeGuard(
                        loaded, settings.enabled, false));
        invalidateSettings();
        return proxyRestoreContext;
    }

    private boolean cancelPingForUnload() {
        settingsProbeRestoreGeneration.incrementAndGet();
        settingsProbeRestorePending = false;
        PingTaskSnapshot replaced;
        synchronized (pingControl) {
            replaced = detachPingLocked();
            pingGeneration.incrementAndGet();
            cancelReplacedFutureLocked(replaced);
            Future<?> queuedRestore = pingRestoreFuture;
            pingRestoreFuture = null;
            pingRestoreSequence++;
            if (queuedRestore != null) queuedRestore.cancel(false);
            Future<?> settingsRestore = settingsProbeRestoreFuture;
            settingsProbeRestoreFuture = null;
            if (settingsRestore != null) settingsRestore.cancel(false);
        }
        boolean gentleNativeCancel = (replaced.future != null
                && replaced.kind == PingKind.PROXY_GET)
                || activeProxyPingTasks.get() > 0L;
        closeReplacedSession(replaced);
        subscriptions.cancelPendingProbesNonBlocking();
        probeResumeGuard = null;
        if ("running".equals(pingState)) {
            pingState = "cancelled";
        }
        return gentleNativeCancel;
    }

    private PingTaskSnapshot detachPingLocked() {
        PingTaskSnapshot snapshot = new PingTaskSnapshot(
                pingFuture, pingKind, pingNodes, pingSocksSession);
        pingFuture = null;
        pingKind = PingKind.NONE;
        pingSocksSession = null;
        pingNodes = new ArrayList<>();
        return snapshot;
    }

    private void cancelReplacedFutureLocked(PingTaskSnapshot replaced) {
        if (replaced != null && replaced.future != null) {
            replaced.future.cancel(replaced.kind.interruptOnCancel());
        }
    }

    private void cancelProbeStatusesLocked(PingTaskSnapshot replaced) {
        if (replaced == null) return;
        if (replaced.kind == PingKind.TCP || replaced.kind == PingKind.PROXY_GET) {
            subscriptions.cancelPendingProbes(replaced.nodes);
        }
    }

    private boolean proxyRestoreContextLocked(PingKind replacedKind) {
        return RuntimePolicy.shouldQueueSettingsProbeRestore(
                false, replacedKind == PingKind.PROXY_GET,
                activeProxyPingTasks.get(), probeResumeGuard != null,
                settingsProbeRestorePending);
    }

    private void queuePingRestoreLocked(RuntimeOperationToken operation) {
        Future<?> previous = pingRestoreFuture;
        pingRestoreFuture = null;
        if (previous != null) previous.cancel(false);
        long sequence = ++pingRestoreSequence;
        try {
            Future<?> submitted = pingExecutor.submit(() -> {
                try {
                    restoreConnectionAfterPing(operation);
                } finally {
                    synchronized (pingControl) {
                        if (pingRestoreSequence == sequence) pingRestoreFuture = null;
                    }
                }
            });
            pingRestoreFuture = submitted;
            // Cover completion between submit() and field publication.
            if (submitted.isDone() && pingRestoreSequence == sequence) {
                pingRestoreFuture = null;
            }
        } catch (RuntimeException rejected) {
        }
    }

    private void closeReplacedSession(PingTaskSnapshot replaced) {
        if (replaced != null) socksProbe.closeSession(replaced.session);
    }

    private void runTcpPing(long token, List<ProtocolParser.Node> nodes) {
        BlockingQueue<Future<ProbeOutcome>> completion = new LinkedBlockingQueue<>();
        List<Future<ProbeOutcome>> futures = new ArrayList<>();
        for (ProtocolParser.Node node : nodes) {
            futures.add(RuntimeExecutors.submitCompletion(pingWorkers, completion,
                    () -> tcpProbe(node),
                    new ProbeOutcome(node, false, -1L, "worker_unavailable")));
        }
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        int remaining = futures.size();
        try {
            while (remaining-- > 0 && isPingCurrent(token)) {
                long wait = deadline - System.nanoTime();
                if (wait <= 0L) break;
                Future<ProbeOutcome> completed = completion.poll(wait, TimeUnit.NANOSECONDS);
                if (completed == null) break;
                publishProbeResult(completed.get());
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Exception error) {
        } finally {
            RuntimeExecutors.cancelAndRemove(pingWorkers, futures);
            if (isPingCurrent(token)) {
                subscriptions.cancelPendingProbes(nodes);
                pingState = "completed";
                invalidateSettings();
            }
            finishPingTask(token);
        }
    }

    private ProbeOutcome tcpProbe(ProtocolParser.Node node) {
        String host = node.outbound.optString("server", "");
        int port = node.outbound.optInt("server_port", 0);
        long started = System.nanoTime();
        long deadline = started + TimeUnit.SECONDS.toNanos(4);
        Future<InetAddress[]> lookup = null;
        try {
            lookup = dnsExecutor.submit(() -> InetAddress.getAllByName(host));
            long dnsWait = deadline - System.nanoTime();
            if (dnsWait <= 0L) throw new TimeoutException("DNS deadline exceeded");
            InetAddress[] addresses = lookup.get(dnsWait, TimeUnit.NANOSECONDS);
            if (addresses == null || addresses.length == 0) {
                throw new IllegalStateException("DNS returned no addresses");
            }
            Exception last = null;
            for (InetAddress address : addresses) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0L) throw new TimeoutException("TCP deadline exceeded");
                try (java.net.Socket socket = new java.net.Socket()) {
                    int timeout = (int) Math.max(1L, Math.min(Integer.MAX_VALUE,
                            TimeUnit.NANOSECONDS.toMillis(remaining)));
                    socket.connect(new InetSocketAddress(address, port), timeout);
                    return new ProbeOutcome(node, true,
                            TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started), "ok");
                } catch (Exception error) {
                    last = error;
                }
            }
            if (last != null) throw last;
            throw new IllegalStateException("TCP connection failed");
        } catch (Exception error) {
            return new ProbeOutcome(node, false, -1L,
                    isQuicOnly(node) ? "tcp_failed_quic" : "tcp_failed");
        } finally {
            RuntimeExecutors.cancelAndRemove(dnsExecutor, lookup);
        }
    }

    private void runProxyPing(long token, List<ProtocolParser.Node> nodes,
                              RuntimeOperationToken runtimeOperation,
                              SocksHttpProbe.Session socksSession) {
        activeProxyPingTasks.incrementAndGet();
        try {
            runProxyPingActive(token, nodes, runtimeOperation, socksSession);
        } finally {
            activeProxyPingTasks.decrementAndGet();
        }
    }

    private void runProxyPingActive(long token, List<ProtocolParser.Node> nodes,
                                    RuntimeOperationToken runtimeOperation,
                                    SocksHttpProbe.Session socksSession) {
        long absoluteDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        long probeDeadline = absoluteDeadline - TimeUnit.SECONDS.toNanos(15);
        ProxySession.StateGuard resumeGuard = null;
        boolean pauseAttempted = false;
        boolean externalProxyChanged = false;
        synchronized (lifecycleLock) {
            probePausing = true;
            try {
                if (!isPingCurrent(token)
                        || !revisionGate.isCurrent(runtimeOperation, loaded, settings.enabled)) return;
                // A page probe must not turn into an unbounded core download.
                // The one process-wide Go family must already be mapped by a
                // connection attempt.
                CoreFamily family = nativeCore.loadedFamily();
                if (family == null) {
                    // Say so on every row: silently clearing the statuses left
                    // the user with no idea why nothing was measured.
                    for (ProtocolParser.Node node : nodes) {
                        subscriptions.setProbeResult(
                                node.normalizedKey, "connect_required", -1L);
                        pingCompleted++;
                    }
                    return;
                }
                pauseAttempted = true;
                resumeGuard = pauseConnectionForProbe(
                        absoluteDeadline, token, runtimeOperation);
                probeResumeGuard = resumeGuard;
                List<ProtocolParser.Node> compatible = new ArrayList<>();
                for (ProtocolParser.Node node : nodes) {
                    if (node.supports(family)) {
                        compatible.add(node);
                    } else {
                        subscriptions.setProbeResult(node.normalizedKey, "restart_required", -1L);
                        pingCompleted++;
                    }
                }
                for (int offset = 0; offset < compatible.size() && isPingCurrent(token); offset += 4) {
                    if (!RuntimePolicy.hasProxyProbeBatchBudget(
                            remainingMillis(probeDeadline))) break;
                    int end = Math.min(compatible.size(), offset + 4);
                    List<ProtocolParser.Node> batch = new ArrayList<>(compatible.subList(offset, end));
                    List<Integer> ports = uniqueLoopbackPorts(batch.size());
                    NativeCoreRuntime.StartResult started = nativeCore.start(
                            family, ProbeConfigRenderer.build(family, batch, ports).toString());
                    if (!started.ok) {
                        String status = started.restartRequired ? "restart_required" : "start_failed";
                        for (ProtocolParser.Node node : batch) {
                            subscriptions.setProbeResult(node.normalizedKey, status, -1L);
                            pingCompleted++;
                        }
                        if (nativeCore.isQuarantined()) break;
                        continue;
                    }
                    List<ProbeOutcome> outcomes = probeBatch(
                            batch, ports, token, probeDeadline, socksSession);
                    if (!isPingCurrent(token)) break;
                    for (ProbeOutcome outcome : outcomes) {
                        publishProbeResult(outcome);
                    }
                    nativeCore.stop(Math.min(3_000L, remainingMillis(probeDeadline)));
                    if (nativeCore.isQuarantined()) break;
                }
                subscriptions.cancelPendingProbes(nodes);
            } catch (ProxySession.ExternalProxyChangeException externalChange) {
                externalProxyChanged = true;
                // The full-path check has to borrow Telegram's proxy setting.
                // Something else owns it, and reporting that as "cancelled"
                // told the user nothing about what to do next.
                for (ProtocolParser.Node node : nodes) {
                    subscriptions.setProbeResult(
                            node.normalizedKey, "proxy_busy", -1L);
                    pingCompleted++;
                }
            } catch (Exception error) {
                if (pauseAttempted && resumeGuard == null) {
                    markProbeGuardUnavailable(nodes);
                } else {
                    subscriptions.cancelPendingProbes(nodes);
                }
            } finally {
                if (RuntimePolicy.proxyProbeMayStopCore(
                        loaded, settings.enabled, pingGeneration.get(), token,
                        revisionGate.generation(), runtimeOperation.generation,
                        revisionGate.settingsRevision(), runtimeOperation.settingsRevision)) {
                    nativeCore.stop(Math.min(3_000L, remainingMillis(absoluteDeadline)));
                }
                boolean deferredRestore = false;
                boolean restoreHandled = false;
                if (revisionGate.isCurrent(runtimeOperation, loaded, settings.enabled)
                        && isPingCurrent(token) && resumeGuard != null) {
                    if (remainingMillis(absoluteDeadline) > 2_100L) {
                        restoreHandled = startInternalLocked(
                                runtimeOperation, true, resumeGuard, absoluteDeadline);
                    } else {
                        deferredRestore = scheduleProbeRestore(runtimeOperation);
                        restoreHandled = deferredRestore;
                    }
                } else if (pauseAttempted && resumeGuard == null && loaded
                        && revisionGate.isCurrent(runtimeOperation, loaded, settings.enabled)
                        && isPingCurrent(token)) {
                    if (RuntimePolicy.shouldDisableAfterProbePauseFailure(
                            externalProxyChanged)) {
                        safeExecute(() -> disableFromJava(
                                RuntimePolicy.TELEGRAM_PROXY_CHANGED));
                    } else if (RuntimePolicy.shouldReconnectAfterProbePauseFailure(
                            true, pauseAttempted, externalProxyChanged)) {
                        requestReconnect("probe_guard_unavailable");
                    }
                }
                maybeClearProbeResumeGuard(resumeGuard,
                        RuntimePolicy.shouldClearProbeResumeGuard(loaded, settings.enabled,
                                restoreHandled && !deferredRestore));
                probePausing = false;
                if (isPingCurrent(token)) {
                    // No exit path may leave rows pending: a return taken
                    // before the loop used to strand them on "Checking…"
                    // with nothing left running to resolve them.
                    subscriptions.cancelPendingProbes(nodes);
                    pingState = "completed";
                    invalidateSettings();
                }
                socksProbe.closeSession(socksSession);
                finishPingTask(token);
            }
        }
    }

    private List<ProbeOutcome> probeBatch(List<ProtocolParser.Node> nodes, List<Integer> ports,
                                          long token, long pageDeadline,
                                          SocksHttpProbe.Session socksSession) {
        BlockingQueue<Future<ProbeOutcome>> completion = new LinkedBlockingQueue<>();
        List<Future<ProbeOutcome>> futures = new ArrayList<>();
        SocksHttpProbe.Session batchSession = socksProbe.beginChildSession(socksSession);
        long batchDeadline = Math.min(pageDeadline,
                System.nanoTime() + TimeUnit.SECONDS.toNanos(6));
        for (int i = 0; i < nodes.size(); i++) {
            final ProtocolParser.Node node = nodes.get(i);
            final int port = ports.get(i);
            futures.add(RuntimeExecutors.submitCompletion(pingWorkers, completion, () -> {
                long timeout = Math.min(6_000L, remainingMillis(batchDeadline));
                SocksHttpProbe.Result result = socksProbe.probe(
                        port, "", "", timeout, batchSession);
                return new ProbeOutcome(node, result.ok, result.millis, result.status);
            }, new ProbeOutcome(node, false, -1L, "worker_unavailable")));
        }
        List<ProbeOutcome> outcomes = new ArrayList<>();
        try {
            while (outcomes.size() < futures.size() && isPingCurrent(token)) {
                long wait = batchDeadline - System.nanoTime();
                if (wait <= 0L) break;
                Future<ProbeOutcome> future = completion.poll(wait, TimeUnit.NANOSECONDS);
                if (future == null) break;
                outcomes.add(future.get());
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
        } finally {
            RuntimeExecutors.cancelAndRemove(pingWorkers, futures);
            socksProbe.closeSession(batchSession);
        }
        Set<String> completed = new LinkedHashSet<>();
        for (ProbeOutcome outcome : outcomes) completed.add(outcome.node.normalizedKey);
        for (ProtocolParser.Node node : nodes) {
            if (!completed.contains(node.normalizedKey)) {
                outcomes.add(new ProbeOutcome(node, false, -1L,
                        isPingCurrent(token) ? "timeout" : "cancelled"));
            }
        }
        return outcomes;
    }

    private ProxySession.StateGuard pauseConnectionForProbe(
            long deadline, long pingToken,
            RuntimeOperationToken runtimeOperation) throws Exception {
        ProxySession.StateGuard pendingGuard = probeResumeGuard;
        cancelReconnect();
        RuntimeState state = stateMachine.get();
        if (state == RuntimeState.RUNNING || state == RuntimeState.STARTING
                || state == RuntimeState.ERROR) {
            try {
                stateMachine.transition(RuntimeState.STOPPING);
            } catch (Exception ignored) {
            }
        }
        invalidateSettings();
        ProxySession.RestoreOutcome restoreOutcome = proxySession.restoreForProbe(
                Math.min(2_000L, remainingMillis(deadline)));
        if (restoreOutcome == ProxySession.RestoreOutcome.FAILED) {
            throw new IllegalStateException("Telegram proxy restore deadline exceeded");
        }
        if (restoreOutcome == ProxySession.RestoreOutcome.PRESERVED) {
            throw new ProxySession.ExternalProxyChangeException();
        }
        long captureBudget = Math.min(2_000L, remainingMillis(deadline));
        if (captureBudget <= 0L) {
            throw new IllegalStateException("Telegram proxy guard deadline exceeded");
        }
        ProxySession.StateGuard currentGuard;
        if (restoreOutcome == ProxySession.RestoreOutcome.INACTIVE && pendingGuard == null) {
            currentGuard = proxySession.captureAndRetainState(captureBudget,
                    () -> isPingCurrent(pingToken)
                            && revisionGate.isCurrent(
                            runtimeOperation, loaded, settings.enabled));
            pendingGuard = currentGuard;
            probeResumeGuard = currentGuard;
        } else {
            currentGuard = proxySession.captureState(captureBudget);
        }
        if (!proxySession.probeResumeAllowed(restoreOutcome, pendingGuard, currentGuard)) {
            throw new ProxySession.ExternalProxyChangeException();
        }
        ProxySession.StateGuard guard = pendingGuard == null ? currentGuard : pendingGuard;
        if (!nativeCore.stop(Math.min(3_000L, remainingMillis(deadline)))) {
            throw new IllegalStateException("core stop failed before probe");
        }
        localPort = 0;
        closeCallRelay();
        try {
            if (stateMachine.get() != RuntimeState.STOPPED) {
                stateMachine.transition(RuntimeState.STOPPED);
            }
        } catch (Exception ignored) {
        }
        return guard;
    }

    private void markProbeGuardUnavailable(List<ProtocolParser.Node> nodes) {
        if (nodes == null) return;
        for (ProtocolParser.Node node : nodes) {
            subscriptions.setProbeResult(node.normalizedKey, "guard_unavailable", -1L);
            pingCompleted++;
        }
    }

    private void restoreConnectionAfterPing(RuntimeOperationToken operation) {
        ProxySession.StateGuard guard = probeResumeGuard;
        synchronized (lifecycleLock) {
            if (!loaded || !settings.enabled) {
                maybeClearProbeResumeGuard(guard, true);
                return;
            }
            // updateSettings()/reconnect owns the newer generation and will
            // consume the same guard in startInternal(). Clearing it here
            // would let that later start overwrite a proxy chosen meanwhile.
            long currentGeneration = revisionGate.generation();
            if (RuntimePolicy.shouldTransferProbeResumeGuard(loaded, settings.enabled,
                    currentGeneration, operation.generation)
                    || revisionGate.settingsRevision() != operation.settingsRevision) return;
            if (stateMachine.get() == RuntimeState.RUNNING) {
                maybeClearProbeResumeGuard(guard, true);
                return;
            }
            probePausing = true;
            boolean restored = false;
            try {
                nativeCore.stop(1_000L);
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
                restored = startInternalLocked(operation, true, guard, deadline);
            } finally {
                maybeClearProbeResumeGuard(guard,
                        RuntimePolicy.shouldClearProbeResumeGuard(
                                loaded, settings.enabled, restored));
                probePausing = false;
            }
        }
    }

    private void maybeClearProbeResumeGuard(ProxySession.StateGuard expected,
                                            boolean shouldClear) {
        if (shouldClear && expected != null && probeResumeGuard == expected) {
            probeResumeGuard = null;
        }
    }

    private boolean scheduleProbeRestore(RuntimeOperationToken operation) {
        return safeExecute(() -> restoreConnectionAfterPing(operation));
    }

    private void scheduleSettingsProbeRestore(long requestedRevision) {
        long request = settingsProbeRestoreGeneration.incrementAndGet();
        settingsProbeRestorePending = true;
        RuntimeOperationToken operation = revisionGate.token(
                revisionGate.generation(), requestedRevision);
        synchronized (pingControl) {
            Future<?> previous = settingsProbeRestoreFuture;
            settingsProbeRestoreFuture = null;
            if (previous != null) previous.cancel(false);
            try {
                // pingExecutor is single-threaded: restoration starts only after
                // the cancelled Proxy GET task has returned and cannot race its
                // Go core. Replacing the prior Future keeps rapid setting changes
                // at one running plus one latest restore.
                Future<?> submitted = pingExecutor.submit(() -> {
                    try {
                        restoreConnectionAfterPing(operation);
                    } finally {
                        if (settingsProbeRestoreGeneration.get() == request) {
                            settingsProbeRestorePending = false;
                            synchronized (pingControl) {
                                settingsProbeRestoreFuture = null;
                            }
                        }
                    }
                });
                settingsProbeRestoreFuture = submitted;
                if (submitted.isDone()
                        && settingsProbeRestoreGeneration.get() == request) {
                    settingsProbeRestoreFuture = null;
                    settingsProbeRestorePending = false;
                }
            } catch (RuntimeException rejected) {
                if (settingsProbeRestoreGeneration.get() == request) {
                    settingsProbeRestorePending = false;
                }
            }
        }
    }

    private void publishProbeResult(ProbeOutcome outcome) {
        subscriptions.setProbeResult(outcome.node.normalizedKey,
                outcome.ok ? "ok" : outcome.status, outcome.millis);
        pingCompleted++;
        invalidateSettings();
    }

    private boolean isPingCurrent(long token) {
        return loaded && pingGeneration.get() == token && !Thread.currentThread().isInterrupted();
    }

    private void finishPingTask(long token) {
        synchronized (pingControl) {
            if (pingGeneration.get() != token) return;
            pingFuture = null;
            pingKind = PingKind.NONE;
            pingSocksSession = null;
        }
    }

    enum PingKind {
        NONE,
        TCP,
        PROXY_GET,
        HEALTH;

        boolean interruptOnCancel() {
            return RuntimePolicy.interruptPingOnCancel(name());
        }
    }

    private static final class PingTaskSnapshot {
        final Future<?> future;
        final PingKind kind;
        final List<ProtocolParser.Node> nodes;
        final SocksHttpProbe.Session session;

        PingTaskSnapshot(Future<?> future, PingKind kind,
                         List<ProtocolParser.Node> nodes,
                         SocksHttpProbe.Session session) {
            this.future = future;
            this.kind = kind == null ? PingKind.NONE : kind;
            this.nodes = nodes == null ? new ArrayList<>() : nodes;
            this.session = session;
        }
    }

    private enum ImportSubmission {
        ACCEPTED,
        BUSY,
        STOPPING
    }

    private enum ManualRefreshSubmission {
        STARTED,
        QUEUED,
        DISABLING,
        STOPPING
    }

    private static boolean isQuicOnly(ProtocolParser.Node node) {
        String type = node == null ? "" : node.outbound.optString("type", "");
        return "hysteria".equals(type) || "hysteria2".equals(type) || "tuic".equals(type);
    }

    private static List<Integer> uniqueLoopbackPorts(int count) throws Exception {
        List<Integer> values = new ArrayList<>();
        int attempts = 0;
        while (values.size() < count && attempts++ < 64) {
            int port = findFreeLoopbackPort();
            if (!values.contains(port)) values.add(port);
        }
        if (values.size() != count) throw new IllegalStateException("cannot reserve probe ports");
        return values;
    }

    private static List<String> parseNodeKeys(JSONArray values) {
        if (values == null || values.length() <= 0
                || values.length() > SubscriptionManager.MAX_PING_KEYS) {
            throw new IllegalArgumentException("ping_nodes requires between 1 and "
                    + SubscriptionManager.MAX_PING_KEYS + " exact keys");
        }
        List<String> result = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (int i = 0; i < values.length(); i++) {
            String key = values.optString(i, "");
            if (key.length() != 64 || !key.matches("[0-9a-f]{64}") || !seen.add(key)) {
                throw new IllegalArgumentException("invalid or duplicate node key");
            }
            result.add(key);
        }
        return result;
    }

    private ImportSubmission requestImportText(String text) {
        if (!loaded) return ImportSubmission.STOPPING;
        ImportRequestGate.Ticket ticket = importRequests.tryStart(
                revisionGate.settingsRevision(), settings.providerId);
        if (ticket == null) return ImportSubmission.BUSY;
        try {
            importRunning = true;
            invalidateSettings();
            importFuture = importExecutor.submit(() -> {
                SubscriptionManager.ImportResult result = null;
                Exception failure = null;
                try {
                    result = subscriptions.importText(text);
                } catch (Exception error) {
                    failure = error;
                }
                final SubscriptionManager.ImportResult imported = result;
                final Exception error = failure;
                boolean queued = importRequests.enqueueApply(ticket, this::safeExecute,
                        () -> applyImportResult(ticket, imported, error));
                if (!queued) {
                    importRunning = false;
                    invalidateSettings();
                }
            });
            return ImportSubmission.ACCEPTED;
        } catch (RuntimeException rejected) {
            importRunning = false;
            importRequests.finish(ticket);
            invalidateSettings();
            return loaded ? ImportSubmission.BUSY : ImportSubmission.STOPPING;
        }
    }

    private void applyImportResult(ImportRequestGate.Ticket ticket,
                                   SubscriptionManager.ImportResult result, Exception error) {
        importRunning = false;
        if (!loaded || !importRequests.isLatest(ticket)) return;
        if (error == null && result != null) {
            boolean settingsUnchanged = importRequests.settingsAreCurrent(
                    ticket, revisionGate.settingsRevision(), settings.providerId);
            if (settingsUnchanged && (result.nodes > 0 || result.urls > 0)) {
                switchToCustomProviderFromJava();
            }
            if (settingsUnchanged && settings.enabled
                    && settings.providerId == SettingsModel.CUSTOM_PROVIDER_ID) {
                requestReconnect("import");
            }
        }
        invalidateSettings();
    }

    private ManualRefreshSubmission queueManualSubscriptionRefresh() {
        boolean deferred;
        boolean scheduleRunner;
        synchronized (settingsRequestLock) {
            if (!loaded) return ManualRefreshSubmission.STOPPING;
            long revision = revisionGate.settingsRevision();
            deferred = appliedSettings.hasPendingApply(revision);
            if (deferred && !requestedSettings.enabled) {
                manualRefreshIntent.clear();
                return ManualRefreshSubmission.DISABLING;
            }
            scheduleRunner = manualRefreshIntent.request();
        }
        if (scheduleRunner && !safeExecute(this::flushManualSubscriptionRefresh)) {
            manualRefreshIntent.clear();
            return ManualRefreshSubmission.STOPPING;
        }
        return deferred || !scheduleRunner
                ? ManualRefreshSubmission.QUEUED : ManualRefreshSubmission.STARTED;
    }

    private void schedulePendingManualRefresh() {
        if (!manualRefreshIntent.schedulePending()) return;
        if (!safeExecute(this::flushManualSubscriptionRefresh)) {
            manualRefreshIntent.clear();
        }
    }

    private void flushManualSubscriptionRefresh() {
        if (!manualRefreshIntent.beginRunner()) return;
        boolean deferred = false;
        boolean retry = false;
        synchronized (settingsRequestLock) {
            if (!loaded) {
                manualRefreshIntent.clear();
                return;
            }
            long revision = revisionGate.settingsRevision();
            if (appliedSettings.hasPendingApply(revision)) {
                if (!requestedSettings.enabled) manualRefreshIntent.clear();
                else deferred = true;
            } else {
                RuntimeOperationToken operation = revisionGate.currentToken();
                if (appliedSettings.allows(operation, loaded, revision)) {
                    long attempt = manualRefreshIntent.claim();
                    if (attempt != 0L
                            && !requestSubscriptionRefresh(false, operation, true, attempt)) {
                        manualRefreshIntent.abandon(attempt);
                        retry = true;
                    }
                }
            }
        }
        if (retry) {
            schedulePendingManualRefresh();
        } else if (deferred) {
            invalidateSettings();
        }
    }

    private boolean requestSubscriptionRefresh(boolean requiredForStart,
                                               RuntimeOperationToken operation, boolean announce) {
        return requestSubscriptionRefresh(requiredForStart, operation, announce, 0L);
    }

    private boolean requestSubscriptionRefresh(boolean requiredForStart,
                                               RuntimeOperationToken operation, boolean announce,
                                               long manualAttempt) {
        SettingsModel refreshSettings = settings;
        int provider = refreshSettings.providerId;
        if (!refreshOperationCurrent(operation, provider)) return false;
        long effectiveManualAttempt = manualAttempt;
        boolean claimedPendingForStart = false;
        if (effectiveManualAttempt == 0L && requiredForStart) {
            effectiveManualAttempt = manualRefreshIntent.claim();
            claimedPendingForStart = effectiveManualAttempt != 0L;
        }
        if (effectiveManualAttempt != 0L
                && attachManualRefreshToCurrent(effectiveManualAttempt)) {
            if (announce) {
                invalidateSettings();
            }
            return true;
        }
        RefreshCompletionGate.Ticket ticket;
        RuntimeException submissionFailure = null;
        long absoluteDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        synchronized (subscriptionRefreshControl) {
            if (!refreshOperationCurrent(operation, provider)) {
                if (claimedPendingForStart) {
                    manualRefreshIntent.abandon(effectiveManualAttempt);
                }
                return false;
            }
            abandonManualRefreshLocked(subscriptionRefreshTicket);
            ticket = subscriptionRefreshes.begin(
                    requiredForStart, operation, provider, absoluteDeadline);
            cancelSubscriptionRefreshResourcesLocked();
            subscriptionRefreshTicket = ticket;
            if (effectiveManualAttempt != 0L) {
                manualSubscriptionRefreshTicket = ticket;
                manualSubscriptionRefreshAttempt = effectiveManualAttempt;
            }
            try {
                subscriptionRefreshFuture = subscriptionExecutor.submit(() -> {
                    if (!refreshTicketCurrent(ticket)) return;
                    Exception failure = null;
                    try {
                        subscriptions.refresh(provider, refreshSettings,
                                ticket.deadlineNanos,
                                () -> !refreshTicketCurrent(ticket));
                    } catch (Exception error) {
                        failure = error;
                    }
                    if (!refreshTicketCurrent(ticket)) {
                        cancelSubscriptionRefresh(ticket);
                        return;
                    }
                    final Exception error = failure;
                    if (!safeExecute(() -> applySubscriptionRefresh(ticket, operation,
                            provider, announce, error))) {
                        cancelSubscriptionRefresh(ticket);
                    }
                });
                subscriptionRefreshTimeout = scheduleSubscriptionDeadline(
                        ticket, operation, provider, announce);
                if (subscriptionRefreshTimeout == null) {
                    throw new RejectedExecutionException("subscription timeout was rejected");
                }
            } catch (RuntimeException rejected) {
                submissionFailure = rejected;
                cancelSubscriptionRefreshResourcesLocked();
            }
        }
        if (submissionFailure != null) {
            applySubscriptionRefresh(ticket, operation, provider, announce,
                    new IllegalStateException(I18n.t(
                            "Обновление подписки недоступно",
                            "Subscription refresh unavailable"), submissionFailure));
        } else if (announce) invalidateSettings();
        return true;
    }

    private ScheduledFuture<?> scheduleSubscriptionDeadline(
            RefreshCompletionGate.Ticket ticket, RuntimeOperationToken operation,
            int provider, boolean announce) {
        if (!loaded || ticket == null) return null;
        long delay = Math.max(0L, ticket.deadlineNanos - System.nanoTime());
        try {
            return subscriptionDeadlineExecutor.schedule(() -> {
                Future<?> worker;
                boolean manual;
                synchronized (subscriptionRefreshControl) {
                    if (subscriptionRefreshTicket != ticket
                            || !subscriptionRefreshes.expireAt(
                            ticket, System.nanoTime())) return;
                    boolean contextCurrent = ticket.contextIsCurrent(
                            revisionGate.currentToken(), settings.providerId, loaded);
                    if (contextCurrent) {
                        manual = completeManualRefresh(ticket);
                    } else {
                        abandonManualRefreshLocked(ticket);
                        manual = false;
                    }
                    subscriptionRefreshTicket = null;
                    worker = subscriptionRefreshFuture;
                    subscriptionRefreshFuture = null;
                    subscriptionRefreshTimeout = null;
                }
                if (worker != null) worker.cancel(true);
                subscriptionHttp.cancelActive();
                boolean effectiveAnnounce = announce || manual;
                boolean queued = safeExecute(() -> applySubscriptionRefresh(
                        ticket, operation, provider, effectiveAnnounce,
                        new TimeoutException(
                                "subscription refresh deadline exceeded"), true));
            }, delay, TimeUnit.NANOSECONDS);
        } catch (RejectedExecutionException rejected) {
            return null;
        }
    }

    private void applySubscriptionRefresh(RefreshCompletionGate.Ticket ticket,
                                          RuntimeOperationToken operation, int provider,
                                          boolean announce, Exception error) {
        applySubscriptionRefresh(ticket, operation, provider,
                announce, error, false);
    }

    private void applySubscriptionRefresh(RefreshCompletionGate.Ticket ticket,
                                          RuntimeOperationToken operation, int provider,
                                          boolean announce, Exception error,
                                          boolean terminalAlreadyClaimed) {
        boolean startRequired = false;
        boolean reconnect = false;
        synchronized (settingsRequestLock) {
            RuntimeOperationToken current = revisionGate.currentToken();
            boolean contextCurrent = ticket.contextIsCurrent(
                    current, settings.providerId, loaded);
            boolean terminalValid = terminalAlreadyClaimed
                    && subscriptionRefreshes.isTerminal(ticket);
            if (!contextCurrent) {
                if (!subscriptionRefreshes.isTerminal(ticket)) {
                    cancelSubscriptionRefresh(ticket);
                }
                return;
            }
            if (terminalAlreadyClaimed) {
                if (!terminalValid) return;
            } else if (!claimSubscriptionRefresh(
                    ticket, current, settings.providerId)) {
                // A dedicated deadline may already own this ticket and have
                // queued its failure behind an earlier worker completion. Do
                // not let that stale success cancel the terminal timeout.
                if (!subscriptionRefreshes.isTerminal(ticket)
                        && !ticket.deadlineReached(System.nanoTime())) {
                    cancelSubscriptionRefresh(ticket);
                }
                return;
            }
            boolean effectiveAnnounce = announce || completeManualRefresh(ticket);
            boolean requiredForStart = ticket.requiredForStart;
            if (error != null) {
                if (effectiveAnnounce || requiredForStart) {
                    invalidateSettings();
                }
                if (requiredForStart && settings.enabled) {
                    fail(error);
                    scheduleReconnect(operation, nextReconnectDelay());
                }
                return;
            }
            ProtocolParser.Node reselected = subscriptions.selected(provider);
            if (effectiveAnnounce) invalidateSettings();
            if (settings.enabled) {
                startRequired = requiredForStart;
                // Reconnecting after every refresh tore down a healthy
                // connection each time the list reloaded, and a source that
                // never refreshes successfully keeps the provider stale, so
                // the next start refreshed again and the connection dropped
                // in a loop. Only a changed active configuration justifies it.
                reconnect = !requiredForStart
                        && RuntimePolicy.activeConfigurationChanged(activeNode, reselected);
            }
        }
        if (startRequired) startInternal(operation);
        else if (reconnect) requestReconnect("subscription_refresh");
    }

    private boolean refreshOperationCurrent(RuntimeOperationToken operation, int provider) {
        return appliedSettings.allows(operation, loaded,
                revisionGate.settingsRevision())
                && settings.providerId == provider
                && revisionGate.generation() == operation.generation
                && revisionGate.settingsRevision() == operation.settingsRevision;
    }

    private boolean refreshTicketCurrent(RefreshCompletionGate.Ticket ticket) {
        return ticket != null && subscriptionRefreshes.isPending(ticket)
                && ticket.contextIsCurrent(revisionGate.currentToken(),
                settings.providerId, loaded);
    }

    private boolean claimSubscriptionRefresh(RefreshCompletionGate.Ticket ticket,
                                             RuntimeOperationToken current,
                                             int provider) {
        ScheduledFuture<?> timeout;
        synchronized (subscriptionRefreshControl) {
            if (subscriptionRefreshTicket != ticket
                    || !subscriptionRefreshes.claimIfCurrent(
                    ticket, current, provider, loaded)) return false;
            subscriptionRefreshTicket = null;
            subscriptionRefreshFuture = null;
            timeout = subscriptionRefreshTimeout;
            subscriptionRefreshTimeout = null;
        }
        if (timeout != null) timeout.cancel(false);
        return true;
    }

    private void cancelSubscriptionRefresh() {
        synchronized (subscriptionRefreshControl) {
            cancelSubscriptionRefreshLocked();
        }
    }

    private void cancelSubscriptionRefreshLocked() {
        subscriptionRefreshes.cancel();
        abandonManualRefreshLocked(manualSubscriptionRefreshTicket);
        subscriptionRefreshTicket = null;
        cancelSubscriptionRefreshResourcesLocked();
    }

    private void cancelSubscriptionRefresh(RefreshCompletionGate.Ticket ticket) {
        synchronized (subscriptionRefreshControl) {
            if (subscriptionRefreshTicket != ticket) return;
            subscriptionRefreshes.cancel();
            abandonManualRefreshLocked(manualSubscriptionRefreshTicket);
            subscriptionRefreshTicket = null;
            cancelSubscriptionRefreshResourcesLocked();
        }
    }

    private boolean attachManualRefreshToCurrent(long attempt) {
        synchronized (subscriptionRefreshControl) {
            RefreshCompletionGate.Ticket current = subscriptionRefreshTicket;
            if (attempt == 0L || current == null || !refreshTicketCurrent(current)
                    || manualSubscriptionRefreshTicket != null) return false;
            manualSubscriptionRefreshTicket = current;
            manualSubscriptionRefreshAttempt = attempt;
            return true;
        }
    }

    private boolean completeManualRefresh(RefreshCompletionGate.Ticket ticket) {
        synchronized (subscriptionRefreshControl) {
            if (ticket == null || manualSubscriptionRefreshTicket != ticket) return false;
            manualRefreshIntent.complete(manualSubscriptionRefreshAttempt);
            manualSubscriptionRefreshTicket = null;
            manualSubscriptionRefreshAttempt = 0L;
            return true;
        }
    }

    private void abandonManualRefreshLocked(RefreshCompletionGate.Ticket ticket) {
        if (ticket == null || manualSubscriptionRefreshTicket != ticket) return;
        manualRefreshIntent.abandon(manualSubscriptionRefreshAttempt);
        manualSubscriptionRefreshTicket = null;
        manualSubscriptionRefreshAttempt = 0L;
    }

    private void cancelSubscriptionRefreshResourcesLocked() {
        Future<?> worker = subscriptionRefreshFuture;
        subscriptionRefreshFuture = null;
        if (worker != null) worker.cancel(true);
        ScheduledFuture<?> timeout = subscriptionRefreshTimeout;
        subscriptionRefreshTimeout = null;
        if (timeout != null) timeout.cancel(false);
        subscriptionHttp.cancelActive();
    }

    private boolean checkCoreUpdate(CoreFamily family) {
        if (!loaded) return isCoreUsable(family);
        verifyCoreReadinessIfNeeded(family);
        try {
            boolean changed = nativeCore.checkForUpdate(family, false);
            markCoreReadinessVerified(family);
            if (changed) reconnectAfterCoreInstall(family);
        } catch (Exception ignored) {
        }
        return isCoreUsable(family);
    }

    private boolean coreInstallRequired() {
        return RuntimePolicy.needsCoreInstall(
                isCoreUsable(CoreFamily.SING_BOX),
                isCoreUsable(CoreFamily.XRAY));
    }

    private boolean hasAnyUsableCore() {
        return RuntimePolicy.mayRunAutomaticCoreMaintenance(
                isCoreUsable(CoreFamily.SING_BOX),
                isCoreUsable(CoreFamily.XRAY));
    }

    private boolean isCoreUsable(CoreFamily family) {
        int mask = coreMask(family);
        return initialCoreInspectionComplete
                && mask != 0
                && (verifiedCoreReadinessMask.get() & mask) != 0
                && nativeCore.hasUsableCore(family);
    }

    private void markCoreReadinessVerified(CoreFamily family) {
        int mask = coreMask(family);
        if (mask != 0) {
            verifiedCoreReadinessMask.getAndUpdate(value -> value | mask);
        }
    }

    private void verifyCoreReadinessIfNeeded(CoreFamily family) {
        int mask = coreMask(family);
        if (mask == 0 || (verifiedCoreReadinessMask.get() & mask) != 0) return;
        try {
            nativeCore.verifyLocalReadiness(family);
            markCoreReadinessVerified(family);
        } catch (Exception ignored) {
        }
    }

    private void requestInitialCoreInspection() {
        if (initialCoreInspectionComplete) return;
        safeCoreExecute(0, this::runInitialCoreInspection);
    }

    private void runInitialCoreInspection() {
        try {
            nativeCore.verifyLocalReadiness(CoreFamily.SING_BOX);
            markCoreReadinessVerified(CoreFamily.SING_BOX);
        } catch (Exception ignored) {
        }
        if (!loaded) return;
        try {
            nativeCore.verifyLocalReadiness(CoreFamily.XRAY);
            markCoreReadinessVerified(CoreFamily.XRAY);
        } catch (Exception ignored) {
        }
        if (!loaded) return;
        initialCoreInspectionComplete = true;
        requestDashboardRefresh();
        requestCoreMaintenance();
        if (isCoreUsable(CoreFamily.SING_BOX)) {
            reconnectAfterCoreInstall(CoreFamily.SING_BOX);
        }
        if (isCoreUsable(CoreFamily.XRAY)) {
            reconnectAfterCoreInstall(CoreFamily.XRAY);
        }
    }

    private void attemptExplicitCoreInstall() {
        if (!initialCoreInspectionComplete) {
            requestInitialCoreInspection();
            return;
        }
        CoreInstallSession.Snapshot snapshot = coreInstallSession.snapshot();
        if (snapshot.state != CoreInstallSession.State.QUEUED) return;
        synchronized (corePreparationLock) {
            snapshot = coreInstallSession.snapshot();
            if (!loaded || snapshot.state != CoreInstallSession.State.QUEUED
                    || coreOperationRunning.get()) return;
            cancelCoreRepairRetryLocked(CoreFamily.SING_BOX, true);
            cancelCoreRepairRetryLocked(CoreFamily.XRAY, true);
            final long installGeneration = snapshot.generation;
            if (safeCoreExecute(CORE_MASK_ALL,
                    () -> runExplicitCoreInstall(installGeneration))) {
                coreMaintenancePendingMask &= ~CORE_MASK_ALL;
            }
        }
    }

    private void runExplicitCoreInstall(long installGeneration) {
        if (!loaded || !coreInstallSession.begin(installGeneration)) return;
        publishCoreInstall(installGeneration, 0, CoreInstallSession.Stage.PREPARING);
        boolean singBoxReady = installCoreFamily(
                installGeneration, CoreFamily.SING_BOX, 0, 50);
        if (!coreInstallSession.isActive(installGeneration)) return;
        boolean xrayReady = installCoreFamily(
                installGeneration, CoreFamily.XRAY, 50, 100);
        if (!coreInstallSession.isActive(installGeneration)) return;
        safeExecute(() -> finishExplicitCoreInstall(
                installGeneration, singBoxReady, xrayReady));
    }

    private boolean installCoreFamily(long installGeneration, CoreFamily family,
                                      int segmentStart, int segmentEnd) {
        if (!loaded || !coreInstallSession.isActive(installGeneration)) return false;
        publishCoreInstall(installGeneration, segmentStart,
                CoreInstallSession.Stage.PREPARING);
        try {
            nativeCore.verifyLocalReadiness(family);
            markCoreReadinessVerified(family);
        } catch (Exception ignored) {
        }
        boolean mayPromoteLocalCandidate = nativeCore.loadedFamily() != family;
        if (mayPromoteLocalCandidate) {
            try {
                nativeCore.prepareLocalCore(family);
                markCoreReadinessVerified(family);
            } catch (Exception ignored) {
            }
        }
        if (!loaded || !coreInstallSession.isActive(installGeneration)) return false;
        try {
            nativeCore.checkForUpdate(family, false,
                    explicitInstallObserver(installGeneration, segmentStart, segmentEnd));
            markCoreReadinessVerified(family);
        } catch (Exception ignored) {
            // A previously verified local core still counts as a successful
            // segment when only its optional network refresh failed.
        }
        if (!loaded || !coreInstallSession.isActive(installGeneration)) return false;
        publishCoreInstall(installGeneration, segmentEnd - 2,
                CoreInstallSession.Stage.VERIFYING);
        if (mayPromoteLocalCandidate) {
            try {
                nativeCore.prepareLocalCore(family);
                markCoreReadinessVerified(family);
            } catch (Exception ignored) {
            }
        }
        boolean usable = isCoreUsable(family);
        publishCoreInstall(installGeneration, segmentEnd,
                CoreInstallSession.Stage.VERIFYING);
        return usable;
    }

    private CoreUpdater.UpdateObserver explicitInstallObserver(
            long installGeneration, int segmentStart, int segmentEnd) {
        final int span = Math.max(1, segmentEnd - segmentStart);
        final int downloadStart = segmentStart + Math.max(1, span / 10);
        final int downloadEnd = Math.max(downloadStart, segmentEnd - Math.max(2, span / 10));
        return new CoreUpdater.UpdateObserver() {
            @Override
            public void onStage(CoreUpdater.UpdateStage stage) {
                if (stage == CoreUpdater.UpdateStage.DOWNLOADING) {
                    publishCoreInstall(installGeneration, downloadStart,
                            CoreInstallSession.Stage.DOWNLOADING);
                } else if (stage == CoreUpdater.UpdateStage.VERIFYING) {
                    publishCoreInstall(installGeneration, segmentEnd - 2,
                            CoreInstallSession.Stage.VERIFYING);
                } else {
                    publishCoreInstall(installGeneration, segmentStart,
                            CoreInstallSession.Stage.PREPARING);
                }
            }

            @Override
            public void onProgress(long downloadedBytes, long totalBytes) {
                if (totalBytes <= 0L) {
                    publishCoreInstall(installGeneration, downloadStart,
                            CoreInstallSession.Stage.DOWNLOADING);
                    return;
                }
                double ratio = Math.min(1d,
                        Math.max(0d, (double) downloadedBytes / (double) totalBytes));
                int progress = downloadStart
                        + (int) Math.floor((downloadEnd - downloadStart) * ratio);
                publishCoreInstall(installGeneration, progress,
                        CoreInstallSession.Stage.DOWNLOADING);
            }
        };
    }

    private void publishCoreInstall(long installGeneration, int progress,
                                    CoreInstallSession.Stage stage) {
        if (coreInstallSession.publish(installGeneration, progress, stage)) {
            requestDashboardRefresh();
        }
    }

    private void finishExplicitCoreInstall(long installGeneration,
                                           boolean singBoxReady, boolean xrayReady) {
        if (!loaded || !coreInstallSession.isActive(installGeneration)) return;
        // Re-read readiness after the worker completes: another verified
        // local promotion may have made a family ready while its network
        // request was winding down.
        singBoxReady |= isCoreUsable(CoreFamily.SING_BOX);
        xrayReady |= isCoreUsable(CoreFamily.XRAY);
        int readyCount = RuntimePolicy.readyCoreCount(singBoxReady, xrayReady);
        // Keep the session active while settling the selected-server request:
        // cancelCorePreparation() may drain pending maintenance immediately,
        // which would otherwise bypass the repair backoff after a partial
        // manual result.
        settleCorePreparationAfterExplicitInstall(singBoxReady, xrayReady);
        if (!coreInstallSession.finish(installGeneration, readyCount)) return;
        handleCoreRepairResult(CoreFamily.SING_BOX, singBoxReady);
        handleCoreRepairResult(CoreFamily.XRAY, xrayReady);
        if (singBoxReady) reconnectAfterCoreInstall(CoreFamily.SING_BOX);
        if (xrayReady) reconnectAfterCoreInstall(CoreFamily.XRAY);
        requestDashboardRefresh();
    }

    private void settleCorePreparationAfterExplicitInstall(
            boolean singBoxReady, boolean xrayReady) {
        CorePreparationGate.Request request;
        synchronized (corePreparationLock) {
            request = corePreparations.current();
        }
        if (request == null) return;
        boolean usable = request.family == CoreFamily.SING_BOX
                ? singBoxReady : xrayReady;
        finishCorePreparation(request, usable);
    }

    private void checkCoreUpdateAndSettle(CoreFamily family) {
        boolean usable = checkCoreUpdate(family);
        handleCoreRepairResult(family, usable);
        requestDashboardRefresh();
        CorePreparationGate.Request request;
        synchronized (corePreparationLock) {
            request = corePreparations.current();
            if (request == null || request.family != family) return;
        }
        if (!safeExecute(() -> finishCorePreparation(request, usable))) {
            corePreparationInFlight.set(false);
        }
    }

    private void reconnectAfterCoreInstall(CoreFamily family) {
        try {
            ProtocolParser.Node selected = subscriptions.selected(settings.providerId);
            if (selected == null) return;
            CoreFamily selectedFamily = CoreSelector.select(selected,
                    nativeCore.loadedFamily(),
                    isCoreUsable(CoreFamily.SING_BOX),
                    isCoreUsable(CoreFamily.XRAY),
                    providerCoverage());
            if (RuntimePolicy.shouldReconnectAfterCoreInstall(
                    loaded, settings.enabled, nativeCore.loadedFamily(),
                    selectedFamily, family)) {
                requestReconnect("core_installed");
            }
        } catch (Exception ignored) {
        }
    }

    private void scheduledCoreCheck() {
        requestCoreMaintenance();
    }

    private void handleCoreRepairResult(CoreFamily family, boolean usable) {
        synchronized (corePreparationLock) {
            // A tick or an already-fired retry may have queued this family
            // while another operation owned the executor. This completed
            // attempt covers that request; a failure's backoff timer becomes
            // the only authority for the next network check.
            coreMaintenancePendingMask &= ~coreMask(family);
            if (usable) {
                // Keep pending-bit settlement and timer invalidation atomic:
                // an already-firing callback must either run before both or
                // observe the incremented generation after both.
                cancelCoreRepairRetryLocked(family, true);
                return;
            }
            CorePreparationGate.Request preparation = corePreparations.current();
            if (preparation != null && preparation.family == family
                    && corePreparationRetry != null) {
                return;
            }
        }
        scheduleCoreRepairRetry(family);
    }

    private void scheduleCoreRepairRetry(CoreFamily family) {
        if (family == null || !loaded || isCoreUsable(family)
                || !hasAnyUsableCore()) return;
        synchronized (corePreparationLock) {
            if (!loaded || isCoreUsable(family) || !hasAnyUsableCore()
                    || coreInstallSession.isActive()) return;
            if (family == CoreFamily.SING_BOX) {
                if (singBoxRepairRetry != null) return;
                long token = ++singBoxRepairGeneration;
                long delay = singBoxRepairBackoff.nextDelaySeconds();
                singBoxRepairRetry = safeSchedule(
                        () -> runCoreRepairRetry(family, token),
                        delay, TimeUnit.SECONDS);
            } else if (family == CoreFamily.XRAY) {
                if (xrayRepairRetry != null) return;
                long token = ++xrayRepairGeneration;
                long delay = xrayRepairBackoff.nextDelaySeconds();
                xrayRepairRetry = safeSchedule(
                        () -> runCoreRepairRetry(family, token),
                        delay, TimeUnit.SECONDS);
            }
        }
    }

    private void runCoreRepairRetry(CoreFamily family, long expectedGeneration) {
        int mask = coreMask(family);
        if (mask == 0) return;
        synchronized (corePreparationLock) {
            if (!loaded) return;
            if (family == CoreFamily.SING_BOX) {
                if (singBoxRepairGeneration != expectedGeneration) return;
                singBoxRepairRetry = null;
            } else if (family == CoreFamily.XRAY) {
                if (xrayRepairGeneration != expectedGeneration) return;
                xrayRepairRetry = null;
            } else {
                return;
            }
            // The retry delay has elapsed, so retain its authority even when
            // a longer two-family operation still advertises this family in
            // coreOperationCoverageMask. requestCoreMaintenance() normally
            // masks covered work; writing the due bit here lets the current
            // operation's final drain run it, while its own terminal result
            // can still clear the bit as already satisfied.
            coreMaintenancePendingMask |= mask;
        }
        attemptCoreMaintenance();
    }

    private void resetCoreRepairBackoff() {
        int missingMask = 0;
        synchronized (corePreparationLock) {
            cancelCoreRepairRetryLocked(CoreFamily.SING_BOX, true);
            cancelCoreRepairRetryLocked(CoreFamily.XRAY, true);
            if (!isCoreUsable(CoreFamily.SING_BOX)) {
                missingMask |= CORE_MASK_SING_BOX;
            }
            if (!isCoreUsable(CoreFamily.XRAY)) {
                missingMask |= CORE_MASK_XRAY;
            }
        }
        if (missingMask != 0 && hasAnyUsableCore()) {
            requestCoreMaintenance(missingMask);
        }
    }

    private void cancelCoreRepairRetry(CoreFamily family, boolean resetBackoff) {
        synchronized (corePreparationLock) {
            cancelCoreRepairRetryLocked(family, resetBackoff);
        }
    }

    private void cancelCoreRepairRetryLocked(CoreFamily family, boolean resetBackoff) {
        if (family == CoreFamily.SING_BOX) {
            singBoxRepairGeneration++;
            ScheduledFuture<?> retry = singBoxRepairRetry;
            singBoxRepairRetry = null;
            if (retry != null) retry.cancel(false);
            if (resetBackoff) singBoxRepairBackoff.reset();
        } else if (family == CoreFamily.XRAY) {
            xrayRepairGeneration++;
            ScheduledFuture<?> retry = xrayRepairRetry;
            xrayRepairRetry = null;
            if (retry != null) retry.cancel(false);
            if (resetBackoff) xrayRepairBackoff.reset();
        }
    }

    private void requestCoreMaintenance() {
        requestCoreMaintenance(CORE_MASK_ALL);
    }

    private void requestCoreMaintenance(int requestedMask) {
        if (!hasAnyUsableCore()) return;
        synchronized (corePreparationLock) {
            if (!loaded) return;
            coreMaintenancePendingMask |= requestedMask
                    & CORE_MASK_ALL & ~coreOperationCoverageMask;
        }
        attemptCoreMaintenance();
    }

    private void attemptCoreMaintenance() {
        synchronized (corePreparationLock) {
            if (!loaded || coreInstallSession.isActive()
                    || coreMaintenancePendingMask == 0) return;
            if (!hasAnyUsableCore()) {
                coreMaintenancePendingMask = 0;
                return;
            }
            int claimedMask = coreMaintenancePendingMask;
            CorePreparationGate.Request preparation = corePreparations.current();
            if (corePreparationRetry != null && preparation != null) {
                // A periodic check must not bypass the install retry deadline.
                // Keep this family pending; the scheduled preparation will
                // consume it when it makes the real update attempt.
                claimedMask &= ~coreMask(preparation.family);
            }
            if (singBoxRepairRetry != null) claimedMask &= ~CORE_MASK_SING_BOX;
            if (xrayRepairRetry != null) claimedMask &= ~CORE_MASK_XRAY;
            if (claimedMask == 0) return;
            final int admittedMask = claimedMask;
            if (safeCoreExecute(admittedMask, () -> runCoreMaintenance(admittedMask))) {
                coreMaintenancePendingMask &= ~admittedMask;
            }
        }
    }

    private void runCoreMaintenance(int mask) {
        if ((mask & CORE_MASK_SING_BOX) != 0) {
            checkCoreUpdateAndSettle(CoreFamily.SING_BOX);
        }
        if ((mask & CORE_MASK_XRAY) != 0) {
            checkCoreUpdateAndSettle(CoreFamily.XRAY);
        }
    }

    private static int coreMask(CoreFamily family) {
        if (family == CoreFamily.SING_BOX) return CORE_MASK_SING_BOX;
        if (family == CoreFamily.XRAY) return CORE_MASK_XRAY;
        return 0;
    }

    private void drainCoreWork() {
        if (!initialCoreInspectionComplete) {
            requestInitialCoreInspection();
            return;
        }
        attemptExplicitCoreInstall();
        attemptCoreMaintenance();
        attemptCorePreparation();
    }

    private void requestCorePreparation(CoreFamily family, String nodeKey) {
        if (!loaded || !settings.enabled || family == null
                || nodeKey == null || nodeKey.isEmpty()) return;
        if (!hasAnyUsableCore() && !coreInstallSession.isActive()) return;
        synchronized (corePreparationLock) {
            if (!loaded || !settings.enabled) return;
            CorePreparationGate.Request current = corePreparations.current();
            if (current == null || current.family != family
                    || !current.nodeKey.equals(nodeKey)) {
                cancelCorePreparationLocked();
                coreInstallBackoff.reset();
                corePreparations.request(family, nodeKey);
            }
        }
        attemptCorePreparation();
    }

    private void attemptCorePreparation() {
        CorePreparationGate.Request request;
        synchronized (corePreparationLock) {
            request = corePreparations.current();
            if (request == null || corePreparationRetry != null
                    || !loaded || !settings.enabled
                    || coreInstallSession.isActive()
                    || !hasAnyUsableCore()) return;
        }
        if (isCoreUsable(request.family)) {
            finishCorePreparation(request, true);
            return;
        }
        if (coreOperationRunning.get()
                || !corePreparationInFlight.compareAndSet(false, true)) return;
        if (!safeCoreExecute(0,
                () -> runCorePreparation(request))) {
            corePreparationInFlight.set(false);
        }
    }

    private void runCorePreparation(CorePreparationGate.Request request) {
        if (!isCurrentCorePreparation(request)
                || !corePreparationMatchesSelection(request)) {
            if (!safeExecute(() -> finishCorePreparation(request, false))) {
                corePreparationInFlight.set(false);
            }
            return;
        }
        try {
            nativeCore.prepareLocalCore(request.family);
            markCoreReadinessVerified(request.family);
        } catch (Exception ignored) {
        }
        boolean usable = isCoreUsable(request.family);
        if (beginCoreUpdateCheck(request.family, !usable)) {
            try {
                nativeCore.checkForUpdate(request.family, false);
                markCoreReadinessVerified(request.family);
            } catch (Exception ignored) {
            }
            usable = isCoreUsable(request.family);
        }
        final boolean prepared = usable;
        if (!safeExecute(() -> finishCorePreparation(request, prepared))) {
            corePreparationInFlight.set(false);
        }
    }

    private boolean beginCoreUpdateCheck(CoreFamily family, boolean requiredForPreparation) {
        int mask = coreMask(family);
        if (mask == 0) return false;
        synchronized (corePreparationLock) {
            if (!loaded) return false;
            boolean maintenanceDue = (coreMaintenancePendingMask & mask) != 0;
            if (!requiredForPreparation && !maintenanceDue) return false;
            // Only a real update attempt consumes a pending maintenance bit.
            // Marking coverage here also lets a tick that arrives during the
            // request queue the other family without duplicating this one.
            coreMaintenancePendingMask &= ~mask;
            coreOperationCoverageMask |= mask;
            return true;
        }
    }

    private void finishCorePreparation(CorePreparationGate.Request request, boolean usable) {
        corePreparationInFlight.set(false);
        if (!isCurrentCorePreparation(request)) {
            attemptCorePreparation();
            return;
        }
        if (!corePreparationMatchesSelection(request)) {
            cancelCorePreparation(true);
            if (loaded && settings.enabled && nativeCore.loadedFamily() == null) {
                requestReconnect("core_selection_changed");
            }
            return;
        }
        if (usable) {
            handleCoreRepairResult(request.family, true);
            cancelCorePreparation(true);
            CoreFamily loadedFamily = nativeCore.loadedFamily();
            restartRequired = CoreProcessState.requiresRestart(
                    loadedFamily, request.family);
            requestDashboardRefresh();
            if (RuntimePolicy.shouldReconnectAfterCoreInstall(
                    loaded, settings.enabled, loadedFamily,
                    request.family, request.family)) {
                requestReconnect("core_installed");
            }
            return;
        }
        scheduleCorePreparationRetry(request);
        requestDashboardRefresh();
    }

    private boolean corePreparationMatchesSelection(CorePreparationGate.Request request) {
        if (!loaded || !settings.enabled || request == null) return false;
        try {
            ProtocolParser.Node selected = subscriptions.selected(settings.providerId);
            if (selected == null || !request.nodeKey.equals(selected.normalizedKey)) {
                return false;
            }
            return CoreSelector.select(selected, nativeCore.loadedFamily(),
                    isCoreUsable(CoreFamily.SING_BOX),
                    isCoreUsable(CoreFamily.XRAY),
                    providerCoverage()) == request.family;
        } catch (Exception ignored) {
            return false;
        }
    }

    private void scheduleCorePreparationRetry(CorePreparationGate.Request request) {
        synchronized (corePreparationLock) {
            if (!isCurrentCorePreparationLocked(request)
                    || corePreparationRetry != null) return;
            long delay = coreInstallBackoff.nextDelaySeconds();
            corePreparationRetry = safeSchedule(() -> {
                synchronized (corePreparationLock) {
                    if (!isCurrentCorePreparationLocked(request)) return;
                    corePreparationRetry = null;
                }
                attemptCorePreparation();
            }, delay, TimeUnit.SECONDS);
        }
    }

    private void resetCorePreparationBackoff() {
        boolean pending;
        synchronized (corePreparationLock) {
            coreInstallBackoff.reset();
            ScheduledFuture<?> retry = corePreparationRetry;
            corePreparationRetry = null;
            if (retry != null) retry.cancel(false);
            pending = corePreparations.current() != null;
        }
        if (pending) attemptCorePreparation();
    }

    private void clearCorePreparation(CoreFamily family, String nodeKey) {
        synchronized (corePreparationLock) {
            CorePreparationGate.Request current = corePreparations.current();
            if (current == null || current.family != family
                    || !current.nodeKey.equals(nodeKey)) return;
            cancelCorePreparationLocked();
            coreInstallBackoff.reset();
        }
        attemptCoreMaintenance();
    }

    private void cancelCorePreparation(boolean resetBackoff) {
        synchronized (corePreparationLock) {
            cancelCorePreparationLocked();
            if (resetBackoff) coreInstallBackoff.reset();
        }
        attemptCoreMaintenance();
    }

    private void cancelCorePreparationLocked() {
        corePreparations.cancel();
        ScheduledFuture<?> retry = corePreparationRetry;
        corePreparationRetry = null;
        if (retry != null) retry.cancel(false);
    }

    private boolean isCurrentCorePreparation(CorePreparationGate.Request request) {
        synchronized (corePreparationLock) {
            return isCurrentCorePreparationLocked(request);
        }
    }

    private boolean isCurrentCorePreparationLocked(CorePreparationGate.Request request) {
        return corePreparations.isCurrent(request);
    }

    private void healthTick() {
        if (!loaded || !settings.enabled || stateMachine.get() != RuntimeState.RUNNING
                || "running".equals(pingState)) return;
        long healthGeneration = generation.get();
        synchronized (pingControl) {
            if (pingKind != PingKind.NONE) return;
            long token = pingGeneration.incrementAndGet();
            pingKind = PingKind.HEALTH;
            pingSocksSession = null;
            try {
                pingFuture = pingExecutor.submit(
                        () -> runHealthCheck(token, healthGeneration));
            } catch (RuntimeException rejected) {
                pingKind = PingKind.NONE;
                pingSocksSession = null;
            }
        }
    }

    private void runHealthCheck(long token, long healthGeneration) {
        ProxySession.Ownership ownership;
        boolean runtimeHealthy;
        try {
            ownership = proxySession.ownership();
            if (!isPingCurrent(token)) return;
            int checkedPort = localPort;
            runtimeHealthy = checkedPort > 0 && nativeCore.isRunning()
                    && isLoopbackListening(checkedPort);
        } catch (Throwable error) {
            return;
        } finally {
            finishPingTask(token);
        }
        try {
            safeExecute(() -> applyHealthResult(token, healthGeneration,
                    ownership, runtimeHealthy));
        } catch (RuntimeException ignored) {
        }
    }

    private void applyHealthResult(long token, long healthGeneration,
                                   ProxySession.Ownership ownership,
                                   boolean runtimeHealthy) {
        if (!loaded || generation.get() != healthGeneration
                || pingGeneration.get() != token
                || stateMachine.get() != RuntimeState.RUNNING
                || "running".equals(pingState)) return;
        if (ownership == ProxySession.Ownership.EXTERNALLY_CHANGED) {
            disableFromJava(RuntimePolicy.TELEGRAM_PROXY_CHANGED);
            return;
        }
        if (ownership != ProxySession.Ownership.OWNED || !runtimeHealthy) {
            requestReconnect("health_runtime");
        }
    }

    private void transition(RuntimeState state) {
        stateMachine.transition(state);
        invalidateSettings();
    }

    private void invalidateSettings() {
        if (!loaded) return;
        requestDashboardRefresh();
    }

    private void requestDashboardRefresh() {
        synchronized (dashboardRefreshLock) {
            if (!loaded || dashboardRefreshFuture != null) return;
            long delay = DashboardRefreshThrottle.delayNanos(
                    System.nanoTime(), lastDashboardRefreshNanos);
            try {
                // Scheduling while holding the lock prevents a zero-delay task
                // from running before dashboardRefreshFuture is assigned.
                dashboardRefreshFuture = coordinator.schedule(
                        this::deliverDashboardRefresh, delay, TimeUnit.NANOSECONDS);
            } catch (RejectedExecutionException ignored) {
                dashboardRefreshFuture = null;
            }
        }
    }

    private void deliverDashboardRefresh() {
        synchronized (dashboardRefreshLock) {
            dashboardRefreshFuture = null;
            if (!loaded) return;
            lastDashboardRefreshNanos = System.nanoTime();
        }
        ExitFyBridge.notifyUiListeners();
    }

    private void cancelDashboardRefresh() {
        synchronized (dashboardRefreshLock) {
            ScheduledFuture<?> pending = dashboardRefreshFuture;
            dashboardRefreshFuture = null;
            if (pending != null) pending.cancel(false);
        }
    }

    private boolean safeExecute(Runnable task) {
        if (!loaded || task == null) return false;
        try {
            coordinator.execute(task);
            return true;
        } catch (RejectedExecutionException rejected) {
            return false;
        }
    }

    private ScheduledFuture<?> safeSchedule(Runnable task, long delay, TimeUnit unit) {
        if (!loaded || task == null) return null;
        try {
            return coordinator.schedule(task, delay, unit);
        } catch (RejectedExecutionException rejected) {
            return null;
        }
    }

    private ScheduledFuture<?> safeScheduleWithFixedDelay(Runnable task, long initialDelay,
                                                           long delay, TimeUnit unit) {
        if (!loaded || task == null) return null;
        try {
            return coordinator.scheduleWithFixedDelay(task, initialDelay, delay, unit);
        } catch (RejectedExecutionException rejected) {
            return null;
        }
    }

    private boolean safeCoreExecute(int coverageMask, Runnable task) {
        if (task == null) return false;
        synchronized (corePreparationLock) {
            if (!loaded) return false;
            if (!coreOperationRunning.compareAndSet(false, true)) return false;
            coreOperationCoverageMask = coverageMask & CORE_MASK_ALL;
        }
        try {
            coreExecutor.execute(() -> {
                try {
                    task.run();
                } finally {
                    synchronized (corePreparationLock) {
                        coreOperationCoverageMask = 0;
                        coreOperationRunning.set(false);
                    }
                    safeExecute(this::drainCoreWork);
                }
            });
            return true;
        } catch (RejectedExecutionException rejected) {
            synchronized (corePreparationLock) {
                coreOperationCoverageMask = 0;
                coreOperationRunning.set(false);
            }
            return false;
        }
    }

    private String runtimeStoppingResponse() {
        return response(false, I18n.t("Runtime останавливается",
                "Runtime is stopping"), "").toString();
    }

    void unload() {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        synchronized (settingsRequestLock) {
            if (!loaded) return;
            loaded = false;
            revisionGate.advanceLifecycle();
        }
        synchronized (corePreparationLock) {
            coreMaintenancePendingMask = 0;
            coreOperationCoverageMask = 0;
            coreOperationRunning.set(false);
            cancelCoreRepairRetryLocked(CoreFamily.SING_BOX, true);
            cancelCoreRepairRetryLocked(CoreFamily.XRAY, true);
        }
        coreInstallSession.cancel();
        cancelCorePreparation(true);
        directSettingsHook.close();
        reconnectRequests.clear();
        cancelDashboardRefresh();
        cancelReconnect();
        manualRefreshIntent.clear();
        cancelSubscriptionRefresh();
        importRequests.cancel();
        importRunning = false;
        Future<?> activeImport = importFuture;
        importFuture = null;
        if (activeImport != null) activeImport.cancel(true);
        boolean gentlePingShutdown = cancelPingForUnload();
        socksProbe.close();
        // The unload restore works only from the immutable in-memory snapshot
        // and must never mutate the durable marker.  Revoking before the
        // daemon starts also prevents an older queued UI completion from
        // erasing a replacement coordinator's marker.
        proxySession.beginShutdown();
        proxySession.cancelPending();
        nativeCore.beginShutdown();
        try {
            if (connectivity != null) connectivity.unregisterNetworkCallback(networkCallback);
        } catch (Throwable ignored) {
        }
        try {
            AndroidUtilities.runOnUIThread(() -> {
                try {
                    NotificationCenter.getGlobalInstance().removeObserver(
                            this, NotificationCenter.proxySettingsChanged);
                } catch (Throwable ignored) {
                }
            });
        } catch (Throwable ignored) {
        }
        // AtomicStore may currently be held by a parser/import worker.  Start
        // guarded restoration on a daemon and wait for it only within the
        // shared deadline; if it finishes later its exact fingerprint check
        // still prevents overwriting a user's proxy.
        FutureTask<Boolean> proxyRestore = beginUnloadProxyRestore(deadline);
        // Abort network work before waiting for executors. A queued refresh
        // must not hide a running core behind the unload deadline.
        subscriptionHttp.close();
        coreHttp.close();
        subscriptions.close();
        coreExecutor.shutdownNow();
        subscriptionExecutor.shutdownNow();
        subscriptionDeadlineExecutor.shutdownNow();
        importExecutor.shutdownNow();
        if (gentlePingShutdown) pingExecutor.shutdown();
        else pingExecutor.shutdownNow();
        pingWorkers.shutdownNow();
        dnsExecutor.shutdownNow();
        coordinator.shutdownNow();
        try {
            nativeCore.shutdownForUnload(remainingMillis(deadline));
        } catch (Throwable ignored) {
        }
        awaitWithin(proxyRestore, deadline);
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) coordinator.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) coreExecutor.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) subscriptionExecutor.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) subscriptionDeadlineExecutor.awaitTermination(
                    wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) importExecutor.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) pingExecutor.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) pingWorkers.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        try {
            long wait = remainingMillis(deadline);
            if (wait > 0L) dnsExecutor.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        activeNode = null;
        localPort = 0;
        closeCallRelay();
        try {
            RuntimeState state = stateMachine.get();
            if (state == RuntimeState.RUNNING || state == RuntimeState.STARTING) {
                stateMachine.transition(RuntimeState.STOPPING);
            }
            if (stateMachine.get() != RuntimeState.STOPPED) stateMachine.transition(RuntimeState.STOPPED);
        } catch (Exception ignored) {
        }
    }

    private FutureTask<Boolean> beginUnloadProxyRestore(long deadline) {
        FutureTask<Boolean> restore = new FutureTask<>(() -> {
            try {
                return proxySession.restoreForUnload(boundedWait(deadline, 2_000L));
            } catch (Throwable error) {
                return false;
            }
        });
        Thread thread = new Thread(restore, "exitfy-proxy-restore");
        thread.setDaemon(true);
        thread.start();
        return restore;
    }

    private static void awaitWithin(Future<?> future, long deadline) {
        long wait = remainingMillis(deadline);
        if (future == null || wait <= 0L) return;
        try {
            future.get(wait, TimeUnit.MILLISECONDS);
        } catch (TimeoutException ignored) {
        } catch (java.util.concurrent.ExecutionException ignored) {
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static long remainingMillis(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0L) return 0L;
        return Math.max(1L, TimeUnit.NANOSECONDS.toMillis(nanos));
    }

    private static long boundedWait(long deadline, long maximumMillis) {
        if (deadline == Long.MAX_VALUE) return Math.max(0L, maximumMillis);
        return Math.min(Math.max(0L, maximumMillis), remainingMillis(deadline));
    }

    private static int findFreeLoopbackPort() throws Exception {
        try (ServerSocket socket = new ServerSocket()) {
            socket.setReuseAddress(false);
            socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            return socket.getLocalPort();
        }
    }

    private static boolean isLoopbackListening(int port) {
        if (port <= 0 || port > 65535) return false;
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 500);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static boolean sameSettings(SettingsModel left, SettingsModel right) {
        return left == null ? right == null : left.equals(right);
    }

    private static JSONObject response(boolean ok, String message, String data) {
        JSONObject value = new JSONObject();
        try {
            value.put("ok", ok).put("message", message == null ? "" : message)
                    .put("data", data == null ? "" : data);
        } catch (Exception ignored) {
        }
        return value;
    }

    private static final class ProbeOutcome {
        final ProtocolParser.Node node;
        final boolean ok;
        final long millis;
        final String status;

        ProbeOutcome(ProtocolParser.Node node, boolean ok, long millis, String status) {
            this.node = node;
            this.ok = ok;
            this.millis = millis;
            this.status = status == null || status.isEmpty() ? "failed" : status;
        }
    }

}
