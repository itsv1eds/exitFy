package com.extera.plugins.exitfy;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

final class RuntimePolicy {
    static final String TELEGRAM_PROXY_CHANGED = "telegram_proxy_changed";
    // 12 s StartCore + 6 s probes + 3 s StopCore + 1 s scheduling slack.
    private static final long PROXY_PROBE_BATCH_BUDGET_MS = 22_000L;

    /**
     * Whether a completed subscription refresh actually changed the server the
     * connection is running on. The key is a digest of the canonical outbound,
     * so equal keys mean the live connection already matches what the refresh
     * produced, and a renamed server keeps its key.
     */
    static boolean activeConfigurationChanged(ProtocolParser.Node active,
                                              ProtocolParser.Node reselected) {
        if (active == null || reselected == null) return true;
        return !active.normalizedKey.equals(reselected.normalizedKey);
    }

    private RuntimePolicy() {
    }

    static boolean preserveCurrentTelegramProxy(String disableReason) {
        return TELEGRAM_PROXY_CHANGED.equals(disableReason);
    }

    static boolean reconnectBlocked(boolean nativeQuarantined) {
        return nativeQuarantined;
    }

    static boolean shouldReconnectAfterCoreInstall(boolean runtimeLoaded,
                                                   boolean settingsEnabled,
                                                   CoreFamily loadedFamily,
                                                   CoreFamily selectedFamily,
                                                   CoreFamily installedFamily) {
        return runtimeLoaded && settingsEnabled && loadedFamily == null
                && installedFamily != null
                && selectedFamily == installedFamily;
    }

    static boolean shouldWaitForCorePreparation(CoreFamily loadedFamily,
                                                boolean usableOnDisk) {
        return loadedFamily == null && !usableOnDisk;
    }

    static boolean needsCoreInstall(boolean singBoxReady, boolean xrayReady) {
        return !singBoxReady || !xrayReady;
    }

    static boolean mayRunAutomaticCoreMaintenance(
            boolean singBoxReady, boolean xrayReady) {
        return singBoxReady || xrayReady;
    }

    static int readyCoreCount(boolean singBoxReady, boolean xrayReady) {
        return (singBoxReady ? 1 : 0) + (xrayReady ? 1 : 0);
    }

    static boolean settingsNeedLifecycleReconcile(SettingsModel previous,
                                                  SettingsModel next,
                                                  RuntimeState state) {
        return settingsNeedLifecycleReconcile(previous, next, state, false);
    }

    static boolean settingsNeedLifecycleReconcile(SettingsModel previous,
                                                  SettingsModel next,
                                                  RuntimeState state,
                                                  boolean probeRestorePending) {
        if (previous == null || next == null || state == null) return true;
        boolean connectionSettingChanged = connectionSettingsChanged(previous, next);
        return connectionSettingChanged
                || (!probeRestorePending && ((next.enabled && state != RuntimeState.RUNNING)
                || (!next.enabled && state != RuntimeState.STOPPED)));
    }

    static boolean connectionSettingsChanged(SettingsModel previous, SettingsModel next) {
        return previous == null || next == null || previous.enabled != next.enabled
                || previous.providerId != next.providerId;
    }

    static ProviderSelectionDecision normalizeProviderSelection(
            int requestedProvider, boolean[] builtInEnabled,
            boolean customConfigured, boolean settingsEnabled) {
        int customProvider = SettingsModel.CUSTOM_PROVIDER_ID;
        boolean[] available = builtInEnabled == null ? new boolean[0] : builtInEnabled;
        if (requestedProvider == customProvider) {
            return new ProviderSelectionDecision(customProvider, false);
        }
        if (requestedProvider >= 0 && requestedProvider < available.length
                && available[requestedProvider]) {
            return new ProviderSelectionDecision(requestedProvider, false);
        }
        for (int provider = 0; provider < available.length; provider++) {
            if (available[provider]) {
                return new ProviderSelectionDecision(provider, false);
            }
        }
        return new ProviderSelectionDecision(customProvider,
                settingsEnabled && !customConfigured);
    }

    static boolean shouldQueueSettingsProbeRestore(boolean connectionSettingsChanged,
                                                   boolean proxyGetSelected,
                                                   long activeProxyTasks,
                                                   boolean storedGuard,
                                                   boolean restoreAlreadyPending) {
        return !connectionSettingsChanged && (proxyGetSelected || activeProxyTasks > 0L
                || storedGuard || restoreAlreadyPending);
    }

    static boolean settingsRevisionIsCurrent(long currentRevision, long requestedRevision) {
        return currentRevision == requestedRevision;
    }

    static boolean callbackIsCurrent(boolean runtimeLoaded, boolean runtimeEnabled,
                                     long currentGeneration, long expectedGeneration) {
        return runtimeLoaded && runtimeEnabled && currentGeneration == expectedGeneration;
    }

    static boolean callbackIsCurrent(boolean runtimeLoaded, boolean runtimeEnabled,
                                     long currentGeneration, long expectedGeneration,
                                     long currentSettingsRevision,
                                     long expectedSettingsRevision) {
        return callbackIsCurrent(runtimeLoaded, runtimeEnabled,
                currentGeneration, expectedGeneration)
                && currentSettingsRevision == expectedSettingsRevision;
    }

    static boolean proxyProbeMayStopCore(boolean runtimeLoaded, boolean runtimeEnabled,
                                         long currentPingGeneration,
                                         long expectedPingGeneration,
                                         long currentGeneration, long expectedGeneration,
                                         long currentSettingsRevision,
                                         long expectedSettingsRevision) {
        return currentPingGeneration == expectedPingGeneration
                && callbackIsCurrent(runtimeLoaded, runtimeEnabled,
                currentGeneration, expectedGeneration,
                currentSettingsRevision, expectedSettingsRevision);
    }

    static boolean hasProxyProbeBatchBudget(long remainingMillis) {
        return remainingMillis >= PROXY_PROBE_BATCH_BUDGET_MS;
    }

    static boolean shouldClearProbeResumeGuard(boolean runtimeLoaded,
                                               boolean runtimeEnabled,
                                               boolean guardedRestartSucceeded) {
        return !runtimeLoaded || !runtimeEnabled || guardedRestartSucceeded;
    }

    static boolean shouldTransferProbeResumeGuard(boolean runtimeLoaded,
                                                  boolean runtimeEnabled,
                                                  long currentGeneration,
                                                  long expectedGeneration) {
        return runtimeLoaded && runtimeEnabled && currentGeneration != expectedGeneration;
    }

    static boolean interruptPingOnCancel(String kind) {
        return "TCP".equals(kind) || "HEALTH".equals(kind);
    }

    static boolean shouldDisableAfterProbePauseFailure(boolean externalProxyChanged) {
        // Timeout/error is UNKNOWN, not proof that the user changed the proxy.
        return externalProxyChanged;
    }

    static boolean shouldReconnectAfterProbePauseFailure(boolean callbackCurrent,
                                                         boolean pauseAttempted,
                                                         boolean externalProxyChanged) {
        return callbackCurrent && pauseAttempted && !externalProxyChanged;
    }

    static boolean replacementNeedsGuardedRestore(String nextKind,
                                                  boolean proxyRestoreContext) {
        return "TCP".equals(nextKind) && proxyRestoreContext;
    }
}

/**
 * Couples a lifecycle generation with the settings revision which authorized
 * it. Settings requests advance their revision before they enter the
 * coordinator queue, so a queued disable invalidates a late native/proxy
 * callback immediately even though the old SettingsModel is still visible.
 */
final class RuntimeRevisionGate {
    private final AtomicLong generation;
    private final AtomicLong settingsRevision;

    RuntimeRevisionGate(AtomicLong generation, AtomicLong settingsRevision) {
        this.generation = generation;
        this.settingsRevision = settingsRevision;
    }

    RuntimeRevisionGate() {
        this(new AtomicLong(), new AtomicLong());
    }

    long requestSettingsChange() {
        return settingsRevision.incrementAndGet();
    }

    long advanceLifecycle() {
        return generation.incrementAndGet();
    }

    RuntimeOperationToken currentToken() {
        return new RuntimeOperationToken(generation.get(), settingsRevision.get());
    }

    RuntimeOperationToken token(long expectedGeneration, long expectedRevision) {
        return new RuntimeOperationToken(expectedGeneration, expectedRevision);
    }

    boolean settingsRequestIsCurrent(long requestedRevision) {
        return settingsRevision.get() == requestedRevision;
    }

    boolean isCurrent(RuntimeOperationToken token, boolean loaded, boolean enabled) {
        return token != null && RuntimePolicy.callbackIsCurrent(
                loaded, enabled, generation.get(), token.generation,
                settingsRevision.get(), token.settingsRevision);
    }

    long generation() {
        return generation.get();
    }

    long settingsRevision() {
        return settingsRevision.get();
    }
}

/**
 * Publishes the settings revision whose {@link SettingsModel} is actually
 * visible to coordinator work. A requested revision advances before its
 * apply task enters the coordinator queue, so the revision gate alone cannot
 * distinguish the new request from the still-visible old provider/HWID.
 */
final class AppliedSettingsGate {
    private final AtomicLong appliedRevision = new AtomicLong();

    void markApplied(long revision) {
        appliedRevision.set(revision);
    }

    boolean allows(RuntimeOperationToken operation, boolean loaded,
                   long currentSettingsRevision) {
        return loaded && operation != null
                && operation.settingsRevision == currentSettingsRevision
                && appliedRevision.get() == operation.settingsRevision;
    }

    boolean hasPendingApply(long currentSettingsRevision) {
        return appliedRevision.get() != currentSettingsRevision;
    }

    boolean shouldDeferManualRefresh(boolean loaded, boolean requestedEnabled,
                                     long currentSettingsRevision) {
        return loaded && requestedEnabled && hasPendingApply(currentSettingsRevision);
    }

}

/** Coalesces one user refresh intent until the latest settings revision is applied. */
final class ManualRefreshIntentGate {
    private boolean pending;
    private boolean runnerScheduled;
    private long attemptSequence;
    private long activeAttempt;

    /** Returns true only when the caller must enqueue a runner. */
    synchronized boolean request() {
        pending = true;
        if (runnerScheduled || activeAttempt != 0L) return false;
        runnerScheduled = true;
        return true;
    }

    /** Called by the queued runner; pending remains set until a refresh starts. */
    synchronized boolean beginRunner() {
        runnerScheduled = false;
        return pending && activeAttempt == 0L;
    }

    synchronized long claim() {
        if (!pending || activeAttempt != 0L) return 0L;
        activeAttempt = ++attemptSequence;
        if (activeAttempt == 0L) activeAttempt = ++attemptSequence;
        return activeAttempt;
    }

    synchronized void complete(long attempt) {
        if (attempt == 0L || activeAttempt != attempt) return;
        activeAttempt = 0L;
        pending = false;
    }

    synchronized void abandon(long attempt) {
        if (attempt != 0L && activeAttempt == attempt) activeAttempt = 0L;
    }

    /** Returns true only when an applied-settings boundary must enqueue a runner. */
    synchronized boolean schedulePending() {
        if (!pending || runnerScheduled || activeAttempt != 0L) return false;
        runnerScheduled = true;
        return true;
    }

    synchronized boolean isPending() {
        return pending;
    }

    synchronized void clear() {
        pending = false;
        runnerScheduled = false;
        activeAttempt = 0L;
    }
}

final class RuntimeOperationToken {
    final long generation;
    final long settingsRevision;

    RuntimeOperationToken(long generation, long settingsRevision) {
        this.generation = generation;
        this.settingsRevision = settingsRevision;
    }
}

/** Thread-safe reconnect coalescing which never lets a network event hide a config change. */
final class ReconnectRequestGate {
    static final class Request {
        final String reason;
        final int priority;

        Request(String reason, int priority) {
            this.reason = reason == null ? "" : reason;
            this.priority = priority;
        }
    }

    private Request pending;
    private Request active;
    private boolean runnerScheduled;

    synchronized boolean offer(String reason, boolean configurationChange) {
        Request candidate = new Request(reason, configurationChange ? 2 : 1);
        if (!runnerScheduled) {
            pending = candidate;
            runnerScheduled = true;
            return true;
        }
        if (active != null && pending == null) {
            if (active.priority > candidate.priority) return false;
            // Repeated network notifications are redundant while the same
            // reconnect is active. Equal-priority config changes are not:
            // the newer settings revision invalidates the active operation,
            // so one latest config request must remain pending.
            if (active.priority == candidate.priority && candidate.priority < 2) return false;
        }
        if (pending == null || candidate.priority >= pending.priority) {
            pending = candidate;
        }
        return false;
    }

    synchronized Request beginNext() {
        active = pending;
        pending = null;
        return active;
    }

    synchronized boolean complete(Request completed) {
        if (active == completed) active = null;
        if (pending != null) return true;
        runnerScheduled = false;
        return false;
    }

    synchronized void clear() {
        active = null;
        pending = null;
        runnerScheduled = false;
    }
}

/** A no-queue, latest-generation gate for large import payloads. */
final class ImportRequestGate {
    interface ApplyQueue {
        boolean execute(Runnable task);
    }

    static final class Ticket {
        final long generation;
        final long settingsRevision;
        final int providerId;

        Ticket(long generation, long settingsRevision, int providerId) {
            this.generation = generation;
            this.settingsRevision = settingsRevision;
            this.providerId = providerId;
        }
    }

    private long latestGeneration;
    private Ticket active;

    synchronized Ticket tryStart(long settingsRevision, int providerId) {
        if (active != null) return null;
        active = new Ticket(++latestGeneration, settingsRevision, providerId);
        return active;
    }

    synchronized void finish(Ticket ticket) {
        if (active == ticket) active = null;
    }

    synchronized boolean isLatest(Ticket ticket) {
        return ticket != null && ticket.generation == latestGeneration;
    }

    synchronized boolean settingsAreCurrent(Ticket ticket,
                                            long settingsRevision, int providerId) {
        return isLatest(ticket) && ticket.settingsRevision == settingsRevision
                && ticket.providerId == providerId;
    }

    boolean enqueueApply(Ticket ticket, ApplyQueue queue, Runnable apply) {
        if (ticket == null || queue == null || apply == null) return false;
        boolean queued;
        try {
            queued = queue.execute(() -> {
                try {
                    apply.run();
                } finally {
                    // Admission remains occupied through the full coordinator
                    // apply, including provider persistence/reconnect/details.
                    finish(ticket);
                }
            });
        } catch (RuntimeException rejected) {
            queued = false;
        }
        if (!queued) finish(ticket);
        return queued;
    }

    synchronized void cancel() {
        latestGeneration++;
        active = null;
    }
}

/** Exactly one terminal result (worker or deadline) is accepted per refresh. */
final class RefreshCompletionGate {
    static final class Ticket {
        final long sequence;
        final long lifecycleGeneration;
        final long settingsRevision;
        final boolean requiredForStart;
        final int providerId;
        final long deadlineNanos;

        Ticket(long sequence, RuntimeOperationToken operation, boolean requiredForStart,
               int providerId, long deadlineNanos) {
            this.sequence = sequence;
            this.lifecycleGeneration = operation == null ? Long.MIN_VALUE : operation.generation;
            this.settingsRevision = operation == null ? Long.MIN_VALUE : operation.settingsRevision;
            this.requiredForStart = requiredForStart;
            this.providerId = providerId;
            this.deadlineNanos = deadlineNanos;
        }

        boolean sameLifecycle(RuntimeOperationToken operation) {
            return operation != null && lifecycleGeneration == operation.generation
                    && settingsRevision == operation.settingsRevision;
        }

        boolean sameContext(RuntimeOperationToken operation, int providerId) {
            return sameLifecycle(operation) && this.providerId == providerId;
        }

        boolean contextIsCurrent(RuntimeOperationToken operation, int providerId,
                                 boolean loaded) {
            return loaded && sameContext(operation, providerId);
        }

        boolean deadlineReached(long nowNanos) {
            return deadlineNanos != Long.MAX_VALUE
                    && nowNanos - deadlineNanos >= 0L;
        }
    }

    private long sequence;
    private Ticket current;
    private long completed;

    synchronized Ticket begin(boolean requiredForStart, RuntimeOperationToken operation) {
        return begin(requiredForStart, operation, Integer.MIN_VALUE);
    }

    synchronized Ticket begin(boolean requiredForStart, RuntimeOperationToken operation,
                              int providerId) {
        return begin(requiredForStart, operation, providerId, Long.MAX_VALUE);
    }

    synchronized Ticket begin(boolean requiredForStart, RuntimeOperationToken operation,
                              int providerId, long deadlineNanos) {
        boolean inheritStartRequirement = current != null
                && completed != current.sequence && current.requiredForStart
                && current.sameContext(operation, providerId);
        current = new Ticket(++sequence, operation,
                requiredForStart || inheritStartRequirement, providerId, deadlineNanos);
        completed = 0L;
        return current;
    }

    synchronized boolean isCurrent(Ticket ticket) {
        return ticket != null && current != null && ticket.sequence == current.sequence;
    }

    synchronized boolean isPending(Ticket ticket) {
        return isCurrent(ticket) && completed != ticket.sequence;
    }

    synchronized boolean claim(Ticket ticket) {
        return claimAt(ticket, System.nanoTime());
    }

    synchronized boolean claimAt(Ticket ticket, long nowNanos) {
        if (!isCurrent(ticket) || completed == ticket.sequence) return false;
        if (ticket.deadlineReached(nowNanos)) return false;
        completed = ticket.sequence;
        return true;
    }

    synchronized boolean claimIfCurrent(Ticket ticket, RuntimeOperationToken operation,
                                        int providerId, boolean loaded) {
        if (ticket == null || !ticket.contextIsCurrent(operation, providerId, loaded)) {
            return false;
        }
        return claim(ticket);
    }

    synchronized boolean expireAt(Ticket ticket, long nowNanos) {
        if (!isCurrent(ticket) || completed == ticket.sequence
                || !ticket.deadlineReached(nowNanos)) return false;
        completed = ticket.sequence;
        return true;
    }

    synchronized boolean isTerminal(Ticket ticket) {
        return isCurrent(ticket) && completed == ticket.sequence;
    }

    synchronized void cancel() {
        current = new Ticket(++sequence, null, false,
                Integer.MIN_VALUE, Long.MAX_VALUE);
        completed = current.sequence;
    }
}

final class ProviderSelectionDecision {
    final int providerId;
    final boolean disable;

    ProviderSelectionDecision(int providerId, boolean disable) {
        this.providerId = providerId;
        this.disable = disable;
    }
}

/** Tracks whether a restored proxy snapshot must guard the next activation. */
final class ActivationGuardState<T> {
    private T value;

    synchronized void restored(T restored, boolean retainForNextActivation) {
        value = retainForNextActivation ? restored : null;
    }

    synchronized T current() {
        return value;
    }

    synchronized void disabled() {
        value = null;
    }
}

/** Tracks the newest settings request independently for every persisted key. */
final class KeyedRevisionGate {
    private final Map<String, Long> revisions = new HashMap<>();

    synchronized void record(String key, long revision) {
        if (key == null || key.isEmpty()) throw new IllegalArgumentException("missing revision key");
        long current = revisions.getOrDefault(key, 0L);
        if (revision > current) revisions.put(key, revision);
    }

    synchronized long current(String key) {
        if (key == null || key.isEmpty()) return 0L;
        return revisions.getOrDefault(key, 0L);
    }
}

/** Forces Python-backed preference writes through the host plugins queue. */
final class PluginSettingDispatcher {
    interface Queue {
        void post(Runnable runnable);
    }

    interface Revision {
        long current();
    }

    interface Validity {
        boolean current();
    }

    private PluginSettingDispatcher() {
    }

    static void dispatch(long expectedRevision, Revision revision,
                         Queue queue, Runnable persistence) {
        dispatch(expectedRevision, revision, () -> true, queue, persistence);
    }

    static void dispatch(long expectedRevision, Revision revision,
                         Validity validity, Queue queue, Runnable persistence) {
        if (revision == null || validity == null || queue == null || persistence == null) return;
        queue.post(() -> {
            if (validity.current() && revision.current() == expectedRevision) persistence.run();
        });
    }
}
