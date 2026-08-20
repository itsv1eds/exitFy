package com.extera.plugins.exitfy;

import android.content.SharedPreferences;
import android.os.Looper;

import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.SharedConfig;
import org.telegram.tgnet.ConnectionsManager;

import java.io.Closeable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

final class ProxySession implements Closeable {
    private static final long DEFAULT_UI_TIMEOUT_MS = 2_000L;
    private static final String SESSION_FILE = "proxy_session.json";
    private static final String RETAIN_ACTIVATION_GUARD = "retainActivationGuard";
    private static final String SESSION_NONCE = "sessionNonce";
    private static final boolean OWNED_PROXY_CALLS = true;

    private final AtomicStore store;
    private final AtomicStore.WriterLease sessionWriterLease;
    private final AtomicBoolean markerWritesAllowed = new AtomicBoolean(true);
    private final AtomicBoolean shutdown = new AtomicBoolean();
    private volatile ProxyBackend backend;
    private final Object operationMonitor = new Object();
    private final AtomicLong operationGeneration = new AtomicLong();
    private final AtomicReference<UiOperation<?>> currentOperation = new AtomicReference<>();
    private volatile String activeSessionSnapshot = "";
    private volatile boolean active;
    private volatile boolean recoveryRequired;
    private volatile boolean recoveryAttemptScheduled;
    private volatile boolean markerReadFailed;
    private volatile long recoveryToken;
    private final ActivationGuardState<StateGuard> activationGuard = new ActivationGuardState<>();

    ProxySession(AtomicStore store) {
        this.store = store;
        // Claim the durable marker before the first read.  A replacement
        // coordinator therefore cannot observe an old writer's commit out of
        // order: a commit already pinned under AtomicStore's commit lock is
        // published first, while every not-yet-pinned old write is revoked.
        this.sessionWriterLease = store.claimWriter(SESSION_FILE);
        JSONObject existing = readSessionMarker();
        if (existing != null && existing.optBoolean("active", false)) {
            activeSessionSnapshot = existing.toString();
            recoveryRequired = true;
        }
    }

    boolean recoverIfNeeded() {
        return recoverIfNeeded(DEFAULT_UI_TIMEOUT_MS);
    }

    private boolean recoverIfNeeded(long timeoutMillis) {
        JSONObject saved = readSessionMarker();
        if (saved == null) return false;
        if (!saved.optBoolean("active", false)) {
            synchronized (operationMonitor) {
                recoveryRequired = false;
                recoveryAttemptScheduled = false;
                markerReadFailed = false;
            }
            return true;
        }
        long token;
        synchronized (operationMonitor) {
            recoveryRequired = true;
            if (recoveryAttemptScheduled) return false;
            token = beginOperation();
            recoveryToken = token;
            recoveryAttemptScheduled = true;
        }
        return recoverFile(saved, SESSION_FILE, token, timeoutMillis);
    }

    private boolean recoverFile(JSONObject saved, String relativeName, long token,
                                long timeoutMillis) {
        try {
            RestoreOutcome outcome = restoreSaved(saved, relativeName, token,
                    Math.max(0L, timeoutMillis),
                    saved.optBoolean(RETAIN_ACTIVATION_GUARD, true));
            active = false;
            forgetSessionSnapshot(saved);
            recoveryRequired = false;
            recoveryAttemptScheduled = false;
            markerReadFailed = false;
            return true;
        } catch (Exception error) {
            // A timed-out restore remains queued. Activation is gated until
            // that exact UI operation finishes and a later retry durably
            // marks the recovery record inactive.
            UiOperation<?> operation = currentOperation.get();
            if (operation == null || operation.token != token) {
                recoveryAttemptScheduled = false;
            }
            return false;
        }
    }

    static Credentials newCredentials() {
        return new Credentials(randomToken(12), randomToken(18));
    }

    void activate(int port, Credentials credentials) throws Exception {
        activate(port, credentials, DEFAULT_UI_TIMEOUT_MS, null);
    }

    void activate(int port, Credentials credentials, long timeoutMillis) throws Exception {
        activate(port, credentials, timeoutMillis, null);
    }

    void activate(int port, Credentials credentials, long timeoutMillis,
                  StateGuard expectedState) throws Exception {
        ensureOpen();
        if (port <= 0 || port > 65535) throw new IllegalArgumentException("invalid local proxy port");
        if (active) throw new IllegalStateException("proxy session already active");
        if (credentials == null) throw new IllegalArgumentException("proxy credentials are missing");
        if (!recoveryReady()) throw recoveryPendingException();
        long token = beginOperation();
        ProxySnapshotModel snapshot = runOnUi(token, timeoutMillis, () -> {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            ProxyBackend proxyBackend = backend();
            return snapshot(preferences, proxyBackend.current(), proxyBackend);
        });
        StateGuard retainedState = activationGuard.current();
        if (!activationGuardsMatch(retainedState, expectedState, snapshot)) {
            throw new ExternalProxyChangeException();
        }

        SharedConfig.ProxyInfo requested = new SharedConfig.ProxyInfo(
                "127.0.0.1", port, credentials.username, credentials.password, "");
        ProxySnapshotModel owned = snapshot.withOwnedFingerprint(fingerprint(requested));
        JSONObject ownedJson = owned.toJson()
                .put(RETAIN_ACTIVATION_GUARD, true)
                .put(SESSION_NONCE, randomToken(16));
        rememberSessionSnapshot(ownedJson);
        try {
            writeSessionMarker(ownedJson);
        } catch (Exception error) {
            forgetSessionSnapshot(ownedJson);
            throw error;
        }

        try {
            runOnUi(token, timeoutMillis, () -> {
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                ProxyBackend value = backend();
                if (!sameProxy(snapshot.previous, value.current())
                        || !samePreferences(snapshot.preferences, preferences)) {
                    throw new ExternalProxyChangeException();
                }
                SharedConfig.ProxyInfo installed = value.add(requested);
                value.setName(installed, "exitFy 4");
                if (!matchesFingerprint(owned.ownedFingerprint, installed)) {
                    throw new IllegalStateException("Telegram proxy fingerprint mismatch");
                }
                value.setCurrent(installed);
                preferences.edit()
                        .putString("proxy_ip", installed.address)
                        .putInt("proxy_port", installed.port)
                        .putString("proxy_user", installed.username)
                        .putString("proxy_pass", installed.password)
                        .putString("proxy_secret", installed.secret)
                        .putBoolean("proxy_enabled", true)
                        .putBoolean("proxy_enabled_calls", OWNED_PROXY_CALLS)
                        .apply();
                ConnectionsManager.setProxySettings(true, installed.address, installed.port,
                        installed.username, installed.password, installed.secret);
                NotificationCenter.getGlobalInstance()
                        .postNotificationName(NotificationCenter.proxySettingsChanged);
                return null;
            });
            if (!markActiveIfCurrent(token)) {
                throw new IllegalStateException("proxy operation cancelled");
            }
            activationGuard.disabled();
        } catch (Exception error) {
            try {
                restoreSaved(ownedJson, SESSION_FILE, beginOperation(), timeoutMillis, true);
            } catch (Exception recoveryError) {
            } finally {
                JSONObject durable = readSessionMarker();
                if (durable != null && !durable.optBoolean("active", false)) {
                    forgetSessionSnapshot(ownedJson);
                }
            }
            throw error;
        }
    }

    StateGuard captureState(long timeoutMillis) throws Exception {
        if (!recoveryReady()) throw recoveryPendingException();
        long token = beginOperation();
        ProxySnapshotModel value = runOnUi(token, timeoutMillis, () -> {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            ProxyBackend proxyBackend = backend();
            return snapshot(preferences, proxyBackend.current(), proxyBackend);
        });
        return new StateGuard(value.previous, value.preferences);
    }

    /**
     * Captures the exact host proxy state and retains it for the next activation
     * only while both the ProxySession operation and its coordinator context are
     * still current. This is the sole safe way to start a probe from INACTIVE:
     * activation compares the retained state again after the probe, so a user
     * proxy change made after this capture is preserved and rejected.
     */
    StateGuard captureAndRetainState(long timeoutMillis, StateRetention validity) throws Exception {
        if (!recoveryReady()) throw recoveryPendingException();
        long token = beginOperation();
        ProxySnapshotModel value = runOnUi(token, timeoutMillis, () -> {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            ProxyBackend proxyBackend = backend();
            return snapshot(preferences, proxyBackend.current(), proxyBackend);
        });
        StateGuard retained = new StateGuard(value.previous, value.preferences);
        synchronized (operationMonitor) {
            if (shutdown.get() || operationGeneration.get() != token
                    || validity == null || !validity.isCurrent()) {
                throw new IllegalStateException("proxy guard context changed");
            }
            activationGuard.restored(retained, true);
        }
        return retained;
    }

    void restore() {
        restore(DEFAULT_UI_TIMEOUT_MS);
    }

    boolean restore(long timeoutMillis) {
        if (recoveryRequired) return recoverIfNeeded(timeoutMillis);
        return restoreOutcome(timeoutMillis, true, true) != RestoreOutcome.FAILED;
    }

    RestoreOutcome restoreForProbe(long timeoutMillis) {
        // A running connection must already have completed recovery. Starting
        // a probe while recovery is unresolved would have no trustworthy
        // durable baseline to guard the later activation.
        if (recoveryRequired) return RestoreOutcome.FAILED;
        return restoreOutcome(timeoutMillis, true, true);
    }

    boolean restoreForDisable(long timeoutMillis) {
        if (recoveryRequired) {
            JSONObject saved = readSessionMarker();
            if (saved == null) return false;
            if (!persistRestoreIntent(saved, false)) return false;
            return recoverIfNeeded(timeoutMillis);
        }
        return restoreOutcome(timeoutMillis, true, false) != RestoreOutcome.FAILED;
    }

    void restoreForDisable() {
        restoreForDisable(DEFAULT_UI_TIMEOUT_MS);
    }

    boolean restoreForUnload(long timeoutMillis) {
        // A bounded unload restore may finish after a new RuntimeCoordinator
        // has written its own session marker. Never overwrite that marker
        // from this old daemon; a stale active marker is harmless because
        // next-start recovery is fingerprint guarded.
        return restoreOutcome(timeoutMillis, false, false) != RestoreOutcome.FAILED;
    }

    private RestoreOutcome restoreOutcome(long timeoutMillis, boolean markSessionInactive,
                                          boolean retainActivationGuard) {
        JSONObject saved = markSessionInactive
                ? readSessionMarker() : sessionSnapshotForUnload();
        if (saved == null) return RestoreOutcome.FAILED;
        if (!saved.optBoolean("active", false)) {
            active = false;
            if (markSessionInactive) forgetSessionSnapshot(null);
            if (!retainActivationGuard) activationGuard.disabled();
            return RestoreOutcome.INACTIVE;
        }
        if (markSessionInactive && !retainActivationGuard
                && !persistRestoreIntent(saved, false)) {
            return RestoreOutcome.FAILED;
        }
        if (markSessionInactive && !retainActivationGuard) {
            saved = readSessionMarker();
            if (saved == null) return RestoreOutcome.FAILED;
        }
        try {
            long token = markSessionInactive ? beginOperation() : beginUnloadOperation();
            RestoreOutcome outcome = restoreSaved(
                    saved, markSessionInactive ? SESSION_FILE : null,
                    token, timeoutMillis, retainActivationGuard);
            active = false;
            forgetSessionSnapshot(saved);
            return outcome;
        } catch (Exception error) {
            return RestoreOutcome.FAILED;
        }
    }

    boolean probeResumeAllowed(RestoreOutcome outcome, StateGuard pending,
                               StateGuard captured) {
        return probeResumeAllowed(outcome, activationGuard.current(), pending, captured);
    }

    static boolean probeResumeAllowed(RestoreOutcome outcome, StateGuard retained,
                                      StateGuard pending, StateGuard captured) {
        if (outcome == null || outcome == RestoreOutcome.FAILED
                || outcome == RestoreOutcome.PRESERVED || captured == null) {
            return false;
        }
        // INACTIVE is valid only when a previous cancelled probe already owns
        // the exact resume guard. A first probe without an active durable
        // session must never adopt the currently selected Telegram proxy.
        if (outcome == RestoreOutcome.INACTIVE && pending == null) return false;
        StateGuard explicit = pending == null ? captured : pending;
        return activationGuardsMatch(retained, explicit, captured);
    }

    static boolean activationGuardsMatch(StateGuard retained, StateGuard explicit,
                                         ProxySnapshotModel actual) {
        if (actual == null || (explicit != null && retained == null)) return false;
        return (retained == null || retained.matches(actual))
                && (explicit == null || explicit.matches(actual));
    }

    static boolean activationGuardsMatch(StateGuard retained, StateGuard explicit,
                                         StateGuard actual) {
        if (actual == null || (explicit != null && retained == null)) return false;
        return (retained == null || retained.matches(actual))
                && (explicit == null || explicit.matches(actual));
    }

    void releasePreservingCurrent() {
        releasePreservingCurrent(DEFAULT_UI_TIMEOUT_MS);
    }

    boolean releasePreservingCurrent(long timeoutMillis) {
        JSONObject saved = readSessionMarker();
        if (saved == null) return false;
        if (recoveryRequired) {
            persistRestoreIntent(saved, false);
            return false;
        }
        if (!saved.optBoolean("active", false)) {
            active = false;
            forgetSessionSnapshot(null);
            activationGuard.disabled();
            return true;
        }
        if (!persistRestoreIntent(saved, false)) return false;
        final JSONObject releaseSnapshot = readSessionMarker();
        if (releaseSnapshot == null) return false;
        long token = beginOperation();
        try {
            runOnUi(token, timeoutMillis, true, () -> {
                ProxySnapshotModel snapshot = ProxySnapshotModel.fromJson(releaseSnapshot);
                removeOwned(backend(), snapshot.ownedFingerprint);
                NotificationCenter.getGlobalInstance()
                        .postNotificationName(NotificationCenter.proxySettingsChanged);
                return null;
            });
            markInactive(SESSION_FILE, releaseSnapshot);
            active = false;
            forgetSessionSnapshot(releaseSnapshot);
            activationGuard.disabled();
            return true;
        } catch (Exception error) {
            return false;
        }
    }

    Ownership ownership() {
        if (!recoveryReady()) return Ownership.UNKNOWN;
        JSONObject saved = readSessionMarker();
        if (saved == null) return Ownership.UNKNOWN;
        if (!active || !saved.optBoolean("active", false)) return Ownership.INACTIVE;
        // Ownership is a read-only health observation. It must never supersede
        // a lifecycle mutation that is already queued on the UI thread (most
        // importantly restoreForDisable()). A newer mutation invalidates this
        // read through operationGeneration, while the read itself leaves the
        // current mutation and its token untouched.
        long token = beginReadOperation();
        try {
            return runReadOnUi(token, DEFAULT_UI_TIMEOUT_MS, () -> {
                ProxySnapshotModel snapshot = ProxySnapshotModel.fromJson(saved);
                SharedConfig.ProxyInfo current = backend().current();
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                if (snapshot.ownedFingerprint.isEmpty() || current == null
                        || !matchesFingerprint(snapshot.ownedFingerprint, current)
                        || !preferences.getBoolean("proxy_enabled", false)
                        || !ownsCallsPreference(preferences.getBoolean(
                                "proxy_enabled_calls", false))) {
                    return Ownership.EXTERNALLY_CHANGED;
                }
                return Ownership.OWNED;
            });
        } catch (Exception error) {
            return Ownership.UNKNOWN;
        }
    }

    boolean reapplyIfOwned() {
        if (!recoveryReady()) return false;
        JSONObject saved = readSessionMarker();
        if (saved == null) return false;
        if (!active || !saved.optBoolean("active", false)) return false;
        long token = beginOperation();
        try {
            return runOnUi(token, DEFAULT_UI_TIMEOUT_MS, () -> {
                ProxySnapshotModel snapshot = ProxySnapshotModel.fromJson(saved);
                SharedConfig.ProxyInfo current = backend().current();
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                if (current == null || !matchesFingerprint(snapshot.ownedFingerprint, current)
                        || !preferences.getBoolean("proxy_enabled", false)) return false;
                ConnectionsManager.setProxySettings(true, current.address, current.port,
                        current.username, current.password, current.secret);
                return true;
            });
        } catch (Exception error) {
            return false;
        }
    }

    void cancelPending() {
        synchronized (operationMonitor) {
            operationGeneration.incrementAndGet();
            UiOperation<?> operation = currentOperation.get();
            if (operation != null && operation.cancelIfPending()) {
                currentOperation.compareAndSet(operation, null);
            }
        }
    }

    boolean recoveryReady() {
        return !shutdown.get() && !recoveryRequired
                && !recoveryAttemptScheduled && !markerReadFailed;
    }

    RecoveryPendingException recoveryPendingException() {
        return markerReadFailed
                ? new RecoveryPendingException(
                "Telegram proxy recovery state is unreadable")
                : new RecoveryPendingException();
    }

    private void ensureOpen() {
        if (shutdown.get()) throw new IllegalStateException("proxy session is shutting down");
    }

    private RestoreOutcome restoreSaved(JSONObject saved, String relativeName,
                                        long token, long timeoutMillis,
                                        boolean retainActivationGuard) throws Exception {
        ProxySnapshotModel durableSnapshot = ProxySnapshotModel.fromJson(saved);
        RestoreOutcome outcome = runOnUi(token, timeoutMillis, true, () -> {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            ProxySnapshotModel snapshot = durableSnapshot;
            ProxyBackend value = backend();
            SharedConfig.ProxyInfo current = value.current();
            boolean currentCalls = preferences.getBoolean("proxy_enabled_calls", false);
            boolean ownedCurrent = current != null
                    && preferences.getBoolean("proxy_enabled", false)
                    && matchesFingerprint(snapshot.ownedFingerprint, current);
            if (!ownedCurrent) {
                removeOwned(value, snapshot.ownedFingerprint);
                NotificationCenter.getGlobalInstance()
                        .postNotificationName(NotificationCenter.proxySettingsChanged);
                return RestoreOutcome.PRESERVED;
            }

            SharedConfig.ProxyInfo previous = proxyFromValue(snapshot.previous);
            SharedConfig.ProxyInfo restored = findExact(value.list(), previous);
            if (previous != null && restored == null) restored = value.add(previous);
            if (restored != null && !snapshot.previousName.isEmpty()) {
                value.setName(restored, snapshot.previousName);
            }
            value.setCurrent(restored);
            ProxySnapshotModel.Preferences raw = snapshot.preferences;
            preferences.edit()
                    .putString("proxy_ip", raw.ip)
                    .putInt("proxy_port", raw.port)
                    .putString("proxy_user", raw.username)
                    .putString("proxy_pass", raw.password)
                    .putString("proxy_secret", raw.secret)
                    .putBoolean("proxy_enabled", raw.enabled)
                    .putBoolean("proxy_enabled_calls",
                            callsPreferenceAfterRestore(raw.calls, currentCalls))
                    .apply();
            if (raw.enabled && restored != null) {
                ConnectionsManager.setProxySettings(true, restored.address, restored.port,
                        restored.username, restored.password, restored.secret);
            } else {
                ConnectionsManager.setProxySettings(false, "", 0, "", "", "");
            }
            removeOwned(value, snapshot.ownedFingerprint);
            NotificationCenter.getGlobalInstance()
                    .postNotificationName(NotificationCenter.proxySettingsChanged);
            return RestoreOutcome.RESTORED;
        });
        if (relativeName != null) {
            markInactive(relativeName, saved);
            activationGuard.restored(new StateGuard(
                    durableSnapshot.previous, durableSnapshot.preferences),
                    retainActivationGuard);
        }
        return outcome;
    }

    boolean persistRestoreIntent(JSONObject saved, boolean retainActivationGuard) {
        if (shutdown.get()) return false;
        if (saved == null || !saved.optBoolean("active", false)) return true;
        try {
            JSONObject intended = JsonGuard.object(saved.toString())
                    .put(RETAIN_ACTIVATION_GUARD, retainActivationGuard);
            writeSessionMarker(intended, saved);
            rememberSessionSnapshot(intended);
            return true;
        } catch (Exception error) {
            return false;
        }
    }

    void markInactive(String relativeName, JSONObject expectedMarker) throws Exception {
        if (!SESSION_FILE.equals(relativeName)) {
            throw new IllegalArgumentException("unexpected proxy marker path");
        }
        writeSessionMarker(new JSONObject().put("active", false), expectedMarker);
    }

    private void writeSessionMarker(JSONObject value) throws Exception {
        writeSessionMarker(value, null);
    }

    private void writeSessionMarker(JSONObject value, JSONObject expectedMarker) throws Exception {
        if (!store.writeJson(SESSION_FILE, value, sessionWriterLease,
                () -> markerWritesAllowed.get() && !shutdown.get()
                        && (expectedMarker == null || durableMarkerMatches(expectedMarker)))) {
            throw new IllegalStateException("proxy marker was not committed");
        }
    }

    private boolean durableMarkerMatches(JSONObject expected) {
        JSONObject current = readSessionMarker();
        if (current == null) return false;
        if (!current.optBoolean("active", false)) return false;
        String expectedNonce = expected.optString(SESSION_NONCE, "");
        if (!expectedNonce.isEmpty()) {
            return expectedNonce.equals(current.optString(SESSION_NONCE, ""));
        }
        String expectedFingerprint = expected.optString("ownedFingerprint", "");
        if (!expectedFingerprint.isEmpty()) {
            return expectedFingerprint.equals(current.optString("ownedFingerprint", ""));
        }
        // Legacy recovery records predate the nonce.  Exact JSON equality is
        // the only safe fallback; address/name heuristics are never used.
        return expected.toString().equals(current.toString());
    }

    private JSONObject readSessionMarker() {
        try {
            JSONObject value = store.readJsonIfExists(SESSION_FILE);
            if (value == null && (active || !activeSessionSnapshot.isEmpty())) {
                markMarkerReadFailed();
                return null;
            }
            markerReadFailed = false;
            return value == null ? new JSONObject() : value;
        } catch (Exception error) {
            markMarkerReadFailed();
            return null;
        }
    }

    private void markMarkerReadFailed() {
        markerReadFailed = true;
        recoveryRequired = true;
        recoveryAttemptScheduled = false;
    }

    void beginShutdown() {
        shutdown.set(true);
        markerWritesAllowed.set(false);
        sessionWriterLease.close();
    }

    private void rememberSessionSnapshot(JSONObject value) {
        synchronized (operationMonitor) {
            activeSessionSnapshot = value == null ? "" : value.toString();
        }
    }

    private void forgetSessionSnapshot(JSONObject expected) {
        synchronized (operationMonitor) {
            if (expected == null || activeSessionSnapshot.equals(expected.toString())) {
                activeSessionSnapshot = "";
            }
        }
    }

    JSONObject sessionSnapshotForUnload() {
        String value;
        synchronized (operationMonitor) {
            value = activeSessionSnapshot;
        }
        if (value == null || value.isEmpty()) return new JSONObject();
        try {
            return JsonGuard.object(value);
        } catch (Exception ignored) {
            return new JSONObject();
        }
    }

    boolean markActiveIfCurrent(long token) {
        synchronized (operationMonitor) {
            if (shutdown.get() || !recoveryReady()
                    || operationGeneration.get() != token) return false;
            active = true;
            return true;
        }
    }

    private void onOperationFinished(long token) {
        if (recoveryToken == token) recoveryAttemptScheduled = false;
    }

    long beginOperation() {
        return beginOperation(false);
    }

    long beginReadOperation() {
        synchronized (operationMonitor) {
            if (shutdown.get()) {
                throw new IllegalStateException("proxy session is shutting down");
            }
            return operationGeneration.get();
        }
    }

    private long beginUnloadOperation() {
        return beginOperation(true);
    }

    private long beginOperation(boolean allowShutdown) {
        synchronized (operationMonitor) {
            if (shutdown.get() && !allowShutdown) {
                throw new IllegalStateException("proxy session is shutting down");
            }
            long token = operationGeneration.incrementAndGet();
            UiOperation<?> previous = currentOperation.getAndSet(null);
            if (previous != null) previous.cancelIfPending();
            return token;
        }
    }

    private <T> T runOnUi(long token, long timeoutMillis, UiCallable<T> callable) throws Exception {
        return runOnUi(token, timeoutMillis, false, callable);
    }

    private <T> T runReadOnUi(long token, long timeoutMillis,
                              UiCallable<T> callable) throws Exception {
        if (operationGeneration.get() != token) {
            throw new IllegalStateException("proxy read cancelled");
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            T value = callable.call();
            if (operationGeneration.get() != token) {
                throw new IllegalStateException("proxy read cancelled");
            }
            return value;
        }
        UiReadOperation<T> operation = new UiReadOperation<>(token, callable);
        AndroidUtilities.runOnUIThread(operation.runnable);
        boolean completed = operation.await(Math.max(0L, timeoutMillis));
        if (!completed) {
            operation.cancelIfPending();
            throw new IllegalStateException("Telegram proxy read timeout");
        }
        if (operation.state.get() == OperationState.CANCELLED
                || operationGeneration.get() != token) {
            throw new IllegalStateException("proxy read cancelled");
        }
        Throwable failure = operation.failure.get();
        if (failure instanceof Exception) throw (Exception) failure;
        if (failure != null) throw new RuntimeException(failure);
        return operation.result.get();
    }

    private <T> T runOnUi(long token, long timeoutMillis, boolean leaveQueuedOnTimeout,
                          UiCallable<T> callable) throws Exception {
        if (operationGeneration.get() != token) throw new IllegalStateException("proxy operation cancelled");
        if (Looper.myLooper() == Looper.getMainLooper()) {
            T value = callable.call();
            if (operationGeneration.get() != token) {
                throw new IllegalStateException("proxy operation cancelled");
            }
            return value;
        }
        UiOperation<T> operation = new UiOperation<>(token, callable);
        currentOperation.set(operation);
        AndroidUtilities.runOnUIThread(operation.runnable);
        boolean completed = operation.await(Math.max(0L, timeoutMillis));
        if (!completed) {
            if (!leaveQueuedOnTimeout && operation.cancelIfPending()) {
                currentOperation.compareAndSet(operation, null);
                throw new IllegalStateException("Telegram proxy UI timeout");
            }
            // Never wait past the caller's absolute budget. A timed-out
            // activation is followed by restoreSaved() from activate()'s
            // catch block. Bounded restore/release operations remain queued
            // so they run immediately after a late activation and undo it.
            throw new IllegalStateException("Telegram proxy UI deadline exceeded");
        }
        currentOperation.compareAndSet(operation, null);
        if (operation.state.get() == OperationState.CANCELLED
                || operationGeneration.get() != token) {
            throw new IllegalStateException("proxy operation cancelled");
        }
        Throwable failure = operation.failure.get();
        if (failure instanceof Exception) throw (Exception) failure;
        if (failure != null) throw new RuntimeException(failure);
        return operation.result.get();
    }

    private static ProxySnapshotModel snapshot(SharedPreferences preferences,
                                               SharedConfig.ProxyInfo previous,
                                               ProxyBackend backend) {
        ProxySnapshotModel.Preferences raw = new ProxySnapshotModel.Preferences(
                preferences.getString("proxy_ip", ""), preferences.getInt("proxy_port", 1080),
                preferences.getString("proxy_user", ""), preferences.getString("proxy_pass", ""),
                preferences.getString("proxy_secret", ""),
                preferences.getBoolean("proxy_enabled", false),
                preferences.getBoolean("proxy_enabled_calls", false));
        ProxySnapshotModel.ProxyValue value = previous == null ? null
                : new ProxySnapshotModel.ProxyValue(previous.address, previous.port,
                previous.username, previous.password, previous.secret);
        return new ProxySnapshotModel(false, value,
                previous == null ? "" : backend.name(previous), raw, "");
    }

    private static boolean samePreferences(ProxySnapshotModel.Preferences expected,
                                           SharedPreferences actual) {
        return expected.enabled == actual.getBoolean("proxy_enabled", false)
                && expected.calls == actual.getBoolean("proxy_enabled_calls", false)
                && expected.port == actual.getInt("proxy_port", 1080)
                && expected.ip.equals(actual.getString("proxy_ip", ""))
                && expected.username.equals(actual.getString("proxy_user", ""))
                && expected.password.equals(actual.getString("proxy_pass", ""))
                && expected.secret.equals(actual.getString("proxy_secret", ""));
    }

    private static boolean samePreferencesValue(ProxySnapshotModel.Preferences expected,
                                                ProxySnapshotModel.Preferences actual) {
        return expected != null && actual != null
                && expected.enabled == actual.enabled && expected.calls == actual.calls
                && expected.port == actual.port && expected.ip.equals(actual.ip)
                && expected.username.equals(actual.username)
                && expected.password.equals(actual.password)
                && expected.secret.equals(actual.secret);
    }

    static boolean ownsCallsPreference(boolean value) {
        // Activation publishes this value together with the owned fingerprint.
        // A different value therefore belongs to the user, not this session.
        return value == OWNED_PROXY_CALLS;
    }

    static boolean callsPreferenceAfterRestore(boolean previousValue, boolean currentValue) {
        // Restore the old value only while the plugin-owned value is intact.
        return ownsCallsPreference(currentValue) ? previousValue : currentValue;
    }

    private static boolean sameProxyValue(ProxySnapshotModel.ProxyValue expected,
                                          ProxySnapshotModel.ProxyValue actual) {
        return expected == null ? actual == null : expected.equals(actual);
    }

    private static boolean sameProxy(ProxySnapshotModel.ProxyValue expected,
                                     SharedConfig.ProxyInfo actual) {
        if (expected == null || actual == null) return expected == null && actual == null;
        return expected.address.equals(actual.address) && expected.port == actual.port
                && expected.username.equals(actual.username)
                && expected.password.equals(actual.password)
                && expected.secret.equals(actual.secret);
    }

    private static SharedConfig.ProxyInfo proxyFromValue(ProxySnapshotModel.ProxyValue value) {
        return value == null ? null : new SharedConfig.ProxyInfo(value.address, value.port,
                value.username, value.password, value.secret);
    }

    private static SharedConfig.ProxyInfo findExact(ArrayList<SharedConfig.ProxyInfo> values,
                                                    SharedConfig.ProxyInfo target) {
        if (target == null) return null;
        String link = target.getLink();
        for (SharedConfig.ProxyInfo item : values) if (link.equals(item.getLink())) return item;
        return null;
    }

    private static void removeOwned(ProxyBackend backend, String savedFingerprint) {
        if (savedFingerprint == null || savedFingerprint.isEmpty()) return;
        for (SharedConfig.ProxyInfo item : backend.list()) {
            if (matchesFingerprint(savedFingerprint, item)) {
                backend.delete(item);
                return;
            }
        }
    }

    private static String randomToken(int bytes) {
        byte[] value = new byte[bytes];
        new SecureRandom().nextBytes(value);
        StringBuilder output = new StringBuilder(bytes * 2);
        for (byte item : value) output.append(String.format(Locale.US, "%02x", item & 255));
        return output.toString();
    }

    private static String fingerprint(SharedConfig.ProxyInfo proxy) {
        if (proxy == null) return "";
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(proxy.getLink().getBytes(StandardCharsets.UTF_8));
            StringBuilder output = new StringBuilder(64);
            for (byte item : digest) output.append(String.format(Locale.US, "%02x", item & 255));
            return output.toString();
        } catch (Exception ignored) {
            return "";
        }
    }

    private static boolean matchesFingerprint(String saved, SharedConfig.ProxyInfo proxy) {
        if (saved == null || saved.isEmpty() || proxy == null) return false;
        // The raw link is an exact beta.1 representation, not a name/address heuristic.
        return saved.equals(fingerprint(proxy)) || saved.equals(proxy.getLink());
    }

    private ProxyBackend backend() {
        ProxyBackend value = backend;
        if (value != null) return value;
        synchronized (this) {
            value = backend;
            if (value == null) {
                value = ProxyBackend.create();
                backend = value;
            }
            return value;
        }
    }

    @Override
    public void close() {
        try {
            cancelPending();
            restore();
        } finally {
            beginShutdown();
        }
    }

    static final class Credentials {
        final String username;
        final String password;

        Credentials(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    static final class StateGuard {
        private final ProxySnapshotModel.ProxyValue proxy;
        private final ProxySnapshotModel.Preferences preferences;

        StateGuard(ProxySnapshotModel.ProxyValue proxy,
                   ProxySnapshotModel.Preferences preferences) {
            this.proxy = proxy;
            this.preferences = preferences == null
                    ? ProxySnapshotModel.Preferences.defaults() : preferences;
        }

        boolean matches(ProxySnapshotModel actual) {
            return actual != null && sameProxyValue(proxy, actual.previous)
                    && samePreferencesValue(preferences, actual.preferences);
        }

        boolean matches(StateGuard actual) {
            return actual != null && sameProxyValue(proxy, actual.proxy)
                    && samePreferencesValue(preferences, actual.preferences);
        }
    }

    static final class ExternalProxyChangeException extends Exception {
        private static final long serialVersionUID = 1L;

        ExternalProxyChangeException() {
            super("Telegram proxy changed while exitFy was paused");
        }
    }

    static final class RecoveryPendingException extends Exception {
        private static final long serialVersionUID = 1L;

        RecoveryPendingException() {
            super("Telegram proxy recovery is still pending");
        }

        RecoveryPendingException(String message) {
            super(message == null || message.isEmpty()
                    ? "Telegram proxy recovery is still pending" : message);
        }
    }

    enum Ownership {
        OWNED,
        EXTERNALLY_CHANGED,
        INACTIVE,
        UNKNOWN
    }

    enum RestoreOutcome {
        RESTORED,
        PRESERVED,
        INACTIVE,
        FAILED
    }

    private enum OperationState {
        PENDING,
        RUNNING,
        CANCELLED,
        DONE
    }

    private final class UiOperation<T> {
        final long token;
        final UiCallable<T> callable;
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<OperationState> state = new AtomicReference<>(OperationState.PENDING);
        final AtomicReference<T> result = new AtomicReference<>();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final Runnable runnable;

        UiOperation(long token, UiCallable<T> callable) {
            this.token = token;
            this.callable = callable;
            this.runnable = () -> {
                if (!state.compareAndSet(OperationState.PENDING, OperationState.RUNNING)) {
                    latch.countDown();
                    return;
                }
                try {
                    if (operationGeneration.get() != this.token) {
                        state.set(OperationState.CANCELLED);
                        return;
                    }
                    T value = this.callable.call();
                    if (operationGeneration.get() != this.token) {
                        state.set(OperationState.CANCELLED);
                    } else {
                        result.set(value);
                        state.set(OperationState.DONE);
                    }
                } catch (Throwable error) {
                    failure.set(error);
                    state.set(OperationState.DONE);
                } finally {
                    latch.countDown();
                    currentOperation.compareAndSet(UiOperation.this, null);
                    onOperationFinished(this.token);
                }
            };
        }

        boolean await(long timeoutMillis) throws InterruptedException {
            return latch.await(timeoutMillis, TimeUnit.MILLISECONDS);
        }

        boolean cancelIfPending() {
            if (!state.compareAndSet(OperationState.PENDING, OperationState.CANCELLED)) return false;
            AndroidUtilities.cancelRunOnUIThread(runnable);
            latch.countDown();
            onOperationFinished(token);
            return true;
        }
    }

    private final class UiReadOperation<T> {
        final long token;
        final UiCallable<T> callable;
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<OperationState> state = new AtomicReference<>(OperationState.PENDING);
        final AtomicReference<T> result = new AtomicReference<>();
        final AtomicReference<Throwable> failure = new AtomicReference<>();
        final Runnable runnable;

        UiReadOperation(long token, UiCallable<T> callable) {
            this.token = token;
            this.callable = callable;
            this.runnable = () -> {
                if (!state.compareAndSet(OperationState.PENDING, OperationState.RUNNING)) {
                    latch.countDown();
                    return;
                }
                try {
                    if (operationGeneration.get() != this.token) {
                        state.set(OperationState.CANCELLED);
                        return;
                    }
                    T value = this.callable.call();
                    if (operationGeneration.get() != this.token) {
                        state.set(OperationState.CANCELLED);
                    } else {
                        result.set(value);
                        state.set(OperationState.DONE);
                    }
                } catch (Throwable error) {
                    failure.set(error);
                    state.set(OperationState.DONE);
                } finally {
                    latch.countDown();
                }
            };
        }

        boolean await(long timeoutMillis) throws InterruptedException {
            return latch.await(timeoutMillis, TimeUnit.MILLISECONDS);
        }

        boolean cancelIfPending() {
            if (!state.compareAndSet(OperationState.PENDING, OperationState.CANCELLED)) return false;
            AndroidUtilities.cancelRunOnUIThread(runnable);
            latch.countDown();
            return true;
        }
    }

    private interface UiCallable<T> {
        T call() throws Exception;
    }

    interface StateRetention {
        boolean isCurrent();
    }
}
