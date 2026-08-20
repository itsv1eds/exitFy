package com.extera.plugins.exitfy;

import android.os.ParcelFileDescriptor;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

final class NativeCoreRuntime implements Closeable {
    private static final long START_TIMEOUT_SECONDS = 12L;
    private static final long STOP_TIMEOUT_SECONDS = 3L;

    static long maximumStartWaitMillis() {
        return TimeUnit.SECONDS.toMillis(START_TIMEOUT_SECONDS);
    }

    static long maximumStopWaitMillis() {
        return TimeUnit.SECONDS.toMillis(STOP_TIMEOUT_SECONDS);
    }

    private final Map<CoreFamily, CoreUpdater> updaters = new EnumMap<>(CoreFamily.class);
    private final NativeCalls nativeCalls;
    private final AdmissionHook admissionHook;
    private final Object lifecycleMonitor = new Object();
    private final ReentrantLock lifecycleAdmission = new ReentrantLock(true);
    private final Object nativeAdmissionLock = new Object();
    private final ExecutorService nativeExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "exitfy-native");
        thread.setDaemon(true);
        return thread;
    });

    private static volatile boolean processNativeOpened;
    private static volatile CoreFamily processLoadedFamily;
    private static volatile int processLoadedCoreApi;
    private static volatile boolean processQuarantined;
    private static final Object PROCESS_CLEANUP_MONITOR = new Object();
    // A timed-out JNI call can outlive its RuntimeCoordinator. Keep cleanup
    // ownership process-wide so every plugin reload does not create another
    // daemon blocked on the same native mutex. Success retains the claim until
    // process death; a quick error/rejection releases it for one later retry.
    private static boolean processCleanupClaimed;
    private volatile Future<String> activeNativeCall;
    private volatile Future<?> lateCleanup;
    private volatile boolean startInProgress;
    private volatile boolean shutdownRequested;
    private volatile boolean running;
    private volatile CoreFamily runningFamily;
    private boolean nativeAdmissionClosed;

    NativeCoreRuntime(CoreUpdater singBox, CoreUpdater xray) {
        this(singBox, xray, NativeCalls.SYSTEM, AdmissionHook.NOOP);
    }

    NativeCoreRuntime(CoreUpdater singBox, CoreUpdater xray,
                      NativeCalls nativeCalls) {
        this(singBox, xray, nativeCalls, AdmissionHook.NOOP);
    }

    NativeCoreRuntime(CoreUpdater singBox, CoreUpdater xray,
                      NativeCalls nativeCalls, AdmissionHook admissionHook) {
        this.updaters.put(CoreFamily.SING_BOX, singBox);
        this.updaters.put(CoreFamily.XRAY, xray);
        this.nativeCalls = nativeCalls == null ? NativeCalls.SYSTEM : nativeCalls;
        this.admissionHook = admissionHook == null ? AdmissionHook.NOOP : admissionHook;
        // The Java process state survives a normal plugin disable/enable.  Do
        // not enter JNI merely to re-read immutable identity while a previous
        // StartCore/StopCore may still be stuck inside the native call lock.
        // A fresh DEX class loader has fresh statics and uses the non-blocking
        // native identity accessor instead (its metadata has a separate lock).
        if (!processNativeOpened && !processQuarantined) {
            String loaded = this.nativeCalls.loadedIdentity();
            if (loaded != null && !loaded.isEmpty()) {
                processNativeOpened = true;
                processLoadedFamily = CoreFamily.parse(loaded);
                processLoadedCoreApi = this.nativeCalls.loadedCoreApi();
                if (processLoadedCoreApi != 1 && processLoadedCoreApi != 2) {
                    processQuarantined = true;
                }
            }
        }
    }

    StartResult start(CoreFamily family, String configJson) {
        lifecycleAdmission.lock();
        try {
            return startWithin(family, configJson, Long.MAX_VALUE);
        } finally {
            lifecycleAdmission.unlock();
        }
    }

    StartResult start(CoreFamily family, String configJson, long timeoutMillis) {
        lifecycleAdmission.lock();
        try {
            long bounded = Math.max(0L, timeoutMillis);
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(bounded);
            return startWithin(family, configJson, deadline);
        } finally {
            lifecycleAdmission.unlock();
        }
    }

    private StartResult startWithin(CoreFamily family, String configJson, long deadline) {
        setStartInProgress(true);
        boolean nativeOpenPhase = false;
        CoreUpdater updater = updater(family);
        try {
            if (shutdownRequested) {
                return StartResult.error(I18n.t("Runtime завершает работу", "Runtime is shutting down"));
            }
            if (processQuarantined) {
                return StartResult.error(I18n.t("Подключение заблокировано до перезапуска exteraGram",
                        "The connection is blocked until exteraGram restarts"));
            }
            if (isProcessCleanupClaimed()) {
                return StartResult.error(I18n.t(
                        "Предыдущее подключение ещё завершается; повторите попытку",
                        "The previous connection is still stopping; try again"));
            }
            if (running) {
                return runningFamily == family ? StartResult.ok()
                        : restartRequired();
            }
            if (processNativeOpened
                    && CoreProcessState.requiresRestart(processLoadedFamily, family)) {
                return restartRequired();
            }

            if (!processNativeOpened) {
                CoreUpdater.PinnedLoadTarget loadTarget = updater.preparePinnedLoadTarget();
                if (loadTarget == null || !loadTarget.file.isFile()) {
                    closeQuietly(loadTarget);
                    return StartResult.missing(updater.requiresNewCore()
                            ? family.displayName + " " + I18n.t(
                            "требует новое ядро для Android 10 arm64-v8a; загрузка выполняется в фоне",
                            "requires a new Android 10 arm64-v8a core; download is running in background")
                            : family.displayName + " " + I18n.t(
                            "не установлен; загрузка выполняется в фоне",
                            "is not installed; download is running in background"));
                }
                if (shutdownRequested) {
                    closeQuietly(loadTarget);
                    return StartResult.error(I18n.t(
                            "Runtime завершает работу", "Runtime is shutting down"));
                }

                nativeOpenPhase = true;
                // Digest, loader-visible ELF tables and the native load all
                // consume one pinned descriptor.  The pathname is details
                // only and must never be reopened by JNI.
                final String corePath = loadTarget.file.getAbsolutePath();
                final int coreApi = loadTarget.coreApi;
                final AtomicBoolean openSubmitted = new AtomicBoolean();
                String openError;
                try {
                    long openBudget = nativeCallBudget(deadline, START_TIMEOUT_SECONDS);
                    openError = runNativeMillis(() -> {
                        try {
                            return nativeCalls.open(loadTarget.descriptor(), corePath,
                                    family.id, coreApi);
                        } finally {
                            closeQuietly(loadTarget);
                        }
                    }, openBudget, () -> openSubmitted.set(true));
                } catch (Exception | Error error) {
                    if (!openSubmitted.get()) closeQuietly(loadTarget);
                    throw error;
                }
                if (openError != null && !openError.isEmpty()) {
                    String openedIdentity = nativeCalls.loadedIdentity();
                    if (openedIdentity != null && !openedIdentity.isEmpty()) {
                        processNativeOpened = true;
                        processLoadedFamily = CoreFamily.parse(openedIdentity);
                        processLoadedCoreApi = nativeCalls.loadedCoreApi();
                    }
                    // A loader failure schedules rollback for the next process.
                    // Do not retry the same mapped or broken binary in this one.
                    processQuarantined = true;
                    updater.markLoaderFailure();
                    return StartResult.error(openError);
                }
                processNativeOpened = true;
                processLoadedFamily = family;
                processLoadedCoreApi = coreApi;
                nativeOpenPhase = false;

                if (updater.isCandidate()) {
                    String selfTestError = runNativeMillis(
                            () -> nativeCalls.start(selfTestConfig(family).toString()),
                            nativeCallBudget(deadline, START_TIMEOUT_SECONDS));
                    if (selfTestError != null && !selfTestError.isEmpty()) {
                        String stopError = stopAfterFailedStart(deadline);
                        updater.markLoaderFailure();
                        processQuarantined = true;
                        if (stopError != null && !stopError.isEmpty()) {
                            scheduleLateCleanup(family);
                        }
                        return StartResult.error("core self-test failed: " + selfTestError
                                + (stopError == null || stopError.isEmpty()
                                ? "" : "; StopCore: " + stopError));
                    }
                    String selfTestStopError = runNativeMillis(
                            nativeCalls::stop,
                            nativeCallBudget(deadline, STOP_TIMEOUT_SECONDS));
                    if (selfTestStopError != null && !selfTestStopError.isEmpty()) {
                        updater.markLoaderFailure();
                        processQuarantined = true;
                        scheduleLateCleanup(family);
                        return StartResult.error("core self-test stop failed: "
                                + selfTestStopError);
                    }
                    updater.markStartSuccess();
                }
            }

            if (shutdownRequested) {
                return StartResult.error(I18n.t(
                        "Runtime завершает работу", "Runtime is shutting down"));
            }
            String error = runNativeMillis(() -> nativeCalls.start(configJson),
                    nativeCallBudget(deadline, START_TIMEOUT_SECONDS));
            if (error != null && !error.isEmpty()) {
                // The core has passed loader/self-test checks. A selected node
                // error is not grounds for rolling back the core binary.
                String stopError = stopAfterFailedStart(deadline);
                if (stopError != null && !stopError.isEmpty()) {
                    processQuarantined = true;
                    scheduleLateCleanup(family);
                    return StartResult.error(error + "; StopCore: " + stopError);
                }
                return StartResult.error(error);
            }
            if (shutdownRequested || processQuarantined) {
                // unload() may exhaust its deadline while StartCore is still
                // inside Go. Its serialized cleanup is already queued behind
                // this call, so never publish a late RUNNING state.
                scheduleLateCleanup(family);
                return StartResult.error(I18n.t(
                        "Runtime завершает работу", "Runtime is shutting down"));
            }
            runningFamily = family;
            // Publish the family before the volatile running flag so lock-free
            // UI/status readers can never observe RUNNING with a null family.
            running = true;
            updater.markStartSuccess();
            return StartResult.ok();
        } catch (TimeoutException timeout) {
            processQuarantined = true;
            if (nativeOpenPhase || updater.isCandidate()) updater.markLoaderFailure();
            scheduleLateCleanup(family);
            return StartResult.error(I18n.t(
                    "StartCore завис; ядро заблокировано до перезапуска приложения",
                    "StartCore hung; the core is blocked until the app restarts"));
        } catch (InterruptedException interrupted) {
            // Future.cancel(true) and executor shutdown interrupt only the
            // Java waiter; they do not cancel a JNI/Go call already running on
            // nativeExecutor.  Treat ownership as uncertain and serialize a
            // StopCore behind that call before allowing the thread to exit.
            processQuarantined = true;
            if (nativeOpenPhase || updater.isCandidate()) updater.markLoaderFailure();
            scheduleLateCleanup(family);
            Thread.currentThread().interrupt();
            return StartResult.error(I18n.t(
                    "Запуск ядра прерван; требуется перезапуск приложения",
                    "Core start was interrupted; restart the app before retrying"));
        } catch (ExecutionException execution) {
            // A Java/JNI exception can be raised after the Go core has already
            // accepted the configuration (for example while converting the
            // result).  Never infer that the core is stopped from that error.
            processQuarantined = true;
            if (nativeOpenPhase || updater.isCandidate()) updater.markLoaderFailure();
            scheduleLateCleanup(family);
            Throwable cause = execution.getCause();
            return StartResult.error(cause == null || cause.getMessage() == null
                    ? execution.getClass().getSimpleName() : cause.getMessage());
        } catch (RejectedExecutionException rejected) {
            // shutdownForUnload closes admission and queues one final StopCore
            // atomically. A post-open self-test/start submission is therefore
            // rejected without being able to overtake that cleanup.
            processQuarantined = true;
            scheduleLateCleanup(family);
            return StartResult.error(I18n.t(
                    "Runtime завершает работу", "Runtime is shutting down"));
        } catch (Exception error) {
            if (nativeOpenPhase) updater.markLoaderFailure();
            return StartResult.error(error.getMessage() == null
                    ? error.getClass().getSimpleName() : error.getMessage());
        } finally {
            setStartInProgress(false);
        }
    }

    boolean stop() {
        lifecycleAdmission.lock();
        try {
            return stopWithin(TimeUnit.SECONDS.toMillis(STOP_TIMEOUT_SECONDS));
        } finally {
            lifecycleAdmission.unlock();
        }
    }

    boolean stop(long timeoutMillis) {
        lifecycleAdmission.lock();
        try {
            return stopWithin(Math.max(0L, timeoutMillis));
        } finally {
            lifecycleAdmission.unlock();
        }
    }

    private boolean stopWithin(long timeoutMillis) {
        if (!running) return true;
        CoreFamily stoppingFamily = runningFamily;
        if (processQuarantined || timeoutMillis <= 0L) {
            scheduleLateCleanup(stoppingFamily);
            return false;
        }
        try {
            String stopError = runNativeMillis(nativeCalls::stop,
                    Math.min(timeoutMillis, TimeUnit.SECONDS.toMillis(STOP_TIMEOUT_SECONDS)));
            admissionHook.afterNativeStopReturned();
            if (stopError != null && !stopError.isEmpty()) {
                processQuarantined = true;
                CoreUpdater updater = stoppingFamily == null ? null : updaters.get(stoppingFamily);
                if (updater != null && updater.isCandidate()) updater.markLoaderFailure();
                scheduleLateCleanup(stoppingFamily);
                return false;
            }
            running = false;
            runningFamily = null;
            return true;
        } catch (TimeoutException timeout) {
            processQuarantined = true;
            scheduleLateCleanup(stoppingFamily);
            return false;
        } catch (InterruptedException interrupted) {
            processQuarantined = true;
            scheduleLateCleanup(stoppingFamily);
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException execution) {
            processQuarantined = true;
            scheduleLateCleanup(stoppingFamily);
            Throwable cause = execution.getCause();
            return false;
        } catch (Exception error) {
            processQuarantined = true;
            scheduleLateCleanup(stoppingFamily);
            return false;
        }
    }

    boolean checkForUpdate(CoreFamily family, boolean force) throws Exception {
        return updater(family).checkForUpdate(force);
    }

    boolean checkForUpdate(CoreFamily family, boolean force,
                           CoreUpdater.UpdateObserver observer) throws Exception {
        return updater(family).checkForUpdate(force, observer);
    }

    boolean hasUsableCore(CoreFamily family) {
        return updater(family).hasUsableCore();
    }

    boolean verifyLocalReadiness(CoreFamily family) throws Exception {
        return updater(family).verifyLocalReadiness();
    }

    boolean prepareLocalCore(CoreFamily family) throws Exception {
        return updater(family).prepareLoadTarget() != null;
    }

    CoreFamily loadedFamily() {
        return processLoadedFamily;
    }

    CoreFamily runningFamily() {
        return runningFamily;
    }

    boolean isRunning() {
        return running;
    }

    boolean isQuarantined() {
        return processQuarantined;
    }

    void beginShutdown() {
        shutdownRequested = true;
    }

    boolean shutdownForUnload(long timeoutMillis) {
        beginShutdown();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0L, timeoutMillis));
        if (!awaitStartCompletion(deadline)) {
            processQuarantined = true;
            CoreFamily cleanupFamily = runningFamily != null
                    ? runningFamily : processLoadedFamily;
            closeNativeAdmission(true, cleanupFamily);
            return false;
        }
        if (processQuarantined) {
            CoreFamily cleanupFamily = runningFamily != null
                    ? runningFamily : processLoadedFamily;
            closeNativeAdmission(true, cleanupFamily);
            awaitLateCleanup(deadline);
            awaitExecutor(deadline);
            return false;
        }
        boolean lifecycleAcquired = tryLifecycleAdmission(deadline);
        if (!lifecycleAcquired) {
            processQuarantined = true;
            CoreFamily cleanupFamily = runningFamily != null
                    ? runningFamily : processLoadedFamily;
            closeNativeAdmission(true, cleanupFamily);
            awaitLateCleanup(deadline);
            awaitExecutor(deadline);
            return false;
        }
        boolean stopped;
        try {
            stopped = stopWithin(remainingMillis(deadline));
        } finally {
            lifecycleAdmission.unlock();
        }
        closeNativeAdmission(!stopped, runningFamily != null
                ? runningFamily : processLoadedFamily);
        awaitExecutor(deadline);
        if (!nativeExecutor.isTerminated()) {
            processQuarantined = true;
            return false;
        }
        return stopped && !processQuarantined;
    }

    @Override
    public void close() {
        shutdownForUnload(TimeUnit.SECONDS.toMillis(STOP_TIMEOUT_SECONDS));
    }

    private CoreUpdater updater(CoreFamily family) {
        CoreUpdater value = updaters.get(family);
        if (value == null) throw new IllegalArgumentException("unsupported core family");
        return value;
    }

    private static StartResult restartRequired() {
        // Naming the loaded and required families would tell the user nothing
        // they can act on, and the interface never exposes them elsewhere.
        return StartResult.restart(I18n.t(
                "Этому серверу нужен другой компонент подключения. "
                        + "Перезапустите exteraGram",
                "This server needs a different connection component. "
                        + "Restart exteraGram"));
    }

    private static JSONObject selfTestConfig(CoreFamily family) throws Exception {
        int port = findFreeLoopbackPort();
        if (family == CoreFamily.XRAY) {
            return new JSONObject()
                    .put("log", new JSONObject().put("loglevel", "none"))
                    .put("inbounds", new JSONArray().put(new JSONObject()
                            .put("listen", "127.0.0.1").put("port", port)
                            .put("protocol", "socks")
                            .put("settings", new JSONObject().put("auth", "noauth"))))
                    .put("outbounds", new JSONArray().put(new JSONObject()
                            .put("tag", "self-test").put("protocol", "blackhole")));
        }
        return new JSONObject()
                .put("log", new JSONObject().put("level", "panic"))
                .put("inbounds", new JSONArray().put(new JSONObject()
                        .put("type", "mixed").put("listen", "127.0.0.1")
                        .put("listen_port", port)))
                .put("outbounds", new JSONArray().put(new JSONObject()
                        .put("type", "block").put("tag", "self-test")))
                .put("route", new JSONObject().put("final", "self-test"));
    }

    private static int findFreeLoopbackPort() throws Exception {
        try (ServerSocket socket = new ServerSocket()) {
            socket.setReuseAddress(false);
            socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            return socket.getLocalPort();
        }
    }

    private String stopAfterFailedStart(long deadline)
            throws TimeoutException, ExecutionException, InterruptedException {
        return runNativeMillis(nativeCalls::stop,
                nativeCallBudget(deadline, STOP_TIMEOUT_SECONDS));
    }

    private void scheduleLateCleanup(CoreFamily family) {
        String familyId = family == null ? "core" : family.id;
        synchronized (nativeAdmissionLock) {
            Future<?> current = lateCleanup;
            if (current != null && !current.isDone()) return;
            if (nativeAdmissionClosed) {
                return;
            }
            try {
                Future<?> submitted = submitCleanupLocked(familyId);
                if (submitted != null) lateCleanup = submitted;
            } catch (RejectedExecutionException rejected) {
            }
        }
    }

    private void closeNativeAdmission(boolean requireFinalCleanup, CoreFamily family) {
        String familyId = family == null ? "core" : family.id;
        synchronized (nativeAdmissionLock) {
            if (!nativeAdmissionClosed) nativeAdmissionClosed = true;
            if (requireFinalCleanup) {
                Future<?> current = lateCleanup;
                if (current == null || current.isDone()) {
                    try {
                        Future<?> submitted = submitCleanupLocked(familyId);
                        if (submitted != null) lateCleanup = submitted;
                    } catch (RejectedExecutionException rejected) {
                    }
                }
                admissionHook.afterFinalCleanupQueued();
            }
            nativeExecutor.shutdown();
        }
    }

    private Future<?> submitCleanupLocked(String familyId) {
        if (!claimProcessCleanup()) return null;
        try {
            return nativeExecutor.submit(() -> {
                boolean complete = false;
                try {
                    String stopError = nativeCalls.stop();
                    if (stopError == null || stopError.isEmpty()) {
                        running = false;
                        runningFamily = null;
                        complete = true;
                    } else {
                    }
                } catch (Throwable error) {
                } finally {
                    if (!complete) processQuarantined = true;
                    if (!complete || !processQuarantined) releaseProcessCleanup();
                }
            });
        } catch (RejectedExecutionException rejected) {
            releaseProcessCleanup();
            throw rejected;
        }
    }

    private static boolean claimProcessCleanup() {
        synchronized (PROCESS_CLEANUP_MONITOR) {
            if (processCleanupClaimed) return false;
            processCleanupClaimed = true;
            return true;
        }
    }

    private static void releaseProcessCleanup() {
        synchronized (PROCESS_CLEANUP_MONITOR) {
            processCleanupClaimed = false;
        }
    }

    private static boolean isProcessCleanupClaimed() {
        synchronized (PROCESS_CLEANUP_MONITOR) {
            return processCleanupClaimed;
        }
    }

    private String runNativeMillis(Callable<String> callable, long timeoutMillis)
            throws TimeoutException, ExecutionException, InterruptedException {
        return runNativeMillis(callable, timeoutMillis, null);
    }

    private String runNativeMillis(Callable<String> callable, long timeoutMillis,
                                   Runnable onSubmitted)
            throws TimeoutException, ExecutionException, InterruptedException {
        if (timeoutMillis <= 0L) throw new TimeoutException("native call budget exhausted");
        Future<String> future;
        synchronized (nativeAdmissionLock) {
            if (nativeAdmissionClosed) {
                throw new RejectedExecutionException("native admission is closed");
            }
            future = nativeExecutor.submit(callable);
            activeNativeCall = future;
            if (onSubmitted != null) onSubmitted.run();
        }
        try {
            return future.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (TimeoutException timeout) {
            throw timeout;
        } finally {
            if (future.isDone() && activeNativeCall == future) activeNativeCall = null;
        }
    }

    private boolean awaitStartCompletion(long deadline) {
        Future<String> nativeCall = activeNativeCall;
        if (nativeCall != null && !nativeCall.isDone()) {
            long wait = remainingMillis(deadline);
            if (wait <= 0L) return false;
            try {
                nativeCall.get(wait, TimeUnit.MILLISECONDS);
            } catch (TimeoutException timeout) {
                return false;
            } catch (ExecutionException ignored) {
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        synchronized (lifecycleMonitor) {
            while (startInProgress) {
                long wait = remainingMillis(deadline);
                if (wait <= 0L) return false;
                try {
                    lifecycleMonitor.wait(wait);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return true;
    }

    private void setStartInProgress(boolean value) {
        synchronized (lifecycleMonitor) {
            startInProgress = value;
            if (!value) lifecycleMonitor.notifyAll();
        }
    }

    private void awaitExecutor(long deadline) {
        long wait = remainingMillis(deadline);
        if (wait <= 0L) return;
        try {
            nativeExecutor.awaitTermination(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean tryLifecycleAdmission(long deadline) {
        if (lifecycleAdmission.tryLock()) return true;
        long wait = remainingMillis(deadline);
        if (wait <= 0L) return false;
        try {
            return lifecycleAdmission.tryLock(wait, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void awaitLateCleanup(long deadline) {
        Future<?> cleanup = lateCleanup;
        if (cleanup == null || cleanup.isDone()) return;
        long wait = remainingMillis(deadline);
        if (wait <= 0L) return;
        try {
            cleanup.get(wait, TimeUnit.MILLISECONDS);
        } catch (TimeoutException ignored) {
        } catch (ExecutionException ignored) {
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static long remainingMillis(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0L) return 0L;
        return Math.max(1L, TimeUnit.NANOSECONDS.toMillis(nanos));
    }

    private static long nativeCallBudget(long deadline, long maximumSeconds)
            throws TimeoutException {
        long maximum = TimeUnit.SECONDS.toMillis(maximumSeconds);
        if (deadline == Long.MAX_VALUE) return maximum;
        long remaining = remainingMillis(deadline);
        if (remaining <= 0L) throw new TimeoutException("native call budget exhausted");
        return Math.min(maximum, remaining);
    }

    private static void closeQuietly(Closeable value) {
        if (value == null) return;
        try {
            value.close();
        } catch (Exception ignored) {
        }
    }

    static final class StartResult {
        final boolean ok;
        final boolean restartRequired;
        final boolean missingCore;
        final String error;

        private StartResult(boolean ok, boolean restartRequired,
                            boolean missingCore, String error) {
            this.ok = ok;
            this.restartRequired = restartRequired;
            this.missingCore = missingCore;
            this.error = error;
        }

        static StartResult ok() {
            return new StartResult(true, false, false, "");
        }

        static StartResult error(String error) {
            return new StartResult(false, false, false,
                    ErrorSanitizer.clean(error == null ? "unknown core error" : error));
        }

        static StartResult restart(String error) {
            return new StartResult(false, true, false,
                    ErrorSanitizer.clean(error == null ? "restart required" : error));
        }

        static StartResult missing(String error) {
            return new StartResult(false, false, true,
                    ErrorSanitizer.clean(error == null ? "core is unavailable" : error));
        }
    }

    interface NativeCalls {
        NativeCalls SYSTEM = new NativeCalls() {
            @Override
            public String open(FileDescriptor descriptor, String path,
                               String identity, int coreApi) throws Exception {
                if (descriptor == null || !descriptor.valid()) {
                    return "core descriptor is not pinned";
                }
                // Keep Java ownership independent from JNI's duplicate.  The
                // descriptor still refers to the inode already attested by
                // CoreFileHandle; no pathname lookup occurs here.
                try (ParcelFileDescriptor duplicate = ParcelFileDescriptor.dup(descriptor)) {
                    return NativeBridge.nativeOpen(duplicate.getFd(), path, identity, coreApi);
                }
            }

            @Override
            public String loadedIdentity() {
                return NativeBridge.nativeLoadedIdentity();
            }

            @Override
            public int loadedCoreApi() {
                return NativeBridge.nativeLoadedCoreApi();
            }

            @Override
            public String start(String configJson) {
                return NativeBridge.nativeStart(configJson);
            }

            @Override
            public String stop() {
                return NativeBridge.nativeStop();
            }
        };

        String open(FileDescriptor descriptor, String path,
                    String identity, int coreApi) throws Exception;

        String loadedIdentity();

        int loadedCoreApi();

        String start(String configJson);

        String stop();
    }

    interface AdmissionHook {
        AdmissionHook NOOP = () -> {
        };

        void afterFinalCleanupQueued();

        default void afterNativeStopReturned() {
        }
    }

    static void resetProcessStateForTests() {
        processNativeOpened = false;
        processLoadedFamily = null;
        processLoadedCoreApi = 0;
        processQuarantined = false;
        synchronized (PROCESS_CLEANUP_MONITOR) {
            processCleanupClaimed = false;
        }
    }
}
