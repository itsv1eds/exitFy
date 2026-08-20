package com.extera.plugins.exitfy;

import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.io.FileDescriptor;
import java.nio.file.Files;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NativeCoreRuntimeTest {
    @After
    public void resetProcessState() {
        NativeCoreRuntime.resetProcessStateForTests();
    }

    @Test
    public void updateCheckCannotPromoteAcrossStartOpenWindow() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-install-race").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch openEntered = new CountDownLatch(1);
        CountDownLatch releaseOpen = new CountDownLatch(1);
        try {
            File core = new File(root, "active.so");
            Files.write(core.toPath(), new byte[]{1});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 1));
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls calls = new FakeNativeCalls();
            calls.openEntered = openEntered;
            calls.releaseOpen = releaseOpen;
            NativeCoreRuntime runtime = new NativeCoreRuntime(
                    singBox, xray, calls);

            Future<NativeCoreRuntime.StartResult> start = workers.submit(
                    () -> runtime.start(CoreFamily.SING_BOX, "{}"));
            assertTrue(openEntered.await(2, TimeUnit.SECONDS));
            Future<Boolean> update = workers.submit(
                    () -> runtime.checkForUpdate(CoreFamily.SING_BOX, true));
            update.get(2, TimeUnit.SECONDS);

            assertTrue("update check called the promotion seam during nativeOpen",
                    singBox.prepareCalls.get() == 1);
            releaseOpen.countDown();
            assertTrue(start.get(2, TimeUnit.SECONDS).ok);
            assertTrue(runtime.stop());
            runtime.shutdownForUnload(1000L);
        } finally {
            releaseOpen.countDown();
            workers.shutdownNow();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void freshMissingCoreReturnsWithoutJoiningBackgroundDownload() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-missing-core").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX, null);
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls calls = new FakeNativeCalls();
            NativeCoreRuntime runtime = new NativeCoreRuntime(
                    singBox, xray, calls);

            long started = System.nanoTime();
            NativeCoreRuntime.StartResult result = runtime.start(CoreFamily.SING_BOX, "{}");
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertFalse(result.ok);
            assertTrue(result.missingCore);
            assertTrue("start unexpectedly joined updater/network work: " + elapsedMillis,
                    elapsedMillis < 500L);
            assertTrue("start invoked checkForUpdate", singBox.updateCalls.get() == 0);
            assertTrue("missing core reached native open", calls.openCalls.get() == 0);
            runtime.shutdownForUnload(1000L);
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void nativeOpenFailureNeverTriesAnotherFamilyInTheProcess() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-open-no-fallback").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            File singCore = new File(root, "sing.so");
            File xrayCore = new File(root, "xray.so");
            Files.write(singCore.toPath(), new byte[]{7});
            Files.write(xrayCore.toPath(), new byte[]{8});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(singCore, 2));
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY,
                    new CoreUpdater.LoadTarget(xrayCore, 2));
            FakeNativeCalls calls = new FakeNativeCalls();
            calls.openError = "dlopen failed";
            NativeCoreRuntime runtime = new NativeCoreRuntime(singBox, xray, calls);

            NativeCoreRuntime.StartResult first =
                    runtime.start(CoreFamily.SING_BOX, "{}");
            assertFalse(first.ok);
            assertTrue(runtime.isQuarantined());
            assertTrue(calls.openCalls.get() == 1);

            NativeCoreRuntime.StartResult second =
                    runtime.start(CoreFamily.XRAY, "{}");
            assertFalse(second.ok);
            assertFalse(second.restartRequired);
            assertTrue("second family reached native open", calls.openCalls.get() == 1);
            assertTrue("second family prepared a load target", xray.prepareCalls.get() == 0);
            runtime.shutdownForUnload(1000L);
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void startErrorKeepsLoadedFamilyAndNeverFallsBackInTheProcess() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-start-no-fallback").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            File singCore = new File(root, "sing.so");
            File xrayCore = new File(root, "xray.so");
            Files.write(singCore.toPath(), new byte[]{9});
            Files.write(xrayCore.toPath(), new byte[]{10});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(singCore, 2));
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY,
                    new CoreUpdater.LoadTarget(xrayCore, 2));
            FakeNativeCalls calls = new FakeNativeCalls();
            calls.startError = "configuration rejected";
            NativeCoreRuntime runtime = new NativeCoreRuntime(singBox, xray, calls);

            NativeCoreRuntime.StartResult first =
                    runtime.start(CoreFamily.SING_BOX, "{}");
            assertFalse(first.ok);
            assertFalse(runtime.isQuarantined());
            assertTrue(calls.openCalls.get() == 1);
            assertTrue(calls.startCalls.get() == 1);

            NativeCoreRuntime.StartResult second =
                    runtime.start(CoreFamily.XRAY, "{}");
            assertFalse(second.ok);
            assertTrue(second.restartRequired);
            assertTrue("second family reached native open", calls.openCalls.get() == 1);
            assertTrue("second family prepared a load target", xray.prepareCalls.get() == 0);
            runtime.shutdownForUnload(1000L);
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void mappedFamilyRestartsAfterItsInstallFileDisappears() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-mapped-without-file").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            File core = new File(root, "sing.so");
            Files.write(core.toPath(), new byte[]{11});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 2));
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls calls = new FakeNativeCalls();
            NativeCoreRuntime runtime = new NativeCoreRuntime(singBox, xray, calls);

            assertTrue(runtime.start(CoreFamily.SING_BOX, "{}").ok);
            assertTrue(runtime.stop());
            assertTrue(core.delete());

            assertTrue(runtime.start(CoreFamily.SING_BOX, "{}").ok);
            assertTrue("mapped core tried to reopen its removed file",
                    calls.openCalls.get() == 1);
            assertTrue("mapped core prepared a second load target",
                    singBox.prepareCalls.get() == 1);
            assertTrue(runtime.stop());
            runtime.shutdownForUnload(1000L);
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void abiTwoStopErrorQueuesRetryAndUnloadWaitsForIt() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-stop-retry").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        ExecutorService waiter = Executors.newSingleThreadExecutor();
        CountDownLatch retryEntered = new CountDownLatch(1);
        CountDownLatch releaseRetry = new CountDownLatch(1);
        try {
            File core = new File(root, "active.so");
            Files.write(core.toPath(), new byte[]{2});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 2));
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls calls = new FakeNativeCalls();
            calls.stopRetryEntered = retryEntered;
            calls.releaseStopRetry = releaseRetry;
            NativeCoreRuntime runtime = new NativeCoreRuntime(
                    singBox, xray, calls);
            assertTrue(runtime.start(CoreFamily.SING_BOX, "{}").ok);

            assertFalse(runtime.stop());
            assertTrue(retryEntered.await(2, TimeUnit.SECONDS));
            Future<Boolean> unload = waiter.submit(() -> runtime.shutdownForUnload(2000L));
            Thread.sleep(100L);
            assertFalse("unload ignored the queued ABI 2 StopCore retry", unload.isDone());
            releaseRetry.countDown();
            assertFalse(unload.get(2, TimeUnit.SECONDS));
            assertTrue("serialized StopCore retry was not executed",
                    calls.stopCalls.get() == 2);
            assertFalse(runtime.isRunning());
        } finally {
            releaseRetry.countDown();
            waiter.shutdownNow();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void unloadClosesAdmissionBeforeLateOpenCanQueueCandidateSelfTest() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-unload-open-race").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch openEntered = new CountDownLatch(1);
        CountDownLatch releaseOpen = new CountDownLatch(1);
        CountDownLatch openExited = new CountDownLatch(1);
        CountDownLatch cleanupQueued = new CountDownLatch(1);
        CountDownLatch allowShutdown = new CountDownLatch(1);
        try {
            File core = new File(root, "candidate.so");
            Files.write(core.toPath(), new byte[]{3});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 2), true);
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls calls = new FakeNativeCalls();
            calls.openEntered = openEntered;
            calls.releaseOpen = releaseOpen;
            calls.openExited = openExited;
            NativeCoreRuntime runtime = new NativeCoreRuntime(
                    singBox, xray, calls, () -> {
                cleanupQueued.countDown();
                awaitLatch(allowShutdown);
            });

            Future<NativeCoreRuntime.StartResult> start = workers.submit(
                    () -> runtime.start(CoreFamily.SING_BOX, "{}"));
            assertTrue(openEntered.await(2, TimeUnit.SECONDS));
            Future<Boolean> unload = workers.submit(() -> runtime.shutdownForUnload(100L));
            assertTrue("unload never queued its final serialized cleanup",
                    cleanupQueued.await(2, TimeUnit.SECONDS));

            // Reproduce the old ordering window: nativeOpen returns after the
            // cleanup is queued but before shutdown() is called. Admission is
            // already closed, so candidate StartCore must never enter the queue.
            releaseOpen.countDown();
            assertTrue(openExited.await(2, TimeUnit.SECONDS));
            allowShutdown.countDown();

            assertFalse(unload.get(2, TimeUnit.SECONDS));
            assertFalse(start.get(2, TimeUnit.SECONDS).ok);
            assertTrue(calls.stopObserved.await(2, TimeUnit.SECONDS));
            assertTrue("candidate self-test was admitted after unload",
                    calls.startCalls.get() == 0);
            assertTrue("final StopCore was not serialized exactly once",
                    calls.stopCalls.get() == 1);
            assertFalse("fake Go core remained running after unload", calls.coreRunning);
        } finally {
            releaseOpen.countDown();
            allowShutdown.countDown();
            workers.shutdownNow();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void unloadDeadlineDoesNotWaitForConcurrentJavaStopPublication() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-unload-stop-monitor").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        ExecutorService workers = Executors.newSingleThreadExecutor();
        CountDownLatch stopReturned = new CountDownLatch(1);
        CountDownLatch releaseStopPublication = new CountDownLatch(1);
        try {
            File core = new File(root, "active.so");
            Files.write(core.toPath(), new byte[]{4});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 2));
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls calls = new FakeNativeCalls();
            NativeCoreRuntime.AdmissionHook hook = new NativeCoreRuntime.AdmissionHook() {
                @Override
                public void afterFinalCleanupQueued() {
                }

                @Override
                public void afterNativeStopReturned() {
                    stopReturned.countDown();
                    awaitLatch(releaseStopPublication);
                }
            };
            NativeCoreRuntime runtime = new NativeCoreRuntime(
                    singBox, xray, calls, hook);
            assertTrue(runtime.start(CoreFamily.SING_BOX, "{}").ok);

            Future<Boolean> stop = workers.submit(() -> {
                return runtime.stop();
            });
            assertTrue("StopCore did not reach the Java publication barrier",
                    stopReturned.await(2, TimeUnit.SECONDS));
            long began = System.nanoTime();
            assertFalse(runtime.shutdownForUnload(100L));
            long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began);
            assertTrue("unload blocked behind the Java lifecycle monitor: " + elapsed,
                    elapsed < 750L);

            releaseStopPublication.countDown();
            boolean concurrentStop = stop.get(2, TimeUnit.SECONDS);
            assertTrue("concurrent StopCore did not publish success; quarantined="
                    + runtime.isQuarantined() + " calls=" + calls.stopCalls.get(), concurrentStop);
            long cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (calls.stopCalls.get() < 2 && System.nanoTime() < cleanupDeadline) {
                Thread.sleep(10L);
            }
            assertTrue("final serialized StopCore cleanup was not executed",
                    calls.stopCalls.get() == 2);
            assertFalse("fake core remained running after timed unload", calls.coreRunning);
        } finally {
            releaseStopPublication.countDown();
            workers.shutdownNow();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void hungNativeCallHasOneProcessCleanupAcrossRuntimeReloads() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-global-cleanup").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        CountDownLatch startEntered = new CountDownLatch(1);
        CountDownLatch releaseStart = new CountDownLatch(1);
        try {
            File core = new File(root, "active.so");
            Files.write(core.toPath(), new byte[]{5});
            FakeUpdater firstSingBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 2));
            FakeUpdater firstXray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls firstCalls = new FakeNativeCalls();
            firstCalls.startEntered = startEntered;
            firstCalls.releaseStart = releaseStart;
            NativeCoreRuntime first = new NativeCoreRuntime(
                    firstSingBox, firstXray, firstCalls);

            NativeCoreRuntime.StartResult timedOut = first.start(
                    CoreFamily.SING_BOX, "{}", 50L);
            assertFalse(timedOut.ok);
            assertTrue("StartCore never entered the fake native call",
                    startEntered.await(2, TimeUnit.SECONDS));
            assertTrue(first.isQuarantined());

            FakeUpdater secondSingBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 2));
            FakeUpdater secondXray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls secondCalls = new FakeNativeCalls();
            NativeCoreRuntime replacement = new NativeCoreRuntime(
                    secondSingBox, secondXray, secondCalls);
            assertFalse(replacement.shutdownForUnload(100L));
            assertTrue("replacement runtime queued a duplicate process StopCore",
                    secondCalls.stopCalls.get() == 0);

            releaseStart.countDown();
            assertTrue("original serialized cleanup never ran",
                    firstCalls.stopObserved.await(2, TimeUnit.SECONDS));
            assertTrue(firstCalls.stopCalls.get() == 1);
            assertTrue(secondCalls.stopCalls.get() == 0);
            first.shutdownForUnload(500L);
        } finally {
            releaseStart.countDown();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void nativeResultOutOfMemoryQuarantinesAndSerializesCleanup() throws Exception {
        File root = Files.createTempDirectory("exitfy-native-result-oom").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            File core = new File(root, "active.so");
            Files.write(core.toPath(), new byte[]{6});
            FakeUpdater singBox = new FakeUpdater(root, http, CoreFamily.SING_BOX,
                    new CoreUpdater.LoadTarget(core, 2));
            FakeUpdater xray = new FakeUpdater(root, http, CoreFamily.XRAY, null);
            FakeNativeCalls calls = new FakeNativeCalls();
            calls.startOutOfMemory = true;
            NativeCoreRuntime runtime = new NativeCoreRuntime(
                    singBox, xray, calls);

            NativeCoreRuntime.StartResult result = runtime.start(CoreFamily.SING_BOX, "{}");
            assertFalse(result.ok);
            assertTrue("native NewString OOME did not quarantine uncertain start",
                    runtime.isQuarantined());
            assertTrue("serialized cleanup was not queued after native OOME",
                    calls.stopObserved.await(2, TimeUnit.SECONDS));
            assertTrue(calls.stopCalls.get() == 1);
            assertFalse(runtime.shutdownForUnload(500L));
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    private static final class FakeUpdater extends CoreUpdater {
        final AtomicInteger prepareCalls = new AtomicInteger();
        final AtomicInteger updateCalls = new AtomicInteger();
        final CoreUpdater.LoadTarget target;
        final boolean candidate;

        FakeUpdater(File root, LimitedHttpClient http, CoreFamily family,
                    CoreUpdater.LoadTarget target) throws Exception {
            this(root, http, family, target, false);
        }

        FakeUpdater(File root, LimitedHttpClient http, CoreFamily family,
                    CoreUpdater.LoadTarget target, boolean candidate) throws Exception {
            super(new AtomicStore(root), http, "arm64-v8a", family,
                    "http://127.0.0.1/unused");
            this.target = target;
            this.candidate = candidate;
        }

        @Override
        synchronized CoreUpdater.LoadTarget prepareLoadTarget() {
            prepareCalls.incrementAndGet();
            return target;
        }

        @Override
        synchronized CoreUpdater.PinnedLoadTarget preparePinnedLoadTarget() {
            prepareCalls.incrementAndGet();
            return CoreUpdater.PinnedLoadTarget.forTests(target);
        }

        @Override
        boolean checkForUpdate(boolean force) {
            updateCalls.incrementAndGet();
            return true;
        }

        @Override
        boolean isCandidate() {
            return candidate;
        }

        @Override
        synchronized void markStartSuccess() {
        }

        @Override
        String version() {
            return "test";
        }
    }

    private static final class FakeNativeCalls implements NativeCoreRuntime.NativeCalls {
        final AtomicInteger openCalls = new AtomicInteger();
        final AtomicInteger stopCalls = new AtomicInteger();
        final AtomicInteger startCalls = new AtomicInteger();
        final CountDownLatch stopObserved = new CountDownLatch(1);
        volatile boolean coreRunning;
        CountDownLatch openEntered;
        CountDownLatch releaseOpen;
        CountDownLatch openExited;
        CountDownLatch stopRetryEntered;
        CountDownLatch releaseStopRetry;
        CountDownLatch startEntered;
        CountDownLatch releaseStart;
        volatile boolean startOutOfMemory;
        volatile String openError = "";
        volatile String startError = "";

        @Override
        public String open(FileDescriptor descriptor, String path,
                           String identity, int coreApi) {
            openCalls.incrementAndGet();
            if (openEntered != null) openEntered.countDown();
            await(releaseOpen);
            if (openExited != null) openExited.countDown();
            return openError;
        }

        @Override
        public String loadedIdentity() {
            return "";
        }

        @Override
        public int loadedCoreApi() {
            return 0;
        }

        @Override
        public String start(String configJson) {
            startCalls.incrementAndGet();
            coreRunning = true;
            if (startOutOfMemory) throw new OutOfMemoryError("NewString failed");
            if (startEntered != null) startEntered.countDown();
            await(releaseStart);
            return startError;
        }

        @Override
        public String stop() {
            int call = stopCalls.incrementAndGet();
            if (stopRetryEntered != null && call == 1) return "retryable stop failure";
            if (stopRetryEntered != null && call == 2) {
                stopRetryEntered.countDown();
                await(releaseStopRetry);
            }
            coreRunning = false;
            stopObserved.countDown();
            return "";
        }

        private static void await(CountDownLatch latch) {
            if (latch == null) return;
            try {
                if (!latch.await(2, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("test latch timed out");
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("test interrupted", interrupted);
            }
        }
    }

    private static void awaitLatch(CountDownLatch latch) {
        if (latch == null) return;
        try {
            if (!latch.await(2, TimeUnit.SECONDS)) {
                throw new IllegalStateException("test latch timed out");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("test interrupted", interrupted);
        }
    }
}
