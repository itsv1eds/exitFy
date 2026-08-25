package com.extera.plugins.exitfy;

import org.json.JSONObject;
import org.json.JSONArray;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CoreUpdaterTest {

    static {
        // These fixtures exercise digest, ELF and asset-set handling. Signature
        // behaviour has its own test, and signing every fixture would need the
        // private half of the release key, which never reaches the tree.
        CoreUpdater.useDefaultManifestPublicKeyForTests("");
    }
    @Test
    public void updateObserverReceivesOrderedStagesAndAdvertisedDownloadProgress()
            throws Exception {
        byte[] core = fakeCore((byte) 74);
        CoreServer server = new CoreServer(core, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-progress").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        List<CoreUpdater.UpdateStage> stages = new ArrayList<>();
        List<Long> downloaded = new ArrayList<>();
        List<Long> totals = new ArrayList<>();
        AtomicBoolean observerFailedOnce = new AtomicBoolean();
        try {
            CoreUpdater updater = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");
            CoreUpdater.UpdateObserver observer = new CoreUpdater.UpdateObserver() {
                @Override
                public void onStage(CoreUpdater.UpdateStage stage) {
                    stages.add(stage);
                }

                @Override
                public void onProgress(long downloadedBytes, long totalBytes) {
                    downloaded.add(downloadedBytes);
                    totals.add(totalBytes);
                    if (downloadedBytes > 0L && downloadedBytes < totalBytes
                            && observerFailedOnce.compareAndSet(false, true)) {
                        throw new IllegalStateException("observer failure");
                    }
                }
            };

            assertTrue(updater.checkForUpdate(true, observer));
            assertEquals(java.util.Arrays.asList(
                    CoreUpdater.UpdateStage.PREPARING,
                    CoreUpdater.UpdateStage.DOWNLOADING,
                    CoreUpdater.UpdateStage.VERIFYING), stages);
            assertTrue("observer exception path was not exercised", observerFailedOnce.get());
            assertFalse(downloaded.isEmpty());
            assertEquals(0L, downloaded.get(0).longValue());
            assertEquals(core.length, downloaded.get(downloaded.size() - 1).longValue());
            long previous = -1L;
            for (int index = 0; index < downloaded.size(); index++) {
                assertTrue("core progress regressed", downloaded.get(index) >= previous);
                assertEquals("observer received transport length instead of manifest size",
                        core.length, totals.get(index).longValue());
                previous = downloaded.get(index);
            }
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void readinessIncludesActivePendingAndRequestedRollbackOnly() throws Exception {
        String[] prefixes = {"active", "pending", "backup", "backup", "active"};
        boolean[] rollbackRequested = {false, false, true, false, true};
        boolean[] expectedUsable = {true, true, true, false, false};
        for (int index = 0; index < prefixes.length; index++) {
            File root = Files.createTempDirectory("exitfy-core-readiness").toFile();
            AtomicStore store = new AtomicStore(root);
            LimitedHttpClient http = new LimitedHttpClient();
            byte[] core = fakeCore((byte) (90 + index));
            try {
                String prefix = prefixes[index];
                store.writeBytes("core/xray/" + prefix + "/libxray.so", core);
                JSONObject metadata = coreMetadata(prefix, core);
                if (rollbackRequested[index]) {
                    metadata.put("rollbackRequested", true);
                }
                store.writeJson("core/xray/core.json", metadata);

                CoreUpdater updater = new CoreUpdater(
                        store, http, "arm64-v8a", CoreFamily.XRAY);
                assertEquals(expectedUsable[index], updater.hasUsableCore());
            } finally {
                http.close();
                TestFiles.deleteRecursively(root);
            }
        }

        File emptyRoot = Files.createTempDirectory("exitfy-core-readiness-empty").toFile();
        LimitedHttpClient emptyHttp = new LimitedHttpClient();
        try {
            CoreUpdater empty = new CoreUpdater(
                    new AtomicStore(emptyRoot), emptyHttp,
                    "arm64-v8a", CoreFamily.XRAY);
            assertFalse(empty.hasUsableCore());
        } finally {
            emptyHttp.close();
            TestFiles.deleteRecursively(emptyRoot);
        }
    }

    @Test
    public void localVerificationRevokesShallowReadinessWithoutUsingNetwork()
            throws Exception {
        File root = Files.createTempDirectory(
                "exitfy-core-local-readiness-verification").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] expected = fakeCore((byte) 71);
        byte[] replaced = fakeCore((byte) 72);
        try {
            store.writeBytes("core/xray/active/libxray.so", replaced);
            store.writeJson("core/xray/core.json",
                    coreMetadata("active", expected));
            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);

            assertTrue("metadata snapshot should expose the pre-inspection state",
                    updater.hasUsableCore());
            assertFalse(updater.verifyLocalReadiness());
            assertFalse(updater.hasUsableCore());
            assertFalse(store.child("core/xray/active/libxray.so").exists());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void rejectsEveryCoreAbiExceptArm64() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-wrong-abi").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            try {
                new CoreUpdater(new AtomicStore(root), http,
                        "x86_64", CoreFamily.XRAY);
                throw new AssertionError("non-arm64 core ABI was accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("arm64-v8a"));
            }
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void futureLastCheckIsTreatedAsStale() throws Exception {
        byte[] core = fakeCore((byte) 75);
        CoreServer server = new CoreServer(core, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-future-clock").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        long future = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365);
        try {
            store.writeBytes("core/xray/active/libxray.so", core);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(core))
                    .put("activeVersion", "xray-v26.7.11-w2")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("lastCheck", future));
            CoreUpdater updater = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");

            assertFalse(updater.checkForUpdate(false));
            long corrected = store.readJson("core/xray/core.json").optLong("lastCheck", 0L);
            assertTrue("future timestamp suppressed the release check", corrected > 0L);
            assertTrue("future timestamp was retained", corrected < future);
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void missingHighVersionMetadataCannotBlockRecoveryDownload() throws Exception {
        byte[] core = fakeCore((byte) 76);
        CoreServer server = new CoreServer(core, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-missing-high-version").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", String.join("", Collections.nCopies(64, "a")))
                    .put("activeVersion", "xray-v99.0.0-w99")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");

            assertTrue(updater.checkForUpdate(true));
            JSONObject metadata = store.readJson("core/xray/core.json");
            assertFalse(metadata.has("activeVersion"));
            assertEquals("xray-v26.7.11-w2", metadata.optString("pendingVersion"));
            assertArrayEquals(core, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void invalidHighPendingCoreCannotBlockRecoveryDownload() throws Exception {
        byte[] invalid = fakeCore((byte) 77);
        byte[] current = fakeCore((byte) 78);
        CoreServer server = new CoreServer(current, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-invalid-high-pending").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            store.writeBytes("core/xray/pending/libxray.so", invalid);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("pendingDigest", sha256(fakeCore((byte) 79)))
                    .put("pendingVersion", "xray-v99.0.0-w99")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");

            assertTrue(updater.checkForUpdate(true));
            JSONObject metadata = store.readJson("core/xray/core.json");
            assertEquals("xray-v26.7.11-w2", metadata.optString("pendingVersion"));
            assertEquals(sha256(current), metadata.optString("pendingDigest"));
            assertArrayEquals(current, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void staleUpdaterCannotReplaceNewerPendingRelease() throws Exception {
        byte[] olderCore = fakeCore((byte) 71);
        byte[] newerCore = fakeCore((byte) 72);
        CoreServer olderServer = new CoreServer(olderCore, CoreFamily.XRAY, null);
        CoreServer newerServer = new CoreServer(newerCore, CoreFamily.XRAY,
                CoreUpdaterTest::promoteFixtureToWrapperThree);
        File root = Files.createTempDirectory("exitfy-core-stale-updater").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient olderHttp = new LimitedHttpClient();
        LimitedHttpClient newerHttp = new LimitedHttpClient();
        try {
            // Construct the old updater before the newer transaction commits,
            // so its in-memory metadata is deliberately stale.
            CoreUpdater older = new CoreUpdater(store, olderHttp,
                    "arm64-v8a", CoreFamily.XRAY, olderServer.baseUrl() + "/releases");
            CoreUpdater newer = new CoreUpdater(store, newerHttp,
                    "arm64-v8a", CoreFamily.XRAY, newerServer.baseUrl() + "/releases");
            assertTrue(newer.checkForUpdate(true));
            assertFalse(older.checkForUpdate(true));

            JSONObject metadata = store.readJson("core/xray/core.json");
            assertEquals("xray-v26.7.11-w3", metadata.optString("pendingVersion"));
            assertEquals(sha256(newerCore), metadata.optString("pendingDigest"));
            assertArrayEquals(newerCore, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));
        } finally {
            olderHttp.close();
            newerHttp.close();
            olderServer.close();
            newerServer.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void prepareAndFinalCommitShareOneStoreStateLock() throws Exception {
        byte[] oldPending = fakeCore((byte) 73);
        byte[] newPending = fakeCore((byte) 74);
        CoreServer server = new CoreServer(newPending, CoreFamily.XRAY,
                CoreUpdaterTest::promoteFixtureToWrapperThree);
        File root = Files.createTempDirectory("exitfy-core-prepare-commit").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        CountDownLatch commitReady = new CountDownLatch(1);
        CountDownLatch releaseCommit = new CountDownLatch(1);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            store.writeBytes("core/xray/pending/libxray.so", oldPending);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("pendingDigest", sha256(oldPending))
                    .put("pendingVersion", "xray-v26.7.11-w2")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases", () -> {
                commitReady.countDown();
                if (!releaseCommit.await(2, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("commit barrier timed out");
                }
            });
            CoreUpdater preparer = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");

            Future<Boolean> update = worker.submit(() -> updater.checkForUpdate(true));
            assertTrue(commitReady.await(3, TimeUnit.SECONDS));
            CoreUpdater.LoadTarget loaded = preparer.prepareLoadTarget();
            assertArrayEquals(oldPending, Files.readAllBytes(loaded.file.toPath()));
            assertEquals(2, loaded.coreApi);
            releaseCommit.countDown();
            assertTrue(update.get(3, TimeUnit.SECONDS));

            JSONObject metadata = store.readJson("core/xray/core.json");
            assertEquals("xray-v26.7.11-w2", metadata.optString("activeVersion"));
            assertEquals("xray-v26.7.11-w3", metadata.optString("pendingVersion"));
            assertArrayEquals(oldPending, Files.readAllBytes(
                    store.child("core/xray/active/libxray.so").toPath()));
            assertArrayEquals(newPending, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));
        } finally {
            releaseCommit.countDown();
            worker.shutdownNow();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void blockedInspectionDoesNotBlockStatusAndStaleSnapshotIsRetried()
            throws Exception {
        byte[] active = fakeCore((byte) 83);
        byte[] pending = fakeCore((byte) 84);
        CoreServer server = new CoreServer(active, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-inspection-race").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch inspectionEntered = new CountDownLatch(1);
        CountDownLatch releaseInspection = new CountDownLatch(1);
        AtomicInteger inspections = new AtomicInteger();
        try {
            store.writeBytes("core/xray/active/libxray.so", active);
            store.writeBytes("core/xray/pending/libxray.so", pending);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(active))
                    .put("activeVersion", "xray-v26.7.11-w2")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("pendingDigest", sha256(pending))
                    .put("pendingVersion", "xray-v26.7.11-w3")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, server.baseUrl() + "/releases", () -> {
            }, file -> {
                int count = inspections.incrementAndGet();
                if (count == 1) {
                    inspectionEntered.countDown();
                    if (!releaseInspection.await(2, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("inspection barrier timed out");
                    }
                }
            });
            CoreUpdater preparer = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, server.baseUrl() + "/releases");

            Future<Boolean> checking = worker.submit(() -> updater.checkForUpdate(true));
            assertTrue(inspectionEntered.await(2, TimeUnit.SECONDS));
            long statusStarted = System.nanoTime();
            assertEquals("xray-v26.7.11-w2", updater.version());
            assertTrue("status waited for large-file inspection",
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - statusStarted) < 100L);

            CoreUpdater.LoadTarget promoted = preparer.prepareLoadTarget();
            assertArrayEquals(pending, Files.readAllBytes(promoted.file.toPath()));
            releaseInspection.countDown();
            assertFalse(checking.get(3, TimeUnit.SECONDS));
            assertTrue("stale inspection snapshot was not retried", inspections.get() >= 4);
            JSONObject metadata = store.readJson("core/xray/core.json");
            assertEquals("xray-v26.7.11-w3", metadata.optString("activeVersion"));
            assertArrayEquals(pending, Files.readAllBytes(
                    store.child("core/xray/active/libxray.so").toPath()));
        } finally {
            releaseInspection.countDown();
            worker.shutdownNow();
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void promotesPendingCoreBeforeFirstNativeLoad() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-pending").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] pending = fakeCore((byte) 7);
        try {
            store.writeBytes("core/sing_box/pending/libvless.so", pending);
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("pendingDigest", sha256(pending))
                    .put("pendingVersion", "sb-v1.13.14-w1007")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2).put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29).put("pendingAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            File active = updater.prepareForFirstLoad();
            assertTrue(active.isFile());
            assertArrayEquals(pending, Files.readAllBytes(active.toPath()));
            assertEquals("sb-v1.13.14-w1007", updater.version());
            assertTrue(active.getPath().contains("core/sing_box/active"));
            assertFalse(store.child("core/sing_box/pending/libvless.so").exists());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void failedCandidateRollsBackOnNextProcessStart() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-rollback").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] oldCore = fakeCore((byte) 1);
        byte[] newCore = fakeCore((byte) 2);
        try {
            store.writeBytes("core/sing_box/active/libvless.so", oldCore);
            store.writeBytes("core/sing_box/pending/libvless.so", newCore);
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("activeDigest", sha256(oldCore))
                    .put("activeVersion", "sb-v1.13.14-w1006")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2).put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29).put("activeAbi", "arm64-v8a")
                    .put("pendingDigest", sha256(newCore))
                    .put("pendingVersion", "sb-v1.13.14-w1007")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2).put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29).put("pendingAbi", "arm64-v8a"));
            CoreUpdater first = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            assertArrayEquals(newCore, Files.readAllBytes(first.prepareForFirstLoad().toPath()));
            first.markLoaderFailure();

            CoreUpdater nextProcess = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            File restored = nextProcess.prepareForFirstLoad();
            assertArrayEquals(oldCore, Files.readAllBytes(restored.toPath()));
            assertEquals("sb-v1.13.14-w1006", nextProcess.version());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void triesTheReleaseAssetUrlBeforeAnyMirror() {
        String asset = "https://github.com/itsv1eds/exitFy/releases/download/"
                + "sb-v1.13.14-w2/libexitfy-sb-arm64-v8a.so";
        java.util.List<String> candidates = CoreUpdater.downloadCandidates(asset);
        assertEquals(asset, candidates.get(0));
        assertTrue(candidates.size() > 1);
        for (String candidate : candidates.subList(1, candidates.size())) {
            assertTrue(candidate.endsWith(asset));
            assertTrue(candidate.startsWith("https://"));
        }
        assertEquals(candidates.size(), new java.util.HashSet<>(candidates).size());
        assertEquals(1, CoreUpdater.downloadCandidates("http://example.com/core.so").size());
        assertEquals(0, CoreUpdater.downloadCandidates("").size());
    }

    @Test
    public void keepsXrayStorageSeparateFromSingBoxStorage() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-families").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] singBox = fakeCore((byte) 3);
        byte[] xray = fakeCore((byte) 4);
        try {
            store.writeBytes("core/sing_box/active/libvless.so", singBox);
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("activeDigest", sha256(singBox))
                    .put("activeVersion", "sb-v1.13.14-w1007")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2).put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29).put("activeAbi", "arm64-v8a"));
            store.writeBytes("core/xray/pending/libxray.so", xray);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("pendingDigest", sha256(xray))
                    .put("pendingVersion", "xray-v26.7.11-w1007")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2).put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29).put("pendingAbi", "arm64-v8a"));

            CoreUpdater singUpdater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            CoreUpdater xrayUpdater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            assertArrayEquals(singBox, Files.readAllBytes(
                    singUpdater.prepareForFirstLoad().toPath()));
            assertArrayEquals(xray, Files.readAllBytes(
                    xrayUpdater.prepareForFirstLoad().toPath()));
            assertEquals("sb-v1.13.14-w1007", singUpdater.version());
            assertEquals("xray-v26.7.11-w1007", xrayUpdater.version());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void aConfiguredKeyMakesTheManifestSignatureMandatory() throws Exception {
        java.security.KeyPairGenerator generator =
                java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.KeyPair pair = generator.generateKeyPair();
        String publicKey = java.util.Base64.getEncoder()
                .encodeToString(pair.getPublic().getEncoded());

        byte[] core = fakeCore((byte) 41);
        CoreServer signed = new CoreServer(core).sign(pair.getPrivate());
        File root = Files.createTempDirectory("exitfy-signed-release").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            CoreUpdater updater = new CoreUpdater(new AtomicStore(root), http,
                    "arm64-v8a", CoreFamily.XRAY, signed.baseUrl() + "/releases");
            updater.useManifestPublicKey(publicKey);
            assertTrue(updater.checkForUpdate(true));
            assertArrayEquals(core,
                    Files.readAllBytes(updater.prepareForFirstLoad().toPath()));

            // The same release is refused by a client holding a different key.
            File other = Files.createTempDirectory("exitfy-foreign-key").toFile();
            CoreUpdater foreign = new CoreUpdater(new AtomicStore(other), http,
                    "arm64-v8a", CoreFamily.XRAY, signed.baseUrl() + "/releases");
            foreign.useManifestPublicKey(java.util.Base64.getEncoder()
                    .encodeToString(generator.generateKeyPair().getPublic().getEncoded()));
            try {
                foreign.checkForUpdate(true);
                throw new AssertionError("foreign key accepted a signed release");
            } catch (Exception expected) {
                assertTrue(expected instanceof java.security.GeneralSecurityException
                        || expected.getCause() instanceof java.security.GeneralSecurityException);
            }
            TestFiles.deleteRecursively(other);
        } finally {
            signed.close();
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void verifiesXrayManifestGithubDigestAndStagesCurrentAbi() throws Exception {
        byte[] core = fakeCore((byte) 11);
        CoreServer server = new CoreServer(core);
        File root = Files.createTempDirectory("exitfy-xray-update").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            CoreUpdater updater = new CoreUpdater(new AtomicStore(root), http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");
            assertTrue(updater.checkForUpdate(true));
            File active = updater.prepareForFirstLoad();
            assertArrayEquals(core, Files.readAllBytes(active.toPath()));
            assertEquals("xray-v26.7.11-w2", updater.version());
            assertEquals(2, updater.activeCoreApi());
            assertTrue(updater.isCandidate());
            assertTrue(active.getPath().endsWith("core/xray/active/libxray.so"));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void initialCandidateWithoutBackupIsRejectedAndNotReinstalled() throws Exception {
        byte[] candidate = fakeCore((byte) 63);
        CoreServer server = new CoreServer(candidate, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-initial-candidate-reject").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            CoreUpdater first = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");
            assertTrue(first.checkForUpdate(true));
            assertArrayEquals(candidate, Files.readAllBytes(
                    first.prepareForFirstLoad().toPath()));
            first.markLoaderFailure();

            CoreUpdater nextProcess = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");
            assertNull(nextProcess.prepareForFirstLoad());
            JSONObject metadata = store.readJson("core/xray/core.json");
            assertEquals(sha256(candidate), metadata.optString("rejectedDigest"));
            assertFalse(store.child("core/xray/active/libxray.so").exists());
            assertFalse(nextProcess.checkForUpdate(false));
            try {
                nextProcess.checkForUpdate(true);
                throw new AssertionError("rejected digest was reinstalled");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("rejected"));
            }
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void rejectsIncompletePublishedReleaseInsteadOfFallingBack() throws Exception {
        byte[] core = fakeCore((byte) 64);
        CoreServer server = new CoreServer(core, CoreFamily.XRAY, (release, manifest) ->
                release.getJSONArray("assets").remove(0));
        File root = Files.createTempDirectory("exitfy-incomplete-release").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            CoreUpdater updater = new CoreUpdater(new AtomicStore(root), http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");
            try {
                updater.checkForUpdate(true);
                throw new AssertionError("incomplete release was accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("asset set"));
            }
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void schemaTwoSingBoxCoreIsNeverRetainedAsRollback() throws Exception {
        byte[] oldCore = fakeCore((byte) 12);
        byte[] ownedCore = fakeCore((byte) 13);
        CoreServer server = new CoreServer(ownedCore, CoreFamily.SING_BOX, null);
        File root = Files.createTempDirectory("exitfy-owned-sb-update").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            store.writeBytes("core/sing_box/active/libvless.so", oldCore);
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("activeDigest", sha256(oldCore)).put("activeVersion", "legacy")
                    .put("lastCheck", System.currentTimeMillis()));
            CoreUpdater updater = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.SING_BOX, server.baseUrl() + "/releases");
            assertTrue(updater.checkForUpdate(false));
            assertArrayEquals(ownedCore, Files.readAllBytes(
                    updater.prepareForFirstLoad().toPath()));
            JSONObject promoted = store.readJson("core/sing_box/core.json");
            assertEquals("itsv1eds/exitFy", promoted.optString("activeOrigin"));
            assertEquals("", promoted.optString("backupOrigin"));
            assertFalse(store.child("core/sing_box/backup/libvless.so").exists());

            updater.markLoaderFailure();
            CoreUpdater nextProcess = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.SING_BOX, server.baseUrl() + "/releases");
            assertNull(nextProcess.prepareForFirstLoad());
            JSONObject rolledBack = store.readJson("core/sing_box/core.json");
            assertFalse(rolledBack.has("activeVersion"));
            assertEquals(sha256(ownedCore), rolledBack.optString("rejectedDigest"));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void rejectsSingBoxManifestWithUnapprovedBuildTags() throws Exception {
        byte[] core = fakeCore((byte) 14);
        CoreServer server = new CoreServer(core, CoreFamily.SING_BOX, (release, manifest) ->
                manifest.getJSONObject("wrapper").getJSONArray("buildTags")
                        .put("with_wireguard"));
        File root = Files.createTempDirectory("exitfy-sb-bad-tags").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            CoreUpdater updater = new CoreUpdater(new AtomicStore(root), http,
                    "arm64-v8a", CoreFamily.SING_BOX, server.baseUrl() + "/releases");
            try {
                updater.checkForUpdate(true);
                throw new AssertionError("unapproved sing-box build tags were accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("build contract"));
            }
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void releaseSelectionSkipsDraftPrereleaseAndWrongFamily() throws Exception {
        JSONArray releases = new JSONArray()
                .put(new JSONObject().put("tag_name", "sb-v9.0.0-w2")
                        .put("draft", true).put("prerelease", false))
                .put(new JSONObject().put("tag_name", "sb-v8.0.0-w2")
                        .put("draft", false).put("prerelease", true))
                .put(new JSONObject().put("tag_name", "xray-v26.8.0-w2")
                        .put("draft", false).put("prerelease", false))
                .put(new JSONObject().put("tag_name", "sb-v1.13.14-w2")
                        .put("draft", false).put("prerelease", false))
                .put(new JSONObject().put("tag_name", "sb-v1.13.14-w7")
                        .put("draft", false).put("prerelease", false));
        assertEquals("sb-v1.13.14-w7",
                CoreUpdater.selectRelease(releases, CoreFamily.SING_BOX)
                        .optString("tag_name"));
        assertEquals("xray-v26.8.0-w2",
                CoreUpdater.selectRelease(releases, CoreFamily.XRAY)
                        .optString("tag_name"));
    }

    @Test
    public void releasePaginationStreamsBestAndRequiresEmptyPageEleven() throws Exception {
        JSONArray page = new JSONArray();
        for (int index = 0; index < 100; index++) {
            page.put(new JSONObject().put("tag_name", "xray-v1.0." + index + "-w2")
                    .put("note", "comma,inside,string"));
        }
        CoreUpdater.validateReleasePageShape(page.toString());
        byte[] pageBytes = page.toString().getBytes(StandardCharsets.UTF_8);
        CoreUpdater.ReleasePageAccumulator accumulator =
                new CoreUpdater.ReleasePageAccumulator(CoreFamily.XRAY, 32 * 1024 * 1024);
        for (int pageIndex = 1; pageIndex <= 10; pageIndex++) {
            assertEquals(100, accumulator.accept(pageBytes, pageIndex));
        }
        assertEquals(1000, accumulator.totalEntries());
        assertEquals(0, accumulator.accept("[]".getBytes(StandardCharsets.UTF_8), 11));
        assertEquals("xray-v1.0.99-w2",
                accumulator.finish().optString("tag_name"));

        CoreUpdater.ReleasePageAccumulator truncated =
                new CoreUpdater.ReleasePageAccumulator(CoreFamily.XRAY, 32 * 1024 * 1024);
        for (int pageIndex = 1; pageIndex <= 10; pageIndex++) {
            truncated.accept(pageBytes, pageIndex);
        }
        try {
            truncated.accept(new JSONArray().put(new JSONObject()
                    .put("tag_name", "xray-v2.0.0-w2"))
                    .toString().getBytes(StandardCharsets.UTF_8), 11);
            throw new AssertionError("eleventh release page was accepted");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("1000 entries"));
        }

        JSONArray hostile = new JSONArray(page.toString());
        hostile.put(new JSONObject());
        try {
            CoreUpdater.validateReleasePageShape(hostile.toString());
            throw new AssertionError("101-entry release page was accepted before JSON parse");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("100 entries"));
        }
    }

    @Test
    public void releasePaginationEnforcesCumulativeThirtyTwoMiBBudget() throws Exception {
        JSONArray page = new JSONArray();
        for (int index = 0; index < 100; index++) {
            page.put(new JSONObject().put("tag_name", "xray-v1.0." + index + "-w2"));
        }
        byte[] json = page.toString().getBytes(StandardCharsets.UTF_8);
        int paddedSize = (32 * 1024 * 1024 - 2) / 10;
        byte[] padded = new byte[paddedSize];
        java.util.Arrays.fill(padded, (byte) ' ');
        System.arraycopy(json, 0, padded, 0, json.length);

        CoreUpdater.ReleasePageAccumulator accumulator =
                new CoreUpdater.ReleasePageAccumulator(CoreFamily.XRAY, 32 * 1024 * 1024);
        for (int pageIndex = 1; pageIndex <= 10; pageIndex++) {
            accumulator.accept(padded, pageIndex);
        }
        assertEquals((long) paddedSize * 10L, accumulator.totalBytes());
        try {
            accumulator.accept("[] ".getBytes(StandardCharsets.UTF_8), 11);
            throw new AssertionError("32 MiB + 1 release history was accepted");
        } catch (IllegalStateException expected) {
            assertTrue(expected.getMessage().contains("cumulative byte"));
        }
    }

    @Test
    public void rejectsDuplicateAndExtraReleaseAssets() throws Exception {
        assertXrayReleaseRejected((release, manifest) -> {
            JSONArray assets = release.getJSONArray("assets");
            assets.put(new JSONObject(assets.getJSONObject(0).toString()).put("id", 99));
        }, (byte) 81);
        assertXrayReleaseRejected((release, manifest) -> release.getJSONArray("assets")
                .put(new JSONObject().put("id", 100).put("name", "unexpected.bin")
                        .put("size", 1).put("digest", "sha256:"
                                + String.join("", Collections.nCopies(64, "a")))
                        .put("browser_download_url", "https://example.invalid/extra")),
                (byte) 82);
    }

    @Test
    public void rejectsTamperedSingBoxManifestContracts() throws Exception {
        assertSingBoxManifestRejected((release, manifest) ->
                        manifest.put("schema", 2),
                (byte) 19, "core contract");
        assertSingBoxManifestRejected((release, manifest) ->
                        manifest.put("configContract", 2),
                (byte) 15, "core contract");
        assertSingBoxManifestRejected((release, manifest) ->
                        manifest.getJSONObject("upstream").put("repository", "example/foreign"),
                (byte) 16, "release pins");
        assertSingBoxManifestRejected((release, manifest) ->
                        manifest.getJSONObject("assets").getJSONObject("arm64-v8a")
                                .put("sha256", String.join("", Collections.nCopies(64, "0"))),
                (byte) 17, "asset contract");
        assertSingBoxManifestRejected((release, manifest) ->
                        manifest.getJSONObject("wrapper").getJSONObject("sourceBundle")
                                .put("sha256", String.join("", Collections.nCopies(64, "0"))),
                (byte) 18, "source bundle");
    }

    private static void assertSingBoxManifestRejected(CoreServer.ManifestMutation mutation,
                                                       byte marker,
                                                       String messageFragment) throws Exception {
        byte[] core = fakeCore(marker);
        CoreServer server = new CoreServer(core, CoreFamily.SING_BOX, mutation);
        File root = Files.createTempDirectory("exitfy-sb-reject").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            CoreUpdater updater = new CoreUpdater(new AtomicStore(root), http,
                    "arm64-v8a", CoreFamily.SING_BOX, server.baseUrl() + "/releases");
            try {
                updater.checkForUpdate(true);
                throw new AssertionError("tampered sing-box manifest was accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage(), expected.getMessage().contains(messageFragment));
            }
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    private static void assertXrayReleaseRejected(CoreServer.ManifestMutation mutation,
                                                   byte marker) throws Exception {
        byte[] core = fakeCore(marker);
        CoreServer server = new CoreServer(core, CoreFamily.XRAY, mutation);
        File root = Files.createTempDirectory("exitfy-xray-release-reject").toFile();
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            CoreUpdater updater = new CoreUpdater(new AtomicStore(root), http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");
            try {
                updater.checkForUpdate(true);
                throw new AssertionError("invalid release asset set was accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage(), expected.getMessage().contains("asset"));
            }
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void discardsCorruptedActiveCoreInsteadOfRetryingItForever() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-corrupt-active").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] active = fakeCore((byte) 9);
        try {
            store.writeBytes("core/sing_box/active/libvless.so", active);
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("activeDigest", sha256(fakeCore((byte) 8)))
                    .put("activeVersion", "corrupted"));
            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            assertNull(updater.prepareForFirstLoad());
            assertFalse(store.child("core/sing_box/active/libvless.so").exists());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void refusesPendingCoreWhoseStoredDigestDoesNotMatch() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-corrupt-pending").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            store.writeBytes("core/sing_box/pending/libvless.so", fakeCore((byte) 4));
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("pendingDigest", sha256(fakeCore((byte) 5)))
                    .put("pendingVersion", "bad")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2).put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29).put("pendingAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            try {
                updater.prepareForFirstLoad();
                throw new AssertionError("mismatched pending core was promoted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("digest"));
            }
            assertFalse(store.child("core/sing_box/pending/libvless.so").exists());
            assertFalse(store.child("core/sing_box/active/libvless.so").exists());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void rejectsActiveCoreWithoutPinnedDigestMetadata() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-unpinned").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            store.writeBytes("core/sing_box/active/libvless.so", fakeCore((byte) 6));
            store.writeJson("core/sing_box/core.json",
                    new JSONObject().put("activeVersion", "unpinned"));
            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            assertNull(updater.prepareForFirstLoad());
            assertFalse(store.child("core/sing_box/active/libvless.so").exists());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void recoversPromotionAtEverySuccessfulCrashCut() throws Exception {
        for (int cut = 0; cut < 3; cut++) {
            File root = Files.createTempDirectory("exitfy-core-promote-recovery").toFile();
            AtomicStore store = new AtomicStore(root);
            LimitedHttpClient http = new LimitedHttpClient();
            byte[] oldCore = fakeCore((byte) 31);
            byte[] newCore = fakeCore((byte) 32);
            String oldDigest = sha256(oldCore);
            String newDigest = sha256(newCore);
            try {
                if (cut == 0) {
                    store.writeBytes("core/sing_box/active/libvless.so", oldCore);
                    store.writeBytes("core/sing_box/pending/libvless.so", newCore);
                } else if (cut == 1) {
                    store.writeBytes("core/sing_box/pending/libvless.so", newCore);
                    store.writeBytes("core/sing_box/backup/libvless.so", oldCore);
                } else {
                    store.writeBytes("core/sing_box/active/libvless.so", newCore);
                    store.writeBytes("core/sing_box/backup/libvless.so", oldCore);
                }
                JSONObject transaction = new JSONObject().put("type", "promote")
                        .put("pendingDigest", newDigest).put("pendingVersion", "new")
                        .put("pendingOrigin", "itsv1eds/exitFy")
                        .put("pendingCoreApi", 2).put("pendingManifestSchema", 3)
                        .put("pendingMinAndroidApi", 29).put("pendingAbi", "arm64-v8a")
                        .put("previousDigest", oldDigest).put("previousVersion", "old")
                        .put("previousOrigin", "itsv1eds/exitFy")
                        .put("previousCoreApi", 2).put("previousManifestSchema", 3)
                        .put("previousMinAndroidApi", 29).put("previousAbi", "arm64-v8a")
                        .put("backupExpected", true);
                store.writeJson("core/sing_box/core.json", new JSONObject()
                        .put("activeDigest", oldDigest).put("activeVersion", "old")
                        .put("activeOrigin", "itsv1eds/exitFy")
                        .put("activeCoreApi", 2).put("activeManifestSchema", 3)
                        .put("activeMinAndroidApi", 29).put("activeAbi", "arm64-v8a")
                        .put("pendingDigest", newDigest).put("pendingVersion", "new")
                        .put("pendingOrigin", "itsv1eds/exitFy")
                        .put("pendingCoreApi", 2).put("pendingManifestSchema", 3)
                        .put("pendingMinAndroidApi", 29).put("pendingAbi", "arm64-v8a")
                        .put("transaction", transaction));

                CoreUpdater updater = new CoreUpdater(
                        store, http, "arm64-v8a", CoreFamily.SING_BOX);
                assertArrayEquals(newCore, Files.readAllBytes(
                        updater.prepareForFirstLoad().toPath()));
                assertEquals("new", updater.version());
                assertTrue(updater.isCandidate());
                assertArrayEquals(oldCore, Files.readAllBytes(
                        store.child("core/sing_box/backup/libvless.so").toPath()));
            } finally {
                http.close();
                TestFiles.deleteRecursively(root);
            }
        }
    }

    @Test
    public void failedPromotionRestoresPreviousCoreAtEveryCrashCut() throws Exception {
        for (int cut = 0; cut < 5; cut++) {
            File root = Files.createTempDirectory("exitfy-core-promote-abort").toFile();
            AtomicStore store = new AtomicStore(root);
            LimitedHttpClient http = new LimitedHttpClient();
            byte[] previous = fakeCore((byte) 33);
            byte[] target = fakeCore((byte) 34);
            byte[] invalidTarget = fakeCore((byte) 35);
            String previousDigest = sha256(previous);
            String targetDigest = sha256(target);
            try {
                if (cut == 0 || cut == 1) {
                    store.writeBytes("core/xray/active/libxray.so", previous);
                } else if (cut == 2 || cut == 3) {
                    store.writeBytes("core/xray/backup/libxray.so", previous);
                } else {
                    store.writeBytes("core/xray/active/libxray.so", invalidTarget);
                    store.writeBytes("core/xray/backup/libxray.so", previous);
                }
                if (cut == 1 || cut == 3) {
                    store.writeBytes("core/xray/pending/libxray.so", invalidTarget);
                }
                JSONObject transaction = new JSONObject().put("type", "promote")
                        .put("pendingDigest", targetDigest)
                        .put("pendingVersion", "xray-v26.8.0-w2")
                        .put("pendingOrigin", "itsv1eds/exitFy")
                        .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                        .put("previousDigest", previousDigest)
                        .put("previousVersion", "xray-v26.7.11-w2")
                        .put("previousOrigin", "itsv1eds/exitFy")
                        .put("previousCoreApi", 2)
                        .put("previousManifestSchema", 3)
                        .put("previousMinAndroidApi", 29)
                        .put("previousAbi", "arm64-v8a")
                        .put("previousCandidatePresent", true)
                        .put("previousCandidate", true)
                        .put("previousRollbackRequestedPresent", false)
                        .put("previousRollbackRequested", false)
                        .put("backupExpected", true);
                store.writeJson("core/xray/core.json", new JSONObject()
                        .put("activeDigest", previousDigest)
                        .put("activeVersion", "xray-v26.7.11-w2")
                        .put("activeOrigin", "itsv1eds/exitFy")
                        .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                        .put("candidate", true)
                        .put("pendingDigest", targetDigest)
                        .put("pendingVersion", "xray-v26.8.0-w2")
                        .put("pendingOrigin", "itsv1eds/exitFy")
                        .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                        .put("transaction", transaction));

                CoreUpdater updater = new CoreUpdater(
                        store, http, "arm64-v8a", CoreFamily.XRAY);
                CoreUpdater.LoadTarget restored = updater.prepareLoadTarget();
                assertNotNull("previous core missing at crash cut " + cut, restored);
                assertArrayEquals("previous core changed at crash cut " + cut,
                        previous, Files.readAllBytes(restored.file.toPath()));
                JSONObject recovered = store.readJson("core/xray/core.json");
                assertEquals("xray-v26.7.11-w2",
                        recovered.optString("activeVersion"));
                assertEquals(previousDigest, recovered.optString("activeDigest"));
                assertEquals("itsv1eds/exitFy", recovered.optString("activeOrigin"));
                assertEquals(2, recovered.optInt("activeCoreApi"));
                assertTrue(recovered.optBoolean("candidate"));
                assertFalse(recovered.has("transaction"));
                assertFalse(recovered.has("pendingDigest"));
                assertFalse(store.child("core/xray/pending/libxray.so").exists());
            } finally {
                http.close();
                TestFiles.deleteRecursively(root);
            }
        }
    }

    @Test
    public void failedLegacyPromotionJournalPreservesDurablePreviousFlags() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-legacy-promote-abort").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] previous = fakeCore((byte) 102);
        byte[] target = fakeCore((byte) 103);
        String previousDigest = sha256(previous);
        try {
            store.writeBytes("core/xray/active/libxray.so", previous);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", previousDigest)
                    .put("activeVersion", "xray-v26.7.11-w2")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("candidate", true)
                    .put("rollbackRequested", false)
                    .put("pendingDigest", sha256(target))
                    .put("pendingVersion", "xray-v26.8.0-w2")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                    .put("transaction", new JSONObject()
                            .put("type", "promote")
                            .put("pendingDigest", sha256(target))
                            .put("pendingVersion", "xray-v26.8.0-w2")
                            .put("pendingOrigin", "itsv1eds/exitFy")
                            .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                            .put("previousDigest", previousDigest)
                            .put("previousVersion", "xray-v26.7.11-w2")
                            .put("previousOrigin", "itsv1eds/exitFy")
                            .put("previousCoreApi", 2)
                            .put("previousManifestSchema", 3)
                            .put("previousMinAndroidApi", 29)
                            .put("previousAbi", "arm64-v8a")
                            .put("backupExpected", true)));

            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            assertArrayEquals(previous,
                    Files.readAllBytes(updater.prepareLoadTarget().file.toPath()));
            JSONObject recovered = store.readJson("core/xray/core.json");
            assertTrue(recovered.optBoolean("candidate"));
            assertTrue(recovered.has("rollbackRequested"));
            assertFalse(recovered.optBoolean("rollbackRequested"));
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void recoversRollbackKilledAfterBackupWasCopied() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-rollback-recovery").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] oldCore = fakeCore((byte) 41);
        byte[] newCore = fakeCore((byte) 42);
        String oldDigest = sha256(oldCore);
        try {
            // File copy completed, but durable metadata still describes the
            // failed candidate and retains the rollback journal.
            store.writeBytes("core/sing_box/active/libvless.so", oldCore);
            store.writeBytes("core/sing_box/backup/libvless.so", oldCore);
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("activeDigest", sha256(newCore)).put("activeVersion", "new")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2).put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29).put("activeAbi", "arm64-v8a")
                    .put("backupDigest", oldDigest).put("backupVersion", "old")
                    .put("backupOrigin", "itsv1eds/exitFy")
                    .put("backupCoreApi", 2).put("backupManifestSchema", 3)
                    .put("backupMinAndroidApi", 29).put("backupAbi", "arm64-v8a")
                    .put("candidate", true).put("rollbackRequested", true)
                    .put("transaction", new JSONObject().put("type", "rollback")
                            .put("targetDigest", oldDigest).put("targetVersion", "old")
                            .put("targetOrigin", "itsv1eds/exitFy")
                            .put("targetCoreApi", 2).put("targetManifestSchema", 3)
                            .put("targetMinAndroidApi", 29).put("targetAbi", "arm64-v8a")));
            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            assertArrayEquals(oldCore, Files.readAllBytes(updater.prepareForFirstLoad().toPath()));
            assertEquals("old", updater.version());
            assertFalse(updater.isCandidate());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void backgroundUpdateRecoversTransactionBeforeIntervalShortCircuit() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-background-recovery").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] oldCore = fakeCore((byte) 51);
        byte[] newCore = fakeCore((byte) 52);
        String oldDigest = sha256(oldCore);
        String newDigest = sha256(newCore);
        String oldVersion = "sb-v1.13.13-w2";
        String newVersion = "sb-v1.13.14-w2";
        try {
            store.writeBytes("core/sing_box/active/libvless.so", newCore);
            store.writeBytes("core/sing_box/backup/libvless.so", oldCore);
            store.writeJson("core/sing_box/core.json", new JSONObject()
                    .put("activeDigest", oldDigest).put("activeVersion", oldVersion)
                    .put("pendingDigest", newDigest).put("pendingVersion", newVersion)
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                    .put("lastCheck", System.currentTimeMillis())
                    .put("transaction", new JSONObject().put("type", "promote")
                            .put("pendingDigest", newDigest).put("pendingVersion", newVersion)
                            .put("pendingOrigin", "itsv1eds/exitFy")
                            .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                            .put("previousDigest", oldDigest).put("previousVersion", oldVersion)
                            .put("backupExpected", true)));
            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.SING_BOX);
            assertFalse(updater.checkForUpdate(false));
            assertEquals(newVersion, updater.version());
            assertTrue(updater.isCandidate());
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void streamingDownloadDeletesPartialFileWhenLimitIsExceeded() throws Exception {
        ServerSocket listener = new ServerSocket();
        listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
        Thread server = new Thread(() -> {
            try (Socket socket = listener.accept()) {
                CoreServer.readHeaders(socket.getInputStream());
                OutputStream output = socket.getOutputStream();
                output.write("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
                        .getBytes(StandardCharsets.ISO_8859_1));
                byte[] block = new byte[32 * 1024];
                for (int i = 0; i < 40; i++) output.write(block);
                output.flush();
            } catch (Exception ignored) {
            }
        }, "exitfy-oversize-core");
        server.setDaemon(true);
        server.start();

        File root = Files.createTempDirectory("exitfy-stream-limit").toFile();
        File partial = new File(root, "partial.so");
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            try {
                http.getBinaryToFile("http://127.0.0.1:" + listener.getLocalPort() + "/core",
                        Collections.emptyMap(), partial, 1024 * 1024);
                throw new AssertionError("oversized streamed core accepted");
            } catch (Exception expected) {
                assertTrue(expected.getMessage().contains("limit"));
            }
            assertFalse(partial.exists());
        } finally {
            http.close();
            listener.close();
            server.join(500L);
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void legacyCoreIsDiscardedAndSchemaThreeCoreHasNoLegacyBackup() throws Exception {
        byte[] legacy = fakeCore((byte) 61);
        byte[] abiTwo = fakeCore((byte) 62);
        CoreServer server = new CoreServer(abiTwo, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-api-migration").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            store.writeBytes("core/xray/active/libxray.so", legacy);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(legacy))
                    .put("activeVersion", "xray-v26.7.11-w1")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 1)
                    .put("lastCheck", System.currentTimeMillis()));
            CoreUpdater updater = new CoreUpdater(store, http,
                    "arm64-v8a", CoreFamily.XRAY, server.baseUrl() + "/releases");
            assertEquals(0, updater.activeCoreApi());
            assertTrue(updater.checkForUpdate(false));
            assertArrayEquals(abiTwo, Files.readAllBytes(
                    updater.prepareForFirstLoad().toPath()));
            assertEquals(2, updater.activeCoreApi());
            JSONObject metadata = store.readJson("core/xray/core.json");
            assertFalse(store.child("core/xray/backup/libxray.so").exists());
            assertFalse(metadata.has("backupCoreApi"));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void rollbackDiscardsPendingBelowRestoredBackupFloor() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-rollback-floor").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] failed = fakeCore((byte) 85);
        byte[] backup = fakeCore((byte) 86);
        byte[] olderPending = fakeCore((byte) 87);
        try {
            store.writeBytes("core/xray/active/libxray.so", failed);
            store.writeBytes("core/xray/backup/libxray.so", backup);
            store.writeBytes("core/xray/pending/libxray.so", olderPending);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(failed))
                    .put("activeVersion", "xray-v26.7.11-w5")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("backupDigest", sha256(backup))
                    .put("backupVersion", "xray-v26.7.11-w4")
                    .put("backupOrigin", "itsv1eds/exitFy")
                    .put("backupCoreApi", 2)
                    .put("backupManifestSchema", 3)
                    .put("backupMinAndroidApi", 29)
                    .put("backupAbi", "arm64-v8a")
                    .put("pendingDigest", sha256(olderPending))
                    .put("pendingVersion", "xray-v26.7.11-w3")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                    .put("candidate", true)
                    .put("rollbackRequested", true));

            CoreUpdater updater = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            CoreUpdater.LoadTarget target = updater.prepareLoadTarget();
            assertArrayEquals(backup, Files.readAllBytes(target.file.toPath()));
            assertEquals("xray-v26.7.11-w4", updater.version());
            assertFalse(store.child("core/xray/pending/libxray.so").exists());
            assertFalse(store.readJson("core/xray/core.json").has("pendingVersion"));
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void activeCandidateIsSelfTestedBeforePendingAndKeepsLastGoodRollback()
            throws Exception {
        File root = Files.createTempDirectory("exitfy-core-candidate-last-good").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] lastGood = fakeCore((byte) 104);
        byte[] activeCandidate = fakeCore((byte) 105);
        byte[] newerPending = fakeCore((byte) 106);
        try {
            store.writeBytes("core/xray/active/libxray.so", activeCandidate);
            store.writeBytes("core/xray/backup/libxray.so", lastGood);
            store.writeBytes("core/xray/pending/libxray.so", newerPending);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(activeCandidate))
                    .put("activeVersion", "xray-v26.7.11-w3")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("backupDigest", sha256(lastGood))
                    .put("backupVersion", "xray-v26.7.11-w2")
                    .put("backupOrigin", "itsv1eds/exitFy")
                    .put("backupCoreApi", 2)
                    .put("backupManifestSchema", 3)
                    .put("backupMinAndroidApi", 29)
                    .put("backupAbi", "arm64-v8a")
                    .put("pendingDigest", sha256(newerPending))
                    .put("pendingVersion", "xray-v26.7.11-w4")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                    .put("candidate", true));

            CoreUpdater firstProcess = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            CoreUpdater.LoadTarget firstTarget = firstProcess.prepareLoadTarget();
            assertArrayEquals(activeCandidate, Files.readAllBytes(firstTarget.file.toPath()));
            assertArrayEquals(lastGood, Files.readAllBytes(
                    store.child("core/xray/backup/libxray.so").toPath()));
            assertArrayEquals(newerPending, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));

            firstProcess.markLoaderFailure();
            CoreUpdater secondProcess = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            CoreUpdater.LoadTarget secondTarget = secondProcess.prepareLoadTarget();
            assertArrayEquals(newerPending, Files.readAllBytes(secondTarget.file.toPath()));
            assertArrayEquals("last-good rollback was overwritten by an unverified candidate",
                    lastGood, Files.readAllBytes(
                            store.child("core/xray/backup/libxray.so").toPath()));

            secondProcess.markLoaderFailure();
            CoreUpdater thirdProcess = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            assertArrayEquals(lastGood, Files.readAllBytes(
                    thirdProcess.prepareLoadTarget().file.toPath()));
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void successfulActiveCandidateAllowsPendingPromotionOnNextLoad()
            throws Exception {
        File root = Files.createTempDirectory("exitfy-core-candidate-success").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] lastGood = fakeCore((byte) 107);
        byte[] activeCandidate = fakeCore((byte) 108);
        byte[] newerPending = fakeCore((byte) 109);
        try {
            store.writeBytes("core/xray/active/libxray.so", activeCandidate);
            store.writeBytes("core/xray/backup/libxray.so", lastGood);
            store.writeBytes("core/xray/pending/libxray.so", newerPending);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(activeCandidate))
                    .put("activeVersion", "xray-v26.7.11-w3")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("backupDigest", sha256(lastGood))
                    .put("backupVersion", "xray-v26.7.11-w2")
                    .put("backupOrigin", "itsv1eds/exitFy")
                    .put("backupCoreApi", 2)
                    .put("backupManifestSchema", 3)
                    .put("backupMinAndroidApi", 29)
                    .put("backupAbi", "arm64-v8a")
                    .put("pendingDigest", sha256(newerPending))
                    .put("pendingVersion", "xray-v26.7.11-w4")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                    .put("candidate", true));

            CoreUpdater firstProcess = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            assertArrayEquals(activeCandidate, Files.readAllBytes(
                    firstProcess.prepareLoadTarget().file.toPath()));
            firstProcess.markStartSuccess();

            CoreUpdater secondProcess = new CoreUpdater(
                    store, http, "arm64-v8a", CoreFamily.XRAY);
            assertArrayEquals(newerPending, Files.readAllBytes(
                    secondProcess.prepareLoadTarget().file.toPath()));
            assertArrayEquals("verified active core did not become the next rollback",
                    activeCandidate, Files.readAllBytes(
                            store.child("core/xray/backup/libxray.so").toPath()));
        } finally {
            http.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void backupVersionIsPartOfUpdateDowngradeFloor() throws Exception {
        byte[] releaseCore = fakeCore((byte) 88);
        CoreServer server = new CoreServer(releaseCore, CoreFamily.XRAY,
                CoreUpdaterTest::promoteFixtureToWrapperThree);
        File root = Files.createTempDirectory("exitfy-core-backup-floor").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] active = fakeCore((byte) 89);
        byte[] backup = fakeCore((byte) 90);
        try {
            store.writeBytes("core/xray/active/libxray.so", active);
            store.writeBytes("core/xray/backup/libxray.so", backup);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(active))
                    .put("activeVersion", "xray-v26.7.11-w2")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("backupDigest", sha256(backup))
                    .put("backupVersion", "xray-v26.7.11-w4")
                    .put("backupOrigin", "itsv1eds/exitFy")
                    .put("backupCoreApi", 2)
                    .put("backupManifestSchema", 3)
                    .put("backupMinAndroidApi", 29)
                    .put("backupAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, server.baseUrl() + "/releases");
            assertFalse(updater.checkForUpdate(true));
            assertFalse(store.child("core/xray/pending/libxray.so").exists());
            assertArrayEquals(backup, Files.readAllBytes(
                    store.child("core/xray/backup/libxray.so").toPath()));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void ownedInvalidActiveVersionRepairsOnlyOnExactReleaseDigest() throws Exception {
        byte[] core = fakeCore((byte) 91);
        CoreServer matching = new CoreServer(core, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-version-repair").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        try {
            store.writeBytes("core/xray/active/libxray.so", core);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(core))
                    .put("activeVersion", "corrupted-owned-version")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("lastCheck", System.currentTimeMillis()));
            CoreUpdater updater = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, matching.baseUrl() + "/releases");
            assertFalse(updater.checkForUpdate(false));
            assertEquals("xray-v26.7.11-w2",
                    store.readJson("core/xray/core.json").optString("activeVersion"));
            assertArrayEquals(core, Files.readAllBytes(updater.prepareLoadTarget().file.toPath()));
        } finally {
            http.close();
            matching.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void ownedInvalidBackupVersionRepairsOnlyOnExactReleaseDigest() throws Exception {
        byte[] releaseCore = fakeCore((byte) 100);
        CoreServer matching = new CoreServer(releaseCore, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-backup-version-repair").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] active = fakeCore((byte) 101);
        try {
            store.writeBytes("core/xray/active/libxray.so", active);
            store.writeBytes("core/xray/backup/libxray.so", releaseCore);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(active))
                    .put("activeVersion", "xray-v26.7.10-w2")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("backupDigest", sha256(releaseCore))
                    .put("backupVersion", "corrupted-owned-version")
                    .put("backupOrigin", "itsv1eds/exitFy")
                    .put("backupCoreApi", 2)
                    .put("backupManifestSchema", 3)
                    .put("backupMinAndroidApi", 29)
                    .put("backupAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, matching.baseUrl() + "/releases");
            assertTrue(updater.checkForUpdate(true));
            JSONObject repaired = store.readJson("core/xray/core.json");
            assertEquals("xray-v26.7.11-w2", repaired.optString("backupVersion"));
            assertArrayEquals(releaseCore, Files.readAllBytes(
                    store.child("core/xray/backup/libxray.so").toPath()));
            assertArrayEquals(releaseCore, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));
        } finally {
            http.close();
            matching.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void ownedInvalidActiveAndBackupVersionsFailClosedOnDifferentDigest()
            throws Exception {
        byte[] releaseCore = fakeCore((byte) 92);
        CoreServer server = new CoreServer(releaseCore, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-version-fail-closed").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] active = fakeCore((byte) 93);
        byte[] backup = fakeCore((byte) 94);
        try {
            store.writeBytes("core/xray/active/libxray.so", active);
            store.writeBytes("core/xray/backup/libxray.so", backup);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(active))
                    .put("activeVersion", "invalid-active")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("backupDigest", sha256(backup))
                    .put("backupVersion", "invalid-backup")
                    .put("backupOrigin", "itsv1eds/exitFy")
                    .put("backupCoreApi", 2)
                    .put("backupManifestSchema", 3)
                    .put("backupMinAndroidApi", 29)
                    .put("backupAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, server.baseUrl() + "/releases");
            try {
                updater.checkForUpdate(true);
                throw new AssertionError("different release digest repaired corrupt metadata");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("exact digest repair"));
            }
            assertArrayEquals(active, Files.readAllBytes(
                    updater.prepareLoadTarget().file.toPath()));
            assertArrayEquals(backup, Files.readAllBytes(
                    store.child("core/xray/backup/libxray.so").toPath()));
            assertFalse(store.child("core/xray/pending/libxray.so").exists());
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void invalidOwnedPendingIsDiscardedAndDownloadedAgain() throws Exception {
        byte[] releaseCore = fakeCore((byte) 95);
        CoreServer server = new CoreServer(releaseCore, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-invalid-pending-version").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] active = fakeCore((byte) 96);
        byte[] invalidPending = fakeCore((byte) 97);
        try {
            store.writeBytes("core/xray/active/libxray.so", active);
            store.writeBytes("core/xray/pending/libxray.so", invalidPending);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(active))
                    .put("activeVersion", "xray-v26.7.10-w2")
                    .put("activeOrigin", "itsv1eds/exitFy")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a")
                    .put("pendingDigest", sha256(invalidPending))
                    .put("pendingVersion", "invalid-owned-pending")
                    .put("pendingOrigin", "itsv1eds/exitFy")
                    .put("pendingCoreApi", 2)
                    .put("pendingManifestSchema", 3)
                    .put("pendingMinAndroidApi", 29)
                    .put("pendingAbi", "arm64-v8a")
                    .put("lastCheck", System.currentTimeMillis()));
            CoreUpdater updater = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, server.baseUrl() + "/releases");
            assertTrue(updater.checkForUpdate(false));
            assertArrayEquals(releaseCore, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));
            assertEquals("xray-v26.7.11-w2",
                    store.readJson("core/xray/core.json").optString("pendingVersion"));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void missingOriginCannotBlockSchemaThreeRecoveryDownload() throws Exception {
        byte[] releaseCore = fakeCore((byte) 98);
        CoreServer server = new CoreServer(releaseCore, CoreFamily.XRAY, null);
        File root = Files.createTempDirectory("exitfy-core-legacy-version").toFile();
        AtomicStore store = new AtomicStore(root);
        LimitedHttpClient http = new LimitedHttpClient();
        byte[] legacy = fakeCore((byte) 99);
        try {
            store.writeBytes("core/xray/active/libxray.so", legacy);
            store.writeJson("core/xray/core.json", new JSONObject()
                    .put("activeDigest", sha256(legacy))
                    .put("activeVersion", "legacy-unversioned")
                    .put("activeCoreApi", 2)
                    .put("activeManifestSchema", 3)
                    .put("activeMinAndroidApi", 29)
                    .put("activeAbi", "arm64-v8a"));
            CoreUpdater updater = new CoreUpdater(store, http, "arm64-v8a",
                    CoreFamily.XRAY, server.baseUrl() + "/releases");
            assertTrue(updater.checkForUpdate(true));
            assertFalse(store.child("core/xray/active/libxray.so").exists());
            assertArrayEquals(releaseCore, Files.readAllBytes(
                    store.child("core/xray/pending/libxray.so").toPath()));
        } finally {
            http.close();
            server.close();
            TestFiles.deleteRecursively(root);
        }
    }

    private static byte[] fakeCore(byte marker) {
        return TestElfFiles.core(marker);
    }

    private static JSONObject coreMetadata(String prefix, byte[] core) throws Exception {
        return new JSONObject()
                .put(prefix + "Digest", sha256(core))
                .put(prefix + "Version", "xray-v26.7.11-w2")
                .put(prefix + "Origin", "itsv1eds/exitFy")
                .put(prefix + "CoreApi", 2)
                .put(prefix + "ManifestSchema", 3)
                .put(prefix + "MinAndroidApi", 29)
                .put(prefix + "Abi", "arm64-v8a");
    }

    private static void promoteFixtureToWrapperThree(JSONObject release, JSONObject manifest)
            throws Exception {
        release.put("tag_name", "xray-v26.7.11-w3");
        manifest.put("releaseTag", "xray-v26.7.11-w3");
    }

    private static String sha256(byte[] value) throws Exception {
        StringBuilder output = new StringBuilder();
        for (byte item : MessageDigest.getInstance("SHA-256").digest(value)) {
            output.append(String.format("%02x", item & 255));
        }
        return output.toString();
    }

    private static final class CoreServer implements Closeable {
        private final ServerSocket listener;
        private final Thread worker;
        private final byte[] core;
        private final byte[] manifest;
        private byte[] releases;
        private byte[] manifestSignature;
        private final byte[] sourceBundle = "corresponding source fixture".getBytes(
                StandardCharsets.UTF_8);
        private volatile boolean running = true;

        CoreServer(byte[] core) throws Exception {
            this(core, CoreFamily.XRAY, null);
        }

        /** Serves a detached manifest signature made by the supplied key. */
        CoreServer sign(java.security.PrivateKey key) throws Exception {
            java.security.Signature signer =
                    java.security.Signature.getInstance("SHA256withECDSA");
            signer.initSign(key);
            signer.update(manifest);
            manifestSignature = signer.sign();
            JSONArray parsed = new JSONArray(new String(releases, StandardCharsets.UTF_8));
            parsed.getJSONObject(0).getJSONArray("assets")
                    .put(new JSONObject().put("id", 30)
                            .put("name", "manifest.json.sig")
                            .put("size", manifestSignature.length)
                            .put("digest", "sha256:" + sha256(manifestSignature))
                            .put("browser_download_url", baseUrl() + "/signature"));
            releases = parsed.toString().getBytes(StandardCharsets.UTF_8);
            return this;
        }

        CoreServer(byte[] core, CoreFamily family, ManifestMutation mutation) throws Exception {
            this.core = core;
            listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            String base = baseUrl();
            String coreDigest = sha256(core);
            JSONObject manifestAssets = new JSONObject();
            JSONArray releaseAssets = new JSONArray();
            String[] abis = {"arm64-v8a"};
            int[] machines = {183};
            int[] classes = {64};
            String[] machineNames = {"EM_AARCH64"};
            for (int index = 0; index < abis.length; index++) {
                String name = (family == CoreFamily.XRAY ? "libxray-" : "libexitfy-sb-")
                        + abis[index] + ".so";
                manifestAssets.put(abis[index], new JSONObject()
                        .put("name", name).put("size", core.length)
                        .put("sha256", coreDigest).put("elfClass", classes[index])
                        .put("elfMachine", machines[index])
                        .put("elfMachineName", machineNames[index])
                        .put("exports", new JSONArray().put("StartCore").put("StopCore")));
                releaseAssets.put(new JSONObject().put("id", index + 1).put("name", name)
                        .put("size", core.length).put("digest", "sha256:" + coreDigest)
                        .put("browser_download_url", base + "/core"));
            }
            String tag = family == CoreFamily.XRAY ? "xray-v26.7.11-w2"
                    : "sb-v1.13.14-w2";
            JSONObject upstream = family == CoreFamily.XRAY
                    ? new JSONObject().put("repository", "XTLS/libXray")
                    .put("tag", "v26.7.11")
                    .put("commit", "294fb37343205b9b0cb7b7b1b423d3d4b60d9998")
                    : new JSONObject().put("repository", "SagerNet/sing-box")
                    .put("tag", "v1.13.14")
                    .put("commit", "25a600db24f7680ad9806ce5427bd0ab8afe1114")
                    .put("goVersion", "1.24.7");
            JSONObject wrapper = new JSONObject().put("repository", "itsv1eds/exitFy")
                    .put("commit", "eab489fa85a345f584882158b9f2b30a0a12b140");
            if (family == CoreFamily.SING_BOX) {
                String sourceName = "exitfy-sb-v1.13.14-source.tar.gz";
                String sourceDigest = sha256(sourceBundle);
                wrapper.put("ndkVersion", "27.2.12479018")
                        .put("buildTags", new JSONArray()
                                .put("badlinkname").put("tfogo_checklinkname0")
                                .put("with_quic").put("with_utls"))
                        .put("sourceBundle", new JSONObject().put("name", sourceName)
                                .put("size", sourceBundle.length).put("sha256", sourceDigest));
                releaseAssets.put(new JSONObject().put("id", 10).put("name", sourceName)
                        .put("size", sourceBundle.length).put("digest", "sha256:" + sourceDigest)
                        .put("browser_download_url", base + "/source"));
            }
            JSONObject manifestObject = new JSONObject()
                    .put("schema", 3).put("coreApi", 2).put("configContract", 1)
                    .put("family", family.id).put("minAndroidApi", 29)
                    .put("releaseTag", tag)
                    .put("upstream", upstream)
                    .put("wrapper", wrapper)
                    .put("requiredExports", new JSONArray().put("StartCore").put("StopCore"))
                    .put("assets", manifestAssets);
            JSONObject release = new JSONObject().put("tag_name", tag)
                    .put("draft", false).put("prerelease", false)
                    .put("assets", releaseAssets);
            if (mutation != null) mutation.apply(release, manifestObject);
            manifest = manifestObject.toString().getBytes(StandardCharsets.UTF_8);
            releaseAssets.put(new JSONObject().put("id", 20).put("name", "manifest.json")
                            .put("size", manifest.length)
                            .put("digest", "sha256:" + sha256(manifest))
                            .put("browser_download_url", base + "/manifest"));
            releases = new JSONArray().put(release).toString().getBytes(StandardCharsets.UTF_8);
            worker = new Thread(this::loop, "exitfy-core-test-http");
            worker.setDaemon(true);
            worker.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + listener.getLocalPort();
        }

        private void loop() {
            while (running) {
                try (Socket socket = listener.accept()) {
                    socket.setSoTimeout(2000);
                    String request = readHeaders(socket.getInputStream());
                    String path = request.split(" ", 3)[1];
                    byte[] body;
                    int status;
                    if (path.equals("/releases") || path.startsWith("/releases?")) {
                        body = releases;
                        status = 200;
                    } else if (path.equals("/signature")) {
                        body = manifestSignature;
                        status = 200;
                    } else if (path.equals("/manifest")) {
                        body = manifest;
                        status = 200;
                    } else if (path.equals("/core")) {
                        body = core;
                        status = 200;
                    } else if (path.equals("/source")) {
                        body = sourceBundle;
                        status = 200;
                    } else {
                        body = new byte[0];
                        status = 404;
                    }
                    String headers = "HTTP/1.1 " + status + (status == 200 ? " OK" : " Error")
                            + "\r\nContent-Length: " + body.length
                            + "\r\nConnection: close\r\n\r\n";
                    OutputStream output = socket.getOutputStream();
                    output.write(headers.getBytes(StandardCharsets.ISO_8859_1));
                    output.write(body);
                    output.flush();
                } catch (Exception ignored) {
                }
            }
        }

        private static String readHeaders(InputStream input) throws Exception {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            int matched = 0;
            while (output.size() < 32 * 1024) {
                int value = input.read();
                if (value < 0) break;
                output.write(value);
                int expected = matched == 0 || matched == 2 ? '\r' : '\n';
                if (value == expected) {
                    if (++matched == 4) break;
                } else {
                    matched = value == '\r' ? 1 : 0;
                }
            }
            return new String(output.toByteArray(), StandardCharsets.ISO_8859_1);
        }

        @Override
        public void close() {
            running = false;
            try {
                listener.close();
            } catch (Exception ignored) {
            }
            try {
                worker.join(500);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            }
        }

        private interface ManifestMutation {
            void apply(JSONObject release, JSONObject manifest) throws Exception;
        }
    }
}
