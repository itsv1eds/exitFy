package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AtomicStoreTest {
    @Test
    public void optionalStrictReadDistinguishesMissingFromCorruptState() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-optional-read").toFile();
        AtomicStore store = new AtomicStore(root);
        File durable = new File(root, "state.json");
        try {
            assertTrue(store.readJsonIfExists("state.json") == null);
            Files.write(durable.toPath(), "{not-json".getBytes(StandardCharsets.UTF_8));
            try {
                store.readJsonIfExists("state.json");
                throw new AssertionError("corrupt optional state was treated as missing");
            } catch (Exception expected) {
                assertTrue(durable.isFile());
            }
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void incrementalSizeMatchesSerializedUnicodeJson() throws Exception {
        JSONObject value = new JSONObject()
                .put("кириллица", "Привет 👋")
                .put("escaped", "line\nquote\"")
                .put("array", new JSONArray().put(true).put(42).put(JSONObject.NULL));
        assertEquals(value.toString().getBytes(StandardCharsets.UTF_8).length,
                AtomicStore.jsonUtf8Size(value, AtomicStore.MAX_JSON_BYTES));
    }

    @Test
    public void oversizedJsonIsRejectedBeforeCreatingTarget() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-limit").toFile();
        AtomicStore store = new AtomicStore(root);
        try {
            JSONArray values = new JSONArray();
            String block = repeat('x', 16 * 1024);
            for (int i = 0; i < 520; i++) values.put(block);
            try {
                store.writeJson("oversized.json", new JSONObject().put("values", values));
                throw new AssertionError("oversized JSON accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("8 MiB"));
            }
            assertFalse(store.child("oversized.json").exists());
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void revokedWriterCannotMoveStagedFileOrOverwriteReplacement() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-writer").toFile();
        AtomicStore first = new AtomicStore(root);
        AtomicStore second = new AtomicStore(root);
        AtomicStore.WriterLease firstLease = first.claimWriter("state.json");
        CountDownLatch guardEntered = new CountDownLatch(1);
        CountDownLatch releaseGuard = new CountDownLatch(1);
        CountDownLatch replacementStarted = new CountDownLatch(1);
        AtomicReference<Throwable> firstError = new AtomicReference<>();
        AtomicReference<Throwable> replacementError = new AtomicReference<>();
        AtomicReference<AtomicStore.WriterLease> secondLease = new AtomicReference<>();
        try {
            Thread staleWrite = new Thread(() -> {
                try {
                    first.writeJson("state.json", new JSONObject().put("owner", "first"),
                            firstLease, () -> {
                                guardEntered.countDown();
                                try {
                                    return releaseGuard.await(3, TimeUnit.SECONDS);
                                } catch (InterruptedException error) {
                                    Thread.currentThread().interrupt();
                                    return false;
                                }
                            });
                } catch (Throwable error) {
                    firstError.set(error);
                }
            }, "exitfy-stale-atomic-writer");
            staleWrite.start();
            assertTrue("first writer did not reach commit guard",
                    guardEntered.await(2, TimeUnit.SECONDS));
            Thread replacementWrite = new Thread(() -> {
                try {
                    replacementStarted.countDown();
                    AtomicStore.WriterLease lease = second.claimWriter("state.json");
                    secondLease.set(lease);
                    second.writeJson("state.json", new JSONObject().put("owner", "second"),
                            lease, lease::isActive);
                } catch (Throwable error) {
                    replacementError.set(error);
                }
            }, "exitfy-replacement-atomic-writer");
            replacementWrite.start();
            assertTrue("replacement writer did not start",
                    replacementStarted.await(2, TimeUnit.SECONDS));
            firstLease.close();
            releaseGuard.countDown();
            staleWrite.join(3000L);
            replacementWrite.join(3000L);
            assertFalse("revoked writer did not finish", staleWrite.isAlive());
            assertFalse("replacement writer did not finish", replacementWrite.isAlive());
            assertTrue(firstError.get() instanceof AtomicStore.StaleWriteException);
            assertTrue("replacement write failed: " + replacementError.get(),
                    replacementError.get() == null);
            assertEquals("second", first.readJson("state.json").getString("owner"));
        } finally {
            releaseGuard.countDown();
            firstLease.close();
            if (secondLease.get() != null) secondLease.get().close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void cleansKilledProcessStagesWithoutTouchingOtherTargets() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-orphans").toFile();
        AtomicStore store = new AtomicStore(root);
        File orphan = new File(root, "state.json.tmp.killed.stage");
        File unrelated = new File(root, "other.json.tmp.killed.stage");
        try {
            Files.write(orphan.toPath(), new byte[1024]);
            Files.write(unrelated.toPath(), new byte[128]);
            store.readJson("state.json");
            assertFalse("killed-process stage was not reclaimed", orphan.exists());
            assertTrue("cleanup crossed the target prefix", unrelated.exists());
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void failedWriteAlwaysRemovesItsRegisteredStage() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-stage-finally").toFile();
        AtomicStore store = new AtomicStore(root, (target, staged) -> {
            throw new java.io.IOException("injected commit failure");
        });
        try {
            try {
                store.writeJson("state.json", new JSONObject().put("value", "new"));
                throw new AssertionError("injected write failure was ignored");
            } catch (java.io.IOException expected) {
                assertTrue(expected.getMessage().contains("injected"));
            }
            File[] stages = root.listFiles((directory, name) ->
                    name.startsWith("state.json.tmp.") && name.endsWith(".stage"));
            assertTrue(stages == null || stages.length == 0);
            assertFalse(store.child("state.json").exists());
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void commitPinnedBeforeCloseIsPublishedAndReplacementReadsIt() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-linear-commit").toFile();
        CountDownLatch commitPinned = new CountDownLatch(1);
        CountDownLatch releaseCommit = new CountDownLatch(1);
        AtomicStore oldStore = new AtomicStore(root, (target, staged) -> {
            commitPinned.countDown();
            if (!releaseCommit.await(3, TimeUnit.SECONDS)) {
                throw new IllegalStateException("commit barrier timed out");
            }
        });
        AtomicStore replacementStore = new AtomicStore(root);
        AtomicStore.WriterLease oldLease = oldStore.claimWriter("state.json");
        AtomicReference<Throwable> oldError = new AtomicReference<>();
        AtomicBoolean oldCommitted = new AtomicBoolean();
        AtomicReference<String> replacementObserved = new AtomicReference<>();
        AtomicReference<Throwable> replacementError = new AtomicReference<>();
        AtomicReference<AtomicStore.WriterLease> replacementLease = new AtomicReference<>();
        try {
            Thread oldWrite = new Thread(() -> {
                try {
                    oldCommitted.set(oldStore.writeJson("state.json",
                            new JSONObject().put("owner", "committed-before-close"),
                            oldLease, oldLease::isActive));
                } catch (Throwable error) {
                    oldError.set(error);
                }
            }, "exitfy-linear-old-writer");
            oldWrite.start();
            assertTrue("write did not reach irrevocable commit barrier",
                    commitPinned.await(2, TimeUnit.SECONDS));

            long closeStarted = System.nanoTime();
            oldLease.close();
            assertTrue("lease close was not O(1)",
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - closeStarted) < 250L);

            Thread replacement = new Thread(() -> {
                try {
                    AtomicStore.WriterLease lease = replacementStore.claimWriter("state.json");
                    replacementLease.set(lease);
                    replacementObserved.set(replacementStore.readJson("state.json")
                            .optString("owner", ""));
                } catch (Throwable error) {
                    replacementError.set(error);
                }
            }, "exitfy-linear-replacement-reader");
            replacement.start();
            releaseCommit.countDown();
            oldWrite.join(3000L);
            replacement.join(3000L);

            assertFalse(oldWrite.isAlive());
            assertFalse(replacement.isAlive());
            assertTrue("pinned commit was falsely reported cancelled: " + oldError.get(),
                    oldError.get() == null && oldCommitted.get());
            assertTrue("replacement failed: " + replacementError.get(),
                    replacementError.get() == null);
            assertEquals("committed-before-close", replacementObserved.get());
        } finally {
            releaseCommit.countDown();
            oldLease.close();
            if (replacementLease.get() != null) replacementLease.get().close();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void readRejectsHostileLowEntropyArrayBeforeMaterializingIt() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-json-values").toFile();
        AtomicStore store = new AtomicStore(root);
        try {
            StringBuilder hostile = new StringBuilder(2_100_032);
            hostile.append("{\"values\":[");
            for (int index = 0; index < 1_000_000; index++) {
                if (index > 0) hostile.append(',');
                hostile.append('0');
            }
            hostile.append("]}");
            Files.write(store.child("hostile.json").toPath(),
                    hostile.toString().getBytes(StandardCharsets.UTF_8));

            assertEquals(0, store.readJson("hostile.json").length());
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void readAcceptsStringBoundaryAndRejectsOneDecodedByteMore() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-json-string").toFile();
        AtomicStore store = new AtomicStore(root);
        try {
            String accepted = "{\"value\":\"" + repeat('a', JsonGuard.MAX_STRING_BYTES) + "\"}";
            Files.write(store.child("state.json").toPath(),
                    accepted.getBytes(StandardCharsets.UTF_8));
            assertEquals(JsonGuard.MAX_STRING_BYTES,
                    store.readJson("state.json").getString("value").length());

            String rejected = "{\"value\":\""
                    + repeat('a', JsonGuard.MAX_STRING_BYTES + 1) + "\"}";
            Files.write(store.child("state.json").toPath(),
                    rejected.getBytes(StandardCharsets.UTF_8));
            assertEquals(0, store.readJson("state.json").length());
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void writeAndReadUseTheSameStringTokenBoundary() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-json-roundtrip").toFile();
        AtomicStore store = new AtomicStore(root);
        try {
            String accepted = repeat('a', JsonGuard.MAX_STRING_BYTES);
            assertTrue(store.writeJson("state.json",
                    new JSONObject().put("value", accepted)));
            assertEquals(accepted, store.readJson("state.json").getString("value"));

            try {
                store.writeJson("state.json", new JSONObject().put(
                        "value", accepted + "a"));
                throw new AssertionError("oversized JSON string was persisted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("64 KiB"));
            }
            assertEquals("rejected write replaced the last good state", accepted,
                    store.readJson("state.json").getString("value"));
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void readRejectsOversizedLenientScalarBeforeMaterializingIt() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-json-scalar").toFile();
        AtomicStore store = new AtomicStore(root);
        try {
            String rejected = "{value:" + repeat('a', JsonGuard.MAX_STRING_BYTES + 1) + "}";
            Files.write(store.child("state.json").toPath(),
                    rejected.getBytes(StandardCharsets.UTF_8));
            assertEquals(0, store.readJson("state.json").length());
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void interruptedReadCancelsPreflightWithoutClearingInterrupt() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-json-cancel").toFile();
        AtomicStore store = new AtomicStore(root);
        AtomicReference<JSONObject> observed = new AtomicReference<>();
        AtomicBoolean interruptPreserved = new AtomicBoolean();
        try {
            Files.write(store.child("state.json").toPath(),
                    "{\"value\":true}".getBytes(StandardCharsets.UTF_8));
            Thread worker = new Thread(() -> {
                Thread.currentThread().interrupt();
                observed.set(store.readJson("state.json"));
                interruptPreserved.set(Thread.currentThread().isInterrupted());
            }, "exitfy-atomic-json-cancel");
            worker.start();
            worker.join(2_000L);

            assertFalse("read worker did not finish", worker.isAlive());
            assertEquals(0, observed.get().length());
            assertTrue("read cleared the interrupt flag", interruptPreserved.get());
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void interruptedStrictRecoveryNeverEntersBlockingReadHook() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-json-recovery").toFile();
        CountDownLatch readEntered = new CountDownLatch(1);
        CountDownLatch releaseRead = new CountDownLatch(1);
        AtomicStore store = new AtomicStore(root, AtomicStore.CommitObserver.NO_OP, target -> {
            readEntered.countDown();
            releaseRead.await();
        });
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean interruptPreserved = new AtomicBoolean();
        try {
            store.writeJson("state.json", new JSONObject().put("owner", "durable"));
            Thread worker = new Thread(() -> {
                Thread.currentThread().interrupt();
                try {
                    store.readJsonStrict("state.json");
                } catch (Throwable error) {
                    failure.set(error);
                } finally {
                    interruptPreserved.set(Thread.currentThread().isInterrupted());
                }
            }, "exitfy-atomic-json-recovery");
            worker.start();
            worker.join(2_000L);

            assertFalse("recovery worker did not finish", worker.isAlive());
            assertTrue("strict recovery ignored cancellation: " + failure.get(),
                    failure.get() instanceof java.io.InterruptedIOException);
            assertEquals("cancelled recovery entered blocking I/O", 1L, readEntered.getCount());
            assertTrue("recovery cleared the caller interrupt", interruptPreserved.get());
            assertEquals("durable", new AtomicStore(root).readJson("state.json")
                    .getString("owner"));
        } finally {
            releaseRead.countDown();
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void interruptedWriteStopsBeforeReplacingDurableState() throws Exception {
        File root = Files.createTempDirectory("exitfy-atomic-json-write-cancel").toFile();
        AtomicStore store = new AtomicStore(root);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean interruptPreserved = new AtomicBoolean();
        try {
            store.writeJson("state.json", new JSONObject().put("owner", "old"));
            Thread worker = new Thread(() -> {
                Thread.currentThread().interrupt();
                try {
                    store.writeJson("state.json", new JSONObject().put("owner", "new"));
                    failure.set(new AssertionError("interrupted write committed"));
                } catch (Throwable error) {
                    failure.set(error);
                } finally {
                    interruptPreserved.set(Thread.currentThread().isInterrupted());
                }
            }, "exitfy-atomic-json-write-cancel");
            worker.start();
            worker.join(2_000L);

            assertFalse("write worker did not finish", worker.isAlive());
            assertTrue("unexpected write error: " + failure.get(),
                    failure.get() instanceof IllegalStateException
                            && failure.get().getMessage().contains("interrupted"));
            assertTrue("write cleared the interrupt flag", interruptPreserved.get());
            assertEquals("old", store.readJson("state.json").getString("owner"));
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int i = 0; i < count; i++) result.append(value);
        return result.toString();
    }
}
