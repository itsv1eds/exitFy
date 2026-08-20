package com.extera.plugins.exitfy;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LimitedHttpClientTest {
    @Test
    public void preservesCallerHeadersOnlyAcrossSameOriginRedirects() throws Exception {
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://subscriptions.example/start", 302,
                        "https://subscriptions.example:443/next", "")
                .add("https://subscriptions.example:443/next", 200, null, "ok");
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-HWID", "private-hwid");
        headers.put("X-Device-Model", "private-model");

        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            LimitedHttpClient.Response response = client.get(
                    "https://subscriptions.example/start", headers);
            assertEquals("ok", new String(response.body, StandardCharsets.UTF_8));
        }

        assertEquals(2, factory.opened.size());
        for (FakeConnection connection : factory.opened) {
            assertFalse(connection.getInstanceFollowRedirects());
            assertEquals("private-hwid", connection.getRequestProperty("X-HWID"));
            assertEquals("private-model", connection.getRequestProperty("X-Device-Model"));
            assertTrue(awaitDisconnected(connection));
        }
        assertTrue(LimitedHttpClient.sameOrigin(
                new URL("https://subscriptions.example/start"),
                new URL("https://subscriptions.example:443/next")));
    }

    @Test
    public void permanentlyStripsCallerHeadersAfterCrossOriginRedirect() throws Exception {
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://subscriptions.example/start", 302,
                        "https://cdn.example/download", "")
                .add("https://cdn.example/download", 307,
                        "https://subscriptions.example/return", "")
                .add("https://subscriptions.example/return", 200, null, "ok");
        Map<String, String> headers = Collections.singletonMap("X-HWID", "private-hwid");

        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            assertEquals(200, client.get("https://subscriptions.example/start", headers).status);
        }

        assertEquals("private-hwid", factory.opened.get(0).getRequestProperty("X-HWID"));
        assertNull(factory.opened.get(1).getRequestProperty("X-HWID"));
        // Returning to the original origin must not reintroduce a secret that
        // was already stripped at the trust boundary.
        assertNull(factory.opened.get(2).getRequestProperty("X-HWID"));
        assertEquals("exitFy/4.0 exteraGram Android",
                factory.opened.get(2).getRequestProperty("User-Agent"));
    }

    @Test
    public void rejectsHttpsDowngradeBeforeOpeningRedirectTarget() throws Exception {
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://subscriptions.example/start", 302,
                        "http://subscriptions.example/plain", "");

        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            try {
                client.get("https://subscriptions.example/start",
                        Collections.singletonMap("X-HWID", "private-hwid"));
                fail("HTTPS downgrade accepted");
            } catch (IOException expected) {
                assertTrue(expected.getMessage().contains("downgrade"));
            }
        }

        assertEquals(1, factory.opened.size());
        assertTrue(awaitDisconnected(factory.opened.get(0)));
    }

    @Test
    public void rejectsRedirectAfterFiveFollowedHops() throws Exception {
        ScriptedFactory factory = new ScriptedFactory();
        for (int index = 0; index <= LimitedHttpClient.MAX_REDIRECTS; index++) {
            factory.add("https://redirect.example/hop" + index, 302,
                    "/hop" + (index + 1), "");
        }

        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            try {
                client.get("https://redirect.example/hop0", Collections.emptyMap());
                fail("redirect limit was not enforced");
            } catch (IOException expected) {
                assertTrue(expected.getMessage().contains("limit"));
            }
        }

        assertEquals(LimitedHttpClient.MAX_REDIRECTS + 1, factory.opened.size());
        for (FakeConnection connection : factory.opened) {
            assertTrue(awaitDisconnected(connection));
        }
    }

    @Test
    public void streamingCoreDownloadStillFollowsCrossOriginWithoutCustomHeaders()
            throws Exception {
        byte[] core = "fake-core-binary".getBytes(StandardCharsets.UTF_8);
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://github.example/release/core.so", 302,
                        "https://objects.example/assets/core.so", "")
                .add("https://objects.example/assets/core.so", 200, null, core);
        File root = Files.createTempDirectory("exitfy-http-redirect").toFile();
        File target = new File(root, "core.so");
        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            LimitedHttpClient.StreamResponse response = client.getBinaryToFile(
                    "https://github.example/release/core.so", Collections.emptyMap(),
                    target, 1024);
            assertEquals(200, response.status);
            assertEquals(core.length, response.size);
            assertArrayEquals(core, Files.readAllBytes(target.toPath()));
        } finally {
            TestFiles.deleteRecursively(root);
        }
        assertEquals(2, factory.opened.size());
    }

    @Test
    public void streamingProgressIsCumulativeAndListenerFailureIsObservational()
            throws Exception {
        byte[] core = new byte[70 * 1024];
        for (int index = 0; index < core.length; index++) {
            core[index] = (byte) (index & 0xff);
        }
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://assets.example/core.so", 200, null, core);
        File root = Files.createTempDirectory("exitfy-http-progress").toFile();
        File target = new File(root, "core.so");
        List<Long> downloaded = new ArrayList<>();
        List<Long> totals = new ArrayList<>();
        AtomicBoolean threwOnce = new AtomicBoolean();
        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            LimitedHttpClient.StreamResponse response = client.getBinaryToFile(
                    "https://assets.example/core.so", Collections.emptyMap(),
                    target, core.length, (current, total) -> {
                        downloaded.add(current);
                        totals.add(total);
                        if (current > 0L && current < core.length
                                && threwOnce.compareAndSet(false, true)) {
                            throw new IllegalStateException("observer failure");
                        }
                    });

            assertEquals(core.length, response.size);
            assertArrayEquals(core, Files.readAllBytes(target.toPath()));
        } finally {
            TestFiles.deleteRecursively(root);
        }

        assertTrue("listener exception path was not exercised", threwOnce.get());
        assertFalse(downloaded.isEmpty());
        assertEquals(0L, downloaded.get(0).longValue());
        assertEquals(core.length, downloaded.get(downloaded.size() - 1).longValue());
        long previous = -1L;
        for (int index = 0; index < downloaded.size(); index++) {
            assertTrue("download progress regressed", downloaded.get(index) >= previous);
            assertEquals(core.length, totals.get(index).longValue());
            previous = downloaded.get(index);
        }
    }

    @Test
    public void streamingProgressPreservesUnknownContentLengthAndFinalBytes()
            throws Exception {
        byte[] core = new byte[70 * 1024];
        for (int index = 0; index < core.length; index++) {
            core[index] = (byte) (255 - (index & 0xff));
        }
        String url = "https://assets.example/unknown-length-core.so";
        ScriptedFactory factory = new ScriptedFactory()
                .add(url, 200, null, core)
                .contentLength(url, -1L);
        File root = Files.createTempDirectory("exitfy-http-unknown-progress").toFile();
        File target = new File(root, "core.so");
        List<Long> downloaded = new ArrayList<>();
        List<Long> totals = new ArrayList<>();
        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            LimitedHttpClient.StreamResponse response = client.getBinaryToFile(
                    url, Collections.emptyMap(), target, core.length,
                    (current, total) -> {
                        downloaded.add(current);
                        totals.add(total);
                    });

            assertEquals(core.length, response.size);
            assertArrayEquals(core, Files.readAllBytes(target.toPath()));
        } finally {
            TestFiles.deleteRecursively(root);
        }

        assertFalse(downloaded.isEmpty());
        assertEquals(0L, downloaded.get(0).longValue());
        assertEquals(core.length, downloaded.get(downloaded.size() - 1).longValue());
        long previous = -1L;
        for (int index = 0; index < downloaded.size(); index++) {
            assertTrue("unknown-length progress regressed", downloaded.get(index) >= previous);
            assertEquals(-1L, totals.get(index).longValue());
            previous = downloaded.get(index);
        }
    }

    @Test
    public void cancellationBetweenRedirectHopsDoesNotOpenNextConnection() throws Exception {
        AtomicReference<LimitedHttpClient> current = new AtomicReference<>();
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://subscriptions.example/start", 302,
                        "https://subscriptions.example/next", "")
                .onLocationRead("https://subscriptions.example/start",
                        () -> current.get().cancelActive())
                .add("https://subscriptions.example/next", 200, null, "late");

        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            current.set(client);
            try {
                client.get("https://subscriptions.example/start", Collections.emptyMap());
                fail("redirect continued after cancellation");
            } catch (IOException expected) {
                assertTrue(expected.getMessage().contains("cancelled"));
            }
        }

        assertEquals(1, factory.opened.size());
        assertTrue(awaitDisconnected(factory.opened.get(0)));
    }

    @Test
    public void cancelledRequestScopeCannotStartNextSubscriptionUrl() throws Exception {
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://subscriptions.example/next", 200, null, "ok");
        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            LimitedHttpClient.RequestScope stale = client.beginRequestScope();
            client.cancelActive();
            try {
                client.get("https://subscriptions.example/next",
                        Collections.singletonMap("X-HWID", "old-hwid"), stale);
                fail("cancelled request scope opened the next URL");
            } catch (IOException expected) {
                assertTrue(expected.getMessage().contains("scope was cancelled"));
            }
            assertEquals(0, factory.opened.size());

            LimitedHttpClient.RequestScope current = client.beginRequestScope();
            assertEquals(200, client.get("https://subscriptions.example/next",
                    Collections.singletonMap("X-HWID", "new-hwid"), current).status);
        }
        assertEquals(1, factory.opened.size());
        assertEquals("new-hwid", factory.opened.get(0).getRequestProperty("X-HWID"));
    }

    @Test
    public void streamingCancellationDeletesPartialFileEvenWhenInputIgnoresDisconnect()
            throws Exception {
        AtomicReference<LimitedHttpClient> current = new AtomicReference<>();
        byte[] body = "first-second-third".getBytes(StandardCharsets.UTF_8);
        ScriptedFactory factory = new ScriptedFactory().addStream(
                "https://assets.example/core.so", 200, null,
                new CancelAfterFirstChunkInputStream(body,
                        () -> current.get().cancelActive()));
        File root = Files.createTempDirectory("exitfy-http-cancel").toFile();
        File target = new File(root, "core.so.download");
        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            current.set(client);
            try {
                client.getBinaryToFile("https://assets.example/core.so",
                        Collections.emptyMap(), target, 1024);
                fail("cancelled stream completed");
            } catch (IOException expected) {
                assertTrue(expected.getMessage().contains("cancelled"));
            }
            assertFalse("partial target survived cancellation", target.exists());
        } finally {
            TestFiles.deleteRecursively(root);
        }
        assertEquals(1, factory.opened.size());
        assertTrue(awaitDisconnected(factory.opened.get(0)));
    }

    @Test
    public void queuedRequestIsCancelledBeforeItCanOpenConnection() throws Exception {
        CountDownLatch firstRead = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        ScriptedFactory factory = new ScriptedFactory()
                .addStream("https://subscriptions.example/first", 200, null,
                        new BlockingIgnoringInputStream(firstRead, releaseFirst))
                .add("https://subscriptions.example/queued", 200, null, "late");
        AtomicReference<Throwable> firstError = new AtomicReference<>();
        AtomicReference<Throwable> queuedError = new AtomicReference<>();
        try (LimitedHttpClient client = new LimitedHttpClient(factory)) {
            Thread first = new Thread(() -> {
                try {
                    client.get("https://subscriptions.example/first", Collections.emptyMap());
                } catch (Throwable error) {
                    firstError.set(error);
                }
            }, "exitfy-http-first");
            first.start();
            assertTrue(firstRead.await(2, TimeUnit.SECONDS));

            Thread queued = new Thread(() -> {
                try {
                    client.get("https://subscriptions.example/queued", Collections.emptyMap());
                } catch (Throwable error) {
                    queuedError.set(error);
                }
            }, "exitfy-http-queued");
            queued.start();
            assertTrue("second request did not queue", awaitWaiting(queued));

            client.cancelActive();
            releaseFirst.countDown();
            first.join(2000L);
            queued.join(2000L);
            assertFalse(first.isAlive());
            assertFalse(queued.isAlive());
            assertTrue(firstError.get() instanceof IOException);
            assertTrue(queuedError.get() instanceof IOException);
            assertTrue(firstError.get().getMessage().contains("cancelled"));
            assertTrue(queuedError.get().getMessage().contains("cancelled"));
        } finally {
            releaseFirst.countDown();
        }
        assertEquals("queued request opened after cancellation", 1, factory.opened.size());
    }

    @Test
    public void closeDuringConnectionConstructionRejectsAndCleansLateTransport() throws Exception {
        CountDownLatch openEntered = new CountDownLatch(1);
        CountDownLatch releaseOpen = new CountDownLatch(1);
        AtomicReference<Throwable> requestError = new AtomicReference<>();
        ScriptedFactory factory = new ScriptedFactory()
                .add("https://subscriptions.example/late-open", 200, null, "late")
                .onOpen("https://subscriptions.example/late-open", () -> {
                    openEntered.countDown();
                    try {
                        if (!releaseOpen.await(2, TimeUnit.SECONDS)) {
                            throw new AssertionError("late-open barrier timed out");
                        }
                    } catch (InterruptedException error) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError(error);
                    }
                });
        LimitedHttpClient client = new LimitedHttpClient(factory);
        Thread request = new Thread(() -> {
            try {
                client.get("https://subscriptions.example/late-open", Collections.emptyMap());
            } catch (Throwable error) {
                requestError.set(error);
            }
        }, "exitfy-http-late-open");
        try {
            request.start();
            assertTrue(openEntered.await(2, TimeUnit.SECONDS));
            client.close();
            releaseOpen.countDown();
            request.join(2_000L);

            assertFalse("late connection request did not finish", request.isAlive());
            assertTrue(requestError.get() instanceof IOException);
            assertTrue(requestError.get().getMessage().contains("closed"));
            assertEquals(1, factory.opened.size());
            assertTrue(awaitDisconnected(factory.opened.get(0)));
        } finally {
            releaseOpen.countDown();
            client.close();
            request.join(2_000L);
        }
    }

    @Test
    public void cancelPublishesRevocationBeforePotentiallyBlockingDisconnect() throws Exception {
        assertRevocationVisibleBeforeDisconnectReturns(false);
    }

    @Test
    public void closePublishesClosedStateBeforePotentiallyBlockingDisconnect() throws Exception {
        assertRevocationVisibleBeforeDisconnectReturns(true);
    }

    @Test
    public void disableCancellationNeverWaitsForPermanentlyBlockingDisconnect() throws Exception {
        assertRevocationCallIsBounded(false);
    }

    @Test
    public void unloadCloseNeverWaitsForPermanentlyBlockingDisconnect() throws Exception {
        assertRevocationCallIsBounded(true);
    }

    private static void assertRevocationCallIsBounded(boolean closeClient) throws Exception {
        CountDownLatch readEntered = new CountDownLatch(1);
        CountDownLatch releaseRead = new CountDownLatch(1);
        CountDownLatch disconnectEntered = new CountDownLatch(1);
        CountDownLatch releaseDisconnect = new CountDownLatch(1);
        AtomicInteger disconnectCalls = new AtomicInteger();
        AtomicReference<Thread> disconnectThread = new AtomicReference<>();
        AtomicReference<Throwable> activeError = new AtomicReference<>();
        ScriptedFactory factory = new ScriptedFactory()
                .addStream("https://subscriptions.example/permanent", 200, null,
                        new BlockingIgnoringInputStream(readEntered, releaseRead))
                .onDisconnect("https://subscriptions.example/permanent", () -> {
                    disconnectCalls.incrementAndGet();
                    disconnectThread.set(Thread.currentThread());
                    disconnectEntered.countDown();
                    boolean interrupted = false;
                    try {
                        while (true) {
                            try {
                                releaseDisconnect.await();
                                return;
                            } catch (InterruptedException error) {
                                // Model a vendor disconnect which ignores both
                                // its transport timeout and thread interruption.
                                interrupted = true;
                            }
                        }
                    } finally {
                        if (interrupted) Thread.currentThread().interrupt();
                    }
                });
        LimitedHttpClient client = new LimitedHttpClient(factory);
        Thread active = new Thread(() -> {
            try {
                client.get("https://subscriptions.example/permanent",
                        Collections.emptyMap());
            } catch (Throwable error) {
                activeError.set(error);
            }
        }, "exitfy-http-permanent-active");
        try {
            active.start();
            assertTrue(readEntered.await(2, TimeUnit.SECONDS));

            long started = System.nanoTime();
            if (closeClient) client.close();
            else client.cancelActive();
            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

            assertTrue("revocation blocked the unload/disable caller for " + elapsedMillis + " ms",
                    elapsedMillis < 500L);
            assertTrue("disconnect cleanup was not scheduled",
                    disconnectEntered.await(2, TimeUnit.SECONDS));
            assertTrue("disconnect ran on the caller thread",
                    disconnectThread.get() != Thread.currentThread());
            assertTrue("disconnect cleanup must never keep the process alive",
                    disconnectThread.get().isDaemon());

            releaseRead.countDown();
            active.join(2_000L);
            assertFalse("revoked HTTP worker did not finish", active.isAlive());
            assertTrue(activeError.get() instanceof IOException);
            assertEquals("connection ownership invoked disconnect more than once",
                    1, disconnectCalls.get());
        } finally {
            releaseRead.countDown();
            releaseDisconnect.countDown();
            client.close();
            active.join(2_000L);
        }
    }

    private static void assertRevocationVisibleBeforeDisconnectReturns(boolean closeClient)
            throws Exception {
        CountDownLatch firstRead = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch disconnectEntered = new CountDownLatch(1);
        CountDownLatch disconnectFinished = new CountDownLatch(1);
        CountDownLatch staleRejected = new CountDownLatch(1);
        AtomicBoolean revocationVisible = new AtomicBoolean();
        AtomicReference<Throwable> activeError = new AtomicReference<>();
        AtomicReference<Throwable> staleError = new AtomicReference<>();
        ScriptedFactory factory = new ScriptedFactory()
                .addStream("https://subscriptions.example/active", 200, null,
                        new BlockingIgnoringInputStream(firstRead, releaseFirst))
                .add("https://subscriptions.example/stale", 200, null, "must-not-open")
                .onDisconnect("https://subscriptions.example/active", () -> {
                    disconnectEntered.countDown();
                    try {
                        // close()/cancelActive() must publish closed/generation
                        // state before entering a potentially slow transport
                        // disconnect. Holding registrationLock here used to
                        // prevent the stale request from observing revocation.
                        revocationVisible.set(staleRejected.await(1, TimeUnit.SECONDS));
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    } finally {
                        disconnectFinished.countDown();
                    }
                });

        LimitedHttpClient client = new LimitedHttpClient(factory);
        try {
            LimitedHttpClient.RequestScope staleScope = client.beginRequestScope();
            Thread active = new Thread(() -> {
                try {
                    client.get("https://subscriptions.example/active",
                            Collections.emptyMap());
                } catch (Throwable error) {
                    activeError.set(error);
                }
            }, "exitfy-http-active");
            active.start();
            assertTrue(firstRead.await(2, TimeUnit.SECONDS));

            Thread revoker = new Thread(() -> {
                if (closeClient) client.close();
                else client.cancelActive();
            }, closeClient ? "exitfy-http-close" : "exitfy-http-cancel");
            revoker.start();
            assertTrue(disconnectEntered.await(2, TimeUnit.SECONDS));

            Thread stale = new Thread(() -> {
                try {
                    client.get("https://subscriptions.example/stale",
                            Collections.emptyMap(), staleScope);
                } catch (Throwable error) {
                    staleError.set(error);
                } finally {
                    staleRejected.countDown();
                }
            }, "exitfy-http-stale");
            stale.start();

            stale.join(2_000L);
            revoker.join(2_000L);
            assertFalse("stale request remained blocked by disconnect", stale.isAlive());
            assertFalse("HTTP revocation remained blocked", revoker.isAlive());
            assertTrue("disconnect cleanup did not finish",
                    disconnectFinished.await(2, TimeUnit.SECONDS));
            assertTrue("disconnect ran before revocation became observable",
                    revocationVisible.get());
            assertTrue(staleError.get() instanceof IOException);
            assertEquals("stale request opened a connection", 1, factory.opened.size());

            releaseFirst.countDown();
            active.join(2_000L);
            assertFalse(active.isAlive());
            assertTrue(activeError.get() instanceof IOException);
        } finally {
            releaseFirst.countDown();
            client.close();
        }
    }

    private static boolean awaitWaiting(Thread thread) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            Thread.State state = thread.getState();
            if (state == Thread.State.WAITING || state == Thread.State.TIMED_WAITING) return true;
            if (!thread.isAlive()) return false;
            Thread.yield();
        }
        return false;
    }

    private static boolean awaitDisconnected(FakeConnection connection)
            throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            if (connection.disconnected) return true;
            Thread.yield();
        }
        return connection.disconnected;
    }

    private static final class ScriptedFactory implements LimitedHttpClient.ConnectionFactory {
        private final Map<String, Script> scripts = new HashMap<>();
        final List<FakeConnection> opened = new ArrayList<>();

        ScriptedFactory add(String url, int status, String location, String body) {
            return add(url, status, location, body.getBytes(StandardCharsets.UTF_8));
        }

        ScriptedFactory add(String url, int status, String location, byte[] body) {
            scripts.put(url, new Script(status, location, body));
            return this;
        }

        ScriptedFactory addStream(String url, int status, String location, InputStream stream) {
            scripts.put(url, new Script(status, location, new byte[0], stream));
            return this;
        }

        ScriptedFactory contentLength(String url, long contentLength) {
            Script script = scripts.get(url);
            if (script == null) throw new IllegalArgumentException("missing scripted URL");
            script.contentLength = contentLength;
            return this;
        }

        ScriptedFactory onLocationRead(String url, Runnable callback) {
            Script script = scripts.get(url);
            if (script == null) throw new IllegalArgumentException("missing scripted URL");
            script.onLocationRead = callback;
            return this;
        }

        ScriptedFactory onOpen(String url, Runnable callback) {
            Script script = scripts.get(url);
            if (script == null) throw new IllegalArgumentException("missing scripted URL");
            script.onOpen = callback;
            return this;
        }

        ScriptedFactory onDisconnect(String url, Runnable callback) {
            Script script = scripts.get(url);
            if (script == null) throw new IllegalArgumentException("missing scripted URL");
            script.onDisconnect = callback;
            return this;
        }

        @Override
        public HttpURLConnection open(URL target) throws IOException {
            Script script = scripts.get(target.toString());
            if (script == null) throw new IOException("unexpected URL: " + target);
            Runnable callback = script.onOpen;
            script.onOpen = null;
            if (callback != null) callback.run();
            FakeConnection connection = new FakeConnection(target, script);
            opened.add(connection);
            return connection;
        }
    }

    private static final class Script {
        final int status;
        final String location;
        final byte[] body;
        final InputStream stream;
        long contentLength;
        Runnable onLocationRead;
        Runnable onDisconnect;
        Runnable onOpen;

        Script(int status, String location, byte[] body) {
            this(status, location, body, null);
        }

        Script(int status, String location, byte[] body, InputStream stream) {
            this.status = status;
            this.location = location;
            this.body = body;
            this.stream = stream;
            this.contentLength = body.length;
        }
    }

    private static final class FakeConnection extends HttpURLConnection {
        private final Script script;
        volatile boolean disconnected;

        FakeConnection(URL url, Script script) {
            super(url);
            this.script = script;
        }

        @Override
        public int getResponseCode() {
            return script.status;
        }

        @Override
        public long getContentLengthLong() {
            return script.contentLength;
        }

        @Override
        public String getHeaderField(String name) {
            if (name != null && name.equalsIgnoreCase("Location")) {
                Runnable callback = script.onLocationRead;
                script.onLocationRead = null;
                if (callback != null) callback.run();
                return script.location;
            }
            return null;
        }

        @Override
        public Map<String, List<String>> getHeaderFields() {
            if (script.location == null) return Collections.emptyMap();
            return Collections.singletonMap("Location", Collections.singletonList(script.location));
        }

        @Override
        public InputStream getInputStream() {
            return script.stream == null
                    ? new ByteArrayInputStream(script.body) : script.stream;
        }

        @Override
        public InputStream getErrorStream() {
            return new ByteArrayInputStream(script.body);
        }

        @Override
        public void disconnect() {
            disconnected = true;
            Runnable callback = script.onDisconnect;
            script.onDisconnect = null;
            if (callback != null) callback.run();
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void connect() {
        }
    }

    private static final class CancelAfterFirstChunkInputStream extends InputStream {
        private final byte[] value;
        private final Runnable cancel;
        private int position;
        private int reads;

        CancelAfterFirstChunkInputStream(byte[] value, Runnable cancel) {
            this.value = value;
            this.cancel = cancel;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (position >= value.length) return -1;
            int count = Math.min(Math.min(5, length), value.length - position);
            System.arraycopy(value, position, buffer, offset, count);
            position += count;
            if (++reads == 2) cancel.run();
            return count;
        }

        @Override
        public int read() {
            byte[] one = new byte[1];
            int count = read(one, 0, 1);
            return count < 0 ? -1 : one[0] & 255;
        }
    }

    private static final class BlockingIgnoringInputStream extends InputStream {
        private final CountDownLatch entered;
        private final CountDownLatch release;
        private boolean sent;

        BlockingIgnoringInputStream(CountDownLatch entered, CountDownLatch release) {
            this.entered = entered;
            this.release = release;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (sent) return -1;
            entered.countDown();
            try {
                if (!release.await(3, TimeUnit.SECONDS)) throw new IOException("test timeout");
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException(error);
            }
            sent = true;
            buffer[offset] = 'x';
            return 1;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int count = read(one, 0, 1);
            return count < 0 ? -1 : one[0] & 255;
        }
    }
}
