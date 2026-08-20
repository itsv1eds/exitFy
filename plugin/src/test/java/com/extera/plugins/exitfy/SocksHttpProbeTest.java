package com.extera.plugins.exitfy;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SocksHttpProbeTest {
    @Test
    public void cancellingReplacedSessionNeverCancelsLatestSession() {
        SocksHttpProbe probe = new SocksHttpProbe();
        SocksHttpProbe.Session replaced = probe.beginSession();
        SocksHttpProbe.Session latest = probe.beginSession();
        try {
            probe.closeSession(replaced);
            assertFalse(probe.isSessionCurrent(replaced));
            assertTrue(probe.isSessionCurrent(latest));
        } finally {
            probe.closeSession(latest);
            probe.close();
        }
    }

    @Test
    public void usesRemoteDnsAndHandlesPartialSocksReads() throws Exception {
        PartialSocksServer server = new PartialSocksServer();
        SocksHttpProbe probe = new SocksHttpProbe();
        SocksHttpProbe.Session session = probe.beginSession();
        try {
            SocksHttpProbe.Result result = probe.probe(
                    server.port(), "", "", 3000L, session);
            server.await();
            assertEquals(SocksHttpProbe.TARGET_HOST, server.requestedHost.get());
            assertTrue(!result.ok);
            assertTrue("tls_failed".equals(result.status)
                    || "proxy_get_failed".equals(result.status));
        } finally {
            probe.closeSession(session);
            probe.close();
            server.close();
        }
    }

    @Test
    public void socksReadsShareOneAbsoluteDeadline() throws Exception {
        PhasedSlowSocksServer server = new PhasedSlowSocksServer();
        SocksHttpProbe probe = new SocksHttpProbe();
        SocksHttpProbe.Session session = probe.beginSession();
        long started = System.nanoTime();
        try {
            SocksHttpProbe.Result result = probe.probe(
                    server.port(), "", "", 1000L, session);
            long elapsed = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
                    System.nanoTime() - started);
            assertFalse(result.ok);
            assertEquals("timeout", result.status);
            assertTrue("probe exceeded its absolute deadline: " + elapsed + " ms",
                    elapsed < 1400L);
        } finally {
            probe.closeSession(session);
            probe.close();
            server.close();
        }
    }

    private static final class PartialSocksServer implements Closeable {
        final AtomicReference<String> requestedHost = new AtomicReference<>("");
        private final AtomicReference<Throwable> failure = new AtomicReference<>();
        private final ServerSocket listener;
        private final Thread worker;

        PartialSocksServer() throws Exception {
            listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            worker = new Thread(this::serve, "exitfy-test-socks");
            worker.setDaemon(true);
            worker.start();
        }

        int port() {
            return listener.getLocalPort();
        }

        void await() throws Exception {
            worker.join(3000L);
            if (worker.isAlive()) throw new AssertionError("SOCKS test server did not finish");
            if (failure.get() != null) throw new AssertionError(failure.get());
        }

        private void serve() {
            try (Socket socket = listener.accept()) {
                socket.setSoTimeout(2000);
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();
                readExact(input, 3);
                writePartial(output, new byte[]{5, 0});

                byte[] header = readExact(input, 5);
                if (header[0] != 5 || header[1] != 1 || header[3] != 3) {
                    throw new AssertionError("SOCKS domain request expected");
                }
                int length = header[4] & 255;
                requestedHost.set(new String(readExact(input, length), StandardCharsets.US_ASCII));
                readExact(input, 2);
                writePartial(output, new byte[]{5, 0, 0, 1, 127, 0, 0, 1, 0, 0});

                // Let the client write its TLS ClientHello, then close. The test
                // intentionally validates SOCKS framing without any Internet access.
                ByteArrayOutputStream hello = new ByteArrayOutputStream();
                byte[] buffer = new byte[256];
                int read = input.read(buffer);
                if (read > 0) hello.write(buffer, 0, read);
            } catch (Throwable error) {
                failure.set(error);
            }
        }

        private static byte[] readExact(InputStream input, int size) throws Exception {
            byte[] result = new byte[size];
            int offset = 0;
            while (offset < size) {
                int read = input.read(result, offset, size - offset);
                if (read < 0) throw new AssertionError("truncated client request");
                offset += read;
            }
            return result;
        }

        private static void writePartial(OutputStream output, byte[] value) throws Exception {
            for (byte item : value) {
                output.write(item);
                output.flush();
            }
        }

        @Override
        public void close() {
            try { listener.close(); } catch (Exception ignored) { }
            try { worker.join(500L); } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static final class PhasedSlowSocksServer implements Closeable {
        private final ServerSocket listener;
        private final Thread worker;

        PhasedSlowSocksServer() throws Exception {
            listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            worker = new Thread(this::serve, "exitfy-test-slow-socks");
            worker.setDaemon(true);
            worker.start();
        }

        int port() {
            return listener.getLocalPort();
        }

        private void serve() {
            try (Socket socket = listener.accept()) {
                socket.setSoTimeout(2000);
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();
                readExact(input, 3);
                Thread.sleep(650L);
                output.write(new byte[]{5, 0});
                output.flush();

                byte[] header = readExact(input, 5);
                int length = header[4] & 255;
                readExact(input, length + 2);
                // The second protocol read must use only the remaining ~350 ms,
                // not a fresh one-second SO_TIMEOUT.
                Thread.sleep(900L);
            } catch (Throwable ignored) {
            }
        }

        private static byte[] readExact(InputStream input, int size) throws Exception {
            byte[] result = new byte[size];
            int offset = 0;
            while (offset < size) {
                int read = input.read(result, offset, size - offset);
                if (read < 0) throw new AssertionError("truncated client request");
                offset += read;
            }
            return result;
        }

        @Override
        public void close() {
            try { listener.close(); } catch (Exception ignored) { }
            try { worker.join(2000L); } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
