package com.extera.plugins.exitfy;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

final class SocksHttpProbe implements Closeable {
    static final String TARGET_HOST = "www.gstatic.com";
    static final int TARGET_PORT = 443;
    static final String TARGET_PATH = "/generate_204";
    static final int MAX_RESPONSE_BYTES = 16 * 1024;

    private final Object socketLock = new Object();
    private final Set<Session> sessions = new HashSet<>();
    private boolean closed;

    Session beginSession() {
        synchronized (socketLock) {
            Session session = new Session(null, closed);
            if (!session.closed) sessions.add(session);
            return session;
        }
    }

    Session beginChildSession(Session parent) {
        synchronized (socketLock) {
            boolean unavailable = closed || parent == null || parent.closed
                    || !sessions.contains(parent);
            Session session = new Session(parent, unavailable);
            if (!session.closed) sessions.add(session);
            return session;
        }
    }

    Result probe(int socksPort, String username, String password,
                 long timeoutMillis, Session expectedSession) {
        long started = System.nanoTime();
        long deadline = started + TimeUnit.MILLISECONDS.toNanos(Math.max(1L, timeoutMillis));
        Socket raw = new Socket();
        if (!register(raw, expectedSession)) {
            closeQuietly(raw);
            return Result.failed("cancelled");
        }
        try {
            checkCancelled(deadline);
            raw.connect(new InetSocketAddress("127.0.0.1", socksPort), remaining(deadline));
            InputStream input = raw.getInputStream();
            OutputStream output = raw.getOutputStream();
            negotiate(raw, input, output, username, password, deadline);
            connectRemoteDns(raw, input, output, TARGET_HOST, TARGET_PORT, deadline);

            SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(raw, TARGET_HOST, TARGET_PORT, true);
            if (!replace(raw, tls, expectedSession)) {
                closeQuietly(tls);
                throw new IllegalStateException("probe session cancelled");
            }
            raw = tls;
            SSLParameters parameters = tls.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            tls.setSSLParameters(parameters);
            tls.setSoTimeout(remaining(deadline));
            tls.startHandshake();

            output = tls.getOutputStream();
            output.write(("GET " + TARGET_PATH + " HTTP/1.1\r\n"
                    + "Host: " + TARGET_HOST + "\r\n"
                    + "User-Agent: exitFy/4.0\r\n"
                    + "Accept: */*\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            output.flush();
            String headers = readHeaders(tls, tls.getInputStream(), deadline);
            String first = headers.split("\r?\n", 2)[0];
            String[] status = first.split(" ", 3);
            if (status.length < 2 || !"204".equals(status[1])) {
                return Result.failed("http_status");
            }
            return Result.ok(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return Result.failed("cancelled");
        } catch (Exception error) {
            if (!isSessionCurrent(expectedSession)) return Result.failed("cancelled");
            return Result.failed(classify(error));
        } finally {
            synchronized (socketLock) {
                if (expectedSession != null) expectedSession.sockets.remove(raw);
            }
            closeQuietly(raw);
        }
    }

    void cancelActive() {
        Set<Socket> cancelled = new HashSet<>();
        synchronized (socketLock) {
            for (Session session : sessions) {
                session.closed = true;
                cancelled.addAll(session.sockets);
                session.sockets.clear();
            }
            sessions.clear();
        }
        for (Socket socket : cancelled) closeQuietly(socket);
    }

    void closeSession(Session session) {
        if (session == null) return;
        Set<Socket> cancelled = new HashSet<>();
        synchronized (socketLock) {
            Set<Session> closing = new HashSet<>();
            closing.add(session);
            for (Session candidate : sessions) {
                if (candidate.parent == session) closing.add(candidate);
            }
            for (Session value : closing) {
                value.closed = true;
                sessions.remove(value);
                cancelled.addAll(value.sockets);
                value.sockets.clear();
            }
        }
        for (Socket socket : cancelled) closeQuietly(socket);
    }

    @Override
    public void close() {
        Set<Socket> cancelled = new HashSet<>();
        synchronized (socketLock) {
            closed = true;
            for (Session session : sessions) {
                session.closed = true;
                cancelled.addAll(session.sockets);
                session.sockets.clear();
            }
            sessions.clear();
        }
        for (Socket socket : cancelled) closeQuietly(socket);
    }

    private boolean register(Socket socket, Session expectedSession) {
        synchronized (socketLock) {
            if (!isCurrentLocked(expectedSession)) return false;
            expectedSession.sockets.add(socket);
            return true;
        }
    }

    private boolean replace(Socket previous, Socket next, Session expectedSession) {
        synchronized (socketLock) {
            if (!isCurrentLocked(expectedSession)) {
                if (expectedSession != null) expectedSession.sockets.remove(previous);
                return false;
            }
            expectedSession.sockets.remove(previous);
            expectedSession.sockets.add(next);
            return true;
        }
    }

    boolean isSessionCurrent(Session expectedSession) {
        synchronized (socketLock) {
            return isCurrentLocked(expectedSession);
        }
    }

    private boolean isCurrentLocked(Session session) {
        return !closed && session != null && !session.closed && sessions.contains(session)
                && (session.parent == null || (!session.parent.closed
                && sessions.contains(session.parent)));
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) return;
        try {
            socket.close();
        } catch (Exception ignored) {
        }
    }

    static final class Session {
        private final Session parent;
        private final Set<Socket> sockets = new HashSet<>();
        private boolean closed;

        private Session(Session parent, boolean closed) {
            this.parent = parent;
            this.closed = closed;
        }
    }

    private static void negotiate(Socket socket, InputStream input, OutputStream output,
                                  String username, String password, long deadline) throws Exception {
        boolean authenticated = username != null && !username.isEmpty()
                && password != null && !password.isEmpty();
        output.write(new byte[]{5, 1, (byte) (authenticated ? 2 : 0)});
        output.flush();
        byte[] response = readExact(socket, input, 2, deadline);
        if (response[0] != 5 || response[1] == (byte) 0xff) {
            throw new IllegalStateException("SOCKS method rejected");
        }
        if (response[1] == 2) authenticate(socket, input, output,
                username, password, deadline);
        else if (response[1] != 0) throw new IllegalStateException("SOCKS method unsupported");
    }

    private static void authenticate(Socket socket, InputStream input, OutputStream output,
                                     String username, String password, long deadline) throws Exception {
        byte[] user = username == null ? new byte[0] : username.getBytes(StandardCharsets.UTF_8);
        byte[] pass = password == null ? new byte[0] : password.getBytes(StandardCharsets.UTF_8);
        if (user.length == 0 || pass.length == 0 || user.length > 255 || pass.length > 255) {
            throw new IllegalArgumentException("invalid SOCKS credentials");
        }
        ByteArrayOutputStream request = new ByteArrayOutputStream(user.length + pass.length + 3);
        request.write(1);
        request.write(user.length);
        request.write(user);
        request.write(pass.length);
        request.write(pass);
        output.write(request.toByteArray());
        output.flush();
        byte[] response = readExact(socket, input, 2, deadline);
        if (response[0] != 1 || response[1] != 0) {
            throw new IllegalStateException("SOCKS authentication failed");
        }
    }

    private static void connectRemoteDns(Socket socket, InputStream input, OutputStream output,
                                         String host, int port, long deadline) throws Exception {
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        if (name.length == 0 || name.length > 255) throw new IllegalArgumentException("invalid probe host");
        ByteArrayOutputStream request = new ByteArrayOutputStream(name.length + 7);
        request.write(5);
        request.write(1);
        request.write(0);
        request.write(3); // Domain name: DNS resolution happens through the proxy core.
        request.write(name.length);
        request.write(name);
        request.write((port >>> 8) & 255);
        request.write(port & 255);
        output.write(request.toByteArray());
        output.flush();

        byte[] header = readExact(socket, input, 4, deadline);
        if (header[0] != 5 || header[1] != 0) throw new IllegalStateException("SOCKS connect failed");
        int addressBytes;
        if (header[3] == 1) addressBytes = 4;
        else if (header[3] == 4) addressBytes = 16;
        else if (header[3] == 3) {
            addressBytes = readExact(socket, input, 1, deadline)[0] & 255;
        }
        else throw new IllegalStateException("invalid SOCKS response");
        readExact(socket, input, addressBytes + 2, deadline);
    }

    private static String readHeaders(Socket socket, InputStream input, long deadline)
            throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream(512);
        byte[] buffer = new byte[512];
        int matched = 0;
        while (output.size() < MAX_RESPONSE_BYTES) {
            checkCancelled(deadline);
            socket.setSoTimeout(remaining(deadline));
            int read = input.read(buffer, 0,
                    Math.min(buffer.length, MAX_RESPONSE_BYTES - output.size()));
            if (read < 0) throw new IllegalStateException("truncated HTTP response");
            if (read == 0) continue;
            for (int index = 0; index < read; index++) {
                int value = buffer[index] & 255;
                output.write(value);
                if ((matched == 0 || matched == 2) && value == '\r') matched++;
                else if ((matched == 1 || matched == 3) && value == '\n') matched++;
                else matched = value == '\r' ? 1 : 0;
                if (matched == 4) return output.toString("ISO-8859-1");
            }
        }
        throw new IllegalStateException("HTTP response headers exceed 16 KiB");
    }

    private static byte[] readExact(Socket socket, InputStream input, int size, long deadline)
            throws Exception {
        byte[] value = new byte[size];
        int offset = 0;
        while (offset < size) {
            checkCancelled(deadline);
            socket.setSoTimeout(remaining(deadline));
            int read = input.read(value, offset, size - offset);
            if (read < 0) throw new IllegalStateException("truncated SOCKS response");
            if (read > 0) offset += read;
        }
        return value;
    }

    private static void checkCancelled(long deadline) throws Exception {
        if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
        if (System.nanoTime() >= deadline) throw new java.net.SocketTimeoutException("probe deadline");
    }

    private static int remaining(long deadline) throws Exception {
        checkCancelled(deadline);
        long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
        return (int) Math.max(1L, Math.min(Integer.MAX_VALUE, millis));
    }

    private static String classify(Exception error) {
        String name = error.getClass().getSimpleName().toLowerCase(Locale.US);
        if (name.contains("timeout")) return "timeout";
        if (name.contains("ssl") || name.contains("certificate")) return "tls_failed";
        String message = error.getMessage() == null ? "" : error.getMessage().toLowerCase(Locale.US);
        if (message.contains("socks")) return "socks_failed";
        return "proxy_get_failed";
    }

    static final class Result {
        final boolean ok;
        final long millis;
        final String status;

        private Result(boolean ok, long millis, String status) {
            this.ok = ok;
            this.millis = millis;
            this.status = status;
        }

        static Result ok(long millis) {
            return new Result(true, Math.max(0L, millis), "ok");
        }

        static Result failed(String status) {
            return new Result(false, -1L, status == null ? "proxy_get_failed" : status);
        }
    }
}
