package com.extera.plugins.exitfy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;


// TLS is verified normally. This client fetches subscriptions, which carry the
// user's own server credentials and decide which servers they connect through;
// accepting any certificate handed anyone on the path both of those. Core
// downloads are additionally pinned to a signed manifest, so verification here
// is the second lock, not the only one.
final class LimitedHttpClient implements Closeable {
    static final int MAX_WIRE_BYTES = 8 * 1024 * 1024;
    static final int MAX_EXPANDED_BYTES = 8 * 1024 * 1024;
    static final int MAX_REDIRECTS = 5;
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 20_000;
    private static final int MAX_REDIRECT_LOCATION_CHARS = 16 * 1024;
    private static final int MAX_DISCONNECT_WORKERS = 2;
    private static final int MAX_PENDING_DISCONNECT_BATCHES = 32;
    private static final AtomicInteger DISCONNECT_THREAD_SEQUENCE = new AtomicInteger();
    private static final ThreadPoolExecutor DISCONNECT_CLEANUP = disconnectCleanupExecutor();

    private final Semaphore singleFlight = new Semaphore(1, true);
    /*
     * Registration and close must be one operation. A synchronizedSet alone
     * leaves a window where close() observes an empty set and a request then
     * registers a live connection after the client has been closed.
     */
    private final Object registrationLock = new Object();
    private final Set<HttpURLConnection> active = new HashSet<>();
    private final ConnectionFactory connectionFactory;
    private volatile boolean closed;
    // Guarded by registrationLock. A request snapshots this value before it
    // waits for singleFlight, so cancelActive() also cancels requests which
    // were already queued and catches the gap between two redirect hops.
    private long cancellationGeneration;

    LimitedHttpClient() {
        this(target -> (HttpURLConnection) target.openConnection());
    }

    LimitedHttpClient(ConnectionFactory connectionFactory) {
        if (connectionFactory == null) throw new IllegalArgumentException("connection factory is missing");
        this.connectionFactory = connectionFactory;
    }

    Response get(String url, Map<String, String> headers) throws IOException {
        return request(url, headers, MAX_WIRE_BYTES, MAX_EXPANDED_BYTES, true, null);
    }

    Response get(String url, Map<String, String> headers, RequestScope scope) throws IOException {
        return request(url, headers, MAX_WIRE_BYTES, MAX_EXPANDED_BYTES, true, scope);
    }

    RequestScope beginRequestScope() throws IOException {
        return new RequestScope(this, beginRequest(null));
    }

    Response getBinary(String url, Map<String, String> headers, int maximumBytes) throws IOException {
        if (maximumBytes <= 0 || maximumBytes > 64 * 1024 * 1024) {
            throw new IllegalArgumentException("invalid binary response limit");
        }
        return request(url, headers, maximumBytes, maximumBytes, false, null);
    }

    StreamResponse getBinaryToFile(String url, Map<String, String> headers,
                                   File target, int maximumBytes) throws IOException {
        return getBinaryToFile(url, headers, target, maximumBytes, null);
    }

    StreamResponse getBinaryToFile(String url, Map<String, String> headers,
                                   File target, int maximumBytes,
                                   ProgressListener progressListener) throws IOException {
        if (target == null) throw new IllegalArgumentException("download target is missing");
        if (maximumBytes <= 0 || maximumBytes > 64 * 1024 * 1024) {
            throw new IllegalArgumentException("invalid binary response limit");
        }
        boolean acquired = false;
        HttpURLConnection connection = null;
        boolean complete = false;
        long requestGeneration = beginRequest();
        try {
            singleFlight.acquire();
            acquired = true;
            OpenResponse opened = openFollowingRedirects(
                    url, headers, false, requestGeneration);
            connection = opened.connection;
            int status = opened.status;
            long contentLength = connection.getContentLengthLong();
            if (contentLength > maximumBytes) {
                throw new IOException("HTTP response exceeds configured limit");
            }
            File parent = target.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs() && !parent.isDirectory()) {
                throw new IOException("cannot create download directory");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            checkRequestActive(requestGeneration);
            InputStream raw = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            long total = 0L;
            notifyProgress(progressListener, 0L, contentLength);
            try (InputStream source = raw;
                 FileOutputStream output = new FileOutputStream(target, false)) {
                byte[] buffer = new byte[32 * 1024];
                if (source != null) {
                    int read;
                    while (true) {
                        checkRequestActive(requestGeneration);
                        read = source.read(buffer);
                        checkRequestActive(requestGeneration);
                        if (read < 0) break;
                        if (read == 0) continue;
                        total += read;
                        if (total > maximumBytes) throw new IOException("binary response exceeds limit");
                        output.write(buffer, 0, read);
                        digest.update(buffer, 0, read);
                        notifyProgress(progressListener, total, contentLength);
                    }
                }
                output.flush();
                output.getFD().sync();
            }
            // Cancellation may race with the final read/fsync. Never mark a
            // staged core complete after its request generation was revoked.
            Map<String, String> responseHeaders = copyHeaders(connection.getHeaderFields());
            checkRequestActive(requestGeneration);
            complete = true;
            return new StreamResponse(status, total, hex(digest.digest()), responseHeaders);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("HTTP request interrupted", error);
        } catch (java.security.GeneralSecurityException error) {
            throw new IOException("SHA-256 is unavailable", error);
        } finally {
            if (!complete && target.exists()) {
                //noinspection ResultOfMethodCallIgnored
                target.delete();
            }
            if (connection != null) {
                releaseConnection(connection);
            }
            if (acquired) singleFlight.release();
        }
    }

    private static void notifyProgress(ProgressListener listener,
                                       long downloadedBytes, long totalBytes) {
        if (listener == null) return;
        try {
            listener.onProgress(Math.max(0L, downloadedBytes), totalBytes);
        } catch (Throwable ignored) {
            // Progress is observational and must never invalidate a verified download.
        }
    }

    private Response request(String url, Map<String, String> headers, int wireLimit,
                             int expandedLimit, boolean allowGzip,
                             RequestScope scope) throws IOException {
        boolean acquired = false;
        HttpURLConnection connection = null;
        long requestGeneration = beginRequest(scope);
        try {
            singleFlight.acquire();
            acquired = true;
            OpenResponse opened = openFollowingRedirects(
                    url, headers, allowGzip, requestGeneration);
            connection = opened.connection;
            int status = opened.status;
            long contentLength = connection.getContentLengthLong();
            if (contentLength > wireLimit) {
                throw new IOException("HTTP response exceeds configured limit");
            }
            checkRequestActive(requestGeneration);
            InputStream raw = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            byte[] wire = raw == null ? new byte[0]
                    : readLimited(raw, wireLimit, requestGeneration);
            String encoding = connection.getHeaderField("Content-Encoding");
            byte[] body = wire;
            if (allowGzip && ((encoding != null && encoding.toLowerCase(Locale.US).contains("gzip"))
                    || (wire.length >= 2 && wire[0] == 0x1f && wire[1] == (byte) 0x8b))) {
                checkRequestActive(requestGeneration);
                body = readLimited(new GZIPInputStream(new ByteArrayInputStream(wire)),
                        expandedLimit, requestGeneration);
            }
            Map<String, String> responseHeaders = copyHeaders(connection.getHeaderFields());
            checkRequestActive(requestGeneration);
            return new Response(status, body, responseHeaders);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("HTTP request interrupted", error);
        } finally {
            if (connection != null) {
                releaseConnection(connection);
            }
            if (acquired) singleFlight.release();
        }
    }

    private OpenResponse openFollowingRedirects(String value, Map<String, String> headers,
                                                boolean allowGzip,
                                                long requestGeneration) throws IOException {
        URL current = requireHttpUrl(value);
        Map<String, String> callerHeaders = snapshotHeaders(headers);
        boolean sendCallerHeaders = true;
        int followed = 0;
        while (true) {
            // Queued requests and a redirect continuation must observe a
            // published cancel/close before the factory can create even a
            // temporary transport. The second check under registrationLock
            // below closes the unavoidable construction-vs-cancel window.
            checkRequestActive(requestGeneration);
            HttpURLConnection connection = null;
            boolean registered = false;
            boolean handedOff = false;
            try {
                // Connection construction/configuration may invoke vendor
                // code. Keep it outside registrationLock, then atomically
                // re-check close/cancellation before publishing ownership.
                connection = openConnection(current,
                        sendCallerHeaders ? callerHeaders : null, allowGzip);
                synchronized (registrationLock) {
                    if (closed) throw new IOException("HTTP client is closed");
                    if (requestGeneration != cancellationGeneration) {
                        throw new IOException("HTTP request cancelled");
                    }
                    active.add(connection);
                    registered = true;
                }
                int status = connection.getResponseCode();
                if (!isRedirect(status)) {
                    handedOff = true;
                    return new OpenResponse(connection, status);
                }
                String location = connection.getHeaderField("Location");
                if (location == null || location.trim().isEmpty()) {
                    handedOff = true;
                    return new OpenResponse(connection, status);
                }
                RedirectStep next = redirectStep(current, location, followed);
                followed++;
                if (!next.sameOrigin) sendCallerHeaders = false;
                current = next.target;
            } finally {
                if (!handedOff && connection != null) {
                    if (registered) releaseConnection(connection);
                    else disconnectLater(Collections.singleton(connection));
                }
            }
        }
    }

    private long beginRequest() throws IOException {
        return beginRequest(null);
    }

    private long beginRequest(RequestScope scope) throws IOException {
        synchronized (registrationLock) {
            if (closed) throw new IOException("HTTP client is closed");
            if (scope != null && (scope.owner != this
                    || scope.cancellationGeneration != cancellationGeneration)) {
                throw new IOException("HTTP request scope was cancelled");
            }
            return cancellationGeneration;
        }
    }

    private void checkRequestActive(long requestGeneration) throws IOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new IOException("HTTP request interrupted");
        }
        synchronized (registrationLock) {
            if (closed) throw new IOException("HTTP client is closed");
            if (requestGeneration != cancellationGeneration) {
                throw new IOException("HTTP request cancelled");
            }
        }
    }

    private HttpURLConnection openConnection(URL target, Map<String, String> headers,
                                             boolean allowGzip) throws IOException {
        HttpURLConnection connection = connectionFactory.open(target);
        if (connection == null) throw new IOException("connection factory returned null");
        try {
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            // Manual redirects prevent caller-provided subscription headers from
            // being forwarded by HttpURLConnection to a different origin.
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept-Encoding", allowGzip ? "gzip" : "identity");
            connection.setRequestProperty("Connection", "close");
            connection.setRequestProperty("User-Agent", "exitFy/4.0 exteraGram Android");
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    String name = header.getKey();
                    if (name == null || header.getValue() == null) continue;
                    String lower = name.toLowerCase(Locale.US);
                    if (lower.equals("host") || lower.equals("connection")
                            || lower.equals("accept-encoding")) continue;
                    connection.setRequestProperty(name, header.getValue());
                }
            }
            return connection;
        } catch (IOException | RuntimeException | Error failure) {
            disconnectLater(Collections.singleton(connection));
            throw failure;
        }
    }

    private void releaseConnection(HttpURLConnection connection) {
        boolean owned;
        synchronized (registrationLock) {
            owned = active.remove(connection);
        }
        // cancelActive()/close() atomically transfer every snapshotted
        // connection to the shared cleanup executor. The request path may
        // disconnect only when it still owned the registration, so a race can
        // never call an implementation-defined disconnect twice.
        if (owned) disconnectLater(Collections.singleton(connection));
    }

    static RedirectStep redirectStep(URL current, String location, int followed)
            throws IOException {
        if (current == null) throw new IOException("redirect source is missing");
        if (followed < 0 || followed >= MAX_REDIRECTS) {
            throw new IOException("HTTP redirect limit exceeded");
        }
        String cleanLocation = location == null ? "" : location.trim();
        if (cleanLocation.isEmpty()) throw new IOException("HTTP redirect location is missing");
        if (cleanLocation.length() > MAX_REDIRECT_LOCATION_CHARS) {
            throw new IOException("HTTP redirect location is too long");
        }
        URL target = requireHttpUrl(new URL(current, cleanLocation));
        String fromScheme = current.getProtocol().toLowerCase(Locale.US);
        String toScheme = target.getProtocol().toLowerCase(Locale.US);
        if (fromScheme.equals("https") && toScheme.equals("http")) {
            throw new IOException("HTTPS redirect downgrade is forbidden");
        }
        return new RedirectStep(target, sameOrigin(current, target));
    }

    static boolean sameOrigin(URL first, URL second) {
        if (first == null || second == null) return false;
        return first.getProtocol().equalsIgnoreCase(second.getProtocol())
                && first.getHost().equalsIgnoreCase(second.getHost())
                && effectivePort(first) == effectivePort(second);
    }

    private static URL requireHttpUrl(String value) throws IOException {
        if (value == null) throw new IOException("HTTP URL is missing");
        return requireHttpUrl(new URL(value));
    }

    private static URL requireHttpUrl(URL target) throws IOException {
        String scheme = target.getProtocol() == null
                ? "" : target.getProtocol().toLowerCase(Locale.US);
        if ((!scheme.equals("http") && !scheme.equals("https")) || target.getHost().isEmpty()) {
            throw new IOException("unsupported HTTP URL");
        }
        return target;
    }

    private static int effectivePort(URL target) {
        if (target.getPort() >= 0) return target.getPort();
        return target.getProtocol().equalsIgnoreCase("https") ? 443 : 80;
    }

    private static boolean isRedirect(int status) {
        return status == HttpURLConnection.HTTP_MOVED_PERM
                || status == HttpURLConnection.HTTP_MOVED_TEMP
                || status == HttpURLConnection.HTTP_SEE_OTHER
                || status == 307 || status == 308;
    }

    private static Map<String, String> snapshotHeaders(Map<String, String> headers) {
        Map<String, String> result = new HashMap<>();
        if (headers == null) return result;
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if (header.getKey() != null && header.getValue() != null) {
                result.put(header.getKey(), header.getValue());
            }
        }
        return result;
    }

    @Override
    public void close() {
        Set<HttpURLConnection> connections;
        synchronized (registrationLock) {
            closed = true;
            cancellationGeneration++;
            connections = new HashSet<>(active);
            active.clear();
        }
        disconnectLater(connections);
    }

    void cancelActive() {
        Set<HttpURLConnection> connections;
        synchronized (registrationLock) {
            cancellationGeneration++;
            connections = new HashSet<>(active);
            active.clear();
        }
        disconnectLater(connections);
    }

    private static void disconnectLater(Set<HttpURLConnection> connections) {
        if (connections == null || connections.isEmpty()) return;
        // Revocation is already visible before this point. Never run transport
        // cleanup on a settings/unload caller: HttpURLConnection.disconnect()
        // has no deadline contract and vendor implementations may block.
        try {
            DISCONNECT_CLEANUP.execute(() -> disconnectAllNow(connections));
        } catch (RejectedExecutionException ignored) {
            // The shared pool and queue are deliberately bounded. Dropping an
            // already-revoked transport is safer than blocking the caller or
            // creating unbounded cleanup threads; the request can no longer
            // publish a result and the process/GC owns final reclamation.
        }
    }

    private static void disconnectAllNow(Set<HttpURLConnection> connections) {
        for (HttpURLConnection connection : connections) {
            disconnectNow(connection);
        }
    }

    private static void disconnectNow(HttpURLConnection connection) {
        if (connection == null) return;
        try {
            connection.disconnect();
        } catch (Throwable ignored) {
        }
    }

    private static ThreadPoolExecutor disconnectCleanupExecutor() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                MAX_DISCONNECT_WORKERS, MAX_DISCONNECT_WORKERS,
                30L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(MAX_PENDING_DISCONNECT_BATCHES),
                runnable -> {
                    Thread thread = new Thread(runnable, "exitfy-http-disconnect-"
                            + DISCONNECT_THREAD_SEQUENCE.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
        executor.allowCoreThreadTimeOut(true);
        return executor;
    }

    static final class RequestScope {
        private final LimitedHttpClient owner;
        private final long cancellationGeneration;

        private RequestScope(LimitedHttpClient owner, long cancellationGeneration) {
            this.owner = owner;
            this.cancellationGeneration = cancellationGeneration;
        }
    }

    static byte[] readLimited(InputStream input, int maximum) throws IOException {
        return readLimited(input, maximum, null);
    }

    private byte[] readLimited(InputStream input, int maximum,
                               long requestGeneration) throws IOException {
        return readLimited(input, maximum, () -> checkRequestActive(requestGeneration));
    }

    private static byte[] readLimited(InputStream input, int maximum,
                                      RequestCheck requestCheck) throws IOException {
        try (InputStream source = input;
             ByteArrayOutputStream output = new ByteArrayOutputStream(Math.min(8192, maximum))) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while (true) {
                if (requestCheck != null) requestCheck.check();
                read = source.read(buffer);
                if (requestCheck != null) requestCheck.check();
                if (read < 0) break;
                if (read == 0) continue;
                total += read;
                if (total > maximum) throw new IOException("expanded response exceeds limit");
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private interface RequestCheck {
        void check() throws IOException;
    }

    private static Map<String, String> copyHeaders(Map<String, List<String>> source) {
        Map<String, String> output = new HashMap<>();
        if (source == null) return output;
        for (Map.Entry<String, List<String>> item : source.entrySet()) {
            if (item.getKey() == null || item.getValue() == null || item.getValue().isEmpty()) continue;
            output.put(item.getKey().toLowerCase(Locale.US), item.getValue().get(0));
        }
        return output;
    }

    private static String hex(byte[] value) {
        StringBuilder output = new StringBuilder(value.length * 2);
        for (byte item : value) output.append(String.format(Locale.US, "%02x", item & 255));
        return output.toString();
    }


    interface ConnectionFactory {
        HttpURLConnection open(URL target) throws IOException;
    }

    private static final class OpenResponse {
        final HttpURLConnection connection;
        final int status;

        OpenResponse(HttpURLConnection connection, int status) {
            this.connection = connection;
            this.status = status;
        }
    }

    static final class RedirectStep {
        final URL target;
        final boolean sameOrigin;

        RedirectStep(URL target, boolean sameOrigin) {
            this.target = target;
            this.sameOrigin = sameOrigin;
        }
    }

    static final class Response {
        final int status;
        final byte[] body;
        final Map<String, String> headers;

        Response(int status, byte[] body, Map<String, String> headers) {
            this.status = status;
            this.body = body;
            this.headers = headers;
        }

        String header(String name) {
            return headers.get(name.toLowerCase(Locale.US));
        }
    }

    static final class StreamResponse {
        final int status;
        final long size;
        final String sha256;
        final Map<String, String> headers;

        StreamResponse(int status, long size, String sha256, Map<String, String> headers) {
            this.status = status;
            this.size = size;
            this.sha256 = sha256;
            this.headers = headers;
        }
    }

    interface ProgressListener {
        void onProgress(long downloadedBytes, long totalBytes);
    }
}
