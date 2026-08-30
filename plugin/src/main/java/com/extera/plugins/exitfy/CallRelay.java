package com.extera.plugins.exitfy;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Carries call media through the connection exitFy already runs.
 *
 * <p>Telegram hands group-call media straight to its reflectors: unlike a
 * one-to-one call, that path takes no proxy. Pointing an endpoint at a loopback
 * port lets the media be tunnelled instead, and this forwarder is the other end
 * of that port: every datagram it receives is wrapped in a SOCKS5 UDP request
 * and sent through the running core, so a call leaves by the same server the
 * user already chose. No third party is involved.</p>
 *
 * <p>Only addresses inside Telegram's reflector ranges are ever forwarded. The
 * port is on loopback and anything else reaching it would otherwise turn this
 * into an open relay for whatever asked.</p>
 */
final class CallRelay implements Closeable {
    static final int MAX_MAPPINGS = 8;
    private static final int MAX_DATAGRAM_BYTES = 2048;
    private static final long IDLE_TIMEOUT_MS = 120_000L;
    private static final int HANDSHAKE_TIMEOUT_MS = 4_000;

    private final Object lock = new Object();
    private final Map<String, Mapping> mappings = new LinkedHashMap<>();
    private final String proxyHost;
    private final int proxyPort;
    private final String username;
    private final String password;

    private final AtomicLong fromTelegram = new AtomicLong();
    private final AtomicLong toTelegram = new AtomicLong();
    private final AtomicLong mapped = new AtomicLong();
    private volatile String lastRefusal = "";

    private Selector selector;
    private Thread worker;
    private volatile boolean running;

    CallRelay(String proxyHost, int proxyPort, String username, String password) {
        this.proxyHost = proxyHost == null ? "127.0.0.1" : proxyHost;
        this.proxyPort = proxyPort;
        this.username = username == null ? "" : username;
        this.password = password == null ? "" : password;
    }

    /**
     * Local port that stands in for one reflector endpoint. Repeat requests for
     * the same endpoint reuse their port: a call renegotiating must not consume
     * the budget.
     */
    int mapEndpoint(String targetIp, int targetPort) throws Exception {
        if (!TelegramReflectors.isForwardable(targetIp)) {
            throw refuse("address is not a public endpoint");
        }
        if (targetPort < 1 || targetPort > 65535) {
            throw refuse("port is out of range");
        }
        String key = targetIp + ":" + targetPort;
        synchronized (lock) {
            Mapping existing = mappings.get(key);
            if (existing != null && existing.usable()) {
                existing.lastActivity = System.currentTimeMillis();
                return existing.localPort;
            }
            if (existing != null) closeQuietly(existing);
            dropIdleLocked();
            if (mappings.size() >= MAX_MAPPINGS) {
                throw new IllegalStateException("too many call endpoints");
            }
            Mapping mapping;
            try {
                mapping = openMapping(targetIp, targetPort);
            } catch (Exception error) {
                lastRefusal = ErrorSanitizer.clean(error.getMessage() == null
                        ? error.getClass().getSimpleName() : error.getMessage());
                throw error;
            }
            mappings.put(key, mapping);
            mapped.incrementAndGet();
            ensureWorkerLocked();
            selector.wakeup();
            return mapping.localPort;
        }
    }

    /**
     * Enough to tell where a failing call stops without a debugger: no
     * mappings means the endpoints were never rewritten, mappings with
     * nothing sent means the call layer refused the loopback endpoint, and
     * traffic out with none back means the node is not carrying UDP.
     */
    String statistics() {
        return mapped.get() + "/" + fromTelegram.get() + "/" + toTelegram.get();
    }

    /** Why the last endpoint could not be mapped, for when nothing is. */
    String lastRefusal() {
        return lastRefusal;
    }

    private IllegalArgumentException refuse(String reason) {
        lastRefusal = reason;
        return new IllegalArgumentException(reason);
    }

    @Override
    public void close() {
        Thread stopping;
        Selector closing;
        List<Mapping> current;
        synchronized (lock) {
            running = false;
            stopping = worker;
            closing = selector;
            worker = null;
            selector = null;
            current = new ArrayList<>(mappings.values());
            mappings.clear();
        }
        if (closing != null) {
            closing.wakeup();
            try {
                closing.close();
            } catch (IOException ignored) {
            }
        }
        if (stopping != null) {
            try {
                stopping.join(1_000L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        for (Mapping mapping : current) closeQuietly(mapping);
    }

    private void dropIdleLocked() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Mapping>> items = mappings.entrySet().iterator();
        while (items.hasNext()) {
            Mapping mapping = items.next().getValue();
            if (!mapping.usable() || now - mapping.lastActivity > IDLE_TIMEOUT_MS) {
                items.remove();
                closeQuietly(mapping);
            }
        }
    }

    private void ensureWorkerLocked() throws IOException {
        if (running && worker != null && worker.isAlive()) return;
        running = true;
        Thread thread = new Thread(this::pump, "exitfy-call-relay");
        thread.setDaemon(true);
        worker = thread;
        thread.start();
    }

    private Mapping openMapping(String targetIp, int targetPort) throws Exception {
        Socket control = null;
        DatagramChannel client = null;
        DatagramChannel core = null;
        try {
            control = new Socket();
            control.connect(new InetSocketAddress(proxyHost, proxyPort), HANDSHAKE_TIMEOUT_MS);
            control.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            control.setTcpNoDelay(true);
            InetSocketAddress relay = negotiate(control);

            client = DatagramChannel.open();
            client.configureBlocking(false);
            client.socket().bind(new InetSocketAddress(
                    InetAddress.getByName("127.0.0.1"), 0));

            core = DatagramChannel.open();
            core.configureBlocking(false);
            core.socket().bind(new InetSocketAddress(
                    InetAddress.getByName("127.0.0.1"), 0));

            Mapping mapping = new Mapping(targetIp, targetPort, control, client, core, relay);
            synchronized (lock) {
                if (selector == null) selector = Selector.open();
            }
            client.register(selector, SelectionKey.OP_READ, mapping);
            core.register(selector, SelectionKey.OP_READ, mapping);
            return mapping;
        } catch (Exception error) {
            closeQuietly(control);
            closeQuietly(client);
            closeQuietly(core);
            throw error;
        }
    }

    /** RFC 1928 greeting, optional RFC 1929 login, then a UDP association. */
    private InetSocketAddress negotiate(Socket control) throws IOException {
        OutputStream out = control.getOutputStream();
        InputStream in = control.getInputStream();
        boolean login = !username.isEmpty() && !password.isEmpty();
        out.write(login ? new byte[]{5, 2, 0, 2} : new byte[]{5, 1, 0});
        out.flush();
        byte[] greeting = readExactly(in, 2);
        if (greeting[0] != 5) throw new IOException("proxy is not SOCKS5");
        int method = greeting[1] & 0xFF;
        if (method == 2) {
            if (!login) throw new IOException("proxy asked for a login exitFy did not set");
            byte[] user = username.getBytes(StandardCharsets.UTF_8);
            byte[] secret = password.getBytes(StandardCharsets.UTF_8);
            if (user.length > 255 || secret.length > 255) {
                throw new IOException("proxy credentials are too long");
            }
            ByteBuffer auth = ByteBuffer.allocate(3 + user.length + secret.length);
            auth.put((byte) 1).put((byte) user.length).put(user)
                    .put((byte) secret.length).put(secret);
            out.write(auth.array());
            out.flush();
            byte[] result = readExactly(in, 2);
            if (result[1] != 0) throw new IOException("proxy rejected the login");
        } else if (method != 0) {
            throw new IOException("proxy offered no usable authentication");
        }

        // Associating from 0.0.0.0:0 lets the core accept datagrams from
        // whichever local port this mapping ends up bound to.
        out.write(new byte[]{5, 3, 0, 1, 0, 0, 0, 0, 0, 0});
        out.flush();
        byte[] head = readExactly(in, 4);
        if (head[0] != 5) throw new IOException("proxy is not SOCKS5");
        if (head[1] != 0) throw new IOException("proxy refused the UDP association");
        String host;
        int type = head[3] & 0xFF;
        if (type == 1) {
            byte[] raw = readExactly(in, 4);
            host = (raw[0] & 0xFF) + "." + (raw[1] & 0xFF) + "."
                    + (raw[2] & 0xFF) + "." + (raw[3] & 0xFF);
        } else if (type == 3) {
            int length = readExactly(in, 1)[0] & 0xFF;
            host = new String(readExactly(in, length), StandardCharsets.US_ASCII);
        } else if (type == 4) {
            throw new IOException("proxy answered with an IPv6 relay");
        } else {
            throw new IOException("proxy answered with an unknown address type");
        }
        byte[] portBytes = readExactly(in, 2);
        int port = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);
        if (port < 1) throw new IOException("proxy answered with no relay port");
        // A relay bound to the wildcard address is reached at the proxy itself.
        if (host.equals("0.0.0.0") || host.isEmpty()) host = proxyHost;
        return new InetSocketAddress(InetAddress.getByName(host), port);
    }

    private static byte[] readExactly(InputStream in, int length) throws IOException {
        byte[] value = new byte[length];
        int read = 0;
        while (read < length) {
            int step = in.read(value, read, length - read);
            if (step < 0) throw new IOException("proxy closed the connection");
            read += step;
        }
        return value;
    }

    private void pump() {
        ByteBuffer buffer = ByteBuffer.allocateDirect(MAX_DATAGRAM_BYTES);
        while (running) {
            Selector current;
            synchronized (lock) {
                current = selector;
            }
            if (current == null) return;
            try {
                current.select(1_000L);
            } catch (IOException stopped) {
                return;
            } catch (RuntimeException ignored) {
                continue;
            }
            if (!running) return;
            Iterator<SelectionKey> keys = current.selectedKeys().iterator();
            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove();
                if (!key.isValid() || !key.isReadable()) continue;
                Mapping mapping = (Mapping) key.attachment();
                try {
                    if (key.channel() == mapping.client) forwardToCore(mapping, buffer);
                    else forwardToClient(mapping, buffer);
                } catch (Exception ignored) {
                }
            }
            expireIdle();
        }
    }

    private void expireIdle() {
        List<Mapping> expired = new ArrayList<>();
        synchronized (lock) {
            long now = System.currentTimeMillis();
            Iterator<Map.Entry<String, Mapping>> items = mappings.entrySet().iterator();
            while (items.hasNext()) {
                Mapping mapping = items.next().getValue();
                if (!mapping.usable() || now - mapping.lastActivity > IDLE_TIMEOUT_MS) {
                    items.remove();
                    expired.add(mapping);
                }
            }
        }
        for (Mapping mapping : expired) closeQuietly(mapping);
    }

    private void forwardToCore(Mapping mapping, ByteBuffer buffer) throws IOException {
        buffer.clear();
        SocketAddress from = mapping.client.receive(buffer);
        if (from == null) return;
        buffer.flip();
        int length = buffer.remaining();
        if (length <= 0 || length > MAX_DATAGRAM_BYTES - 10) return;
        mapping.lastClient = from;
        mapping.lastActivity = System.currentTimeMillis();
        fromTelegram.incrementAndGet();
        ByteBuffer wrapped = ByteBuffer.allocate(10 + length);
        wrapped.put((byte) 0).put((byte) 0).put((byte) 0).put((byte) 1);
        for (String part : mapping.targetIp.split("\\.")) {
            wrapped.put((byte) Integer.parseInt(part));
        }
        wrapped.put((byte) ((mapping.targetPort >> 8) & 0xFF));
        wrapped.put((byte) (mapping.targetPort & 0xFF));
        wrapped.put(buffer);
        wrapped.flip();
        mapping.core.send(wrapped, mapping.relay);
    }

    private void forwardToClient(Mapping mapping, ByteBuffer buffer) throws IOException {
        buffer.clear();
        SocketAddress from = mapping.core.receive(buffer);
        if (from == null || !from.equals(mapping.relay)) return;
        buffer.flip();
        if (buffer.remaining() < 10) return;
        buffer.get();
        buffer.get();
        if (buffer.get() != 0) return;
        int type = buffer.get() & 0xFF;
        int skip = type == 1 ? 4 : (type == 4 ? 16 : -1);
        if (type == 3) {
            if (!buffer.hasRemaining()) return;
            skip = buffer.get() & 0xFF;
        }
        if (skip < 0 || buffer.remaining() < skip + 2) return;
        buffer.position(buffer.position() + skip + 2);
        SocketAddress client = mapping.lastClient;
        if (client == null || !buffer.hasRemaining()) return;
        mapping.lastActivity = System.currentTimeMillis();
        toTelegram.incrementAndGet();
        mapping.client.send(buffer, client);
    }

    private static void closeQuietly(Mapping mapping) {
        if (mapping == null) return;
        closeQuietly(mapping.control);
        closeQuietly(mapping.client);
        closeQuietly(mapping.core);
    }

    private static void closeQuietly(Closeable value) {
        if (value == null) return;
        try {
            value.close();
        } catch (IOException ignored) {
        }
    }

    private static final class Mapping {
        final String targetIp;
        final int targetPort;
        final Socket control;
        final DatagramChannel client;
        final DatagramChannel core;
        final InetSocketAddress relay;
        final int localPort;
        volatile SocketAddress lastClient;
        volatile long lastActivity;

        Mapping(String targetIp, int targetPort, Socket control,
                DatagramChannel client, DatagramChannel core, InetSocketAddress relay) {
            this.targetIp = targetIp;
            this.targetPort = targetPort;
            this.control = control;
            this.client = client;
            this.core = core;
            this.relay = relay;
            this.localPort = client.socket().getLocalPort();
            this.lastActivity = System.currentTimeMillis();
        }

        boolean usable() {
            return control.isConnected() && !control.isClosed()
                    && client.isOpen() && core.isOpen();
        }
    }
}
