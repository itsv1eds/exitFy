package com.extera.plugins.exitfy;

import org.json.JSONObject;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;

/** The saved port is only a preference, never evidence that a host proxy is ours. */
final class LocalPortAllocator {
    private static final String FILE = "local_proxy_port.json";
    private final AtomicStore store;
    private final AtomicStore.WriterLease lease;
    private int preferred;

    LocalPortAllocator(AtomicStore store) throws Exception {
        this.store = store;
        lease = store.claimWriter(FILE);
        JSONObject saved = store.readJsonIfExists(FILE);
        preferred = saved == null ? 0 : saved.getInt("port");
        if (preferred != 0 && (preferred < 1 || preferred > 65535)) {
            throw new IllegalStateException("invalid saved exitFy port");
        }
    }

    synchronized int allocate(Set<Integer> foreignPorts, boolean persistent) throws Exception {
        if (!lease.isActive()) throw new IllegalStateException("exitFy port ownership changed");
        Set<Integer> excluded = new HashSet<>(foreignPorts);
        excluded.add(12334);
        excluded.add(10808);
        if (persistent && preferred > 0 && !excluded.contains(preferred)) {
            try (ServerSocket socket = bind(preferred)) { return preferred; }
            catch (java.io.IOException occupied) { /* Try a different free port. */ }
        }
        for (int attempt = 0; attempt < 32; attempt++) {
            int candidate;
            try (ServerSocket socket = bind(0)) { candidate = socket.getLocalPort(); }
            if (excluded.contains(candidate)) continue;
            if (persistent) {
                if (!store.writeJson(FILE, new JSONObject().put("port", candidate), lease, lease::isActive)) {
                    throw new IllegalStateException("exitFy port ownership changed");
                }
                preferred = candidate;
            }
            return candidate;
        }
        throw new IllegalStateException(I18n.t("Нет свободного локального порта", "No free local port"));
    }

    static boolean isLoopback(String host) {
        String value = host == null ? "" : host.trim().toLowerCase(java.util.Locale.ROOT);
        if (value.startsWith("[") && value.endsWith("]")) value = value.substring(1, value.length()-1);
        return value.equals("localhost") || value.equals("::1") || value.equals("0:0:0:0:0:0:0:1")
                || value.matches("(?:.*:)?127\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    }

    void close() { lease.close(); }

    private static ServerSocket bind(int port) throws Exception {
        ServerSocket socket = new ServerSocket();
        try {
            socket.setReuseAddress(false);
            socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
            return socket;
        } catch (Exception error) { socket.close(); throw error; }
    }
}
