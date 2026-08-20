package com.extera.plugins.exitfy;

final class ReconnectBackoff {
    private static final long[] DELAYS_SECONDS = {1L, 2L, 5L, 10L, 30L, 60L};

    private int attempt;

    synchronized long nextDelaySeconds(boolean reset) {
        if (reset) attempt = 0;
        return delaySeconds(attempt++);
    }

    synchronized void reset() {
        attempt = 0;
    }

    static boolean resetsForReason(String reason) {
        return "manual_node_added".equals(reason) || "custom_subscription_added".equals(reason)
                || "subscription_deleted".equals(reason) || "manual_node_deleted".equals(reason)
                || "node_selected".equals(reason) || "nodes_cleared".equals(reason)
                || "import".equals(reason) || "subscription_refresh".equals(reason)
                || "core_installed".equals(reason)
                || "core_selection_changed".equals(reason)
                || "manual".equals(reason);
    }

    static long delaySeconds(int attempt) {
        int bounded = Math.max(0, Math.min(attempt, DELAYS_SECONDS.length - 1));
        return DELAYS_SECONDS[bounded];
    }
}
