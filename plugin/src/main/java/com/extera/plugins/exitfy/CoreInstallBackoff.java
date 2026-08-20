package com.extera.plugins.exitfy;

final class CoreInstallBackoff {
    private static final long[] DELAYS_SECONDS = {
            5L, 30L, 2L * 60L, 10L * 60L, 60L * 60L,
    };

    private int attempt;

    synchronized long nextDelaySeconds() {
        int index = Math.min(attempt, DELAYS_SECONDS.length - 1);
        attempt++;
        return DELAYS_SECONDS[index];
    }

    synchronized void reset() {
        attempt = 0;
    }
}
