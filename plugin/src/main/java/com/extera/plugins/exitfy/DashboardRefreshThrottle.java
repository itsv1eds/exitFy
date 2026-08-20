package com.extera.plugins.exitfy;

import java.util.concurrent.TimeUnit;

/** Pure timing policy kept separate so it can be tested without Android host classes. */
final class DashboardRefreshThrottle {
    static final long INTERVAL_NANOS = TimeUnit.MILLISECONDS.toNanos(250L);

    private DashboardRefreshThrottle() {
    }

    static long delayNanos(long nowNanos, long lastNanos) {
        if (lastNanos <= 0L) return 0L;
        long elapsed = nowNanos - lastNanos;
        if (elapsed < 0L || elapsed >= INTERVAL_NANOS) return 0L;
        return INTERVAL_NANOS - elapsed;
    }
}
