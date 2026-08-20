package com.extera.plugins.exitfy;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CoreInstallBackoffTest {
    @Test
    public void followsBoundedRetryScheduleAndReset() {
        CoreInstallBackoff backoff = new CoreInstallBackoff();

        assertEquals(5L, backoff.nextDelaySeconds());
        assertEquals(30L, backoff.nextDelaySeconds());
        assertEquals(120L, backoff.nextDelaySeconds());
        assertEquals(600L, backoff.nextDelaySeconds());
        assertEquals(3_600L, backoff.nextDelaySeconds());
        assertEquals(3_600L, backoff.nextDelaySeconds());

        backoff.reset();
        assertEquals(5L, backoff.nextDelaySeconds());
    }
}
