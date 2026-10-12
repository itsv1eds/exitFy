package com.extera.plugins.exitfy;

import org.junit.Test;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.Assert.*;

public class LatencyCheckRunnerTest {
    @Test public void workerLinkageFailureDoesNotCancelHealthySiblings() throws Exception {
        ThreadPoolExecutor workers = RuntimeExecutors.bounded(2, 2, "latency-test");
        List<String> outcomes = new ArrayList<>();
        try {
            LatencyCheckRunner.run(Arrays.asList("broken", "healthy", "next"), workers, 2,
                    deadline(2000), () -> true, item -> {
                        if (item.equals("broken")) throw new NoSuchMethodError("probe dependency");
                        return "ok:" + item;
                    }, item -> "busy:" + item, item -> "failed:" + item, outcomes::add);
            assertEquals(3, outcomes.size());
            assertTrue(outcomes.contains("failed:broken"));
            assertTrue(outcomes.contains("ok:healthy"));
            assertTrue(outcomes.contains("ok:next"));
        } finally { workers.shutdownNow(); }
    }

    @Test public void fiftyServerPageDoesNotOverflowASmallWorkerQueue() throws Exception {
        ThreadPoolExecutor workers = RuntimeExecutors.bounded(4, 4, "latency-test");
        List<Integer> items = new ArrayList<>(), outcomes = new ArrayList<>();
        for (int i = 0; i < 50; i++) items.add(i);
        try {
            LatencyCheckRunner.run(items, workers, 4, deadline(2000), () -> true,
                    item -> item, item -> -1, item -> -2, outcomes::add);
            assertEquals(50, outcomes.size());
            assertFalse(outcomes.contains(-1));
            assertFalse(outcomes.contains(-2));
            assertTrue(workers.getQueue().isEmpty());
        } finally { workers.shutdownNow(); }
    }

    @Test public void supersededRunCannotPublishLateResults() throws Exception {
        ThreadPoolExecutor workers = RuntimeExecutors.bounded(2, 2, "latency-test");
        AtomicBoolean current = new AtomicBoolean(true);
        List<Integer> outcomes = new ArrayList<>();
        try {
            LatencyCheckRunner.run(Arrays.asList(1, 2, 3, 4), workers, 2, deadline(2000), current::get,
                    item -> item, item -> -1, item -> -2, value -> {
                        outcomes.add(value); current.set(false);
                    });
            assertEquals(1, outcomes.size());
            assertTrue(workers.getQueue().isEmpty());
        } finally { workers.shutdownNow(); }
    }

    @Test public void busyWorkersReturnTerminalOutcomesWithoutRunningProbesInline() throws Exception {
        ThreadPoolExecutor workers = RuntimeExecutors.bounded(1, 1, "latency-test");
        CountDownLatch release = new CountDownLatch(1), entered = new CountDownLatch(1);
        List<String> outcomes = new ArrayList<>();
        try {
            workers.submit(() -> { entered.countDown(); try { release.await(); } catch (InterruptedException ignored) { } });
            assertTrue(entered.await(1000, TimeUnit.MILLISECONDS));
            workers.submit(() -> { });
            LatencyCheckRunner.run(Arrays.asList("a", "b"), workers, 1, deadline(1000), () -> true,
                    item -> { fail("probe ran on coordinator"); return ""; },
                    item -> "busy:" + item, item -> "failed:" + item, outcomes::add);
            assertEquals(Arrays.asList("busy:a", "busy:b"), outcomes);
        } finally { release.countDown(); workers.shutdownNow(); }
    }

    @Test public void deadlineStopsBlockedWorkAndLeavesNoQueuedProbe() throws Exception {
        ThreadPoolExecutor workers = RuntimeExecutors.bounded(1, 1, "latency-test");
        CountDownLatch interrupted = new CountDownLatch(1);
        List<Integer> outcomes = new ArrayList<>();
        try {
            LatencyCheckRunner.run(Arrays.asList(1, 2), workers, 1, deadline(300), () -> true,
                    item -> {
                        try { new CountDownLatch(1).await(); }
                        catch (InterruptedException cancel) { interrupted.countDown(); }
                        return item;
                    }, item -> -1, item -> -2, outcomes::add);
            assertTrue(outcomes.isEmpty());
            assertTrue(interrupted.await(1000, TimeUnit.MILLISECONDS));
            assertTrue(workers.getQueue().isEmpty());
        } finally { workers.shutdownNow(); }
    }

    private static long deadline(long millis) {
        return System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis);
    }
}
