package com.extera.plugins.exitfy;

import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Bounded daemon executors and removable completion tasks used by runtime probes. */
final class RuntimeExecutors {
    private RuntimeExecutors() {
    }

    static ThreadPoolExecutor bounded(int workers, int queueCapacity,
                                      String threadName) {
        if (workers <= 0 || queueCapacity <= 0) {
            throw new IllegalArgumentException("invalid executor bounds");
        }
        return new ThreadPoolExecutor(workers, workers, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity), runnable -> {
            Thread thread = new Thread(runnable, threadName);
            thread.setDaemon(true);
            return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
    }

    static ScheduledThreadPoolExecutor replacing(String threadName) {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(
                1, runnable -> {
            Thread thread = new Thread(runnable, threadName);
            thread.setDaemon(true);
            return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
        executor.setRemoveOnCancelPolicy(true);
        executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        executor.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
        return executor;
    }

    static <T> Future<T> submitCompletion(
            ThreadPoolExecutor executor, BlockingQueue<Future<T>> completion,
            Callable<T> task, T rejectedValue) {
        if (executor == null || completion == null || task == null) {
            throw new IllegalArgumentException("completion task is missing");
        }
        FutureTask<T> accepted = completionTask(task, completion);
        try {
            executor.execute(accepted);
            return accepted;
        } catch (RejectedExecutionException rejected) {
            // Publish one deterministic terminal outcome without running the
            // potentially blocking probe on the page coordinator.
            FutureTask<T> immediate = completionTask(() -> rejectedValue, completion);
            immediate.run();
            return immediate;
        }
    }

    private static <T> FutureTask<T> completionTask(
            Callable<T> task, BlockingQueue<Future<T>> completion) {
        return new FutureTask<T>(task) {
            @Override
            protected void done() {
                completion.offer(this);
            }
        };
    }

    static void cancelAndRemove(ThreadPoolExecutor executor, Future<?> future) {
        if (future == null) return;
        future.cancel(true);
        if (executor != null && future instanceof Runnable) {
            executor.remove((Runnable) future);
            executor.purge();
        }
    }

    static void cancelAndRemove(ThreadPoolExecutor executor,
                                List<? extends Future<?>> futures) {
        if (futures == null) return;
        for (Future<?> future : futures) {
            if (future == null) continue;
            future.cancel(true);
            if (executor != null && future instanceof Runnable) {
                executor.remove((Runnable) future);
            }
        }
        if (executor != null) executor.purge();
    }
}
