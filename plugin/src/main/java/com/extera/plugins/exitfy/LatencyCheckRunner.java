package com.extera.plugins.exitfy;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;

/** Keep only a worker-sized window queued and isolate each failed probe. */
final class LatencyCheckRunner {
    private LatencyCheckRunner() { }

    static <T, R> void run(List<T> items, ThreadPoolExecutor workers, int parallelism,
                          long deadline, BooleanSupplier current, Function<T, R> probe,
                          Function<T, R> unavailable, Function<T, R> failed,
                          Consumer<R> publish) throws InterruptedException {
        if (parallelism < 1) throw new IllegalArgumentException("invalid probe parallelism");
        BlockingQueue<Future<R>> completion = new LinkedBlockingQueue<>();
        Map<Future<R>, T> pending = new LinkedHashMap<>();
        int next = 0;
        try {
            while (current.getAsBoolean() && System.nanoTime() < deadline
                    && (next < items.size() || !pending.isEmpty())) {
                while (next < items.size() && pending.size() < parallelism
                        && current.getAsBoolean() && System.nanoTime() < deadline) {
                    T item = items.get(next++);
                    Future<R> future = RuntimeExecutors.submitCompletion(workers, completion,
                            () -> probe.apply(item), unavailable.apply(item));
                    pending.put(future, item);
                }
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0L || !current.getAsBoolean()) break;
                Future<R> future = completion.poll(remaining, TimeUnit.NANOSECONDS);
                if (future == null) break;
                T item = pending.remove(future);
                if (item == null) continue;
                R result;
                try { result = future.get(); }
                catch (ExecutionException | CancellationException error) { result = failed.apply(item); }
                if (current.getAsBoolean()) publish.accept(result);
            }
        } finally {
            RuntimeExecutors.cancelAndRemove(workers, new ArrayList<>(pending.keySet()));
        }
    }
}
