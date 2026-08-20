package com.extera.plugins.exitfy;

import org.json.JSONObject;
import org.json.JSONArray;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.IdentityHashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class AtomicStore {
    static final int MAX_JSON_BYTES = 8 * 1024 * 1024;
    private static final ConcurrentHashMap<String, FileState> FILE_STATES =
            new ConcurrentHashMap<>();
    private static final AtomicLong WRITER_SEQUENCE = new AtomicLong();
    private final File root;
    private final CommitObserver commitObserver;
    private final ReadObserver readObserver;

    AtomicStore(File root) {
        this(root, CommitObserver.NO_OP, ReadObserver.NO_OP);
    }

    AtomicStore(File root, CommitObserver commitObserver) {
        this(root, commitObserver, ReadObserver.NO_OP);
    }

    AtomicStore(File root, CommitObserver commitObserver, ReadObserver readObserver) {
        this.root = root;
        this.commitObserver = commitObserver == null ? CommitObserver.NO_OP : commitObserver;
        this.readObserver = readObserver == null ? ReadObserver.NO_OP : readObserver;
        if (!root.exists() && !root.mkdirs() && !root.isDirectory()) {
            throw new IllegalStateException("cannot create private data directory");
        }
    }

    JSONObject readJson(String relativeName) {
        try {
            return readJsonStrict(relativeName);
        } catch (Exception ignored) {
            return new JSONObject();
        }
    }

    /**
     * Reads an existing durable JSON object without mapping cancellation,
     * corruption or I/O failure to an indistinguishable empty object.
     */
    JSONObject readJsonStrict(String relativeName) throws Exception {
        JSONObject value = readJsonInternal(relativeName, false);
        if (value == null) {
            throw new IOException("durable JSON state is missing");
        }
        return value;
    }

    /**
     * Returns {@code null} only when the durable file does not exist. Existing
     * empty, oversized, malformed or unreadable files remain hard failures so
     * callers never replace recoverable state with first-run defaults.
     */
    JSONObject readJsonIfExists(String relativeName) throws Exception {
        return readJsonInternal(relativeName, true);
    }

    private JSONObject readJsonInternal(String relativeName, boolean allowMissing)
            throws Exception {
        File target = child(relativeName);
        FileState state = stateFor(target);
        synchronized (state.commitLock) {
            ensureJsonReadActive();
            readObserver.onStrictRead(target);
            ensureJsonReadActive();
            cleanupOrphanStagesLocked(target, state);
            if (!target.exists()) {
                if (allowMissing) return null;
                throw new IOException("durable JSON state is missing");
            }
            if (!target.isFile() || target.length() <= 0 || target.length() > MAX_JSON_BYTES) {
                throw new IOException("durable JSON state is missing or outside limits");
            }
            int length = (int) target.length();
            byte[] value = new byte[length];
            try (FileInputStream input = new FileInputStream(target)) {
                int offset = 0;
                while (offset < value.length) {
                    ensureJsonReadActive();
                    int read = input.read(value, offset, value.length - offset);
                    if (read < 0) throw new IOException("durable JSON state was truncated");
                    if (read == 0) continue;
                    offset += read;
                }
                ensureJsonReadActive();
                return JsonGuard.objectUtf8(value);
            }
        }
    }

    private static void ensureJsonReadActive() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("durable JSON recovery interrupted");
        }
    }

    boolean writeJson(String relativeName, JSONObject value) throws Exception {
        return writeJson(relativeName, value, null, null);
    }

    boolean writeJson(String relativeName, JSONObject value, WriterLease lease,
                      CommitGuard guard) throws Exception {
        if (value == null) throw new IllegalArgumentException("JSON state is missing");
        ensureJsonWorkActive();
        // Measure incrementally before JSONObject.toString() can materialize an
        // arbitrarily large String and UTF-8 copy. Individual strings are
        // bounded by their owning parsers; the aggregate is bounded here.
        jsonUtf8Size(value, MAX_JSON_BYTES);
        ensureJsonWorkActive();
        // Serialize exactly once. The same preflight used by readJson keeps
        // write/read behavior symmetric without adding another full-size JSON
        // copy before the UTF-8 byte array required by the atomic writer.
        String serialized = value.toString();
        JsonGuard.requireDepth(serialized);
        byte[] bytes = serialized.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_JSON_BYTES) {
            throw new IllegalArgumentException("JSON state exceeds 8 MiB");
        }
        return writeBytes(relativeName, bytes, lease, guard);
    }

    static int jsonUtf8Size(Object value, int maximumBytes) {
        if (maximumBytes < 0) throw new IllegalArgumentException("invalid JSON byte limit");
        JsonSizer sizer = new JsonSizer(maximumBytes);
        sizer.add(value, 0);
        return sizer.bytes;
    }

    boolean writeBytes(String relativeName, byte[] value) throws Exception {
        return writeBytes(relativeName, value, null, null);
    }

    private boolean writeBytes(String relativeName, byte[] value, WriterLease lease,
                               CommitGuard guard) throws Exception {
        File target = child(relativeName);
        FileState state = stateFor(target);
        if (lease != null && lease.state != state) {
            throw new IllegalArgumentException("writer lease belongs to another file");
        }
        File parent = target.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IllegalStateException("cannot create data directory");
        }
        File staged;
        synchronized (state.commitLock) {
            cleanupOrphanStagesLocked(target, state);
            staged = File.createTempFile(target.getName() + ".tmp.", ".stage", parent);
            state.liveStages.add(staged.getAbsolutePath());
        }
        try {
            try (FileOutputStream output = new FileOutputStream(staged, false)) {
                output.write(value);
                output.flush();
                output.getFD().sync();
            }
            synchronized (state.commitLock) {
                try {
                    if (lease != null) {
                        if (!lease.isActive() || guard == null || !guard.canCommit()
                                || !lease.beginCommit()) {
                            throw new StaleWriteException("writer lease is no longer active");
                        }
                    }
                    commitObserver.onCommitPinned(target, staged);
                    try {
                        Files.move(staged.toPath(), target.toPath(),
                                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                    } catch (AtomicMoveNotSupportedException unsupported) {
                        Files.move(staged.toPath(), target.toPath(),
                                StandardCopyOption.REPLACE_EXISTING);
                    }
                } finally {
                    if (lease != null) lease.finishCommit();
                }
            }
            return true;
        } finally {
            synchronized (state.commitLock) {
                state.liveStages.remove(staged.getAbsolutePath());
            }
            if (staged.exists()) {
                //noinspection ResultOfMethodCallIgnored
                staged.delete();
            }
        }
    }

    WriterLease claimWriter(String relativeName) {
        FileState state = stateFor(child(relativeName));
        synchronized (state.commitLock) {
            cleanupOrphanStagesLocked(child(relativeName), state);
            long id = WRITER_SEQUENCE.incrementAndGet();
            if (id == 0L) id = WRITER_SEQUENCE.incrementAndGet();
            state.activeWriter.set(id);
            return new WriterLease(state, id);
        }
    }

    private static FileState stateFor(File target) {
        try {
            return FILE_STATES.computeIfAbsent(target.getCanonicalPath(), ignored -> new FileState());
        } catch (java.io.IOException error) {
            throw new IllegalArgumentException("invalid private path", error);
        }
    }

    File child(String relativeName) {
        if (relativeName == null || relativeName.contains("..") || new File(relativeName).isAbsolute()) {
            throw new IllegalArgumentException("invalid private path");
        }
        File result = new File(root, relativeName);
        try {
            String rootPath = root.getCanonicalPath() + File.separator;
            String resultPath = result.getCanonicalPath();
            if (!resultPath.startsWith(rootPath)) {
                throw new IllegalArgumentException("private path escapes root");
            }
        } catch (java.io.IOException error) {
            throw new IllegalArgumentException("invalid private path", error);
        }
        return result;
    }

    interface CommitGuard {
        boolean canCommit();
    }

    interface CommitObserver {
        CommitObserver NO_OP = (target, staged) -> { };

        void onCommitPinned(File target, File staged) throws Exception;
    }

    interface ReadObserver {
        ReadObserver NO_OP = target -> { };

        void onStrictRead(File target) throws Exception;
    }

    static final class WriterLease implements Closeable {
        private final FileState state;
        private final long id;
        private final AtomicBoolean closed = new AtomicBoolean();

        WriterLease(FileState state, long id) {
            this.state = state;
            this.id = id;
        }

        boolean isActive() {
            long current = state.activeWriter.get();
            return !closed.get() && (current == id || current == -id);
        }

        boolean beginCommit() {
            if (closed.get() || !state.activeWriter.compareAndSet(id, -id)) return false;
            // close() racing before the CAS revokes id and makes the CAS fail;
            // close() racing after it observes COMMITTING and the write owns the
            // linearization point even if the physical move completes later.
            return true;
        }

        void finishCommit() {
            state.activeWriter.compareAndSet(-id, closed.get() ? 0L : id);
        }

        @Override
        public void close() {
            closed.set(true);
            state.activeWriter.compareAndSet(id, 0L);
        }
    }

    static final class StaleWriteException extends java.io.IOException {
        StaleWriteException(String message) {
            super(message);
        }
    }

    private static final class FileState {
        final Object commitLock = new Object();
        final AtomicLong activeWriter = new AtomicLong();
        final Set<String> liveStages = new HashSet<>();
    }

    private static void cleanupOrphanStagesLocked(File target, FileState state) {
        File parent = target.getParentFile();
        if (parent == null || !parent.isDirectory()) return;
        String prefix = target.getName() + ".tmp.";
        File[] candidates = parent.listFiles((directory, name) ->
                name.startsWith(prefix) && name.endsWith(".stage"));
        if (candidates == null) return;
        for (File candidate : candidates) {
            if (state.liveStages.contains(candidate.getAbsolutePath())) continue;
            try {
                Files.deleteIfExists(candidate.toPath());
            } catch (Exception ignored) {
            }
        }
    }

    private static final class JsonSizer {
        private static final int MAX_DEPTH = 64;
        private final int maximum;
        private final IdentityHashMap<Object, Boolean> stack = new IdentityHashMap<>();
        int bytes;
        int visited;
        int structuralValues;

        JsonSizer(int maximum) {
            this.maximum = maximum;
        }

        void add(Object value, int depth) {
            checkInterrupted();
            if (structuralValues >= JsonGuard.MAX_STRUCTURAL_VALUES) {
                throw new IllegalArgumentException("JSON structure exceeds "
                        + JsonGuard.MAX_STRUCTURAL_VALUES + " values");
            }
            structuralValues++;
            if (depth > MAX_DEPTH) throw new IllegalArgumentException("JSON nesting exceeds limit");
            if (value == null || value == JSONObject.NULL) {
                addAscii(4);
            } else if (value instanceof JSONObject) {
                enter(value);
                addAscii(1);
                JSONObject object = (JSONObject) value;
                Iterator<String> keys = object.keys();
                boolean first = true;
                while (keys.hasNext()) {
                    if (!first) addAscii(1);
                    first = false;
                    String key = keys.next();
                    addQuoted(key);
                    addAscii(1);
                    add(object.opt(key), depth + 1);
                }
                addAscii(1);
                leave(value);
            } else if (value instanceof JSONArray) {
                enter(value);
                addAscii(1);
                JSONArray array = (JSONArray) value;
                for (int i = 0; i < array.length(); i++) {
                    if (i > 0) addAscii(1);
                    add(array.opt(i), depth + 1);
                }
                addAscii(1);
                leave(value);
            } else if (value instanceof String || value instanceof Character) {
                addQuoted(String.valueOf(value));
            } else if (value instanceof Boolean || value instanceof Number) {
                addUtf8(String.valueOf(value));
            } else {
                // JSONObject serializes unknown values as quoted strings.
                addQuoted(String.valueOf(value));
            }
        }

        private void addQuoted(String value) {
            String text = value == null ? "" : value;
            addAscii(2);
            int tokenBytes = 0;
            for (int i = 0; i < text.length(); i++) {
                if ((i & 0x0fff) == 0) ensureJsonWorkActive();
                char c = text.charAt(i);
                int decodedBytes;
                if (Character.isHighSurrogate(c) && i + 1 < text.length()
                        && Character.isLowSurrogate(text.charAt(i + 1))) {
                    decodedBytes = 4;
                } else if (c <= 0x7f) {
                    decodedBytes = 1;
                } else if (c <= 0x7ff) {
                    decodedBytes = 2;
                } else {
                    decodedBytes = 3;
                }
                tokenBytes = addTokenBytes(tokenBytes, decodedBytes);
                if (c == '"' || c == '\\' || c == '\b' || c == '\f'
                        || c == '\n' || c == '\r' || c == '\t') {
                    addAscii(2);
                } else if (c < 0x20) {
                    addAscii(6);
                } else if (Character.isHighSurrogate(c) && i + 1 < text.length()
                        && Character.isLowSurrogate(text.charAt(i + 1))) {
                    addAscii(4);
                    i++;
                } else if (c <= 0x7f) {
                    addAscii(1);
                } else if (c <= 0x7ff) {
                    addAscii(2);
                } else {
                    addAscii(3);
                }
            }
        }

        private void addUtf8(String value) {
            int tokenBytes = 0;
            for (int i = 0; i < value.length(); i++) {
                if ((i & 0x0fff) == 0) ensureJsonWorkActive();
                char c = value.charAt(i);
                int count;
                if (c <= 0x7f) count = 1;
                else if (c <= 0x7ff) count = 2;
                else if (Character.isHighSurrogate(c) && i + 1 < value.length()
                        && Character.isLowSurrogate(value.charAt(i + 1))) {
                    count = 4;
                    i++;
                } else count = 3;
                tokenBytes = addTokenBytes(tokenBytes, count);
                addAscii(count);
            }
        }

        private int addTokenBytes(int current, int count) {
            if (current > JsonGuard.MAX_STRING_BYTES - count) {
                throw new IllegalArgumentException(
                        "JSON string or scalar token exceeds 64 KiB");
            }
            return current + count;
        }

        private void addAscii(int count) {
            if (count < 0 || bytes > maximum - count) {
                throw new IllegalArgumentException("JSON state exceeds 8 MiB");
            }
            bytes += count;
        }

        private void enter(Object value) {
            if (stack.put(value, Boolean.TRUE) != null) {
                throw new IllegalArgumentException("cyclic JSON state");
            }
        }

        private void leave(Object value) {
            stack.remove(value);
        }

        private void checkInterrupted() {
            if ((visited++ & 0x0fff) == 0) ensureJsonWorkActive();
        }
    }

    private static void ensureJsonWorkActive() {
        if (Thread.currentThread().isInterrupted()) {
            throw new IllegalStateException("JSON preflight interrupted");
        }
    }
}
