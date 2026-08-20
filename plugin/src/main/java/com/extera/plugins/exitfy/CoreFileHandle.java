package com.extera.plugins.exitfy;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;

import java.io.Closeable;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/** A single, pinned core descriptor shared by digest, ELF inspection and JNI load. */
final class CoreFileHandle implements Closeable, ElfInspector.Reader {
    private static final int DIGEST_BUFFER_BYTES = 64 * 1024;
    // Linux UAPI O_CLOEXEC, used consistently on supported API 29+.
    private static final int O_CLOEXEC_COMPAT = 0x80000;
    private static final boolean ANDROID_RUNTIME = isAndroidRuntime();

    private final File path;
    private final FileDescriptor descriptor;
    private final RandomAccessFile hostFile;
    private final long length;
    private final AndroidStamp androidStamp;
    private final HostStamp hostStamp;
    private final AtomicBoolean closed = new AtomicBoolean();

    private CoreFileHandle(File path, FileDescriptor descriptor, RandomAccessFile hostFile,
                           long length, AndroidStamp androidStamp, HostStamp hostStamp) {
        this.path = path;
        this.descriptor = descriptor;
        this.hostFile = hostFile;
        this.length = length;
        this.androidStamp = androidStamp;
        this.hostStamp = hostStamp;
    }

    static CoreFileHandle open(File file) throws IOException {
        if (file == null) throw new IOException("core file is missing");
        return ANDROID_RUNTIME ? openAndroid(file) : openHostForTests(file);
    }

    private static CoreFileHandle openAndroid(File file) throws IOException {
        FileDescriptor descriptor = null;
        try {
            int flags = OsConstants.O_RDONLY | O_CLOEXEC_COMPAT
                    | OsConstants.O_NOFOLLOW | OsConstants.O_NONBLOCK;
            descriptor = Os.open(file.getAbsolutePath(), flags, 0);
            StructStat stat = Os.fstat(descriptor);
            if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_nlink != 1L
                    || stat.st_size < 0L) {
                throw new IOException("core is not a single-link regular file");
            }
            return new CoreFileHandle(file, descriptor, null, stat.st_size,
                    AndroidStamp.capture(stat), null);
        } catch (ErrnoException | IOException error) {
            if (descriptor != null) {
                try {
                    Os.close(descriptor);
                } catch (ErrnoException ignored) {
                }
            }
            if (error instanceof IOException) throw (IOException) error;
            throw new IOException("cannot safely open core", error);
        }
    }

    /** JVM-only fallback. Android production always uses O_NOFOLLOW above. */
    private static CoreFileHandle openHostForTests(File file) throws IOException {
        BasicFileAttributes before = Files.readAttributes(file.toPath(),
                BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.isSymbolicLink()) {
            throw new IOException("core is not a regular file");
        }
        RandomAccessFile opened = new RandomAccessFile(file, "r");
        try {
            long length = opened.length();
            HostStamp stamp = new HostStamp(before.fileKey(), before.size(),
                    before.lastModifiedTime().toMillis());
            return new CoreFileHandle(file, opened.getFD(), opened, length, null, stamp);
        } catch (IOException error) {
            opened.close();
            throw error;
        }
    }

    File file() {
        return path;
    }

    FileDescriptor descriptor() {
        if (closed.get()) throw new IllegalStateException("core descriptor is closed");
        return descriptor;
    }

    Verification verify(String expectedAbi, String expectedDigest) throws Exception {
        if (expectedDigest == null || !expectedDigest.matches("[0-9a-f]{64}")) {
            return Verification.error("core digest metadata is missing");
        }
        String beforeDigest = sha256();
        ElfInspector.Result elf = ElfInspector.inspect(this, expectedAbi);
        String afterDigest = sha256();
        if (!stable() || !beforeDigest.equals(afterDigest)) {
            return Verification.error("core changed during verification");
        }
        if (!expectedDigest.equals(afterDigest)) {
            return Verification.error("core digest mismatch");
        }
        if (!elf.valid) return Verification.error(elf.error);
        return new Verification(true, "", afterDigest, elf);
    }

    String sha256() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[DIGEST_BUFFER_BYTES];
        long offset = 0L;
        while (offset < length) {
            int requested = (int) Math.min(buffer.length, length - offset);
            int read = read(offset, buffer, 0, requested);
            if (read != requested) throw new IOException("core digest read was truncated");
            digest.update(buffer, 0, read);
            offset += read;
        }
        return hex(digest.digest());
    }

    private boolean stable() throws IOException {
        if (ANDROID_RUNTIME) {
            try {
                StructStat current = Os.fstat(descriptor);
                return androidStamp.matches(current) && OsConstants.S_ISREG(current.st_mode)
                        && current.st_nlink == 1L;
            } catch (ErrnoException error) {
                throw new IOException("cannot revalidate core descriptor", error);
            }
        }
        BasicFileAttributes current = Files.readAttributes(path.toPath(),
                BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return current.isRegularFile() && !current.isSymbolicLink()
                && hostStamp.matches(current) && hostFile.length() == length;
    }

    @Override
    public long length() {
        return length;
    }

    @Override
    public int read(long offset, byte[] output, int outputOffset, int count)
            throws IOException {
        if (closed.get()) throw new IOException("core descriptor is closed");
        if (offset < 0L || output == null || outputOffset < 0 || count < 0
                || outputOffset > output.length || count > output.length - outputOffset
                || offset > length || count > length - offset) {
            throw new IOException("core read escapes file");
        }
        int total = 0;
        if (ANDROID_RUNTIME) {
            try {
                while (total < count) {
                    int read = Os.pread(descriptor, output, outputOffset + total,
                            count - total, offset + total);
                    if (read <= 0) throw new IOException("core read was truncated");
                    total += read;
                }
                return total;
            } catch (ErrnoException error) {
                throw new IOException("core descriptor read failed", error);
            }
        }
        synchronized (hostFile) {
            hostFile.seek(offset);
            while (total < count) {
                int read = hostFile.read(output, outputOffset + total, count - total);
                if (read < 0) throw new IOException("core read was truncated");
                if (read > 0) total += read;
            }
        }
        return total;
    }

    @Override
    public void close() throws IOException {
        if (!closed.compareAndSet(false, true)) return;
        if (ANDROID_RUNTIME) {
            try {
                Os.close(descriptor);
            } catch (ErrnoException error) {
                throw new IOException("cannot close core descriptor", error);
            }
        } else {
            hostFile.close();
        }
    }

    private static boolean isAndroidRuntime() {
        String vm = System.getProperty("java.vm.name", "");
        String runtime = System.getProperty("java.runtime.name", "");
        return vm.toLowerCase(Locale.US).contains("dalvik")
                || runtime.toLowerCase(Locale.US).contains("android");
    }

    private static String hex(byte[] value) {
        StringBuilder output = new StringBuilder(value.length * 2);
        for (byte item : value) output.append(String.format(Locale.US, "%02x", item & 255));
        return output.toString();
    }

    static final class Verification {
        final boolean valid;
        final String error;
        final String digest;
        final ElfInspector.Result elf;

        Verification(boolean valid, String error, String digest, ElfInspector.Result elf) {
            this.valid = valid;
            this.error = error;
            this.digest = digest;
            this.elf = elf;
        }

        static Verification error(String error) {
            return new Verification(false, error, "", ElfInspector.Result.error(error));
        }
    }

    private static final class AndroidStamp {
        final long device;
        final long inode;
        final int mode;
        final long links;
        final long size;
        final long modifiedSeconds;
        final long modifiedNanos;
        final long changedSeconds;
        final long changedNanos;

        AndroidStamp(long device, long inode, int mode, long links, long size,
                     long modifiedSeconds, long modifiedNanos,
                     long changedSeconds, long changedNanos) {
            this.device = device;
            this.inode = inode;
            this.mode = mode;
            this.links = links;
            this.size = size;
            this.modifiedSeconds = modifiedSeconds;
            this.modifiedNanos = modifiedNanos;
            this.changedSeconds = changedSeconds;
            this.changedNanos = changedNanos;
        }

        static AndroidStamp capture(StructStat value) {
            return new AndroidStamp(value.st_dev, value.st_ino, value.st_mode,
                    value.st_nlink, value.st_size, value.st_mtim.tv_sec,
                    value.st_mtim.tv_nsec, value.st_ctim.tv_sec, value.st_ctim.tv_nsec);
        }

        boolean matches(StructStat value) {
            return device == value.st_dev && inode == value.st_ino && mode == value.st_mode
                    && links == value.st_nlink && size == value.st_size
                    && modifiedSeconds == value.st_mtim.tv_sec
                    && modifiedNanos == value.st_mtim.tv_nsec
                    && changedSeconds == value.st_ctim.tv_sec
                    && changedNanos == value.st_ctim.tv_nsec;
        }
    }

    private static final class HostStamp {
        final Object key;
        final long size;
        final long modified;

        HostStamp(Object key, long size, long modified) {
            this.key = key;
            this.size = size;
            this.modified = modified;
        }

        boolean matches(BasicFileAttributes value) {
            Object currentKey = value.fileKey();
            return (key == null ? currentKey == null : key.equals(currentKey))
                    && size == value.size()
                    && modified == value.lastModifiedTime().toMillis();
        }
    }
}
