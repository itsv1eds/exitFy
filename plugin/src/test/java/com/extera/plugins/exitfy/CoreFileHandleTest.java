package com.extera.plugins.exitfy;

import org.junit.Assume;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CoreFileHandleTest {
    @Test
    public void verifiesDigestAndElfThroughOneDescriptor() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-handle").toFile();
        try {
            File core = new File(root, "core.so");
            byte[] bytes = TestElfFiles.core((byte) 71);
            Files.write(core.toPath(), bytes);
            try (CoreFileHandle handle = CoreFileHandle.open(core)) {
                CoreFileHandle.Verification verified = handle.verify(
                        "arm64-v8a", sha256(bytes));
                assertTrue(verified.error, verified.valid);
                assertTrue(verified.elf.valid);
                assertTrue(handle.descriptor().valid());
            }
            try (CoreFileHandle handle = CoreFileHandle.open(core)) {
                assertFalse(handle.verify("arm64-v8a", repeat('0', 64)).valid);
            }
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void retainedDescriptorDoesNotFollowAReplacedPath() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-pinned").toFile();
        try {
            File active = new File(root, "active.so");
            byte[] original = TestElfFiles.core((byte) 81);
            byte[] replacement = TestElfFiles.core((byte) 82);
            Files.write(active.toPath(), original);
            try (CoreFileHandle handle = CoreFileHandle.open(active)) {
                assertTrue(handle.verify("arm64-v8a", sha256(original)).valid);
                File staged = new File(root, "replacement.so");
                Files.write(staged.toPath(), replacement);
                Files.move(staged.toPath(), active.toPath(),
                        StandardCopyOption.REPLACE_EXISTING);

                byte[] marker = new byte[1];
                assertEquals(1, handle.read(handle.length() - 1L, marker, 0, 1));
                assertEquals(81, marker[0] & 0xff);
                assertEquals(82, Files.readAllBytes(active.toPath())[replacement.length - 1] & 0xff);
            }
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    @Test
    public void refusesSymlinkAtOpenBoundary() throws Exception {
        File root = Files.createTempDirectory("exitfy-core-symlink").toFile();
        try {
            File target = new File(root, "target.so");
            File link = new File(root, "link.so");
            Files.write(target.toPath(), TestElfFiles.core((byte) 91));
            try {
                Files.createSymbolicLink(link.toPath(), target.toPath().getFileName());
            } catch (UnsupportedOperationException | SecurityException error) {
                Assume.assumeNoException(error);
            }
            boolean rejected = false;
            try (CoreFileHandle ignored = CoreFileHandle.open(link)) {
                // Must not be reached.
            } catch (Exception expected) {
                rejected = true;
            }
            assertTrue(rejected);
        } finally {
            TestFiles.deleteRecursively(root);
        }
    }

    private static String sha256(byte[] value) throws Exception {
        StringBuilder output = new StringBuilder();
        for (byte item : MessageDigest.getInstance("SHA-256").digest(value)) {
            output.append(String.format("%02x", item & 0xff));
        }
        return output.toString();
    }

    private static String repeat(char value, int count) {
        char[] output = new char[count];
        java.util.Arrays.fill(output, value);
        return new String(output);
    }
}
