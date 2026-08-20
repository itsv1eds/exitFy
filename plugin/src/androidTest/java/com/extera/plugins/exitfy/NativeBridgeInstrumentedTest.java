package com.extera.plugins.exitfy;

import android.content.Context;
import android.os.ParcelFileDescriptor;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileOutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class NativeBridgeInstrumentedTest {
    @Test
    public void rejectsCorruptCoreLoadsFakeCoreAndSerializesStartStop() throws Exception {
        System.loadLibrary("exitfy_bridge");
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        File corrupt = new File(context.getCacheDir(), "corrupt-core.so");
        try (FileOutputStream output = new FileOutputStream(corrupt, false)) {
            output.write(new byte[]{1, 2, 3, 4});
        }
        assertTrue(openCore(corrupt, repeatAscii(4097), "sing_box", 2)
                .contains("UTF-8 limit"));
        assertFalse(openCore(corrupt, corrupt.getAbsolutePath(),
                "sing_box\u0000x", 2).isEmpty());
        assertFalse(openCore(corrupt, "sing_box", 2).isEmpty());

        File fake = new File(context.getApplicationInfo().nativeLibraryDir, "libexitfy_fake_core.so");
        File alternate = new File(context.getApplicationInfo().nativeLibraryDir,
                "libexitfy_fake_core_alt.so");
        File apiOne = new File(context.getApplicationInfo().nativeLibraryDir,
                "libexitfy_fake_core_v1.so");
        assertTrue(fake.isFile());
        assertTrue(alternate.isFile());
        assertTrue(apiOne.isFile());
        // Exercise the real legacy ABI: StartCore returns char*, while
        // StopCore is void and must remain safe/idempotent on repeat calls.
        assertEquals("", NativeBridgeTestHooks.nativeExerciseApiOne(
                apiOne.getAbsolutePath()));
        assertEquals("", openCore(apiOne, "sing_box", 1));
        assertEquals("sing_box", NativeBridge.nativeLoadedIdentity());
        assertEquals(1, NativeBridge.nativeLoadedCoreApi());
        assertEquals("", NativeBridge.nativeStart("{}"));
        assertEquals("", NativeBridge.nativeStop());
        assertEquals("", NativeBridge.nativeStop());
        // Fake C cores can be retained safely while the debug bridge resets
        // only its pointers, giving the ABI 2 checks a deterministic order in
        // the same instrumentation process. Production has no reset export.
        NativeBridgeTestHooks.nativeResetBridgeForTests();
        assertEquals("", NativeBridge.nativeLoadedIdentity());
        assertEquals(0, NativeBridge.nativeLoadedCoreApi());
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            NativeBridgeTestHooks.nativeSetMetadataPause(true);
            Future<String> open = workers.submit(
                    () -> openCore(fake, "sing_box", 2));
            try {
                long metadataDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                while (!NativeBridgeTestHooks.nativeMetadataPauseEntered()
                        && System.nanoTime() < metadataDeadline) {
                    Thread.sleep(10L);
                }
                assertTrue("nativeOpen never reached metadata publication",
                        NativeBridgeTestHooks.nativeMetadataPauseEntered());
                assertEquals("", NativeBridge.nativeLoadedIdentity());
                assertEquals(0, NativeBridge.nativeLoadedCoreApi());
            } finally {
                NativeBridgeTestHooks.nativeSetMetadataPause(false);
            }
            assertEquals("", open.get(2, TimeUnit.SECONDS));
            assertEquals("sing_box", NativeBridge.nativeLoadedIdentity());
            assertEquals(2, NativeBridge.nativeLoadedCoreApi());
            assertEquals("", openCore(fake, "sing_box", 2));
            assertFalse(openCore(fake, "sing_box", 1).isEmpty());
            assertFalse(openCore(alternate, "sing_box", 2).isEmpty());
            assertFalse(openCore(alternate, "xray", 2).isEmpty());

            assertEquals("", NativeBridge.nativeStart(repeatAscii(16 * 1024 * 1024)));
            assertTrue(NativeBridge.nativeStart(repeatAscii(16 * 1024 * 1024 + 1))
                    .contains("16777216"));
            assertTrue(NativeBridge.nativeStart("{}\u0000{\"hidden\":true}")
                    .contains("conversion failed"));
            StringBuilder chunkBoundary = new StringBuilder(1100);
            while (chunkBoundary.length() < 1023) chunkBoundary.append('a');
            chunkBoundary.appendCodePoint(0x1f642).append(" unicode_input");
            assertEquals("UTF-8 input ok", NativeBridge.nativeStart(
                    chunkBoundary.toString()));
            assertEquals("replacement input ok", NativeBridge.nativeStart(
                    "\ud83d replacement_input"));

            Future<String> start = workers.submit(() -> NativeBridge.nativeStart("{\"slow\":true}"));
            Thread.sleep(50);
            long identityBegan = System.nanoTime();
            assertEquals("sing_box", NativeBridge.nativeLoadedIdentity());
            long identityWaitedMs = TimeUnit.NANOSECONDS.toMillis(
                    System.nanoTime() - identityBegan);
            assertTrue("loader identity blocked behind StartCore", identityWaitedMs < 200L);
            long began = System.nanoTime();
            Future<?> stop = workers.submit(() -> {
                assertEquals("", NativeBridge.nativeStop());
                return null;
            });
            assertEquals("", start.get(2, TimeUnit.SECONDS));
            stop.get(2, TimeUnit.SECONDS);
            long waitedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began);
            assertTrue("StopCore raced StartCore", waitedMs >= 200);
            assertEquals("Ошибка ядра 🚀", NativeBridge.nativeStart("{\"unicode\":true}"));
            String malformed = NativeBridge.nativeStart("{\"malformed\":true}");
            assertTrue(malformed.contains("\ufffd"));
            String limited = NativeBridge.nativeStart("{\"long_error\":true}");
            assertTrue(limited.codePointCount(0, limited.length()) <= 1024);
            assertTrue(limited.getBytes(StandardCharsets.UTF_8).length <= 4096);
            String malformedBoundary = NativeBridge.nativeStart(
                    "{\"boundary_bad\":true}");
            assertTrue(malformedBoundary.contains("\ufffd"));
            assertTrue(malformedBoundary.getBytes(StandardCharsets.UTF_8).length <= 4096);
            assertEquals("", NativeBridge.nativeStart("{\"boundary_valid\":true}"));
            assertEquals("", NativeBridge.nativeStart("{}"));
            assertEquals("", NativeBridge.nativeStop());
            assertEquals("", NativeBridge.nativeStart("{\"stop_error\":true}"));
            assertEquals("Ошибка остановки 🛑", NativeBridge.nativeStop());
            assertEquals("", NativeBridge.nativeStop());
        } finally {
            NativeBridgeTestHooks.nativeSetMetadataPause(false);
            workers.shutdownNow();
        }
    }

    private static String openCore(File file, String identity, int coreApi)
            throws Exception {
        return openCore(file, file.getAbsolutePath(), identity, coreApi);
    }

    private static String openCore(File descriptorFile, String libraryPath,
                                   String identity, int coreApi) throws Exception {
        try (ParcelFileDescriptor descriptor = ParcelFileDescriptor.open(
                descriptorFile, ParcelFileDescriptor.MODE_READ_ONLY)) {
            return NativeBridge.nativeOpen(descriptor.getFd(), libraryPath,
                    identity, coreApi);
        }
    }

    private static String repeatAscii(int length) {
        char[] value = new char[length];
        java.util.Arrays.fill(value, 'a');
        return new String(value);
    }
}
