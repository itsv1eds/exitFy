package com.extera.plugins.exitfy;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ElfInspectorTest {
    @Test
    public void validatesLoaderDynamicTablesAbiAndRequiredExports() {
        byte[] elf = TestElfFiles.elf64(4096L);
        assertTrue(ElfInspector.inspect(elf, "arm64-v8a").valid);
        assertFalse(ElfInspector.inspect(elf, "unsupported").valid);

        byte[] missingDynamic = elf.clone();
        le(missingDynamic).putInt(TestElfFiles.DYNAMIC_PROGRAM_OFFSET, 0);
        assertFalse(ElfInspector.inspect(missingDynamic, "arm64-v8a").valid);
    }

    @Test
    public void ignoresOptionalSectionTableAndRejectsHashReachabilityForgeries() {
        byte[] forgedSections = TestElfFiles.elf64(4096L);
        ByteBuffer sections = le(forgedSections);
        sections.putLong(40, 0x600L);
        sections.putShort(58, (short) 64);
        sections.putShort(60, (short) 2);
        forgedSections[0x600] = 99;
        assertTrue(ElfInspector.inspect(forgedSections, "arm64-v8a").valid);

        byte[] gnuSymoffsetHole = TestElfFiles.elf64(4096L);
        le(gnuSymoffsetHole).putInt(TestElfFiles.GNU_HASH_OFFSET + 4, 3);
        assertFalse(ElfInspector.inspect(gnuSymoffsetHole, "arm64-v8a").valid);

        byte[] wrongGnuNameHash = TestElfFiles.elf64(4096L);
        ByteBuffer gnu = le(wrongGnuNameHash);
        gnu.putInt(TestElfFiles.GNU_HASH_OFFSET + 28,
                gnu.getInt(TestElfFiles.GNU_HASH_OFFSET + 28) ^ 2);
        assertFalse(ElfInspector.inspect(wrongGnuNameHash, "arm64-v8a").valid);

        byte[] missingGnuBloomBits = TestElfFiles.elf64(4096L);
        le(missingGnuBloomBits).putLong(TestElfFiles.GNU_HASH_OFFSET + 16, 0L);
        assertFalse(ElfInspector.inspect(missingGnuBloomBits, "arm64-v8a").valid);

        byte[] brokenSysvChain = TestElfFiles.elf64(4096L);
        le(brokenSysvChain).putInt(TestElfFiles.SYSV_HASH_OFFSET + 16, 0);
        assertFalse(ElfInspector.inspect(brokenSysvChain, "arm64-v8a").valid);
    }

    @Test
    public void enforcesRuntimePageAlignment() {
        byte[] legacy = TestElfFiles.elf64(4096L);
        assertTrue(ElfInspector.inspect(legacy, "arm64-v8a", 4096).valid);
        assertFalse(ElfInspector.inspect(legacy, "arm64-v8a", 16 * 1024).valid);
        assertTrue(ElfInspector.inspect(TestElfFiles.elf64(16 * 1024L),
                "arm64-v8a", 16 * 1024).valid);
    }

    @Test
    public void rejectsCorruptElf() {
        assertFalse(ElfInspector.inspect(new byte[128], "arm64-v8a").valid);

        byte[] hostileSymbolCount = TestElfFiles.elf64(4096L);
        le(hostileSymbolCount).putInt(TestElfFiles.SYSV_HASH_OFFSET + 4, 65_537);
        assertFalse(ElfInspector.inspect(hostileSymbolCount, "arm64-v8a").valid);

        byte[] hostileBucketCount = TestElfFiles.elf64(4096L);
        le(hostileBucketCount).putInt(TestElfFiles.SYSV_HASH_OFFSET, 65_537);
        assertFalse(ElfInspector.inspect(hostileBucketCount, "arm64-v8a").valid);

        byte[] hostileBloomCount = TestElfFiles.elf64(4096L);
        le(hostileBloomCount).putInt(TestElfFiles.GNU_HASH_OFFSET + 8, 131_072);
        assertFalse(ElfInspector.inspect(hostileBloomCount, "arm64-v8a").valid);
    }

    private static ByteBuffer le(byte[] value) {
        return ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN);
    }
}
