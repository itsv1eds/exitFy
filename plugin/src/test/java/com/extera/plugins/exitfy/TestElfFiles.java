package com.extera.plugins.exitfy;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Loader-shaped ELF fixtures shared by updater and inspector tests. */
final class TestElfFiles {
    static final int STRINGS_OFFSET = 0x300;
    static final int SYMBOLS_OFFSET = 0x340;
    static final int SYSV_HASH_OFFSET = 0x3a0;
    static final int GNU_HASH_OFFSET = 0x3c0;
    static final int DYNAMIC_OFFSET = 0x400;
    static final int DYNAMIC_SIZE = 7 * 16;
    static final int PROGRAM_OFFSET = 64;
    static final int DYNAMIC_PROGRAM_OFFSET = PROGRAM_OFFSET + 56;

    private TestElfFiles() {
    }

    static byte[] core(byte marker) {
        byte[] value = elf64(1024 * 1024, 16 * 1024L);
        value[value.length - 1] = marker;
        return value;
    }

    static byte[] elf64(long loadAlignment) {
        return elf64(4096, loadAlignment);
    }

    private static byte[] elf64(int fileSize, long loadAlignment) {
        byte[] value = new byte[fileSize];
        ByteBuffer buffer = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN);
        value[0] = 0x7f;
        value[1] = 'E';
        value[2] = 'L';
        value[3] = 'F';
        value[4] = 2; // ELFCLASS64
        value[5] = 1; // ELFDATA2LSB
        value[6] = 1; // EV_CURRENT
        buffer.putShort(16, (short) 3); // ET_DYN
        buffer.putShort(18, (short) 183); // EM_AARCH64
        buffer.putInt(20, 1);
        buffer.putLong(32, PROGRAM_OFFSET);
        buffer.putShort(52, (short) 64);
        buffer.putShort(54, (short) 56);
        buffer.putShort(56, (short) 2);

        putProgram(buffer, PROGRAM_OFFSET, 1, 5, 0, 0,
                fileSize, fileSize, loadAlignment);
        putProgram(buffer, DYNAMIC_PROGRAM_OFFSET, 2, 4,
                DYNAMIC_OFFSET, DYNAMIC_OFFSET,
                DYNAMIC_SIZE, DYNAMIC_SIZE, 8);

        byte[] strings = "\0StartCore\0StopCore\0".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(strings, 0, value, STRINGS_OFFSET, strings.length);
        putSymbol(buffer, SYMBOLS_OFFSET + 24, 1, 0x200);
        putSymbol(buffer, SYMBOLS_OFFSET + 48, 11, 0x201);

        // SysV hash: one bucket, symbols 1 -> 2 -> end.
        buffer.putInt(SYSV_HASH_OFFSET, 1);
        buffer.putInt(SYSV_HASH_OFFSET + 4, 3);
        buffer.putInt(SYSV_HASH_OFFSET + 8, 1);
        buffer.putInt(SYSV_HASH_OFFSET + 12, 0);
        buffer.putInt(SYSV_HASH_OFFSET + 16, 2);
        buffer.putInt(SYSV_HASH_OFFSET + 20, 0);

        long startHash = gnuHash("StartCore");
        long stopHash = gnuHash("StopCore");
        int bloomShift = 5;
        long bloom = (1L << (startHash & 63L))
                | (1L << ((startHash >>> bloomShift) & 63L))
                | (1L << (stopHash & 63L))
                | (1L << ((stopHash >>> bloomShift) & 63L));
        buffer.putInt(GNU_HASH_OFFSET, 1); // bucket count
        buffer.putInt(GNU_HASH_OFFSET + 4, 1); // first hashed symbol
        buffer.putInt(GNU_HASH_OFFSET + 8, 1); // bloom words
        buffer.putInt(GNU_HASH_OFFSET + 12, bloomShift);
        buffer.putLong(GNU_HASH_OFFSET + 16, bloom);
        buffer.putInt(GNU_HASH_OFFSET + 24, 1);
        buffer.putInt(GNU_HASH_OFFSET + 28, (int) (startHash & ~1L));
        buffer.putInt(GNU_HASH_OFFSET + 32, (int) (stopHash | 1L));

        int dynamic = DYNAMIC_OFFSET;
        dynamic = putDynamic(buffer, dynamic, 5, STRINGS_OFFSET);
        dynamic = putDynamic(buffer, dynamic, 10, strings.length);
        dynamic = putDynamic(buffer, dynamic, 6, SYMBOLS_OFFSET);
        dynamic = putDynamic(buffer, dynamic, 11, 24);
        dynamic = putDynamic(buffer, dynamic, 4, SYSV_HASH_OFFSET);
        putDynamic(buffer, dynamic, 0x6ffffef5L, GNU_HASH_OFFSET);
        // The final entry is already the all-zero DT_NULL terminator.
        return value;
    }

    private static void putProgram(ByteBuffer buffer, int offset, int type, int flags,
                                   long fileOffset, long virtualAddress,
                                   long fileSize, long memorySize, long alignment) {
        buffer.putInt(offset, type);
        buffer.putInt(offset + 4, flags);
        buffer.putLong(offset + 8, fileOffset);
        buffer.putLong(offset + 16, virtualAddress);
        buffer.putLong(offset + 24, virtualAddress);
        buffer.putLong(offset + 32, fileSize);
        buffer.putLong(offset + 40, memorySize);
        buffer.putLong(offset + 48, alignment);
    }

    private static void putSymbol(ByteBuffer buffer, int offset, int name, long value) {
        buffer.putInt(offset, name);
        buffer.put(offset + 4, (byte) 0x12); // GLOBAL FUNC
        buffer.put(offset + 5, (byte) 0); // DEFAULT visibility
        buffer.putShort(offset + 6, (short) 1);
        buffer.putLong(offset + 8, value);
        buffer.putLong(offset + 16, 1L);
    }

    private static int putDynamic(ByteBuffer buffer, int offset, long tag, long value) {
        buffer.putLong(offset, tag);
        buffer.putLong(offset + 8, value);
        return offset + 16;
    }

    static long gnuHash(String name) {
        long hash = 5381L;
        for (byte value : name.getBytes(StandardCharsets.UTF_8)) {
            hash = ((hash << 5) + hash + (value & 0xffL)) & 0xffffffffL;
        }
        return hash;
    }
}
