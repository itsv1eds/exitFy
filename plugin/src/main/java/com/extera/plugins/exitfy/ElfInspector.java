package com.extera.plugins.exitfy;

import android.system.Os;
import android.system.OsConstants;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Bounded ELF loader-contract inspection.
 *
 * <p>Exports are derived from the same PT_DYNAMIC tables used by bionic, never
 * from the optional section table.  In addition to validating the dynamic
 * symbol shape, the inspector proves that every externally visible definition
 * is reachable through every advertised loader hash table.  This prevents a
 * forged SHT_DYNSYM, an un-hashed symbol, or a broken bucket/chain from passing
 * preflight only to fail after {@code dlopen()} has already run constructors.</p>
 */
final class ElfInspector {
    private static final int ET_DYN = 3;
    private static final int PT_LOAD = 1;
    private static final int PT_DYNAMIC = 2;
    private static final int PF_X = 1;

    private static final long DT_NULL = 0;
    private static final long DT_HASH = 4;
    private static final long DT_STRTAB = 5;
    private static final long DT_SYMTAB = 6;
    private static final long DT_STRSZ = 10;
    private static final long DT_SYMENT = 11;
    private static final long DT_GNU_HASH = 0x6ffffef5L;

    private static final int SHN_UNDEF = 0;
    private static final int SHN_LORESERVE = 0xff00;
    private static final int STB_LOCAL = 0;
    private static final int STB_GLOBAL = 1;
    private static final int STT_FUNC = 2;
    private static final int STV_DEFAULT = 0;
    private static final int STV_PROTECTED = 3;

    private static final int LEGACY_PAGE_SIZE = 4096;
    private static final long MAX_PROGRAM_HEADERS = 1024L;
    // DynamicSymbol retains a decoded name and several boxed/object fields.
    // A forged 64 MiB ELF can otherwise advertise a million entries and turn
    // bounded file inspection into a several-hundred-megabyte heap spike.
    // Real Android Go shared libraries stay far below this defensive ceiling.
    private static final long MAX_SYMBOLS = 65_536L;
    private static final int MAX_SYMBOL_NAME_BYTES = 4096;
    private static final Set<String> REQUIRED_EXPORTS = new HashSet<>(
            Arrays.asList("StartCore", "StopCore"));

    private ElfInspector() {
    }

    static Result inspect(File file, String expectedAbi) {
        if (file == null || !file.isFile()) return Result.error("core file is missing");
        try (FileReader reader = new FileReader(file)) {
            return inspect(reader, expectedAbi, runtimePageSize());
        } catch (Exception error) {
            return Result.error("malformed ELF");
        }
    }

    static Result inspect(byte[] value, String expectedAbi) {
        return inspect(value, expectedAbi, LEGACY_PAGE_SIZE);
    }

    static Result inspect(byte[] value, String expectedAbi, int requiredPageSize) {
        if (value == null) return Result.error("invalid ELF magic");
        try {
            return inspect(new ByteArrayReader(value), expectedAbi, requiredPageSize);
        } catch (Exception error) {
            return Result.error("malformed ELF");
        }
    }

    static Result inspect(Reader reader, String expectedAbi) {
        try {
            return inspect(reader, expectedAbi, runtimePageSize());
        } catch (Exception error) {
            return Result.error("malformed ELF");
        }
    }

    static Result inspect(Reader reader, String expectedAbi, int requiredPageSize)
            throws IOException {
        if (reader == null || reader.length() < 52
                || reader.u8(0) != 0x7f || reader.u8(1) != 'E'
                || reader.u8(2) != 'L' || reader.u8(3) != 'F') {
            return Result.error("invalid ELF magic");
        }
        int elfClass = reader.u8(4);
        if (elfClass != 1 && elfClass != 2) return Result.error("invalid ELF class");
        if (reader.u8(5) != 1) return Result.error("only little-endian ELF is supported");
        if (reader.u8(6) != 1) return Result.error("invalid ELF version");
        int osAbi = reader.u8(7);
        if (osAbi != 0 && osAbi != 3) return Result.error("unsupported ELF OS ABI");
        if (reader.u8(8) != 0) return Result.error("unsupported ELF ABI version");
        for (int index = 9; index < 16; index++) {
            if (reader.u8(index) != 0) return Result.error("invalid ELF identification padding");
        }

        boolean is64 = elfClass == 2;
        int nativeHeaderSize = is64 ? 64 : 52;
        if (reader.length() < nativeHeaderSize
                || reader.u16(16) != ET_DYN
                || reader.u32(20) != 1L
                || reader.u16(is64 ? 52 : 40) != nativeHeaderSize) {
            return Result.error("invalid ELF shared-object header");
        }
        int machine = reader.u16(18);
        if (!"arm64-v8a".equals(expectedAbi) || machine != 183) {
            return Result.error("ELF ABI mismatch");
        }
        if (!is64) {
            return Result.error("ELF class mismatch");
        }

        long programOffset = is64 ? reader.u64(32) : reader.u32(28);
        int programEntrySize = reader.u16(is64 ? 54 : 42);
        int programCount = reader.u16(is64 ? 56 : 44);
        int nativeProgramSize = is64 ? 56 : 32;
        long programTableSize = multiply(programEntrySize, programCount);
        if (programOffset <= 0 || programEntrySize != nativeProgramSize
                || programCount <= 0 || programCount > MAX_PROGRAM_HEADERS
                || !reader.range(programOffset, programTableSize)) {
            return Result.error("invalid ELF program table");
        }

        ArrayList<LoadSegment> loads = new ArrayList<>();
        DynamicSegment dynamic = null;
        long minimumLoadAlignment = Long.MAX_VALUE;
        int pageSize = Math.max(LEGACY_PAGE_SIZE, requiredPageSize);
        for (int index = 0; index < programCount; index++) {
            long entry = programOffset + (long) index * programEntrySize;
            long type = reader.u32(entry);
            long flags = is64 ? reader.u32(entry + 4) : reader.u32(entry + 24);
            long fileOffset = is64 ? reader.u64(entry + 8) : reader.u32(entry + 4);
            long virtualAddress = is64 ? reader.u64(entry + 16) : reader.u32(entry + 8);
            long fileSize = is64 ? reader.u64(entry + 32) : reader.u32(entry + 16);
            long memorySize = is64 ? reader.u64(entry + 40) : reader.u32(entry + 20);
            long alignment = is64 ? reader.u64(entry + 48) : reader.u32(entry + 28);
            if (fileSize > memorySize || !reader.range(fileOffset, fileSize)) {
                return Result.error("invalid ELF program segment");
            }
            if (type == PT_LOAD) {
                if (alignment <= 0 || (alignment & (alignment - 1L)) != 0L
                        || Math.floorMod(virtualAddress - fileOffset, alignment) != 0L) {
                    return Result.error("invalid PT_LOAD alignment");
                }
                minimumLoadAlignment = Math.min(minimumLoadAlignment, alignment);
                if (alignment < pageSize
                        || Math.floorMod(virtualAddress - fileOffset, pageSize) != 0L) {
                    return Result.error("core is incompatible with " + pageSize
                            + " byte memory pages");
                }
                loads.add(new LoadSegment(fileOffset, virtualAddress, fileSize,
                        memorySize, flags, alignment));
            } else if (type == PT_DYNAMIC) {
                if (dynamic != null) return Result.error("ELF has multiple PT_DYNAMIC segments");
                dynamic = new DynamicSegment(fileOffset, virtualAddress, fileSize);
            }
        }
        if (loads.isEmpty()) return Result.error("ELF has no PT_LOAD segments");
        if (dynamic == null) return Result.error("ELF has no PT_DYNAMIC segment");
        if (mappedOffset(loads, dynamic.virtualAddress, dynamic.fileSize) != dynamic.fileOffset) {
            return Result.error("PT_DYNAMIC mapping is inconsistent");
        }

        int nativeDynamicSize = is64 ? 16 : 8;
        if (dynamic.fileSize < nativeDynamicSize
                || dynamic.fileSize % nativeDynamicSize != 0L) {
            return Result.error("invalid PT_DYNAMIC size");
        }
        Map<Long, Long> tags = new HashMap<>();
        boolean nullSeen = false;
        for (long offset = dynamic.fileOffset;
             offset < dynamic.fileOffset + dynamic.fileSize;
             offset += nativeDynamicSize) {
            long tag = is64 ? reader.s64(offset) : reader.s32(offset);
            long value = is64 ? reader.u64(offset + 8) : reader.u32(offset + 4);
            if (nullSeen) {
                if (tag != DT_NULL || value != 0L) {
                    return Result.error("nonzero PT_DYNAMIC entry follows DT_NULL");
                }
                continue;
            }
            if (tag == DT_NULL) {
                nullSeen = true;
                continue;
            }
            if (isCriticalTag(tag) && tags.put(tag, value) != null) {
                return Result.error("duplicate critical PT_DYNAMIC tag");
            }
        }
        if (!nullSeen) return Result.error("PT_DYNAMIC is not terminated");
        if (!tags.containsKey(DT_SYMTAB) || !tags.containsKey(DT_STRTAB)
                || !tags.containsKey(DT_STRSZ) || !tags.containsKey(DT_SYMENT)) {
            return Result.error("required PT_DYNAMIC tag is missing");
        }
        if (!tags.containsKey(DT_HASH) && !tags.containsKey(DT_GNU_HASH)) {
            return Result.error("ELF has no loader hash table");
        }

        int nativeSymbolSize = is64 ? 24 : 16;
        if (tags.get(DT_SYMENT) != nativeSymbolSize) {
            return Result.error("DT_SYMENT does not match ELF class");
        }
        long stringsSize = tags.get(DT_STRSZ);
        if (stringsSize <= 0L) return Result.error("invalid DT_STRSZ");
        long stringsOffset = mappedOffset(loads, tags.get(DT_STRTAB), stringsSize);
        if (reader.u8(stringsOffset) != 0) return Result.error("DT_STRTAB must start with NUL");

        SysvHash sysv = tags.containsKey(DT_HASH)
                ? SysvHash.parse(reader, loads, tags.get(DT_HASH)) : null;
        GnuHash gnu = tags.containsKey(DT_GNU_HASH)
                ? GnuHash.parse(reader, loads, tags.get(DT_GNU_HASH), is64) : null;
        long symbolCount = sysv == null ? gnu.symbolCount : sysv.symbolCount;
        if (gnu != null && symbolCount != gnu.symbolCount) {
            return Result.error("loader hash tables disagree on symbol cardinality");
        }
        if (symbolCount <= 0L || symbolCount > MAX_SYMBOLS) {
            return Result.error("invalid dynamic symbol cardinality");
        }
        long symbolsBytes = multiply(symbolCount, nativeSymbolSize);
        long symbolsOffset = mappedOffset(loads, tags.get(DT_SYMTAB), symbolsBytes);

        ArrayList<DynamicSymbol> symbols = new ArrayList<>((int) symbolCount);
        for (int index = 0; index < symbolCount; index++) {
            long offset = symbolsOffset + (long) index * nativeSymbolSize;
            long nameOffset = reader.u32(offset);
            long value = is64 ? reader.u64(offset + 8) : reader.u32(offset + 4);
            long size = is64 ? reader.u64(offset + 16) : reader.u32(offset + 8);
            int info = reader.u8(offset + (is64 ? 4 : 12));
            int other = reader.u8(offset + (is64 ? 5 : 13));
            int sectionIndex = reader.u16(offset + (is64 ? 6 : 14));
            if (index == 0) {
                if (nameOffset != 0L || value != 0L || size != 0L || info != 0
                        || other != 0 || sectionIndex != 0) {
                    return Result.error("dynamic symbol table has no null entry");
                }
                symbols.add(DynamicSymbol.NULL);
                continue;
            }
            if ((other & ~0x03) != 0) {
                return Result.error("dynamic symbol visibility is invalid");
            }
            String name = reader.cString(stringsOffset + nameOffset,
                    stringsOffset + stringsSize, MAX_SYMBOL_NAME_BYTES);
            if (nameOffset >= stringsSize || name.isEmpty()) {
                return Result.error("dynamic symbol name is invalid");
            }
            symbols.add(new DynamicSymbol(name, value, info >>> 4, info & 0x0f,
                    other & 0x03, sectionIndex));
        }

        Map<String, ArrayList<DynamicSymbol>> required = new HashMap<>();
        for (String name : REQUIRED_EXPORTS) required.put(name, new ArrayList<>());
        Set<String> exports = new HashSet<>();
        for (int index = 1; index < symbols.size(); index++) {
            DynamicSymbol symbol = symbols.get(index);
            ArrayList<DynamicSymbol> occurrences = required.get(symbol.name);
            if (occurrences != null) occurrences.add(symbol);
            boolean externallyVisible = symbol.binding != STB_LOCAL
                    && (symbol.visibility == STV_DEFAULT
                    || symbol.visibility == STV_PROTECTED)
                    && symbol.sectionIndex != SHN_UNDEF;
            if (!externallyVisible) continue;
            if (sysv != null && !sysv.reaches(reader, symbols, symbol.name, index)) {
                return Result.error("defined symbol is not reachable through DT_HASH");
            }
            if (gnu != null && !gnu.reaches(reader, symbols, symbol.name, index)) {
                return Result.error("defined symbol is not reachable through DT_GNU_HASH");
            }
            if (!REQUIRED_EXPORTS.contains(symbol.name)) {
                return Result.error("defined core exports do not match the ABI");
            }
            exports.add(symbol.name);
        }

        for (Map.Entry<String, ArrayList<DynamicSymbol>> entry : required.entrySet()) {
            if (entry.getValue().size() != 1) {
                return Result.error("required core export is missing or duplicated");
            }
            DynamicSymbol symbol = entry.getValue().get(0);
            if (symbol.binding != STB_GLOBAL || symbol.type != STT_FUNC
                    || symbol.visibility != STV_DEFAULT
                    || symbol.sectionIndex == SHN_UNDEF
                    || symbol.sectionIndex >= SHN_LORESERVE
                    || !isExecutableFileBacked(loads, symbol.value)) {
                return Result.error("required core export has an invalid shape");
            }
        }
        if (!exports.equals(REQUIRED_EXPORTS)) {
            return Result.error("defined core function exports do not match the ABI");
        }
        return new Result(true, "", machine, is64, minimumLoadAlignment);
    }

    private static boolean isCriticalTag(long tag) {
        return tag == DT_HASH || tag == DT_STRTAB || tag == DT_SYMTAB
                || tag == DT_STRSZ || tag == DT_SYMENT || tag == DT_GNU_HASH;
    }

    private static boolean isExecutableFileBacked(ArrayList<LoadSegment> loads, long address) {
        for (LoadSegment load : loads) {
            if ((load.flags & PF_X) != 0L && address >= load.virtualAddress
                    && address - load.virtualAddress < load.fileSize) return true;
        }
        return false;
    }

    private static long mappedOffset(ArrayList<LoadSegment> loads, long address, long size)
            throws IOException {
        if (address < 0L || size < 0L) throw new IOException("invalid mapped address");
        Set<Long> candidates = new HashSet<>();
        for (LoadSegment load : loads) {
            if (address >= load.virtualAddress
                    && address - load.virtualAddress <= load.fileSize
                    && size <= load.fileSize - (address - load.virtualAddress)) {
                candidates.add(load.fileOffset + address - load.virtualAddress);
            }
        }
        if (candidates.size() != 1) throw new IOException("ambiguous PT_LOAD mapping");
        return candidates.iterator().next();
    }

    private static long mappedAvailable(ArrayList<LoadSegment> loads, long address)
            throws IOException {
        Set<Long> values = new HashSet<>();
        for (LoadSegment load : loads) {
            if (address >= load.virtualAddress
                    && address - load.virtualAddress < load.fileSize) {
                values.add(load.fileSize - (address - load.virtualAddress));
            }
        }
        if (values.size() != 1) throw new IOException("ambiguous PT_LOAD mapping");
        return values.iterator().next();
    }

    private static int runtimePageSize() {
        try {
            long value = Os.sysconf(OsConstants._SC_PAGESIZE);
            if (value >= LEGACY_PAGE_SIZE && value <= 64 * 1024L
                    && (value & (value - 1L)) == 0L) {
                return (int) value;
            }
        } catch (Throwable ignored) {
            // Host-side unit tests and older vendor builds may not expose sysconf.
        }
        return LEGACY_PAGE_SIZE;
    }

    private static long multiply(long left, long right) {
        if (left < 0 || right < 0 || (left != 0 && right > Long.MAX_VALUE / left)) return -1;
        return left * right;
    }

    private static long sysvNameHash(String name) {
        long hash = 0L;
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        for (byte item : bytes) {
            hash = (hash << 4) + (item & 0xffL);
            long high = hash & 0xf0000000L;
            if (high != 0L) hash ^= high >>> 24;
            hash &= ~high;
        }
        return hash & 0xffffffffL;
    }

    private static long gnuNameHash(String name) {
        long hash = 5381L;
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        for (byte item : bytes) hash = ((hash << 5) + hash + (item & 0xffL)) & 0xffffffffL;
        return hash;
    }

    interface Reader {
        long length();

        int read(long offset, byte[] output, int outputOffset, int count) throws IOException;

        default int u8(long offset) throws IOException {
            byte[] one = new byte[1];
            if (read(offset, one, 0, 1) != 1) throw new IOException("truncated ELF");
            return one[0] & 0xff;
        }

        default int u16(long offset) throws IOException {
            return u8(offset) | (u8(offset + 1) << 8);
        }

        default long u32(long offset) throws IOException {
            return (long) u8(offset) | ((long) u8(offset + 1) << 8)
                    | ((long) u8(offset + 2) << 16) | ((long) u8(offset + 3) << 24);
        }

        default int s32(long offset) throws IOException {
            return (int) u32(offset);
        }

        default long u64(long offset) throws IOException {
            long low = u32(offset);
            long high = u32(offset + 4);
            if ((high & 0x80000000L) != 0L) throw new IOException("ELF value exceeds signed range");
            return low | (high << 32);
        }

        /** Raw 64-bit word used for GNU bloom filters, where bit 63 is data. */
        default long bits64(long offset) throws IOException {
            return u32(offset) | (u32(offset + 4) << 32);
        }

        default long s64(long offset) throws IOException {
            long low = u32(offset);
            long high = u32(offset + 4);
            return low | (high << 32);
        }

        default boolean range(long offset, long size) {
            return offset >= 0 && size >= 0 && offset <= length() && size <= length() - offset;
        }

        default String cString(long start, long limit, int maximumBytes) throws IOException {
            if (!range(start, 0) || limit < start) return "";
            int length = (int) Math.min(Math.min(limit - start, maximumBytes + 1L),
                    Integer.MAX_VALUE);
            byte[] bytes = new byte[length];
            int count = 0;
            while (count < length) {
                int value = u8(start + count);
                if (value == 0) break;
                if (count == maximumBytes) throw new IOException("oversized ELF string");
                bytes[count++] = (byte) value;
            }
            if (count == length) throw new IOException("unterminated ELF string");
            try {
                return StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes, 0, count)).toString();
            } catch (CharacterCodingException error) {
                throw new IOException("invalid UTF-8 ELF string", error);
            }
        }
    }

    private static final class ByteArrayReader implements Reader {
        private final byte[] value;

        ByteArrayReader(byte[] value) {
            this.value = value;
        }

        @Override
        public long length() {
            return value.length;
        }

        @Override
        public int read(long offset, byte[] output, int outputOffset, int count)
                throws IOException {
            if (offset < 0 || count < 0 || offset > value.length
                    || count > value.length - offset) throw new IOException("truncated ELF");
            System.arraycopy(value, (int) offset, output, outputOffset, count);
            return count;
        }
    }

    private static final class FileReader implements Reader, Closeable {
        private final RandomAccessFile file;
        private final long length;

        FileReader(File value) throws IOException {
            this.file = new RandomAccessFile(value, "r");
            this.length = file.length();
        }

        @Override
        public long length() {
            return length;
        }

        @Override
        public synchronized int read(long offset, byte[] output, int outputOffset, int count)
                throws IOException {
            if (offset < 0 || count < 0 || offset > length || count > length - offset) {
                throw new IOException("truncated ELF");
            }
            file.seek(offset);
            int total = 0;
            while (total < count) {
                int read = file.read(output, outputOffset + total, count - total);
                if (read < 0) throw new IOException("truncated ELF");
                if (read > 0) total += read;
            }
            return total;
        }

        @Override
        public void close() throws IOException {
            file.close();
        }
    }

    private static final class LoadSegment {
        final long fileOffset;
        final long virtualAddress;
        final long fileSize;
        final long memorySize;
        final long flags;
        final long alignment;

        LoadSegment(long fileOffset, long virtualAddress, long fileSize,
                    long memorySize, long flags, long alignment) {
            this.fileOffset = fileOffset;
            this.virtualAddress = virtualAddress;
            this.fileSize = fileSize;
            this.memorySize = memorySize;
            this.flags = flags;
            this.alignment = alignment;
        }
    }

    private static final class DynamicSegment {
        final long fileOffset;
        final long virtualAddress;
        final long fileSize;

        DynamicSegment(long fileOffset, long virtualAddress, long fileSize) {
            this.fileOffset = fileOffset;
            this.virtualAddress = virtualAddress;
            this.fileSize = fileSize;
        }
    }

    private static final class DynamicSymbol {
        static final DynamicSymbol NULL = new DynamicSymbol("", 0L, 0, 0, 0, 0);
        final String name;
        final long value;
        final int binding;
        final int type;
        final int visibility;
        final int sectionIndex;

        DynamicSymbol(String name, long value, int binding, int type,
                      int visibility, int sectionIndex) {
            this.name = name;
            this.value = value;
            this.binding = binding;
            this.type = type;
            this.visibility = visibility;
            this.sectionIndex = sectionIndex;
        }
    }

    private static final class SysvHash {
        final long symbolCount;
        final long bucketCount;
        final long bucketsOffset;
        final long chainsOffset;

        SysvHash(long symbolCount, long bucketCount, long bucketsOffset, long chainsOffset) {
            this.symbolCount = symbolCount;
            this.bucketCount = bucketCount;
            this.bucketsOffset = bucketsOffset;
            this.chainsOffset = chainsOffset;
        }

        static SysvHash parse(Reader reader, ArrayList<LoadSegment> loads, long address)
                throws IOException {
            long offset = mappedOffset(loads, address, 8L);
            long bucketCount = reader.u32(offset);
            long symbolCount = reader.u32(offset + 4);
            if (bucketCount <= 0L || bucketCount > MAX_SYMBOLS
                    || symbolCount <= 0L || symbolCount > MAX_SYMBOLS) {
                throw new IOException("invalid DT_HASH cardinality");
            }
            long tableSize = 8L + multiply(4L, bucketCount + symbolCount);
            offset = mappedOffset(loads, address, tableSize);
            long buckets = offset + 8L;
            long chains = buckets + bucketCount * 4L;
            for (long index = 0; index < bucketCount; index++) {
                long value = reader.u32(buckets + index * 4L);
                if (value >= symbolCount && value != 0L) {
                    throw new IOException("DT_HASH bucket escapes dynsym");
                }
            }
            for (long index = 0; index < symbolCount; index++) {
                long value = reader.u32(chains + index * 4L);
                if (value >= symbolCount && value != 0L) {
                    throw new IOException("DT_HASH chain escapes dynsym");
                }
            }
            return new SysvHash(symbolCount, bucketCount, buckets, chains);
        }

        boolean reaches(Reader reader, ArrayList<DynamicSymbol> symbols,
                        String name, int target) throws IOException {
            long hash = sysvNameHash(name);
            long index = reader.u32(bucketsOffset + (hash % bucketCount) * 4L);
            int steps = 0;
            while (index != 0L) {
                if (index >= symbolCount || ++steps > symbolCount) {
                    throw new IOException("DT_HASH chain loops");
                }
                if (index == target && name.equals(symbols.get((int) index).name)) return true;
                index = reader.u32(chainsOffset + index * 4L);
            }
            return false;
        }
    }

    private static final class GnuHash {
        final long symbolCount;
        final long symbolOffset;
        final long bucketCount;
        final long bloomOffset;
        final long bloomSize;
        final int bloomShift;
        final int wordBits;
        final long bucketsOffset;
        final long chainsAddress;
        final long maximumChains;
        final ArrayList<LoadSegment> loads;

        GnuHash(long symbolCount, long symbolOffset, long bucketCount,
                long bloomOffset, long bloomSize, int bloomShift, int wordBits,
                long bucketsOffset, long chainsAddress, long maximumChains,
                ArrayList<LoadSegment> loads) {
            this.symbolCount = symbolCount;
            this.symbolOffset = symbolOffset;
            this.bucketCount = bucketCount;
            this.bloomOffset = bloomOffset;
            this.bloomSize = bloomSize;
            this.bloomShift = bloomShift;
            this.wordBits = wordBits;
            this.bucketsOffset = bucketsOffset;
            this.chainsAddress = chainsAddress;
            this.maximumChains = maximumChains;
            this.loads = loads;
        }

        static GnuHash parse(Reader reader, ArrayList<LoadSegment> loads,
                             long address, boolean is64) throws IOException {
            long offset = mappedOffset(loads, address, 16L);
            long bucketCount = reader.u32(offset);
            long symbolOffset = reader.u32(offset + 4);
            long bloomSize = reader.u32(offset + 8);
            long bloomShiftValue = reader.u32(offset + 12);
            if (bucketCount <= 0L || bucketCount > MAX_SYMBOLS
                    || bloomSize <= 0L || bloomSize > MAX_SYMBOLS
                    || (bloomSize & (bloomSize - 1L)) != 0L
                    || symbolOffset <= 0L || symbolOffset > MAX_SYMBOLS
                    || bloomShiftValue >= 32L) {
                throw new IOException("invalid DT_GNU_HASH header");
            }
            long wordSize = is64 ? 8L : 4L;
            long bloomAddress = address + 16L;
            long bloomBytes = multiply(bloomSize, wordSize);
            long bloomOffset = mappedOffset(loads, bloomAddress, bloomBytes);
            long bucketsAddress = bloomAddress + bloomBytes;
            long bucketsSize = multiply(bucketCount, 4L);
            long bucketsOffset = mappedOffset(loads, bucketsAddress, bucketsSize);
            long chainsAddress = bucketsAddress + bucketsSize;
            long maximumChains = Math.min(mappedAvailable(loads, chainsAddress) / 4L,
                    MAX_SYMBOLS);
            int[] terminals = new int[(int) maximumChains];
            Arrays.fill(terminals, -1);
            long maximumTerminal = symbolOffset - 1L;
            for (long bucket = 0; bucket < bucketCount; bucket++) {
                long start = reader.u32(bucketsOffset + bucket * 4L);
                if (start == 0L) continue;
                if (start < symbolOffset || start > MAX_SYMBOLS) {
                    throw new IOException("invalid DT_GNU_HASH bucket");
                }
                long index = start;
                ArrayList<Integer> visited = new ArrayList<>();
                long terminal;
                while (true) {
                    long relative = index - symbolOffset;
                    if (relative < 0L || relative >= maximumChains) {
                        throw new IOException("DT_GNU_HASH chain escapes PT_LOAD");
                    }
                    int cached = terminals[(int) relative];
                    if (cached >= 0) {
                        terminal = cached;
                        break;
                    }
                    visited.add((int) relative);
                    long chainOffset = mappedOffset(loads, chainsAddress + relative * 4L, 4L);
                    long value = reader.u32(chainOffset);
                    if ((value & 1L) != 0L) {
                        terminal = index;
                        break;
                    }
                    index++;
                    if (index > MAX_SYMBOLS || visited.size() > MAX_SYMBOLS) {
                        throw new IOException("DT_GNU_HASH chain exceeds limit");
                    }
                }
                for (int relative : visited) terminals[relative] = (int) terminal;
                maximumTerminal = Math.max(maximumTerminal, terminal);
            }
            long symbolCount = Math.max(symbolOffset, maximumTerminal + 1L);
            if (symbolCount <= 0L || symbolCount > MAX_SYMBOLS) {
                throw new IOException("invalid DT_GNU_HASH cardinality");
            }
            return new GnuHash(symbolCount, symbolOffset, bucketCount,
                    bloomOffset, bloomSize, (int) bloomShiftValue, is64 ? 64 : 32,
                    bucketsOffset, chainsAddress, maximumChains, loads);
        }

        boolean reaches(Reader reader, ArrayList<DynamicSymbol> symbols,
                        String name, int target) throws IOException {
            if (target < symbolOffset) return false;
            long hash = gnuNameHash(name);
            long bloomWordIndex = (hash / wordBits) & (bloomSize - 1L);
            long bloomWord = wordBits == 64
                    ? reader.bits64(bloomOffset + bloomWordIndex * 8L)
                    : reader.u32(bloomOffset + bloomWordIndex * 4L);
            long bloomMask = (1L << (int) (hash % wordBits))
                    | (1L << (int) ((hash >>> bloomShift) % wordBits));
            if ((bloomWord & bloomMask) != bloomMask) return false;
            long index = reader.u32(bucketsOffset + (hash % bucketCount) * 4L);
            if (index == 0L || index < symbolOffset) return false;
            int steps = 0;
            while (true) {
                long relative = index - symbolOffset;
                if (relative < 0L || relative >= maximumChains || index >= symbols.size()
                        || ++steps > MAX_SYMBOLS) {
                    throw new IOException("DT_GNU_HASH lookup escapes dynsym");
                }
                long chainOffset = mappedOffset(loads, chainsAddress + relative * 4L, 4L);
                long chain = reader.u32(chainOffset);
                if ((chain | 1L) == (hash | 1L)
                        && index == target && name.equals(symbols.get((int) index).name)) {
                    return true;
                }
                if ((chain & 1L) != 0L) return false;
                index++;
            }
        }
    }

    static final class Result {
        final boolean valid;
        final String error;
        final int machine;
        final boolean is64;
        final long minimumLoadAlignment;

        Result(boolean valid, String error, int machine, boolean is64,
               long minimumLoadAlignment) {
            this.valid = valid;
            this.error = error;
            this.machine = machine;
            this.is64 = is64;
            this.minimumLoadAlignment = minimumLoadAlignment;
        }

        static Result error(String message) {
            return new Result(false, message, 0, false, 0L);
        }
    }
}
