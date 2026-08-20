package com.extera.plugins.exitfy;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime-only access to bundled endpoints. This is deliberately a static
 * extraction deterrent, not a claim that a client-held value is secret from a
 * debugger or a hooked process.
 */
final class ProviderCatalog {
    private static final int MAX_ENDPOINT_BYTES = 4096;
    private static final int TAG_BYTES = 16;
    private static volatile boolean verified;

    private ProviderCatalog() {
    }

    static int size() {
        return ProviderCatalogData.size();
    }

    static boolean isEnabled(int index) {
        return index >= 0 && index < size() && ProviderCatalogData.enabled(index);
    }

    static String storageKey(int index) {
        if (index < 0 || index >= size()) throw unavailable();
        return "@" + Integer.toHexString(0x6e31 ^ (index * 0x25d7));
    }

    /**
     * Opaque revision for the encrypted catalog slot. The authenticated tag is
     * generated from fresh random material whenever the private endpoint is
     * regenerated, so it invalidates stale cache entries without persisting a
     * URL-derived value which could help recover the endpoint.
     */
    static String revision(int index) {
        if (!isEnabled(index)) throw unavailable();
        byte[] tag = null;
        try {
            tag = ProviderCatalogData.tag(index);
            if (tag.length != TAG_BYTES) throw unavailable();
            char[] output = new char[tag.length * 2];
            final char[] alphabet = "0123456789abcdef".toCharArray();
            for (int position = 0; position < tag.length; position++) {
                int value = tag[position] & 0xff;
                output[position * 2] = alphabet[value >>> 4];
                output[position * 2 + 1] = alphabet[value & 0x0f];
            }
            return new String(output);
        } finally {
            wipe(tag);
        }
    }

    static void verify() {
        if (verified) return;
        synchronized (ProviderCatalog.class) {
            if (verified) return;
            String previous = null;
            for (int index = 0; index < size(); index++) {
                if (!isEnabled(index)) continue;
                String value = endpoint(index);
                if (value.equals(previous)) throw unavailable();
                previous = value;
            }
            verified = true;
        }
    }

    static String endpoint(int index) {
        if (!isEnabled(index)) throw unavailable();
        byte[] first = null;
        byte[] second = null;
        byte[] mixer = null;
        byte[] root = null;
        byte[] streamKey = null;
        byte[] checkKey = null;
        byte[] nonce = null;
        byte[] payload = null;
        byte[] suppliedTag = null;
        byte[] expectedTag = null;
        byte[] fullTag = null;
        byte[] plain = null;
        try {
            first = CatalogMaterialA.value(index);
            second = CatalogMaterialB.value(index);
            mixer = mixer(index);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(first);
            digest.update(mixer);
            root = digest.digest(second);
            streamKey = hmac(root, new byte[]{0x31, (byte) index, 0x5c});
            checkKey = hmac(root, new byte[]{0x72, (byte) index, (byte) 0xa6});

            nonce = ProviderCatalogData.nonce(index);
            payload = ProviderCatalogData.payload(index);
            suppliedTag = ProviderCatalogData.tag(index);
            Mac checker = newMac(checkKey);
            checker.update((byte) index);
            checker.update(nonce);
            fullTag = checker.doFinal(payload);
            expectedTag = Arrays.copyOf(fullTag, TAG_BYTES);
            if (!MessageDigest.isEqual(expectedTag, suppliedTag)) throw unavailable();

            plain = transform(payload, nonce, streamKey);
            if (plain.length == 0 || plain.length > MAX_ENDPOINT_BYTES) throw unavailable();
            String value = strictUtf8(plain);
            URI parsed = new URI(value);
            if (!"https".equalsIgnoreCase(parsed.getScheme())
                    || parsed.getHost() == null || parsed.getHost().isEmpty()
                    || parsed.getRawUserInfo() != null || parsed.getRawFragment() != null) {
                throw unavailable();
            }
            return value;
        } catch (IllegalStateException error) {
            throw error;
        } catch (Exception error) {
            throw unavailable();
        } finally {
            wipe(first);
            wipe(second);
            wipe(mixer);
            wipe(root);
            wipe(streamKey);
            wipe(checkKey);
            wipe(nonce);
            wipe(payload);
            wipe(suppliedTag);
            wipe(expectedTag);
            wipe(fullTag);
            wipe(plain);
        }
    }

    private static byte[] transform(byte[] input, byte[] nonce, byte[] key) throws Exception {
        byte[] output = new byte[input.length];
        byte[] blockInput = Arrays.copyOf(nonce, nonce.length + 4);
        byte[] block = null;
        try {
            int offset = 0;
            int counter = 0;
            while (offset < input.length) {
                int tail = blockInput.length - 4;
                blockInput[tail] = (byte) (counter >>> 24);
                blockInput[tail + 1] = (byte) (counter >>> 16);
                blockInput[tail + 2] = (byte) (counter >>> 8);
                blockInput[tail + 3] = (byte) counter;
                block = hmac(key, blockInput);
                int count = Math.min(block.length, input.length - offset);
                for (int index = 0; index < count; index++) {
                    output[offset + index] = (byte) (input[offset + index] ^ block[index]);
                }
                offset += count;
                counter++;
                wipe(block);
                block = null;
            }
            return output;
        } finally {
            wipe(blockInput);
            wipe(block);
        }
    }

    private static byte[] mixer(int index) {
        byte[] output = new byte[24];
        long state = 0x6a09e667f3bcc909L
                ^ ((long) (index + 1) * 0x9e3779b97f4a7c15L);
        for (int position = 0; position < output.length; position++) {
            state ^= state >>> 12;
            state ^= state << 25;
            state ^= state >>> 27;
            state *= 0x2545f4914f6cdd1dL;
            output[position] = (byte) (state >>> ((position & 7) * 8));
        }
        return output;
    }

    private static byte[] hmac(byte[] key, byte[] value) throws Exception {
        return newMac(key).doFinal(value);
    }

    private static Mac newMac(byte[] key) throws Exception {
        Mac value = Mac.getInstance("HmacSHA256");
        value.init(new SecretKeySpec(key, "HmacSHA256"));
        return value;
    }

    private static String strictUtf8(byte[] value) throws Exception {
        CharBuffer decoded = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value));
        return decoded.toString();
    }

    private static void wipe(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("built-in source unavailable");
    }
}
