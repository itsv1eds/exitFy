package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/** Bounds recursive Android JSON parsing before JSONObject/JSONArray see the input. */
final class JsonGuard {
    static final int MAX_DEPTH = 64;
    // Ten thousand normal stored proxy nodes remain below this value, while a
    // low-entropy JSON array/object cannot make Android's recursive org.json
    // parser allocate millions of boxed values.  The byte-size boundary is
    // enforced independently by each caller (8 MiB for imported/stored data).
    static final int MAX_STRUCTURAL_VALUES = 500_000;
    static final int MAX_STRING_BYTES = 64 * 1024;
    private static final int INTERRUPT_CHECK_MASK = 0x0fff;

    private JsonGuard() {
    }

    static void requireDepth(String value) {
        requireDepth(value, MAX_STRING_BYTES);
    }

    /**
     * Command envelopes may intentionally carry one bounded import string
     * which is larger than a normal persisted JSON scalar. Callers must still
     * impose their own total-wire and field-specific limits.
     */
    static void requireDepth(String value, int maxStringBytes) {
        if (maxStringBytes <= 0) {
            throw new IllegalArgumentException("JSON token limit must be positive");
        }
        String input = value == null ? "" : value;
        char[] stack = new char[MAX_DEPTH];
        boolean[] arrayHasContent = new boolean[MAX_DEPTH];
        int depth = 0;
        int structuralValues = input.isEmpty() ? 0 : 1;
        char quote = 0;
        boolean lineComment = false;
        boolean blockComment = false;
        boolean bareToken = false;
        DecodedStringBudget stringBudget = new DecodedStringBudget(maxStringBytes);
        DecodedStringBudget bareBudget = new DecodedStringBudget(maxStringBytes);
        for (int index = 0; index < input.length(); index++) {
            if ((index & INTERRUPT_CHECK_MASK) == 0
                    && Thread.currentThread().isInterrupted()) {
                throw interrupted();
            }
            char current = input.charAt(index);

            if (lineComment) {
                if (current == '\n' || current == '\r') lineComment = false;
                continue;
            }
            if (blockComment) {
                if (current == '*' && index + 1 < input.length()
                        && input.charAt(index + 1) == '/') {
                    blockComment = false;
                    index++;
                }
                continue;
            }

            if (quote != 0) {
                if (current == quote) {
                    stringBudget.finish();
                    quote = 0;
                    continue;
                }
                if (current == '\\') {
                    if (++index >= input.length()) throw invalidStructure();
                    char escaped = input.charAt(index);
                    if (escaped == 'u') {
                        if (index + 4 >= input.length()) throw invalidUnicodeEscape();
                        int code = 0;
                        for (int offset = 1; offset <= 4; offset++) {
                            int digit = Character.digit(input.charAt(index + offset), 16);
                            if (digit < 0) throw invalidUnicodeEscape();
                            code = (code << 4) | digit;
                        }
                        stringBudget.add((char) code);
                        index += 4;
                    } else {
                        if (escaped < 0x20) throw invalidStructure();
                        stringBudget.add(decodedEscape(escaped));
                    }
                    continue;
                }
                if (current < 0x20) throw invalidStructure();
                stringBudget.add(current);
                continue;
            }

            if (current == '/' && index + 1 < input.length()) {
                char next = input.charAt(index + 1);
                if (next == '/') {
                    if (bareToken) bareBudget.finish();
                    bareToken = false;
                    lineComment = true;
                    index++;
                    continue;
                }
                if (next == '*') {
                    if (bareToken) bareBudget.finish();
                    bareToken = false;
                    blockComment = true;
                    index++;
                    continue;
                }
            } else if (current == '#') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
                lineComment = true;
                continue;
            }

            if (current == '"' || current == '\'') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
                markArrayContent(stack, arrayHasContent, depth);
                quote = current;
                stringBudget.reset();
            } else if (current == '{' || current == '[') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
                markArrayContent(stack, arrayHasContent, depth);
                if (depth >= MAX_DEPTH) throw tooDeep(null);
                stack[depth] = current;
                arrayHasContent[depth] = false;
                depth++;
            } else if (current == '}' || current == ']') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
                char expected = current == '}' ? '{' : '[';
                if (depth <= 0 || stack[depth - 1] != expected) throw invalidStructure();
                if (current == ']' && arrayHasContent[depth - 1]) {
                    structuralValues = addStructuralValue(structuralValues);
                }
                depth--;
            } else if (current == ':') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
                structuralValues = addStructuralValue(structuralValues);
            } else if (current == '=') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
                structuralValues = addStructuralValue(structuralValues);
                // Android JSONTokener accepts both '=' and the legacy '=>'.
                if (index + 1 < input.length() && input.charAt(index + 1) == '>') index++;
            } else if (current == ',' || current == ';') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
                if (depth > 0 && stack[depth - 1] == '[') {
                    structuralValues = addStructuralValue(structuralValues);
                }
            } else if (Character.isWhitespace(current) || current == '/' || current == '\\') {
                if (bareToken) bareBudget.finish();
                bareToken = false;
            } else {
                markArrayContent(stack, arrayHasContent, depth);
                if (!bareToken) {
                    bareToken = true;
                    bareBudget.reset();
                }
                bareBudget.add(current);
            }
        }
        if (bareToken) bareBudget.finish();
        if (Thread.currentThread().isInterrupted()) throw interrupted();
        if (quote != 0 || blockComment || depth != 0) throw invalidStructure();
    }

    static JSONObject object(String value) throws JSONException {
        requireDepth(value);
        try {
            return new JSONObject(value == null ? "{}" : value);
        } catch (StackOverflowError error) {
            throw tooDeep(error);
        }
    }

    static JSONObject object(String value, int maxStringBytes, int maxTotalUtf8Bytes)
            throws JSONException {
        String input = value == null ? "{}" : value;
        if (exceedsUtf8Limit(input, maxTotalUtf8Bytes)) {
            throw new IllegalArgumentException(
                    "JSON input exceeds " + maxTotalUtf8Bytes + " UTF-8 bytes");
        }
        requireDepth(input, maxStringBytes);
        try {
            return new JSONObject(input);
        } catch (StackOverflowError error) {
            throw tooDeep(error);
        }
    }

    static JSONObject objectUtf8(byte[] value) throws JSONException {
        // JSONObject requires a String. Keep exactly one decoded input String;
        // requireDepth() runs before org.json creates its object graph or
        // unescapes another large string token.
        return object(value == null ? null : new String(value, StandardCharsets.UTF_8));
    }

    static JSONArray array(String value) throws JSONException {
        requireDepth(value);
        try {
            return new JSONArray(value == null ? "[]" : value);
        } catch (StackOverflowError error) {
            throw tooDeep(error);
        }
    }

    static boolean exceedsUtf8Limit(String value, int limit) {
        if (limit < 0) throw new IllegalArgumentException("UTF-8 limit must not be negative");
        if (value == null) return false;
        long bytes = 0L;
        for (int index = 0; index < value.length(); index++) {
            if ((index & INTERRUPT_CHECK_MASK) == 0
                    && Thread.currentThread().isInterrupted()) {
                throw interrupted();
            }
            char current = value.charAt(index);
            if (current <= 0x7f) {
                bytes++;
            } else if (current <= 0x7ff) {
                bytes += 2;
            } else if (Character.isHighSurrogate(current) && index + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(index + 1))) {
                bytes += 4;
                index++;
            } else {
                // Conservatively account for malformed UTF-16 as U+FFFD.
                bytes += 3;
            }
            if (bytes > limit) return true;
        }
        if (Thread.currentThread().isInterrupted()) throw interrupted();
        return false;
    }

    private static IllegalArgumentException tooDeep(StackOverflowError cause) {
        return cause == null
                ? new IllegalArgumentException("JSON nesting exceeds 64")
                : new IllegalArgumentException("JSON nesting exceeds 64", cause);
    }

    private static void markArrayContent(char[] stack, boolean[] arrayHasContent,
                                         int depth) {
        if (depth > 0 && stack[depth - 1] == '[') arrayHasContent[depth - 1] = true;
    }

    private static int addStructuralValue(int current) {
        if (current >= MAX_STRUCTURAL_VALUES) {
            throw new IllegalArgumentException(
                    "JSON structure exceeds " + MAX_STRUCTURAL_VALUES + " values");
        }
        return current + 1;
    }

    private static char decodedEscape(char escaped) {
        switch (escaped) {
            case 'b':
                return '\b';
            case 'f':
                return '\f';
            case 'n':
                return '\n';
            case 'r':
                return '\r';
            case 't':
                return '\t';
            default:
                // Android's JSONTokener accepts the standard quote, slash and
                // backslash escapes and historically treats other escaped
                // printable characters literally. Counting the decoded code
                // unit here is conservative and preserves that compatibility.
                return escaped;
        }
    }

    private static IllegalArgumentException invalidUnicodeEscape() {
        return new IllegalArgumentException("JSON contains an invalid Unicode escape");
    }

    private static IllegalArgumentException invalidStructure() {
        return new IllegalArgumentException("JSON structure is mismatched or unterminated");
    }

    private static IllegalStateException interrupted() {
        return new IllegalStateException("JSON preflight interrupted");
    }

    private static final class DecodedStringBudget {
        private final int maximumBytes;
        private int bytes;
        private char pendingHighSurrogate;

        DecodedStringBudget(int maximumBytes) {
            this.maximumBytes = maximumBytes;
        }

        void reset() {
            bytes = 0;
            pendingHighSurrogate = 0;
        }

        void add(char value) {
            if (pendingHighSurrogate != 0) {
                if (Character.isLowSurrogate(value)) {
                    addBytes(4);
                    pendingHighSurrogate = 0;
                    return;
                }
                // Match UTF-8 replacement behavior conservatively for a lone
                // decoded UTF-16 surrogate, then process the current unit.
                addBytes(3);
                pendingHighSurrogate = 0;
            }
            if (Character.isHighSurrogate(value)) {
                pendingHighSurrogate = value;
            } else if (Character.isLowSurrogate(value)) {
                addBytes(3);
            } else if (value <= 0x7f) {
                addBytes(1);
            } else if (value <= 0x7ff) {
                addBytes(2);
            } else {
                addBytes(3);
            }
        }

        void finish() {
            if (pendingHighSurrogate != 0) {
                addBytes(3);
                pendingHighSurrogate = 0;
            }
        }

        private void addBytes(int count) {
            if (bytes > maximumBytes - count) {
                throw new IllegalArgumentException(
                        "JSON string or scalar token exceeds "
                                + describeByteLimit(maximumBytes));
            }
            bytes += count;
        }
    }

    private static String describeByteLimit(int bytes) {
        if (bytes > 0 && bytes % (1024 * 1024) == 0) {
            return (bytes / (1024 * 1024)) + " MiB";
        }
        if (bytes > 0 && bytes % 1024 == 0) return (bytes / 1024) + " KiB";
        return bytes + " bytes";
    }
}
