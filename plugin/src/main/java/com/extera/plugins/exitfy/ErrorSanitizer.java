package com.extera.plugins.exitfy;

import java.util.Locale;
import java.util.regex.Pattern;

/** Bounds and redacts user-facing runtime errors without retaining details. */
final class ErrorSanitizer {
    private static final int MAX_INPUT_CHARS = 64 * 1024;
    private static final int MAX_OUTPUT_CODE_POINTS = 1024;
    private static final int MAX_OUTPUT_UTF8_BYTES = 4096;
    private static final Pattern PROXY_URI = Pattern.compile(
            "(?i)\\b(vless|vmess|trojan|ss|hy2|hysteria2?|tuic)://[^\\s]+"
    );
    private static final Pattern HTTP_URL = Pattern.compile("(?i)https?://[^\\s]+");
    private static final String SECRET_KEY =
            "password|passwd|pass|token|secret|uuid|proxy-authorization|authorization|"
                    + "auth_str|auth-str|auth|obfs-password|obfs_password|obfs|"
                    + "encryption|legacy_seed|legacy-seed|seed|path|headers|cookie|"
                    + "private_key|private-key|privatekey|pre_shared_key|pre-shared-key|"
                    + "presharedkey|psk|access_token|refresh_token|client_secret|"
                    + "x-api-key|x_api_key|api-key|api_key|x-hwid|hwid|username|user|id";
    private static final Pattern SECRET_FIELD = Pattern.compile(
            "(?i)\\b(" + SECRET_KEY + ")[\\\"']?\\s*[:=]\\s*.*$"
    );
    private static final Pattern LONG_HEX = Pattern.compile("(?i)\\b[0-9a-f]{16,}\\b");
    private static final Pattern UUID = Pattern.compile(
            "(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b"
    );

    private ErrorSanitizer() {
    }

    static String clean(String value) {
        String result = normalizeControls(prefixUtf16(value == null ? "" : value, MAX_INPUT_CHARS))
                .trim();
        result = PROXY_URI.matcher(result).replaceAll("$1://<redacted>");
        result = HTTP_URL.matcher(result).replaceAll("https://<redacted>");
        result = redactJsonSecrets(result);
        result = SECRET_FIELD.matcher(result).replaceAll("$1=<redacted>");
        result = UUID.matcher(result).replaceAll("<uuid>");
        result = LONG_HEX.matcher(result).replaceAll("<redacted>");
        return boundedOutput(result);
    }

    static String prefixUtf16(String value, int maxChars) {
        if (value == null || value.isEmpty() || maxChars <= 0) return "";
        if (value.length() <= maxChars) return value;
        int end = maxChars;
        if (end > 0 && Character.isHighSurrogate(value.charAt(end - 1))
                && Character.isLowSurrogate(value.charAt(end))) {
            end--;
        }
        return value.substring(0, end);
    }

    private static String boundedOutput(String value) {
        int index = 0;
        int codePoints = 0;
        int utf8Bytes = 0;
        while (index < value.length() && codePoints < MAX_OUTPUT_CODE_POINTS) {
            int codePoint = value.codePointAt(index);
            int encoded = codePoint <= 0x7f ? 1
                    : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
            if (encoded > MAX_OUTPUT_UTF8_BYTES - utf8Bytes) break;
            index += Character.charCount(codePoint);
            utf8Bytes += encoded;
            codePoints++;
        }
        return index == value.length() ? value : value.substring(0, index);
    }

    private static String normalizeControls(String value) {
        StringBuilder output = null;
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            char replacement = current == '\n' || current == '\r' ? ' ' : current;
            boolean remove = Character.isISOControl(replacement) && replacement != '\t';
            if (output == null && (remove || replacement != current)) {
                output = new StringBuilder(value.length());
                output.append(value, 0, index);
            }
            if (output != null && !remove) output.append(replacement);
        }
        return output == null ? value : output.toString();
    }

    private static String redactJsonSecrets(String value) {
        StringBuilder output = null;
        int copiedUntil = 0;
        int index = 0;
        while (index < value.length()) {
            if (value.charAt(index) != '"') {
                index++;
                continue;
            }
            int keyEnd = jsonStringEnd(value, index);
            if (keyEnd < 0) break;
            int colon = skipWhitespace(value, keyEnd + 1);
            if (colon >= value.length() || value.charAt(colon) != ':') {
                index = keyEnd + 1;
                continue;
            }
            String key = decodeJsonKey(value, index + 1, keyEnd);
            if (!isSecretKey(key)) {
                index = keyEnd + 1;
                continue;
            }
            int valueStart = skipWhitespace(value, colon + 1);
            int valueEnd = jsonValueEnd(value, valueStart);
            int boundary = skipWhitespace(value, valueEnd);
            if (boundary < value.length()) {
                char delimiter = value.charAt(boundary);
                if (delimiter != ',' && delimiter != '}') valueEnd = value.length();
            }
            if (output == null) output = new StringBuilder(value.length());
            output.append(value, copiedUntil, index)
                    .append("\"credential\":\"<redacted>\"");
            copiedUntil = valueEnd;
            index = valueEnd;
        }
        if (output == null) return value;
        output.append(value, copiedUntil, value.length());
        return output.toString();
    }

    private static int jsonStringEnd(String value, int quote) {
        for (int index = quote + 1; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current == '\\') index++;
            else if (current == '"') return index;
        }
        return -1;
    }

    private static int jsonValueEnd(String value, int start) {
        if (start >= value.length()) return value.length();
        char first = value.charAt(start);
        if (first == '"') {
            int end = jsonStringEnd(value, start);
            return end < 0 ? value.length() : end + 1;
        }
        if (first == '{' || first == '[') {
            char[] closers = new char[Math.min(64, Math.max(1, value.length() - start))];
            int depth = 0;
            for (int index = start; index < value.length(); index++) {
                char current = value.charAt(index);
                if (current == '"') {
                    int end = jsonStringEnd(value, index);
                    if (end < 0) return value.length();
                    index = end;
                } else if (current == '{' || current == '[') {
                    if (depth >= closers.length) return value.length();
                    closers[depth++] = current == '{' ? '}' : ']';
                } else if (current == '}' || current == ']') {
                    if (depth <= 0 || closers[depth - 1] != current) return value.length();
                    depth--;
                    if (depth == 0) return index + 1;
                }
            }
            return value.length();
        }
        int index = start;
        while (index < value.length()) {
            char current = value.charAt(index);
            if (current == ',' || current == '}' || current == ']'
                    || current == '\r' || current == '\n') break;
            index++;
        }
        String scalar = value.substring(start, index).trim();
        if (!scalar.equals("true") && !scalar.equals("false") && !scalar.equals("null")
                && !scalar.matches("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")) {
            return value.length();
        }
        return index;
    }

    private static int skipWhitespace(String value, int start) {
        int index = Math.max(0, start);
        while (index < value.length() && Character.isWhitespace(value.charAt(index))) index++;
        return index;
    }

    private static String decodeJsonKey(String value, int start, int end) {
        String raw = value.substring(start, end);
        if (raw.indexOf('\\') < 0) return raw;
        StringBuilder decoded = new StringBuilder(raw.length());
        for (int index = 0; index < raw.length(); index++) {
            char current = raw.charAt(index);
            if (current != '\\' || index + 1 >= raw.length()) {
                decoded.append(current);
                continue;
            }
            char escaped = raw.charAt(++index);
            if (escaped == 'u' && index + 4 < raw.length()) {
                int code = 0;
                boolean valid = true;
                for (int offset = 1; offset <= 4; offset++) {
                    int digit = Character.digit(raw.charAt(index + offset), 16);
                    if (digit < 0) {
                        valid = false;
                        break;
                    }
                    code = (code << 4) | digit;
                }
                if (valid) {
                    decoded.append((char) code);
                    index += 4;
                    continue;
                }
            }
            decoded.append(escaped);
        }
        return decoded.toString();
    }

    private static boolean isSecretKey(String key) {
        if (key == null) return false;
        switch (key.toLowerCase(Locale.US)) {
            case "password":
            case "passwd":
            case "pass":
            case "token":
            case "secret":
            case "uuid":
            case "authorization":
            case "proxy-authorization":
            case "auth_str":
            case "auth-str":
            case "auth":
            case "obfs-password":
            case "obfs_password":
            case "obfs":
            case "encryption":
            case "private_key":
            case "private-key":
            case "privatekey":
            case "pre_shared_key":
            case "pre-shared-key":
            case "presharedkey":
            case "psk":
            case "access_token":
            case "refresh_token":
            case "client_secret":
            case "legacy_seed":
            case "legacy-seed":
            case "seed":
            case "path":
            case "headers":
            case "cookie":
            case "x-api-key":
            case "x_api_key":
            case "api-key":
            case "api_key":
            case "x-hwid":
            case "hwid":
            case "username":
            case "user":
            case "id":
                return true;
            default:
                return false;
        }
    }
}
