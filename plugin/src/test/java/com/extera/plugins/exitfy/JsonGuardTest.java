package com.extera.plugins.exitfy;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class JsonGuardTest {
    @Test
    public void acceptsDepth64AndIgnoresQuotedBrackets() throws Exception {
        assertEquals(1, JsonGuard.array(nestedArray(64)).length());
        String quoted = "{\"value\":\"" + repeat('[', 128) + repeat('}', 128) + "\"}";
        assertEquals(256, JsonGuard.object(quoted).getString("value").length());
    }

    @Test
    public void rejectsDepth65BeforeAndroidJsonParser() {
        for (String value : new String[]{nestedArray(65), "{\"value\":" + nestedArray(64) + "}"}) {
            try {
                if (value.charAt(0) == '{') JsonGuard.object(value);
                else JsonGuard.array(value);
                throw new AssertionError("depth 65 JSON was accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("64"));
            } catch (Exception unexpected) {
                throw new AssertionError(unexpected);
            }
        }
    }

    @Test
    public void acceptsFiveThousandRichStoredNodeShapes() {
        StringBuilder json = new StringBuilder(3 * 1024 * 1024);
        json.append("{\"nodes\":[");
        for (int index = 0; index < 5_000; index++) {
            if (index > 0) json.append(',');
            json.append("{\"uri\":\"vless://node\",\"name\":\"n\",\"normalizedKey\":\"k\","
                    + "\"outbound\":{\"type\":\"vless\",\"server\":\"s\","
                    + "\"server_port\":443,\"uuid\":\"11111111-1111-1111-1111-111111111111\","
                    + "\"encryption\":\"none\",\"packet_encoding\":\"xudp\","
                    + "\"tls\":{\"enabled\":true,\"server_name\":\"s\",\"insecure\":false,"
                    + "\"alpn\":[\"h2\"],\"utls\":{\"enabled\":true,"
                    + "\"fingerprint\":\"chrome\"}},\"transport\":{\"type\":\"ws\","
                    + "\"path\":\"/\",\"headers\":{\"Host\":\"s\"},"
                    + "\"max_early_data\":2048}}}");
        }
        json.append("]}");

        JsonGuard.requireDepth(json.toString());
    }

    @Test
    public void rejectsMillionPrimitiveArrayBeforeAndroidParser() {
        StringBuilder json = new StringBuilder(2_100_000);
        json.append('[');
        for (int index = 0; index < 1_000_000; index++) {
            if (index > 0) json.append(',');
            json.append('0');
        }
        json.append(']');
        assertPreflightRejected(json.toString(), "structure");
    }

    @Test
    public void rejectsHundredsOfThousandsOfObjectPairsBeforeAndroidParser() {
        StringBuilder json = new StringBuilder(3_100_000);
        json.append('{');
        for (int index = 0; index < JsonGuard.MAX_STRUCTURAL_VALUES + 1; index++) {
            if (index > 0) json.append(',');
            json.append("\"a\":0");
        }
        json.append('}');
        assertPreflightRejected(json.toString(), "structure");
    }

    @Test
    public void enforcesDecodedStringTokenBoundary() throws Exception {
        String accepted = repeat('a', JsonGuard.MAX_STRING_BYTES);
        assertEquals(JsonGuard.MAX_STRING_BYTES,
                JsonGuard.object("{\"value\":\"" + accepted + "\"}")
                        .getString("value").length());
        assertPreflightRejected("{\"value\":\"" + accepted + "a\"}", "64 KiB");

        StringBuilder escaped = new StringBuilder(JsonGuard.MAX_STRING_BYTES * 6 + 32);
        escaped.append("{\"value\":\"");
        for (int index = 0; index < JsonGuard.MAX_STRING_BYTES; index++) {
            escaped.append("\\u0061");
        }
        escaped.append("\"}");
        JsonGuard.requireDepth(escaped.toString());
        escaped.insert(escaped.length() - 2, "\\u0061");
        assertPreflightRejected(escaped.toString(), "64 KiB");
    }

    @Test
    public void enforcesUnquotedScalarTokenBoundaryWithoutBreakingLenientJson() throws Exception {
        String accepted = repeat('a', JsonGuard.MAX_STRING_BYTES);
        assertEquals(accepted, JsonGuard.object("{value:" + accepted + "}")
                .getString("value"));
        assertPreflightRejected("{value:" + accepted + "a}", "64 KiB");

        String acceptedNumber = repeat('1', JsonGuard.MAX_STRING_BYTES);
        JsonGuard.requireDepth("{value:" + acceptedNumber + "}");
        assertPreflightRejected("{value:" + acceptedNumber + "1}", "64 KiB");
    }

    @Test
    public void commandEnvelopeAcceptsImportAboveGeneralTokenLimit() throws Exception {
        String text = repeat('a', JsonGuard.MAX_STRING_BYTES + 1);
        assertEquals(text.length(), JsonGuard.object(commandJson(text),
                        RuntimeCoordinator.MAX_COMMAND_TOKEN_UTF8_BYTES,
                        RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES)
                .getString("text").length());
        assertPreflightRejected(commandJson(text), "64 KiB");
    }

    @Test
    public void commandEnvelopeEnforcesEightMiBDecodedImportBoundary() throws Exception {
        String accepted = repeat('a', LimitedHttpClient.MAX_EXPANDED_BYTES);
        String acceptedCommand = commandJson(accepted);
        assertFalse(JsonGuard.exceedsUtf8Limit(
                acceptedCommand, RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES));
        assertEquals(LimitedHttpClient.MAX_EXPANDED_BYTES,
                JsonGuard.object(acceptedCommand,
                                RuntimeCoordinator.MAX_COMMAND_TOKEN_UTF8_BYTES,
                                RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES)
                        .getString("text").length());

        String rejectedCommand = commandJson(accepted + "a");
        try {
            JsonGuard.object(rejectedCommand,
                    RuntimeCoordinator.MAX_COMMAND_TOKEN_UTF8_BYTES,
                    RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES);
            throw new AssertionError("8 MiB + 1 import token was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("8 MiB"));
        }
        assertTrue(JsonGuard.exceedsUtf8Limit(
                accepted + "a", LimitedHttpClient.MAX_EXPANDED_BYTES));
    }

    @Test
    public void commandEnvelopeCarriesFullImportWithNewlinesAndQuotedText() throws Exception {
        String source = fullFiveThousandNodeImport();
        assertEquals(LimitedHttpClient.MAX_EXPANDED_BYTES - 1,
                source.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        String command = new org.json.JSONObject()
                .put("command", "import_text").put("text", source).toString();
        assertFalse(JsonGuard.exceedsUtf8Limit(
                command, RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES));
        assertEquals(source, JsonGuard.object(command,
                        RuntimeCoordinator.MAX_COMMAND_TOKEN_UTF8_BYTES,
                        RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES)
                .getString("text"));

        String quoted = repeat('"', LimitedHttpClient.MAX_EXPANDED_BYTES);
        String quotedCommand = new org.json.JSONObject()
                .put("command", "import_text").put("text", quoted).toString();
        assertFalse(JsonGuard.exceedsUtf8Limit(
                quotedCommand, RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES));
        assertEquals(quoted.length(), JsonGuard.object(quotedCommand,
                        RuntimeCoordinator.MAX_COMMAND_TOKEN_UTF8_BYTES,
                        RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES)
                .getString("text").length());
    }

    @Test
    public void commandEnvelopeRejectsHostileEscapingBeyondInternalCap() throws Exception {
        int controls = RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES / 6 + 1;
        assertTrue(controls < RuntimeCoordinator.MAX_COMMAND_TOKEN_UTF8_BYTES);
        StringBuilder command = new StringBuilder(controls * 6 + 64);
        command.append("{\"command\":\"import_text\",\"text\":\"");
        for (int index = 0; index < controls; index++) command.append("\\u0001");
        command.append("\"}");
        assertTrue(JsonGuard.exceedsUtf8Limit(
                command.toString(), RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES));
        try {
            JsonGuard.object(command.toString(),
                    RuntimeCoordinator.MAX_COMMAND_TOKEN_UTF8_BYTES,
                    RuntimeCoordinator.MAX_COMMAND_JSON_UTF8_BYTES);
            throw new AssertionError("oversized escaped command envelope was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("UTF-8 bytes"));
        }
    }

    @Test
    public void commandEnvelopeEnforcesTotalUtf8BoundaryBeforeParsing() throws Exception {
        String value = "{\"value\":\"кириллица 😀\"}";
        int exactBytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        assertEquals("кириллица 😀", JsonGuard.object(value, 1024, exactBytes)
                .getString("value"));
        try {
            JsonGuard.object(value, 1024, exactBytes - 1);
            throw new AssertionError("oversized command envelope was accepted");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("UTF-8 bytes"));
        }
    }

    @Test
    public void rejectsMismatchedAndUnterminatedTypedContainers() {
        for (String value : new String[]{"{\"a\":[1,2}", "{\"a\":[1,2]", "[1,2}}"}) {
            assertPreflightRejected(value, "mismatched");
        }
    }

    @Test
    public void interruptedPreflightStopsBeforeParsingAndPreservesFlag() throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicBoolean interruptPreserved = new AtomicBoolean();
        Thread worker = new Thread(() -> {
            Thread.currentThread().interrupt();
            try {
                JsonGuard.object("{\"value\":true}");
                failure.set(new AssertionError("interrupted JSON was parsed"));
            } catch (Throwable error) {
                failure.set(error);
            } finally {
                interruptPreserved.set(Thread.currentThread().isInterrupted());
            }
        }, "exitfy-json-preflight-cancel");
        worker.start();
        worker.join(2_000L);
        assertTrue("preflight worker did not finish", !worker.isAlive());
        assertTrue("unexpected error: " + failure.get(),
                failure.get() instanceof IllegalStateException
                        && failure.get().getMessage().contains("interrupted"));
        assertTrue("preflight cleared the interrupt flag", interruptPreserved.get());
    }

    private static void assertPreflightRejected(String value, String expectedMessage) {
        try {
            JsonGuard.requireDepth(value);
            throw new AssertionError("hostile JSON passed preflight");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains(expectedMessage));
        }
    }

    private static String nestedArray(int depth) {
        return repeat('[', depth) + "0" + repeat(']', depth);
    }

    private static String commandJson(String text) {
        return "{\"command\":\"import_text\",\"text\":\"" + text + "\"}";
    }

    private static String fullFiveThousandNodeImport() {
        final int count = SubscriptionParser.MAX_SOURCE_NODES;
        final int target = LimitedHttpClient.MAX_EXPANDED_BYTES - 1;
        final String base = "vless://11111111-1111-1111-1111-111111111111"
                + "@example.com:443?security=tls&type=ws&path=/";
        int fixed = count - 1;
        for (int index = 0; index < count; index++) {
            fixed += base.length() + String.valueOf(index).length();
        }
        int padding = target - fixed;
        int perNode = padding / count;
        int extra = padding % count;
        StringBuilder result = new StringBuilder(target);
        for (int index = 0; index < count; index++) {
            result.append(base);
            int currentPadding = perNode + (index < extra ? 1 : 0);
            for (int offset = 0; offset < currentPadding; offset++) result.append('a');
            result.append(index);
            if (index + 1 < count) result.append('\n');
        }
        return result.toString();
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int i = 0; i < count; i++) result.append(value);
        return result.toString();
    }
}
