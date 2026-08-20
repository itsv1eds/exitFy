package com.extera.plugins.exitfy;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ExitFyCommandResultTest {
    @Test
    public void parsesCompleteRuntimeEnvelope() throws Exception {
        ExitFyCommandResult result = ExitFyCommandResult.parse(new JSONObject()
                .put("ok", true)
                .put("message", "Ready")
                .put("data", "{\"nodes\":[]}")
                .toString());

        assertTrue(result.ok);
        assertEquals("Ready", result.message);
        assertEquals("{\"nodes\":[]}", result.data);
    }

    @Test
    public void preservesExactlyTwoMibOfUtf8Data() throws Exception {
        String data = repeated('x', ExitFyCommandResult.MAX_DATA_UTF8_BYTES);

        ExitFyCommandResult result = ExitFyCommandResult.parse(new JSONObject()
                .put("ok", true)
                .put("message", "")
                .put("data", data)
                .toString());

        assertTrue(result.ok);
        assertEquals(ExitFyCommandResult.MAX_DATA_UTF8_BYTES, result.data.length());
    }

    @Test
    public void rejectsDataOneByteOverLimitWithoutRetainingIt() throws Exception {
        String data = repeated('x', ExitFyCommandResult.MAX_DATA_UTF8_BYTES + 1);

        ExitFyCommandResult result = ExitFyCommandResult.parse(new JSONObject()
                .put("ok", true)
                .put("message", "must not survive")
                .put("data", data)
                .toString());

        assertFalse(result.ok);
        assertFalse(result.message.isEmpty());
        assertEquals("", result.data);
    }

    @Test
    public void utf8LimitCountsMultibyteCodePoints() throws Exception {
        StringBuilder data = new StringBuilder();
        for (int index = 0; index < ExitFyCommandResult.MAX_DATA_UTF8_BYTES / 4; index++) {
            data.append("🚀");
        }
        ExitFyCommandResult accepted = ExitFyCommandResult.parse(new JSONObject()
                .put("ok", true).put("message", "").put("data", data.toString())
                .toString());
        assertTrue(accepted.ok);

        data.append("🚀");
        ExitFyCommandResult rejected = ExitFyCommandResult.parse(new JSONObject()
                .put("ok", true).put("message", "").put("data", data.toString())
                .toString());
        assertFalse(rejected.ok);
        assertEquals("", rejected.data);
    }

    @Test
    public void malformedMissingAndWrongTypedResponsesAreSafeFailures() throws Exception {
        String[] invalid = {
                null,
                "",
                "{",
                "{}",
                new JSONObject().put("ok", "true")
                        .put("message", "").put("data", "").toString(),
                new JSONObject().put("ok", true)
                        .put("message", new JSONObject()).put("data", "").toString(),
                new JSONObject().put("ok", true)
                        .put("message", "").put("data", new JSONObject()).toString(),
        };
        for (String value : invalid) {
            ExitFyCommandResult result = ExitFyCommandResult.parse(value);
            assertFalse(result.ok);
            assertFalse(result.message.isEmpty());
            assertEquals("", result.data);
        }
    }

    @Test
    public void messageUsesTheSameDisplaySanitizerAsDashboardState() throws Exception {
        ExitFyCommandResult bounded = ExitFyCommandResult.parse(new JSONObject()
                .put("ok", false)
                .put("message", repeated('m', 400))
                .put("data", "")
                .toString());
        assertTrue(bounded.message.codePointCount(0, bounded.message.length()) <= 240);

        ExitFyCommandResult secret = ExitFyCommandResult.parse(new JSONObject()
                .put("ok", false)
                .put("message", "failed at https://user:pass@secret.invalid")
                .put("data", "")
                .toString());
        assertEquals("", secret.message);
    }

    @Test
    public void directConstructionCannotBypassDataLimit() {
        ExitFyCommandResult result = new ExitFyCommandResult(
                true, "Ready",
                repeated('x', ExitFyCommandResult.MAX_DATA_UTF8_BYTES + 1));

        assertFalse(result.ok);
        assertFalse(result.message.isEmpty());
        assertEquals("", result.data);
    }

    private static String repeated(char value, int count) {
        StringBuilder output = new StringBuilder(count);
        for (int index = 0; index < count; index++) output.append(value);
        return output.toString();
    }
}
