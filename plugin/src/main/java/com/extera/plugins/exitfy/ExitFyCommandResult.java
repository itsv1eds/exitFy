package com.extera.plugins.exitfy;

import org.json.JSONObject;

/**
 * Bounded result envelope returned by {@link ExitFyBridge#execute(String)}.
 *
 * <p>The runtime currently serializes command data as a string, including the
 * nested JSON returned by {@code list_nodes}. Keeping that string bounded here
 * gives every Android settings surface the same parsing and failure behavior.</p>
 */
final class ExitFyCommandResult {
    static final int MAX_DATA_UTF8_BYTES = 2 * 1024 * 1024;
    private static final int MAX_ENVELOPE_UTF8_BYTES =
            MAX_DATA_UTF8_BYTES * 6 + 4 * 1024;

    final boolean ok;
    final String message;
    final String data;

    ExitFyCommandResult(boolean ok, String message) {
        this(ok, message, "");
    }

    ExitFyCommandResult(boolean ok, String message, String data) {
        String boundedData = data == null ? "" : data;
        boolean validData;
        try {
            validData = !JsonGuard.exceedsUtf8Limit(
                    boundedData, MAX_DATA_UTF8_BYTES);
        } catch (RuntimeException ignored) {
            validData = false;
        }
        if (!validData) {
            this.ok = false;
            this.message = invalidResponseMessage();
            this.data = "";
            return;
        }
        this.ok = ok;
        this.message = ExitFyDashboardState.safeLabel(message, 240, "");
        this.data = boundedData;
    }

    static ExitFyCommandResult parse(String json) {
        if (json == null || json.trim().isEmpty()) return invalid();
        try {
            JSONObject value = JsonGuard.object(
                    json, MAX_DATA_UTF8_BYTES, MAX_ENVELOPE_UTF8_BYTES);
            Object okValue = value.opt("ok");
            Object messageValue = value.opt("message");
            Object dataValue = value.opt("data");
            if (!(okValue instanceof Boolean)
                    || !(messageValue instanceof String)
                    || !(dataValue instanceof String)) {
                return invalid();
            }
            String data = (String) dataValue;
            if (JsonGuard.exceedsUtf8Limit(data, MAX_DATA_UTF8_BYTES)) {
                return invalid();
            }
            return new ExitFyCommandResult(
                    (Boolean) okValue, (String) messageValue, data);
        } catch (Exception | StackOverflowError ignored) {
            return invalid();
        }
    }

    private static ExitFyCommandResult invalid() {
        return new ExitFyCommandResult(false, invalidResponseMessage(), "");
    }

    private static String invalidResponseMessage() {
        return I18n.t("Некорректный ответ runtime", "Invalid runtime response");
    }
}
