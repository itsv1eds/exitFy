package com.extera.plugins.exitfy;

import org.telegram.messenger.LocaleController;

import java.util.Locale;

final class I18n {
    private I18n() {
    }

    static boolean isRussian() {
        try {
            LocaleController.LocaleInfo info = LocaleController.getInstance()
                    .getCurrentLocaleInfo();
            if (info != null && info.shortName != null && !info.shortName.trim().isEmpty()) {
                return isRussianCode(info.shortName);
            }
        } catch (Throwable ignored) {
            // Unit tests and early bootstrap may not have a live host locale yet.
        }
        try {
            return isRussianCode(Locale.getDefault().getLanguage());
        } catch (Throwable ignored) {
            return false;
        }
    }

    static boolean isRussianCode(String value) {
        String normalized = value == null ? "" : value.trim();
        int separator = normalized.indexOf('-');
        if (separator < 0) separator = normalized.indexOf('_');
        if (separator >= 0) normalized = normalized.substring(0, separator);
        return "ru".equalsIgnoreCase(normalized);
    }

    static String t(String russian, String english) {
        return isRussian() ? russian : english;
    }

    static String format(String russian, String english, Object... arguments) {
        return String.format(Locale.getDefault(), t(russian, english), arguments);
    }
}
