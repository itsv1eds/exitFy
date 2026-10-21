package com.extera.plugins.exitfy;

import org.telegram.messenger.LocaleController;

import java.util.Locale;

final class I18n {
    private I18n() {
    }

    static boolean isRussian() {
        return "ru".equals(languageCode());
    }

    static String languageCode() {
        try {
            LocaleController.LocaleInfo info = LocaleController.getInstance()
                    .getCurrentLocaleInfo();
            if (info != null && info.shortName != null && !info.shortName.trim().isEmpty()) {
                return normalizeLanguageCode(info.shortName);
            }
        } catch (Throwable ignored) {
            // Unit tests and early bootstrap may not have a live host locale yet.
        }
        try {
            return normalizeLanguageCode(Locale.getDefault().getLanguage());
        } catch (Throwable ignored) {
            return "en";
        }
    }

    static boolean isRussianCode(String value) {
        return "ru".equals(normalizeLanguageCode(value));
    }

    static String normalizeLanguageCode(String value) {
        String normalized = value == null ? "" : value.trim();
        int separator = normalized.indexOf('-');
        int underscore = normalized.indexOf('_');
        if (separator < 0 || (underscore >= 0 && underscore < separator)) separator = underscore;
        if (separator >= 0) normalized = normalized.substring(0, separator);
        if ("ru".equalsIgnoreCase(normalized)) return "ru";
        if ("zh".equalsIgnoreCase(normalized)) return "zh";
        return "en";
    }

    static String t(String russian, String english) {
        return forLanguage(languageCode(), russian, english);
    }

    static String forLanguage(String language, String russian, String english) {
        switch (normalizeLanguageCode(language)) {
            case "ru": return russian;
            case "zh": return ChineseStrings.translate(english);
            default: return english;
        }
    }

    static String format(String russian, String english, Object... arguments) {
        return String.format(Locale.getDefault(), t(russian, english), arguments);
    }
}
