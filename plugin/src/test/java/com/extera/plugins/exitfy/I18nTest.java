package com.extera.plugins.exitfy;

import org.junit.Test;
import static org.junit.Assert.*;

public class I18nTest {
    @Test public void normalizesClientLanguageCodesIncludingChineseScripts() {
        assertEquals("ru", I18n.normalizeLanguageCode("ru-RU"));
        assertEquals("zh", I18n.normalizeLanguageCode("zh_CN"));
        assertEquals("zh", I18n.normalizeLanguageCode("zh-Hant-TW"));
        assertEquals("en", I18n.normalizeLanguageCode("en-US"));
        assertEquals("en", I18n.normalizeLanguageCode("de"));
        assertFalse(I18n.isRussianCode("russian"));
    }

    @Test public void selectsTranslationsAndKeepsUnknownProtocolNamesReadable() {
        assertEquals("Настройки", I18n.forLanguage("ru", "Настройки", "Settings"));
        assertEquals("Settings", I18n.forLanguage("en", "Настройки", "Settings"));
        assertEquals("高级设置", I18n.forLanguage("zh-Hans", "Дополнительно", "Advanced"));
        assertEquals("TCP", I18n.forLanguage("zh", "TCP", "TCP"));
        assertEquals("第 2 步，共 8 步", String.format(ChineseStrings.translate("Step %s of %s"), 2, 8));
    }
}
