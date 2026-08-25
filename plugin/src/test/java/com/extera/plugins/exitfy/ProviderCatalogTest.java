package com.extera.plugins.exitfy;

import org.junit.Test;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class ProviderCatalogTest {
    @Test
    public void enabledEndpointsDecodeWithStrictHttpsShape() throws Exception {
        assertEquals(SettingsModel.CUSTOM_PROVIDER_ID, ProviderCatalog.size());
        ProviderCatalog.verify();
        Set<String> decoded = new HashSet<>();
        for (int index = 0; index < ProviderCatalog.size(); index++) {
            assertFalse(ProviderCatalog.storageKey(index).contains("http"));
            if (!ProviderCatalog.isEnabled(index)) {
                try {
                    ProviderCatalog.endpoint(index);
                    throw new AssertionError("disabled catalog entry decoded");
                } catch (IllegalStateException expected) {
                    assertEquals("built-in source unavailable", expected.getMessage());
                }
                continue;
            }
            String value = ProviderCatalog.endpoint(index);
            String revision = ProviderCatalog.revision(index);
            URI parsed = new URI(value);
            assertEquals("https", parsed.getScheme());
            assertTrue(parsed.getHost() != null && !parsed.getHost().isEmpty());
            assertTrue(decoded.add(value));
            assertTrue(revision.matches("[0-9a-f]{32}"));
            assertFalse(revision.contains("http"));
        }
        assertNotEquals(ProviderCatalog.storageKey(0), ProviderCatalog.storageKey(1));
        if (ProviderCatalog.isEnabled(0) && ProviderCatalog.isEnabled(1)) {
            assertNotEquals(ProviderCatalog.revision(0), ProviderCatalog.revision(1));
        }
    }

    @Test
    public void invalidCatalogIndexFailsWithoutReturningMaterial() {
        for (int index : new int[]{-1, ProviderCatalog.size()}) {
            try {
                ProviderCatalog.endpoint(index);
                throw new AssertionError("invalid catalog index accepted");
            } catch (IllegalStateException expected) {
                assertEquals("built-in source unavailable", expected.getMessage());
            }
        }
    }

}
