package com.extera.plugins.exitfy;

import org.junit.Test;
import org.json.JSONObject;
import static org.junit.Assert.*;

public class ProxyCompatTest {
    @Test public void legacyApiCreatesReadsAndActivatesAuthenticatedSocks() {
        ProxySnapshotModel.ProxyValue value = new ProxySnapshotModel.ProxyValue(
                "127.0.0.1", 4567, "user", "pass", "");
        Object proxy = ProxyCompat.create(LegacyProxy.class, value);
        assertEquals(value, ProxyCompat.read(proxy));
        assertEquals("127.0.0.1:4567:user:pass:", ProxyCompat.link(proxy));
        ProxyCompat.configure(LegacyManager.class, LegacyProxy.class, true, proxy);
        assertTrue(LegacyManager.enabled);
        assertEquals(value, LegacyManager.value);
        ProxyCompat.configure(LegacyManager.class, LegacyProxy.class, false, null);
        assertFalse(LegacyManager.enabled);
    }

    @Test public void structuredApiCreatesReadsAndActivatesAuthenticatedSocks() {
        ProxySnapshotModel.ProxyValue value = new ProxySnapshotModel.ProxyValue(
                "127.0.0.1", 4567, "user", "pass", "");
        Object proxy = ProxyCompat.create(ModernProxy.class, value);
        assertEquals(value, ProxyCompat.read(proxy));
        assertEquals("127.0.0.1:4567:user:pass:", ProxyCompat.link(proxy));
        ProxyCompat.configure(ModernManager.class, ModernProxy.class, true, proxy);
        assertTrue(ModernManager.enabled);
        assertEquals(ModernSettings.Type.SOCKS5, ModernManager.settings.getType());
        assertEquals("pass", ModernManager.settings.getPassword());
        ProxyCompat.configure(ModernManager.class, ModernProxy.class, false, null);
        assertFalse(ModernManager.enabled);
        assertNull(ModernManager.settings);
    }

    @Test public void fingerprintsStayStableAcrossHostUpgrade() {
        ProxySnapshotModel.ProxyValue value = new ProxySnapshotModel.ProxyValue(
                "127.0.0.1", 4567, "user", "pass", "");
        assertEquals(ProxyCompat.link(ProxyCompat.create(LegacyProxy.class, value)),
                ProxyCompat.link(ProxyCompat.create(ModernProxy.class, value)));
    }

    @Test public void previousWebProxySurvivesSnapshotAndRestore() throws Exception {
        ProxySnapshotModel.ProxyValue web = new ProxySnapshotModel.ProxyValue(
                "https://example.org/path", 0, "", "", "secret", 2);
        ProxySnapshotModel.ProxyValue saved = ProxySnapshotModel.ProxyValue.fromJson(web.toJson());
        assertEquals(web, saved);
        Object restored = ProxyCompat.create(ModernProxy.class, saved);
        assertEquals(web, ProxyCompat.read(restored));
        ProxyCompat.configure(ModernManager.class, ModernProxy.class, true, restored);
        assertEquals(ModernSettings.Type.WEB, ModernManager.settings.getType());
        assertEquals("secret", ModernManager.settings.getSecret());
    }

    @Test public void legacyRecoveryMarkersInferTypeAndPreserveMissingPreference() throws Exception {
        JSONObject old = new JSONObject().put("address", "localhost").put("port", 443)
                .put("secret", "secret");
        assertEquals(1, ProxySnapshotModel.ProxyValue.fromJson(old).type);
        assertEquals(-1, ProxySnapshotModel.Preferences.fromJson(new JSONObject()).type);
        ProxySnapshotModel.Preferences prefs = new ProxySnapshotModel.Preferences(
                "https://example.org", 0, "", "", "secret", true, false, 2);
        assertEquals(2, ProxySnapshotModel.Preferences.fromJson(prefs.toJson()).type);
    }

    @Test public void hostConfigurationFailureIsNotSilentlyAccepted() {
        try {
            ProxyCompat.configure(FailingManager.class, ModernProxy.class, true,
                    ProxyCompat.create(ModernProxy.class, new ProxySnapshotModel.ProxyValue(
                            "127.0.0.1", 1234, "", "", "")));
            fail("host error swallowed");
        } catch (IllegalStateException expected) {
            assertEquals("host failed", expected.getCause().getMessage());
        }
    }

    public static class LegacyProxy {
        public String address, username, password, secret;
        public int port;
        public LegacyProxy(String a, int p, String u, String w, String s) {
            address=a; port=p; username=u; password=w; secret=s;
        }
        public String getLink() { return address+":"+port+":"+username+":"+password+":"+secret; }
    }
    public static class LegacyManager {
        static boolean enabled;
        static ProxySnapshotModel.ProxyValue value;
        public static void setProxySettings(boolean e, String a, int p, String u, String w, String s) {
            enabled=e; value=new ProxySnapshotModel.ProxyValue(a,p,u,w,s);
        }
    }
    public static class ModernProxy {
        public ModernSettings settings;
        public ModernProxy(ModernSettings s) { settings=s; }
    }
    public static class ModernManager {
        static boolean enabled;
        static ModernSettings settings;
        public static void setProxySettings(boolean e, ModernSettings s) { enabled=e; settings=s; }
    }
    public static class FailingManager {
        public static void setProxySettings(boolean e, ModernSettings s) {
            throw new IllegalStateException("host failed");
        }
    }
    public static class ModernSettings {
        public enum Type { SOCKS5, MTPROTO, WEB }
        private Type type;
        private String address="", user="", password="", secret="";
        private int port;
        public Type getType() { return type; }
        public String getAddress() { return address; }
        public int getPort() { return port; }
        public String getUser() { return user; }
        public String getPassword() { return password; }
        public String getSecret() { return secret; }
        public String getLink() { return address+":"+port+":"+user+":"+password+":"+secret; }
        public static Builder builder() { return new Builder(); }
        public static class Builder {
            private final ModernSettings value=new ModernSettings();
            public Builder setType(Type t) { value.type=t; return this; }
            public Builder setAddress(String a) { value.address=a; return this; }
            public Builder setPort(int p) { value.port=p; return this; }
            public Builder setUser(String u) { value.user=u; return this; }
            public Builder setPassword(String p) { value.password=p; return this; }
            public Builder setSecret(String s) { value.secret=s; return this; }
            public ModernSettings build() { return value; }
        }
    }
}
