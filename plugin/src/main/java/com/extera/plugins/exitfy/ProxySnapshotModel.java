package com.extera.plugins.exitfy;

import org.json.JSONObject;

import java.util.Objects;

final class ProxySnapshotModel {
    final boolean active;
    final ProxyValue previous;
    final String previousName;
    final Preferences preferences;
    final String ownedFingerprint;

    ProxySnapshotModel(boolean active, ProxyValue previous, String previousName,
                       Preferences preferences, String ownedFingerprint) {
        this.active = active;
        this.previous = previous;
        this.previousName = previousName == null ? "" : previousName;
        this.preferences = preferences == null ? Preferences.defaults() : preferences;
        this.ownedFingerprint = ownedFingerprint == null ? "" : ownedFingerprint;
    }

    ProxySnapshotModel withOwnedFingerprint(String value) {
        return new ProxySnapshotModel(true, previous, previousName, preferences, value);
    }

    JSONObject toJson() throws Exception {
        JSONObject result = new JSONObject()
                .put("active", active)
                .put("previousName", previousName)
                .put("ownedFingerprint", ownedFingerprint)
                .put("preferences", preferences.toJson());
        if (previous != null) result.put("previous", previous.toJson());
        return result;
    }

    static ProxySnapshotModel fromJson(JSONObject value) {
        if (value == null) value = new JSONObject();
        return new ProxySnapshotModel(
                value.optBoolean("active", false),
                ProxyValue.fromJson(value.optJSONObject("previous")),
                value.optString("previousName", ""),
                Preferences.fromJson(value.optJSONObject("preferences")),
                value.optString("ownedFingerprint", "")
        );
    }

    static final class ProxyValue {
        final String address;
        final int port;
        final String username;
        final String password;
        final String secret;

        ProxyValue(String address, int port, String username, String password, String secret) {
            this.address = address == null ? "" : address;
            this.port = port;
            this.username = username == null ? "" : username;
            this.password = password == null ? "" : password;
            this.secret = secret == null ? "" : secret;
        }

        JSONObject toJson() throws Exception {
            return new JSONObject().put("address", address).put("port", port)
                    .put("username", username).put("password", password).put("secret", secret);
        }

        static ProxyValue fromJson(JSONObject value) {
            if (value == null) return null;
            String address = value.optString("address", "");
            int port = value.optInt("port", 0);
            if (address.isEmpty() || port <= 0) return null;
            return new ProxyValue(address, port, value.optString("username", ""),
                    value.optString("password", ""), value.optString("secret", ""));
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof ProxyValue)) return false;
            ProxyValue value = (ProxyValue) other;
            return port == value.port && address.equals(value.address)
                    && username.equals(value.username) && password.equals(value.password)
                    && secret.equals(value.secret);
        }

        @Override
        public int hashCode() {
            return Objects.hash(address, port, username, password, secret);
        }
    }

    static final class Preferences {
        final String ip;
        final int port;
        final String username;
        final String password;
        final String secret;
        final boolean enabled;
        final boolean calls;

        Preferences(String ip, int port, String username, String password, String secret,
                    boolean enabled, boolean calls) {
            this.ip = ip == null ? "" : ip;
            this.port = port;
            this.username = username == null ? "" : username;
            this.password = password == null ? "" : password;
            this.secret = secret == null ? "" : secret;
            this.enabled = enabled;
            this.calls = calls;
        }

        static Preferences defaults() {
            return new Preferences("", 1080, "", "", "", false, false);
        }

        JSONObject toJson() throws Exception {
            return new JSONObject().put("proxy_ip", ip).put("proxy_port", port)
                    .put("proxy_user", username).put("proxy_pass", password)
                    .put("proxy_secret", secret).put("proxy_enabled", enabled)
                    .put("proxy_enabled_calls", calls);
        }

        static Preferences fromJson(JSONObject value) {
            if (value == null) return defaults();
            return new Preferences(value.optString("proxy_ip", ""), value.optInt("proxy_port", 1080),
                    value.optString("proxy_user", ""), value.optString("proxy_pass", ""),
                    value.optString("proxy_secret", ""), value.optBoolean("proxy_enabled", false),
                    value.optBoolean("proxy_enabled_calls", false));
        }
    }
}
