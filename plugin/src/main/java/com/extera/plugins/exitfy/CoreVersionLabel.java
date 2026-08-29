package com.extera.plugins.exitfy;

/**
 * Turns a release tag into the upstream version a person recognises.
 *
 * <p>Tags read {@code xray-v26.7.28-w7054}: the family prefix repeats what the
 * row already says and the wrapper revision means nothing outside this
 * repository, so only the upstream version is shown.</p>
 */
final class CoreVersionLabel {
    private CoreVersionLabel() {
    }

    static String describe(String releaseTag) {
        String value = releaseTag == null ? "" : releaseTag.trim();
        if (value.isEmpty()) return "";
        int start = value.indexOf("-v");
        if (start < 0) return "";
        String rest = value.substring(start + 1);
        int wrapper = rest.lastIndexOf("-w");
        String version = wrapper > 0 ? rest.substring(0, wrapper) : rest;
        return version.matches("v[0-9]+\\.[0-9]+\\.[0-9]+") ? version : "";
    }
}
