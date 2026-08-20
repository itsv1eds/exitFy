package com.extera.plugins.exitfy;

enum CoreFamily {
    SING_BOX("sing_box", "sing-box"),
    XRAY("xray", "Xray");

    final String id;
    final String displayName;

    CoreFamily(String id, String displayName) {
        this.id = id;
        this.displayName = displayName;
    }

    static CoreFamily parse(String value) {
        if (value != null && value.trim().equalsIgnoreCase(XRAY.id)) return XRAY;
        return SING_BOX;
    }
}
