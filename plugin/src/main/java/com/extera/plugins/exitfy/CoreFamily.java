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

    /** Families named in a comma separated identity list, in listed order. */
    static java.util.List<CoreFamily> parseAll(String value) {
        java.util.List<CoreFamily> families = new java.util.ArrayList<>();
        if (value == null) return families;
        for (String part : value.split(",")) {
            String trimmed = part.trim();
            for (CoreFamily family : values()) {
                if (family.id.equalsIgnoreCase(trimmed) && !families.contains(family)) {
                    families.add(family);
                }
            }
        }
        return families;
    }

    static CoreFamily parse(String value) {
        if (value != null && value.trim().equalsIgnoreCase(XRAY.id)) return XRAY;
        return SING_BOX;
    }
}
