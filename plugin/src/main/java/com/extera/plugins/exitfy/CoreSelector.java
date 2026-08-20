package com.extera.plugins.exitfy;

final class CoreSelector {
    private CoreSelector() {
    }

    static CoreFamily select(ProtocolParser.Node node, CoreFamily loadedFamily,
                             boolean singBoxReady, boolean xrayReady) {
        if (node == null) throw new IllegalArgumentException("node is missing");
        if (loadedFamily != null && node.supports(loadedFamily)) {
            return loadedFamily;
        }
        boolean supportsSingBox = node.supports(CoreFamily.SING_BOX);
        boolean supportsXray = node.supports(CoreFamily.XRAY);
        if (supportsSingBox && !supportsXray) return CoreFamily.SING_BOX;
        if (supportsXray && !supportsSingBox) return CoreFamily.XRAY;
        if (!supportsSingBox) {
            throw new IllegalArgumentException(I18n.t(
                    "Этот сервер не поддерживается",
                    "This server is not supported"));
        }
        if (singBoxReady != xrayReady) {
            return singBoxReady ? CoreFamily.SING_BOX : CoreFamily.XRAY;
        }
        return CoreFamily.SING_BOX;
    }
}
