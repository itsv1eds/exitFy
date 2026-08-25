package com.extera.plugins.exitfy;

import java.util.List;

final class CoreSelector {
    private CoreSelector() {
    }

    /**
     * How many of a provider's servers only one family can run. A provider is
     * rarely uniform: one ships XHTTP, which only Xray represents, another
     * ships Hysteria, which only sing-box represents. Since only one family
     * may be mapped per process, a server that runs on both should map the
     * family that leaves the fewest of its neighbours unreachable.
     */
    static final class Coverage {
        static final Coverage EMPTY = new Coverage(0, 0);

        final int xrayOnly;
        final int singBoxOnly;

        Coverage(int xrayOnly, int singBoxOnly) {
            this.xrayOnly = xrayOnly;
            this.singBoxOnly = singBoxOnly;
        }
    }

    static Coverage coverage(List<ProtocolParser.Node> nodes) {
        if (nodes == null) return Coverage.EMPTY;
        int xrayOnly = 0;
        int singBoxOnly = 0;
        for (ProtocolParser.Node node : nodes) {
            if (node == null) continue;
            boolean xray = node.supports(CoreFamily.XRAY);
            boolean singBox = node.supports(CoreFamily.SING_BOX);
            if (xray && !singBox) xrayOnly++;
            else if (singBox && !xray) singBoxOnly++;
        }
        return new Coverage(xrayOnly, singBoxOnly);
    }

    static CoreFamily select(ProtocolParser.Node node, CoreFamily loadedFamily,
                             boolean singBoxReady, boolean xrayReady) {
        return select(node, loadedFamily, singBoxReady, xrayReady, Coverage.EMPTY);
    }

    static CoreFamily select(ProtocolParser.Node node, CoreFamily loadedFamily,
                             boolean singBoxReady, boolean xrayReady, Coverage coverage) {
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
        Coverage counts = coverage == null ? Coverage.EMPTY : coverage;
        if (counts.xrayOnly != counts.singBoxOnly) {
            return counts.xrayOnly > counts.singBoxOnly
                    ? CoreFamily.XRAY : CoreFamily.SING_BOX;
        }
        return CoreFamily.SING_BOX;
    }
}
