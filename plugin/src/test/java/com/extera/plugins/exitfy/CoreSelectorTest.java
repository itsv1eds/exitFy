package com.extera.plugins.exitfy;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CoreSelectorTest {
    @Test
    public void exhaustivelyCoversCompatibilityReadinessAndLoadedFamilyMatrix()
            throws Exception {
        ProtocolParser.Node[] nodes = {
                node("vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&type=ws&path=%2Fws"),
                node("hysteria2://secret@hy.example:443?sni=hy.example"),
                node("vless://22222222-2222-2222-2222-222222222222@example.com:443"
                        + "?security=tls&type=xhttp&path=%2Fx&mode=packet-up"),
                new ProtocolParser.Node("", "unsupported",
                        new JSONObject()
                                .put("type", "vless")
                                .put("flow", "xtls-rprx-vision")
                                .put("tls", new JSONObject())
                                .put("transport", new JSONObject().put("type", "ws")),
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        };
        CoreFamily[] loadedFamilies = {
                null, CoreFamily.SING_BOX, CoreFamily.XRAY,
        };

        for (ProtocolParser.Node candidate : nodes) {
            boolean supportsSingBox = candidate.supports(CoreFamily.SING_BOX);
            boolean supportsXray = candidate.supports(CoreFamily.XRAY);
            for (CoreFamily loaded : loadedFamilies) {
                for (boolean singBoxReady : new boolean[]{false, true}) {
                    for (boolean xrayReady : new boolean[]{false, true}) {
                        String caseName = "sb=" + supportsSingBox
                                + ",xray=" + supportsXray
                                + ",loaded=" + loaded
                                + ",sbReady=" + singBoxReady
                                + ",xrayReady=" + xrayReady;
                        if (!supportsSingBox && !supportsXray) {
                            try {
                                CoreSelector.select(candidate, loaded,
                                        singBoxReady, xrayReady);
                                fail("unsupported matrix case selected a family: " + caseName);
                            } catch (IllegalArgumentException expected) {
                                // Expected for every readiness/loaded combination.
                            }
                            continue;
                        }
                        CoreFamily expected;
                        if (loaded != null && candidate.supports(loaded)) {
                            expected = loaded;
                        } else if (supportsSingBox != supportsXray) {
                            expected = supportsSingBox
                                    ? CoreFamily.SING_BOX : CoreFamily.XRAY;
                        } else if (singBoxReady != xrayReady) {
                            expected = singBoxReady
                                    ? CoreFamily.SING_BOX : CoreFamily.XRAY;
                        } else {
                            expected = CoreFamily.SING_BOX;
                        }
                        assertEquals(caseName, expected,
                                CoreSelector.select(candidate, loaded,
                                        singBoxReady, xrayReady));
                    }
                }
            }
        }
    }

    @Test
    public void dualCompatibleSelectionKeepsLoadedThenUsesReadinessAndStableTieBreak() {
        ProtocolParser.Node dual = node(
                "vless://11111111-1111-1111-1111-111111111111@example.com:443"
                        + "?security=tls&type=ws&path=%2Fws");

        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(dual, CoreFamily.SING_BOX, false, true));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(dual, CoreFamily.XRAY, true, false));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(dual, null, true, false));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(dual, null, false, true));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(dual, null, true, true));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(dual, null, false, false));
    }

    @Test
    public void singleCompatibleFamilyWinsEvenWhenAnotherFamilyIsLoadedOrReady() {
        ProtocolParser.Node singOnly = node(
                "hysteria2://secret@hy.example:443?sni=hy.example");
        ProtocolParser.Node xrayOnly = node(
                "vless://22222222-2222-2222-2222-222222222222@example.com:443"
                        + "?security=tls&type=xhttp&path=%2Fx&mode=packet-up");

        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(singOnly, CoreFamily.XRAY, false, true));
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(xrayOnly, CoreFamily.SING_BOX, true, false));
    }

    private static ProtocolParser.Node node(String uri) {
        try {
            return ProtocolParser.parse(uri);
        } catch (Exception error) {
            throw new AssertionError(error);
        }
    }

    @Test
    public void aDualServerMapsTheFamilyThatUnlocksMoreOfItsProvider() throws Exception {
        // Only one family maps per process. A provider whose other servers are
        // XHTTP is unusable if a dual-compatible server maps sing-box, and the
        // user has no way to see why.
        ProtocolParser.Node shared = ProtocolParser.parse(
                "vless://33333333-3333-3333-3333-333333333333@edge.example:443"
                        + "?security=tls&sni=edge.example&type=grpc&serviceName=s#Shared");
        assertTrue(shared.supports(CoreFamily.XRAY));
        assertTrue(shared.supports(CoreFamily.SING_BOX));

        CoreSelector.Coverage xrayHeavy = new CoreSelector.Coverage(4, 0);
        CoreSelector.Coverage singBoxHeavy = new CoreSelector.Coverage(0, 3);
        assertEquals(CoreFamily.XRAY,
                CoreSelector.select(shared, null, true, true, xrayHeavy));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(shared, null, true, true, singBoxHeavy));
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(shared, null, true, true, CoreSelector.Coverage.EMPTY));
        // Readiness still outranks coverage: choosing an absent core would
        // stall the connection on a download.
        assertEquals(CoreFamily.SING_BOX,
                CoreSelector.select(shared, null, true, false, xrayHeavy));
    }

    @Test
    public void coverageCountsOnlyServersASingleFamilyCanRun() throws Exception {
        ProtocolParser.Node xrayOnly = ProtocolParser.parse(
                "vless://33333333-3333-3333-3333-333333333333@edge.example:443"
                        + "?security=tls&sni=edge.example&type=xhttp&path=%2Fx#Xhttp");
        ProtocolParser.Node singBoxOnly = ProtocolParser.parse(
                "hysteria2://password@hy2.example:443?sni=edge.example#Hy");
        ProtocolParser.Node shared = ProtocolParser.parse(
                "vless://33333333-3333-3333-3333-333333333333@edge.example:443"
                        + "?security=tls&sni=edge.example&type=grpc&serviceName=s#Shared");
        CoreSelector.Coverage coverage = CoreSelector.coverage(
                java.util.Arrays.asList(xrayOnly, singBoxOnly, shared, null));
        assertEquals(1, coverage.xrayOnly);
        assertEquals(1, coverage.singBoxOnly);
        assertEquals(0, CoreSelector.coverage(null).xrayOnly);
    }
}
