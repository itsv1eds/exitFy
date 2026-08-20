package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class ProbeConfigRendererTest {
    @Test
    public void createsFourIsolatedSingBoxProbeRoutesWithoutFallback() throws Exception {
        ProtocolParser.Node first = node("one.example", "11111111-1111-1111-1111-111111111111");
        ProtocolParser.Node second = node("two.example", "22222222-2222-2222-2222-222222222222");
        JSONObject config = ProbeConfigRenderer.build(CoreFamily.SING_BOX,
                Arrays.asList(first, second), Arrays.asList(31001, 31002));
        assertEquals(2, config.getJSONArray("inbounds").length());
        assertEquals(2, config.getJSONArray("outbounds").length());
        assertFalse(config.getJSONArray("outbounds").getJSONObject(0).has("encryption"));
        assertFalse(config.getJSONArray("outbounds").getJSONObject(1).has("encryption"));
        JSONArray rules = config.getJSONObject("route").getJSONArray("rules");
        assertEquals("probe-out-0", rules.getJSONObject(0).getString("outbound"));
        assertEquals("probe-out-1", rules.getJSONObject(1).getString("outbound"));
        assertFalse(config.toString().contains("direct"));
    }

    @Test
    public void createsFourIsolatedXrayProbeRoutesWithoutFreedom() throws Exception {
        JSONObject config = ProbeConfigRenderer.build(CoreFamily.XRAY,
                Arrays.asList(node("one.example", "11111111-1111-1111-1111-111111111111"),
                        node("two.example", "22222222-2222-2222-2222-222222222222")),
                Arrays.asList(32001, 32002));
        assertEquals(2, config.getJSONArray("inbounds").length());
        assertEquals(2, config.getJSONArray("outbounds").length());
        assertEquals("probe-out-1", config.getJSONObject("routing").getJSONArray("rules")
                .getJSONObject(1).getString("outboundTag"));
        assertFalse(config.toString().contains("freedom"));
    }

    @Test
    public void rejectsForgedStoredOutboundBeforeSingBoxProbeRendering() throws Exception {
        ProtocolParser.Node forged = node(
                "forged.example", "33333333-3333-3333-3333-333333333333");
        forged.outbound.put("routing", new JSONObject().put("final", "direct"));
        try {
            ProbeConfigRenderer.build(CoreFamily.SING_BOX,
                    Arrays.asList(forged), Arrays.asList(33001));
            throw new AssertionError("forged stored outbound reached sing-box probe config");
        } catch (IllegalArgumentException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    @Test
    public void rendersXrayPathEarlyDataAsSingBoxCompatibilityHeader() throws Exception {
        JSONObject outbound = new JSONObject()
                .put("type", "vless").put("server", "early.example").put("server_port", 443)
                .put("uuid", "44444444-4444-4444-4444-444444444444")
                .put("encryption", "none")
                .put("tls", new JSONObject().put("enabled", true)
                        .put("server_name", "early.example").put("insecure", false))
                .put("transport", new JSONObject().put("type", "ws").put("path", "/ws")
                        .put("max_early_data", 2048)
                        .put(ProtocolParser.WS_EARLY_DATA_MODE,
                                ProtocolParser.WS_EARLY_DATA_XRAY_PATH));
        ProtocolParser.Node node = ProtocolParser.fromOutbound("", "early", outbound);
        JSONObject rendered = ProbeConfigRenderer.build(CoreFamily.SING_BOX,
                Arrays.asList(node), Arrays.asList(33002))
                .getJSONArray("outbounds").getJSONObject(0);
        assertFalse(rendered.has("encryption"));
        JSONObject transport = rendered.getJSONObject("transport");
        assertFalse(transport.has(ProtocolParser.WS_EARLY_DATA_MODE));
        assertEquals(ProtocolParser.WS_EARLY_DATA_XRAY_HEADER,
                transport.getString("early_data_header_name"));
    }

    private static ProtocolParser.Node node(String host, String uuid) throws Exception {
        return ProtocolParser.parse("vless://" + uuid + "@" + host
                + ":443?security=tls&type=ws&path=%2Fws");
    }
}
