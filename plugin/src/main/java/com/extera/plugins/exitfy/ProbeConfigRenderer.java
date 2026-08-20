package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

final class ProbeConfigRenderer {
    private ProbeConfigRenderer() {
    }

    static JSONObject build(CoreFamily family, List<ProtocolParser.Node> nodes,
                            List<Integer> ports) throws Exception {
        if (nodes == null || ports == null || nodes.isEmpty() || nodes.size() != ports.size()
                || nodes.size() > 4) {
            throw new IllegalArgumentException("probe batch must contain 1..4 nodes and ports");
        }
        if (family == null) throw new IllegalArgumentException("probe core family is missing");
        for (Integer port : ports) {
            if (port == null || port <= 0 || port > 65535) {
                throw new IllegalArgumentException("invalid probe SOCKS port");
            }
        }
        return family == CoreFamily.XRAY ? buildXray(nodes, ports) : buildSingBox(nodes, ports);
    }

    private static JSONObject buildSingBox(List<ProtocolParser.Node> nodes,
                                           List<Integer> ports) throws Exception {
        JSONArray inbounds = new JSONArray();
        JSONArray outbounds = new JSONArray();
        JSONArray rules = new JSONArray();
        for (int i = 0; i < nodes.size(); i++) {
            ProtocolParser.Node node = nodes.get(i);
            if (node == null) throw new IllegalArgumentException("probe node is missing");
            ProtocolParser.validateNeutralOutbound(node.outbound);
            if (!node.supports(CoreFamily.SING_BOX)) {
                throw new IllegalArgumentException("probe node is not compatible with sing-box");
            }
            String suffix = String.valueOf(i);
            inbounds.put(new JSONObject().put("type", "socks").put("tag", "probe-in-" + suffix)
                    .put("listen", "127.0.0.1").put("listen_port", ports.get(i)));
            outbounds.put(ProtocolParser.renderSingBoxOutbound(node.outbound)
                    .put("tag", "probe-out-" + suffix));
            rules.put(new JSONObject().put("inbound", new JSONArray().put("probe-in-" + suffix))
                    .put("outbound", "probe-out-" + suffix));
        }
        return new JSONObject()
                .put("log", new JSONObject().put("level", "panic"))
                .put("inbounds", inbounds)
                .put("outbounds", outbounds)
                .put("route", new JSONObject().put("rules", rules)
                        .put("final", "probe-out-0"));
    }

    private static JSONObject buildXray(List<ProtocolParser.Node> nodes,
                                        List<Integer> ports) throws Exception {
        JSONArray inbounds = new JSONArray();
        JSONArray outbounds = new JSONArray();
        JSONArray rules = new JSONArray();
        for (int i = 0; i < nodes.size(); i++) {
            ProtocolParser.Node node = nodes.get(i);
            if (node == null) throw new IllegalArgumentException("probe node is missing");
            ProtocolParser.validateNeutralOutbound(node.outbound);
            if (!node.supports(CoreFamily.XRAY)) {
                throw new IllegalArgumentException("probe node is not compatible with Xray");
            }
            String suffix = String.valueOf(i);
            inbounds.put(new JSONObject().put("tag", "probe-in-" + suffix)
                    .put("listen", "127.0.0.1").put("port", ports.get(i))
                    .put("protocol", "socks")
                    .put("settings", new JSONObject().put("auth", "noauth").put("udp", false)));
            outbounds.put(XrayConfigRenderer.renderOutbound(node.outbound)
                    .put("tag", "probe-out-" + suffix));
            rules.put(new JSONObject().put("type", "field")
                    .put("inboundTag", new JSONArray().put("probe-in-" + suffix))
                    .put("outboundTag", "probe-out-" + suffix));
        }
        return new JSONObject()
                .put("log", new JSONObject().put("loglevel", "none"))
                .put("inbounds", inbounds)
                .put("outbounds", outbounds)
                .put("routing", new JSONObject().put("domainStrategy", "AsIs").put("rules", rules));
    }
}
