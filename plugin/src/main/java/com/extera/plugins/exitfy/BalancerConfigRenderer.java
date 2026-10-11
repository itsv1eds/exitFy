package com.extera.plugins.exitfy;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Xray routes both native outbounds and authenticated loopback SB outbounds. */
final class BalancerConfigRenderer {
    static final int MAX_MEMBERS = 256;

    static String poolKey(List<ProtocolParser.Node> nodes) {
        if (nodes == null || nodes.size() < 2) return "";
        StringBuilder key = new StringBuilder();
        for (ProtocolParser.Node node : nodes) key.append(node.normalizedKey).append(';');
        return key.toString();
    }

    static Plan build(List<ProtocolParser.Node> nodes, int port,
                      ProxySession.Credentials credentials, String mode,
                      LocalPortAllocator allocator, Set<Integer> reserved) throws Exception {
        if (nodes == null || nodes.size() < 2 || nodes.size() > MAX_MEMBERS) {
            throw new IllegalArgumentException(I18n.format(
                    "Для балансировщика нужно от 2 до %s серверов",
                    "The balancer requires 2 to %s servers", MAX_MEMBERS));
        }
        if (!SettingsModel.validBalanceMode(mode) || "off".equals(mode)) {
            throw new IllegalArgumentException("invalid balancer mode");
        }
        JSONArray outbounds = new JSONArray();
        List<ProtocolParser.Node> sideNodes = new ArrayList<>();
        List<Integer> sidePorts = new ArrayList<>();
        reserved = new java.util.HashSet<>(reserved);
        reserved.add(port);
        for (int i = 0; i < nodes.size(); i++) {
            ProtocolParser.Node node = nodes.get(i);
            JSONObject outbound;
            if (node.supports(CoreFamily.XRAY)) {
                outbound = XrayConfigRenderer.renderOutbound(node);
            } else if (node.supports(CoreFamily.SING_BOX)) {
                int sidePort = allocator.allocate(reserved, false);
                reserved.add(sidePort);
                sideNodes.add(node);
                sidePorts.add(sidePort);
                outbound = new JSONObject().put("protocol", "socks").put("settings",
                        new JSONObject().put("servers", new JSONArray().put(new JSONObject()
                                .put("address", "127.0.0.1").put("port", sidePort)
                                .put("users", new JSONArray().put(new JSONObject()
                                        .put("user", credentials.username).put("pass", credentials.password))))));
            } else throw new IllegalArgumentException(I18n.t(
                    "Один из серверов не поддерживается", "A server is not supported"));
            outbounds.put(outbound.put("tag", "balance-" + i));
        }
        JSONObject rule = new JSONObject().put("type", "field")
                .put("inboundTag", new JSONArray().put("socks-in"))
                .put("balancerTag", "exitfy-balance");
        JSONObject balancer = new JSONObject().put("tag", "exitfy-balance")
                .put("selector", new JSONArray().put("balance-"))
                .put("fallbackTag", "balance-0")
                .put("strategy", new JSONObject().put("type",
                        "round_robin".equals(mode) ? "roundRobin" : "leastPing"));
        JSONObject main = new JSONObject().put("log", new JSONObject().put("loglevel", "none"))
                .put("inbounds", new JSONArray().put(new JSONObject().put("tag", "socks-in")
                        .put("listen", "127.0.0.1").put("port", port).put("protocol", "socks")
                        .put("settings", new JSONObject().put("auth", "password").put("udp", true)
                                .put("accounts", new JSONArray().put(new JSONObject()
                                        .put("user", credentials.username).put("pass", credentials.password))))))
                .put("outbounds", outbounds)
                .put("routing", new JSONObject().put("domainStrategy", "AsIs")
                        .put("rules", new JSONArray().put(rule))
                        .put("balancers", new JSONArray().put(balancer)))
                .put("burstObservatory", new JSONObject().put("subjectSelector", new JSONArray().put("balance-"))
                        .put("pingConfig", new JSONObject().put("destination", "https://www.gstatic.com/generate_204")
                                .put("connectivity", "").put("interval", "1m").put("sampling", 1)
                                .put("timeout", "5s").put("httpMethod", "GET")));
        JSONObject side = sideNodes.isEmpty() ? null : singBoxPool(sideNodes, sidePorts, credentials);
        return new Plan(main, side, nodes.size());
    }

    private static JSONObject singBoxPool(List<ProtocolParser.Node> nodes, List<Integer> ports,
                                          ProxySession.Credentials credentials) throws Exception {
        JSONObject result = ProtocolParser.buildConfig(nodes.get(0), ports.get(0),
                credentials.username, credentials.password);
        JSONArray inbounds = new JSONArray();
        JSONArray outbounds = new JSONArray();
        JSONArray rules = new JSONArray();
        for (int i = 0; i < nodes.size(); i++) {
            inbounds.put(new JSONObject().put("type", "socks").put("tag", "pool-in-" + i)
                    .put("listen", "127.0.0.1").put("listen_port", ports.get(i))
                    .put("users", new JSONArray().put(new JSONObject()
                            .put("username", credentials.username).put("password", credentials.password))));
            outbounds.put(ProtocolParser.renderSingBoxOutbound(nodes.get(i).outbound).put("tag", "pool-out-" + i));
            rules.put(new JSONObject().put("inbound", new JSONArray().put("pool-in-" + i))
                    .put("outbound", "pool-out-" + i));
        }
        return result.put("inbounds", inbounds).put("outbounds", outbounds)
                .put("route", new JSONObject().put("rules", rules).put("final", "pool-out-0")
                        .put("default_domain_resolver", "dns-primary"));
    }

    static final class Plan {
        final JSONObject main;
        final JSONObject side;
        final int memberCount;
        Plan(JSONObject main, JSONObject side, int memberCount) {
            this.main = main; this.side = side; this.memberCount = memberCount;
        }
    }
}
