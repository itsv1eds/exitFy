package com.extera.plugins.exitfy;

import java.util.List;

/**
 * Turns a parser rejection code into something a person can act on.
 *
 * <p>The parser already classifies why it refused a server, but that
 * classification was only ever consumed by one internal check: users were told
 * "invalid key" and had no way to tell a typo from a transport this build
 * cannot represent.</p>
 */
final class RejectionReason {
    private RejectionReason() {
    }

    static String describe(String reason) {
        if (reason == null) return "";
        switch (reason) {
            case "transport_unsupported":
                return I18n.t("этот способ передачи не поддерживается выбранным ядром",
                        "the selected core cannot run this transport");
            case "security_unsupported":
                return I18n.t("указан неподдерживаемый способ шифрования",
                        "the encryption option is not supported");
            case "mux_unsupported":
                return I18n.t("mux не поддерживается", "mux is not supported");
            case "detour_unsupported":
                return I18n.t("цепочка прокси не поддерживается",
                        "proxy chaining is not supported");
            case "bind_unsupported":
                return I18n.t("привязка к интерфейсу не поддерживается",
                        "binding to an interface is not supported");
            case "dns_strategy_unsupported":
                return I18n.t("настройки DNS в ключе не поддерживаются",
                        "the DNS options in the key are not supported");
            case "trojan_flow_unsupported":
                return I18n.t("flow у Trojan не поддерживается",
                        "Trojan flow is not supported");
            case "vless_vision_tls_required":
                return I18n.t("для vision нужен TLS", "vision requires TLS");
            case "vless_vision_raw_required":
                return I18n.t("vision работает только без транспорта",
                        "vision works only without a transport");
            case "clash_field_unsupported":
            case "clash_root_invalid":
            case "clash_sequence_invalid":
            case "clash_item_indent_invalid":
            case "clash_line_too_large":
                return I18n.t("формат Clash разобран не полностью",
                        "the Clash file could not be read fully");
            case "invalid_json":
            case "json_depth_exceeded":
            case "json_string_too_large":
            case "json_structure_too_large":
                return I18n.t("повреждённый или слишком сложный JSON",
                        "the JSON is malformed or too deeply nested");
            case "hit_config_too_large":
            case "hit_cbor_duplicate":
                return I18n.t("повреждённый конфиг", "the config is malformed");
            case "uri_too_large":
                return I18n.t("ключ слишком длинный", "the key is too long");
            case "source_too_large":
                return I18n.t("подписка слишком большая", "the subscription is too large");
            case "source_node_limit":
                return I18n.t("в подписке слишком много серверов",
                        "the subscription holds too many servers");
            case "import_interrupted":
                return I18n.t("чтение прервано", "reading was interrupted");
            case SubscriptionParser.UNREACHABLE_ONLY:
                return I18n.t("источник вернул заглушки вместо серверов",
                        "the source returned placeholders instead of servers");
            case "shadowsocks":
                return I18n.t("этот метод шифрования Shadowsocks не поддерживается",
                        "this Shadowsocks method is not supported");
            default:
                return I18n.t("ключ не удалось разобрать",
                        "the key could not be read");
        }
    }

    /** The distinct reasons behind one refusal, as a single readable clause. */
    static String summarize(List<String> reasons) {
        if (reasons == null || reasons.isEmpty()) return "";
        StringBuilder text = new StringBuilder();
        int used = 0;
        for (String reason : reasons) {
            String described = describe(reason);
            if (described.isEmpty()) continue;
            if (text.indexOf(described) >= 0) continue;
            if (used > 0) text.append("; ");
            text.append(described);
            if (++used == 3) break;
        }
        return text.toString();
    }
}
