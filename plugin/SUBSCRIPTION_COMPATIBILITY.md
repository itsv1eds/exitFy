# Subscription compatibility in exitFy 4.5

The comparison uses the public [Happ repositories](https://github.com/orgs/Happ-proxy/repositories),
[INCY subscription specification](https://github.com/INCY-DEV/incy-docs/blob/main/ru/dev-docs/subscription-format.en.md),
[INCY full Xray configuration specification](https://github.com/INCY-DEV/incy-docs/blob/main/ru/dev-docs/full-xray-config.en.md),
the [Hiddify format dispatcher](https://github.com/hiddify/hiddify-core/blob/dbf3ffbfbf55d6751e757314b2febbb7b25b72ab/v2/config/parser.go),
[AnyTLS URI specification](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md),
and the pinned [sing-box 1.14.3 schema](https://github.com/SagerNet/sing-box/tree/v1.14.3/option)
and [Xray transport configuration](https://github.com/XTLS/Xray-core/blob/main/infra/conf/transport_method.go).
Happ Android/Desktop and INCY platforms publish releases rather than the app
parser source. Compatibility is tested against their documented formats and
Xray's actual configuration schema, not inferred from a repository name.

## Supported inputs

| Input | exitFy behavior |
| --- | --- |
| Plain proxy links | VLESS, VMess, Trojan, Shadowsocks, Hysteria/Hysteria2, TUIC, AnyTLS, SOCKS5, authenticated HTTP/HTTPS, WireGuard, AmneziaWG |
| Standard or URL-safe Base64 | Decoded with strict UTF-8 and the same body parser; optional padding accepted |
| Full Xray profiles, object/array | Explicit proxy outbounds become selectable servers; transport/protocol settings are preserved |
| sing-box objects/profiles | VLESS, VMess, Trojan, Shadowsocks, Hysteria/Hysteria2, TUIC, AnyTLS, SOCKS4/4a/5 and HTTP/HTTPS; supported multiplex/HTTP/QUIC options retained |
| WireGuard JSON | Legacy single/multiple peers and current `endpoints[]`; translated to userspace Xray with addresses, peer keys, allowed IPs, keepalive and common reserved bytes |
| Wrapped profiles | `response`, `data`, `configs`, `profiles`, bounded recursive wrappers |
| Structured link lists | `links`, `ssConfLinks`; unrelated JSON metadata is not scanned |
| Clash YAML | Explicit supported proxy entries, including SOCKS5 and HTTP/HTTPS; unrelated YAML sections are not scanned |
| WireGuard / AmneziaWG `.conf` | Existing bounded INI parser, also with parameters in `[Device]` |
| AmneziaWG links | `amneziawg://<base64-conf>#Name`, alias `awg://` |
| AmneziaWG JSON | `type: "amneziawg"`, `servers[]` with `config` and optional `name`, including mixed Xray arrays |
| Mixed body metadata | `profile-title` / `subscription-name` headers, then body `#profile-title:` supply the name; comments/routing directives are not servers |

XHTTP links retain `extra.xmux`, string `extra.headers` and separate XHTTP
`extra.downloadSettings` with its address, port, TLS/Reality and nested XHTTP
options. Download channels require an XHTTP transport and a valid destination;
chained socket selectors and use with `stream-one` are rejected. Xmux integer/range
fields follow Xray's signed Int32 representation, including zero defaults,
negative sentinels and reversed range endpoints. Positive `maxConcurrency` and
`maxConnections` cannot both be specified, as in Xray. HTTP header names/values
are bounded and checked; `Host` belongs in the transport's `host` field. Empty
header and xmux objects are valid.

Native Xray profiles retain the standard outbound `mux` object: Boolean
`enabled`, signed Int16 `concurrency` / `xudpConcurrency`, and the XUDP UDP/443
policy (`reject`, `allow`, `skip`, or the empty default). Enabled and disabled
mux settings survive private storage and rendering. Invalid mux entries are
rejected individually; chained proxy references remain unsupported.

sing-box `multiplex` is retained for VLESS/VMess/Trojan/Shadowsocks and requires
sing-box, rather than silently running a plain Xray connection. Padding, stream
limits and supported Brutal options are preserved. Hysteria2 port ranges and
zero/default bandwidth, TUIC default congestion/relay, optional TLS SNI and
certificate-verification defaults follow the pinned core schema. SOCKS version
and UDP-over-TCP options, HTTP headers/path, and AnyTLS session options are kept.
Unknown explicit JSON server types count as rejections; routing helper objects
without server endpoints are not counted as servers.

TCP and XHTTP at the same host/port are different configurations. Exact outbound
duplicates are collapsed independently of display names; adding xmux never
causes a valid TCP sibling to disappear. Bad list entries are counted and
rejected individually, leaving valid siblings available. Private subscription
responses and credentials are not committed as regression fixtures.

## Boundaries

- One request identity: `Happ/5.2.0`, or the user's explicit replacement. No
  retries impersonating other clients and no fallback-host token sharing.
- HTTP/HTTPS proxy links need an `@` credential authority. Bare URLs are not
  proxy servers. SOCKS5 links can omit authentication.
- WireGuard share links preserve keys, address prefixes, endpoint, MTU,
  keepalive and three comma-separated reserved bytes. They run through Xray's
  userspace outbound. AmneziaWG runs through exitFy SB.
- Full-profile listeners, routing, DNS and application-management directives
  do not replace exitFy's runtime configuration or its owned local ports.
  Profiles requiring chained proxy references are rejected with a reason.
- WireGuard system interfaces and explicit local listeners are not imported.
  Per-peer reserved bytes must agree because Xray applies them to the device.
- App-specific encrypted deep links, private app APIs, arbitrary nested
  transport extensions and unsupported engine features are not claimed to
  work. Support for a syntactically valid import does not establish server
  reachability or authentication success.
- Existing document, depth, entry and outbound budgets remain enforced.
  Unknown nested XHTTP extensions are rejected; accepting xmux does not permit
  arbitrary nested runtime configuration through that field.

## Verification

Regression checks cover TCP+XHTTP/xmux from one endpoint in plain/Base64 form,
xmux/header preservation through storage and Xray rendering, malformed nested
settings, separate XHTTP download channels, mixed valid/broken AWG entries, duplicate AWG locations, mixed Xray/AWG
JSON, SOCKS/HTTP credentials, HTTPS TLS, WireGuard IPv6/reserved bytes, inline
metadata and HTTP-header title precedence.
The public 78-case compatibility matrix covers link/Base64, JSON and Clash
forms, IPv6, TCP/TLS/Reality, WebSocket, gRPC gun/multi, HTTP2, HTTPUpgrade,
XHTTP/xmux/SplitHTTP, mKCP, Shadowsocks/2022, the QUIC protocols, ordinary
proxies, AnyTLS and both WireGuard JSON layouts. Separate regressions cover
bad siblings, option/storage preservation, current endpoint wrappers,
multiplex core selection and mixed YAML order. Configuration acceptance by the
core is checked separately from import and does not imply that the remote
server is reachable or accepts the credentials.
