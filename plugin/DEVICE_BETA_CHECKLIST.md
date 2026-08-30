# exitFy 4.1.0 device checklist

Device testing is performed by the beta tester after receiving
`exitfy.plugin`. Use real `arm64-v8a` hardware only:

- One Android 10/API 29 arm64 device and one current Android arm64 device.
- exteraGram 12.5.1 (`e17f1bde…`) and 12.8.1 (`ab284232…`).
- Confirm the plugin is `exitFy_v2`, version `4.1.0`, schema 6, and an
  upgrade preserves settings, subscriptions and nodes. Legacy string, numeric
  and malformed `core_policy` values must become the inert `auto` tombstone;
  no core policy may reach DEX or appear in UI.
- Open the source card and confirm it presents the native server browser.
  Provider selection must respect disabled built-in slots. An old removed
  built-in selection must fall back to Elix; an old Custom selection and its
  cached custom subscriptions must remain Custom.
- Rotate one private built-in endpoint and confirm only that source loses its
  cached nodes/selection and refreshes immediately. Disable the selected
  built-in and confirm it falls back to the next enabled source without a
  refresh/reconnect loop; the dashboard summary must update.
- Confirm API 28 and lower, non-arm64 primary ABI and 32-bit processes are
  rejected before any exitFy runtime file is created. These negative cases may
  be covered by the local tests when matching physical hardware is unavailable.

## Dashboard and direct settings entry

- Confirm both drawer and chat-action entries open the compact exitFy dashboard
  directly. Opening it must only read UI state and must not start the proxy,
  subscriptions, core downloads or ping.
- Verify the dashboard contains connection, active server, source and advanced
  cards. With a component missing it must state that the connection files are
  downloaded once rather than only demanding the install; with every component
  present but no server chosen it must point at the server source instead. A
  running install and a connection error each replace that line rather than
  stacking with it. The advanced card must say what it contains. Whenever either current connection component is missing it must also
  show the one generic installation action. The large connection state remains
  visible, while version text, secondary connection/core/SOCKS details,
  per-family core cards, quick actions and the ActionBar overflow menu are
  absent. It must use Telegram icons only; no missing image placeholders or
  plugin-owned illustrations may appear.
- Open exitFy from the normal plugin list. It must immediately present the same
  dashboard, without briefly showing a standard plugin-settings fragment.
  Standard `Header`, `Switch`, `Selector` and `Custom` rows must not appear;
  every reachable settings subpage must be exitFy's native Android View.
- Test exteraGram light/dark themes and several accent colors. Headers, rows,
  cards, buttons, icons, focus and ripples must inherit the active theme and
  accent; only semantic connection/error states may use green/yellow/red.
- Test narrow portrait, landscape, tablet width and font scale 1.0/1.3/1.5.
  Dashboard cards must remain readable, scrollable and fully
  reachable without clipped values or overlapping ActionBar content.
- With TalkBack, verify connection state is spoken as text, focus follows list
  order, every icon has a useful description, and the ActionBar back action
  and dashboard controls are readable.
- Verify the large connection state, source/active-server summaries,
  connect/disconnect, the refresh control beside the server source and
  active-server ping/cancel. The generic installer may expose only one
  install action and combined stage/progress. No family name, version, policy,
  selection, per-family status, update button or update dialog may be
  reachable.
- Verify provider selection, search, every protocol filter, 50-item pagination,
  explicit node selection, node details, page ping/cancel,
  previous/next, referral, manual-key add/delete, custom-subscription
  add/delete and clear-nodes confirmation. Provider/filter/search changes must
  reset the page offset, and unavailable providers must not be selectable.
- Open Advanced and verify only Proxy GET/TCP ping type, HWID replacement and
  explicit reset. Its description and rows must not mention cores. The saved
  HWID itself must never be prefilled or shown.
- During refreshes and pings, rotate the device and leave/reopen screens;
  stale callbacks must not update destroyed views or execute twice.
- Confirm full saved HWID values, credentials and subscription URLs are never
  shown in dashboard summaries, bulletins or error messages.
- While retry backoff is active, confirm the UI remains responsive and does not
  show a frozen numeric countdown. A 50-node ping should update progressively
  without a full-page reload for each individual result.

## Core installation and migration

- On a fresh install, confirm only
  [itsv1eds/exitFy](https://github.com/itsv1eds/exitFy) is contacted.
  The handoff builds sing-box v1.13.19 and Xray v26.7.28; the wrapper
  revision advances with every core commit, so record the `wN` actually
  installed instead of expecting a fixed tag.
- The mirror fallback was verified against the published
  `xray-v26.7.28-w4023` assets from this machine: all three mirrors returned a
  byte-identical `manifest.json`, and the core fetched through a mirror matched
  the SHA-256 the manifest pins. Re-check only if the mirror list changes.
- Confirm every accepted manifest is schema 3, core API 2, config contract 1,
  `minAndroidApi=29`, and contains exactly one `arm64-v8a` ELF64 asset.
- Start with old schema-2/API-26 active, pending and backup core files. None may
  execute or become rollback; the dashboard must require the same explicit
  two-component install as a clean installation.
- With no usable current core, confirm no download starts merely from opening
  the dashboard or enabling exitFy. Repeat with exactly one usable component:
  `required` and the generic install action must remain visible, while the
  normal background repair of the missing component remains allowed. Tap the
  generic action in both 0/2 and 1/2 states: exactly one coalesced job must
  install/check both schema-3 components, expose bounded monotonic combined
  progress and finish as success only when both are ready. Repeated taps must
  attach to the same generation. Rotation/reopening must resume the current
  state without restarting the job. Turning the connection off must not cancel
  it; plugin unload must cancel the session and invalidate late callbacks.
- The first compatible core needed by the selected server must activate
  automatically without an app restart when no Go core has yet been mapped and
  exitFy is enabled.
- Force the first candidate's loader/start/stop self-test to fail. The legacy
  file must not be restored, the family must remain without a working core and
  the same rejected digest must not be installed automatically again.
- After at least one usable current component exists, verify automatic checks
  for both families at plugin load and every 24 hours. There must be no manual
  core-update command or per-family button; `install_cores` is accepted only
  as the parameterless generic two-component install while either component
  is missing. Also verify streaming size rejection, corrupted asset, wrong
  digest/ELF/export/ABI/manifest rejection and downgrade prevention.
- With a missing required family, trigger repeated connection attempts and
  confirm one coalesced install plus exact retries after
  `5 s → 30 s → 2 min → 10 min → 60 min`. Network recovery and server change
  reset the node-bound backoff. Turning the connection off must not cancel the
  generic user-started install or automatic maintenance of already bootstrapped
  components; plugin unload must cancel timers and late callbacks. Changing
  the selected server must not discard the generic two-component install; only
  stale selected-family preparation/reconnect may be suppressed.
- Map sing-box, then select an Xray-only server; repeat in the opposite
  direction. The required family may be prepared in the background, but the
  existing restart-required block remains and a second Go library must never be
  loaded in the same process.
- Confirm static `strings`/JADX inspection does not expose either built-in
  subscription endpoint, domain or credential token. After upgrading an old
  installation, confirm `subscriptions.json` stores only opaque built-in source
  keys while both providers still refresh successfully.
- Install beside an enabled 3.x `exitfy` and confirm the dashboard says the old
  plugin is still on. Confirm custom subscriptions, manual nodes and an unset
  HWID are imported once, that a second load issues no import commands, and
  that unloading mid-import leaves the import pending instead of losing the
  remaining sources.
- Disable/enable and reload the same beta.24 plugin without killing the process;
  confirm its DEX keeper is reused. Installing another embedded DEX version in
  that process must fail closed until restart.

## Protocols and checks

- Verify common dual-compatible VLESS, VMess, Trojan and Shadowsocks nodes.
  A mapped compatible family must be retained. In a clean process, the sole
  ready family wins; equal readiness and equal absence both choose sing-box.
- Verify VLESS/Reality/WebSocket, VMess/gRPC, Trojan/HTTP, Hysteria,
  Hysteria2, TUIC, XHTTP/SplitHTTP and mKCP/Finalmask according to the internal
  compatibility matrix. The family choice and compatibility filter must not be
  exposed, and an unsupported configuration must never fall back to raw/direct
  TCP.
- Check parser boundaries: JSON depth 64 accepted and 65 rejected; 8 MiB
  accepted and +1 rejected without UI blocking; 16 KiB URI, 5,000-node source,
  10,000-node total and 8 MiB stored-set limits enforced.
- Test C1 controls, emoji and malformed surrogates in custom HWID; the persisted value
  must be at most 256 code points/1024 UTF-8 bytes and cannot inject headers.
- Exercise list pagination at offset 0, a middle page, the last page, 10,000 and
  out-of-range values. No page contains more than 50 nodes and no integer
  overflow creates a phantom next page.
- Exercise TCP and full-path Proxy GET checks on pages of 1, 4 and 50 nodes.
  Proxy GET must pause the active connection, use remote DNS plus system
  TLS/hostname validation, require HTTP 204 and restore the prior connection
  after success, timeout and cancellation. All user-facing wording must describe
  the connection path or check method without naming a core.
- Start a second check while the first runs and toggle the connection during a check.
  Only the newest generation may publish results. A node unavailable in the
  current process must use neutral wording; TCP failure for a QUIC-only node is
  informational and cannot change the selected node.
- Confirm the dashboard contains no node-failover control. Repeated connection and
  health failures must only reconnect the currently selected node.

## Lifecycle and Telegram proxy

- Exhaust reconnect failures and verify exact `1/2/5/10/30/60` second backoff.
  A network flap alone must not reset it; a successful RUNNING state or explicit
  reconnect starts the appropriate new sequence.
- Verify messages, media uploads/downloads and calls with
  `proxy_enabled_calls`. Changing “Use proxy for calls” while exitFy owns the
  proxy must be preserved when exitFy stops.
- Manually change or disable Telegram's proxy while exitFy runs. exitFy must
  disable itself without deleting or overwriting the user's proxy entry.
- Disable exitFy while ownership checks, subscription refresh, reconnect or
  Proxy GET restoration are queued. No late callback may point Telegram at a
  stopped loopback port or re-enable exitFy.
- Switch Wi-Fi/mobile, background/resume, kill/restart and rapidly toggle the
  connection control. Verify the three-second unload deadline, no
  stuck proxy and no leaked workers.
- Exercise subscription partial failure, custom URL/HWID behavior and recovery
  of a Telegram proxy configured before exitFy.
- Confirm user-facing errors contain no credentials, keys, HWID or full URLs
  and clear after a successful connection.
- With the core experiment off, connect on a server one family cannot run and
  confirm the dashboard offers the restart directly and that the connection
  works after it. Confirm a provider whose servers split across families maps
  the family that strands fewer of them.
- Tap the active server card and switch servers from the list it offers.
  Confirm a source with more than 50 servers can be shown 200 at a time and
  that latency checks still cover at most 50.
- Turn failover on, connect to a server that cannot be reached, and confirm the
  next server of the source is selected after the second failure and not
  before. Confirm a subscription that fails to refresh never moves the
  selection. With failover off, the selection must never change on its own.
- With calls through exitFy off, confirm calls behave exactly as before. Turn
  it on, restart, and place a one-to-one call and join a group call: media must
  work and the exit country must be the server's. Confirm the mapping dies with
  the connection -- disconnect mid-call and the media stops rather than falling
  back to a direct path. Watch for audio delay: every packet takes an extra
  loopback hop.
- Confirm a fresh install checks latency over TCP, and that Proxy GET is still
  reachable and works when selected. Long-press a saved subscription and
  reorder, hide and show it: a hidden source keeps its URL, loses its servers
  from the list, and the selected server is re-picked. Confirm a page can hold
  10 servers as well as 200.
- Configure a Telegram proxy outside exitFy and run the full-path check.
  Every row must state that the proxy is in use, not that the check was
  cancelled. Turn on refresh-on-open and a check period, background the app and
  return: the source refreshes when stale and the scheduled check runs over TCP
  without dropping a live connection.
- Confirm Advanced reports both component versions, and that no screen outside
  Advanced names an engine.
- With the experiment on, connect on an XHTTP server and then on a Hysteria
  server without restarting. Both must connect, only one core may run at a
  time, and the restart card must stay hidden. Watch for native crashes: two
  Go runtimes then share the process. Turning the setting back off must keep
  the mapped families working and take effect only in the next process.

An artifact may be handed off once the mandatory local pipeline passes. The 100
connect/disconnect cycles and 72-hour soak are gates for stable `4.1.0`, which
also requires no crash/ANR, stuck proxy, leaked workers or secrets in
user-visible errors. The core experiment is excluded from those gates: it ships
off by default and is not part of the stable path.
