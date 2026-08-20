# exitFy 4.0.0-beta.24

`ExitFy.template.plugin` is the thin Python loader and lifecycle layer. Drawer
and chat-action entries open a compact Telegram-native dashboard implemented as
a stable `BaseFragment`. The normal plugin-settings entry opens that dashboard
directly. A single inert `Text` row exists only so the host registers the entry;
no standard plugin-settings rows, selectors, editors or subpages remain.
Provider and server management, ping type and custom HWID replacement/reset all
live in the dashboard and its own Android View sub-fragments. Core selection
and updates remain automatic. Whenever either connection component is missing,
the dashboard exposes one generic action which installs/checks both components
and reports combined progress; it never exposes family names, versions,
selection or per-family update controls.
The screens use Telegram icons and the current exteraGram theme—there are no
bundled pictures. Runtime code lives in
`src/main/java/com/extera/plugins/exitfy`; the only embedded native
code is the serialized fd-only `android_dlopen_ext`/`StartCore`/`StopCore`
bridge in `src/main/cpp`.

The settings surface uses programmatic Android Views, Telegram ActionBar/dialogs,
Telegram vector/raster resources already shipped by the host and current theme
keys. It has no Compose, Material Components, XML layouts, custom Canvas/Path
drawing or plugin image assets. JSON parsing, runtime commands and ping work
remain off the UI thread. Weak dashboard listeners use
a 250 ms refresh throttle, so a 50-node ping cannot flood the UI thread or
retain a destroyed fragment.
Telegram `ThemeDescription` callbacks recolor text, icons, ripples and generated
card drawables during a live theme/accent change. The dashboard ActionBar has
only the back action: version text, the overflow/about menu, duplicate
connection details, clipboard import and the Telegram-proxy shortcut are
intentionally absent. Subscription refresh remains beside the server-source
card. Dashboard setting mutations derive and revision the complete replacement
atomically, so a concurrent native settings callback cannot restore stale
sibling values.

The server browser keeps search, protocol and page offset only in fragment
memory. It exposes at most 50 bounded node summaries per page and
never renders node keys, raw proxy URIs, subscription URLs or the stored HWID.
It supports provider selection, explicit node selection, manual-node and custom
subscription management, refresh, page ping/cancel, pagination, referral and
clear-with-confirmation. Replacing the HWID starts from an empty editor; reset
is a separate explicit action.

The plugin supports only Android 10/API 29 or newer in a 64-bit process whose
primary ABI is `arm64-v8a`. The Python loader checks all three conditions before
reading either embedded payload or creating exitFy's private runtime directory.
Gradle, D8, the JNI bundle, core updater and ELF validation use the same API 29
and ELF64/`EM_AARCH64` contract.

Core selection is adaptive. A compatible family already mapped in the process
is always retained. Before the first mapping, a server supported by only one
family selects that family; a dual-compatible server selects the sole ready
family, or sing-box when readiness is equal. Ready means a compatible
active/pending release or an available requested rollback. Xray is therefore
selected automatically for configurations such as XHTTP and mKCP which cannot
be represented by sing-box. Only one Go core family may be mapped in a process.
An incompatible mapped family keeps the existing restart-required fail-closed
state; opening or starting one family never falls back to the other in the same
process.

Java digests and inspects loader-visible ELF tables through one pinned
`O_NOFOLLOW` descriptor. JNI maps a duplicate of that descriptor with
`ANDROID_DLEXT_FORCE_LOAD`; it never reopens the pathname. After the
process-wide bridge claim succeeds, one daemon keeper retains the winning DEX
class loader for the rest of the process. Reloading the same beta reuses it;
loading a different embedded DEX version fails closed until exteraGram is
restarted.

The plugin ID remains `exitFy_v2` and the settings schema is 6. Upgrading to
beta.24 does not clear settings, custom subscriptions or custom nodes. A legacy
`core_policy` value is rewritten once to the inert `auto` tombstone and is no
longer sent to DEX or exposed by Android UI. The migration also erases the four
obsolete transient dialog/filter keys from beta.16 because they may contain a
URI, subscription URL, search text or HWID after an interrupted edit. The
provider catalog
contains Elix, Shrimp and Custom; the removed legacy built-in slot falls back
to Elix while the previous Custom slot and its cached data migrate to the new
index. Each built-in cache carries an opaque catalog revision: replacing or
disabling its private endpoint invalidates only that source's cached nodes and
selection immediately. A saved disabled built-in selection falls back to the
first enabled built-in, then Custom; if none is configured, exitFy is disabled
once instead of entering a refresh/reconnect loop. Existing schema-2/API-26
core files are different: active, pending and backup copies are all excluded
from loading and rollback. When either current component is missing, the
dashboard exposes the same explicit two-component installation as a clean
install.

Generated sing-box configurations name both DNS transports and explicitly set
`route.default_domain_resolver`. This avoids sing-box 1.13's CLI deprecation
path, whose `Fatal` logger terminates an embedded Android process with exit
status 1. The companion C-shared adapter also installs a non-terminating
embedded deprecation manager so future migration notices can never kill
exteraGram.

Nodes are changed only by explicit user selection. Connection and health
failures reconnect the currently selected node and never select another one.

Once at least one usable component exists, automatic checks cover both core
families at plugin load and every 24 hours; a missing second component may
therefore continue repairing in the background. There are no manual
per-family core-update commands. With zero or one usable component, the same
generic `install_cores` action remains available, coalesces repeated taps and
publishes only `required/state/progress/stage/generation` through
`coreInstall`; `required` becomes false only when both components are ready.
At zero usable components, no network install starts before that explicit
action. When the selected server later needs a missing family, the existing
single-threaded core executor coalesces duplicate requests and installs it in
the background.
Failures retry after
`5 s → 30 s → 2 min → 10 min → 60 min`, capped at 60 minutes; a recovered
network or changed server resets the node-bound preparation sequence.
Disconnecting exitFy does not cancel a user-started generic installation or
automatic maintenance of already bootstrapped components. The generic
two-component job is independent of server selection and is not discarded
when the selected server changes. That change invalidates only stale
selected-family preparation/reconnect work. Plugin unload cancels the explicit
installation session, retry timers and late network callbacks.

New downloads accept only stable schema-3/core-API-2/config-contract-1 releases
from [itsv1eds/exitFy](https://github.com/itsv1eds/exitFy), with
`minAndroidApi=29` and exactly one `arm64-v8a` asset. The handoff releases are
`sb-v1.13.14-w2011` and `xray-v26.7.11-w2011`; the updater may select a newer
compatible stable revision and never downgrades. A verified candidate is
self-tested before use. A legacy core never becomes its backup, and a failed
first candidate leaves that family without a working core while suppressing
automatic reinstallation of the rejected digest. If no Go core has yet been
mapped, a successful background install automatically schedules reconnect;
if a different Go family has already been mapped, activation waits for the next
process start.

TLS certificate validation is intentionally disabled by product policy for
both subscriptions and the core updater. GitHub's asset digest and the
manifest SHA-256 detect accidental corruption, but over this trust-all channel
they do **not** protect a core `.so` from targeted MITM replacement. Downloads
are streamed with a 64 MiB limit and checked for GitHub digest, manifest SHA,
ELF64/`EM_AARCH64`, 16 KiB `PT_LOAD` alignment and the exact
`StartCore`/`StopCore` exports.

The two bundled subscription endpoints are not present as plaintext strings in
the Java sources, generated DEX, JADX output or plugin artifact. Authenticated
encrypted payloads are decoded only immediately before a request, temporary
byte arrays are wiped, and built-in source metadata is persisted under opaque
keys and an opaque per-slot revision, so an old plaintext or rotated-endpoint
cache is sanitized on load. The plugin build is R8
minified and the verifier rejects the endpoint domains and credential tokens.
This is static-extraction resistance only: a debugger or runtime hook can still
observe any endpoint and configuration which the client must use.

Maintainers edit the normal endpoint values only in the local
`providers.private.json`, created from `providers.private.example.json` and kept
with file mode `0600`. The file is ignored by git and never packaged. Its fixed
keys are `elix` and `shrimp`; replacing a string replaces that endpoint, while
removing a key or assigning `null` disables the corresponding slot without
renumbering saved provider IDs. `generateProviderCatalog` converts the private
file into the encrypted `ProviderCatalogData` and split material classes. Normal
Gradle compilation runs that task automatically when the private file exists;
when it is absent, public/CI builds use the already generated encrypted sources.

The installable artifact is generated at the repository root as
`exitfy.plugin`; do not edit it by
hand. The mandatory local pipeline is:

```sh
java -classpath ~/work/exteraGram-Dev/gradle/wrapper/gradle-wrapper.jar \
  org.gradle.wrapper.GradleWrapperMain -p "$PWD" clean lintPlugin \
  validateEmbeddedDexConfig unitTests buildDex auditDexWithJadx \
  verifyPluginArtifact
```

`auditDexWithJadx` fails if JADX is unavailable. The artifact verifier requires
one DEX, plugin-owned classes only, exactly the seven public Java bridge methods,
exactly
one `arm64-v8a/libexitfy_bridge.so`, the exact five JNI exports, API 29, the
package-private dashboard factory and direct settings hook. It
also rejects 32-bit/x86 Android artifacts, fake cores, local paths, removed
transports, settings-reset code, Compose/Material dependencies, obsolete UI
classes and plugin-owned image resources.
Test-only fake cores are built only
for debug/androidTest and are never embedded in the release plugin.

There is no Android emulator/device smoke job in CI. Real-device verification
is performed by the beta tester using `DEVICE_BETA_CHECKLIST.md`. The reference
`exitfy_old.plugin` is not a build or runtime input.
