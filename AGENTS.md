# Agent instructions for exitFy

This repository is two independently released products: the **exitFy** exteraGram plugin and the **cores** it downloads at runtime. Read this file before changing either. Directory READMEs (`plugin/README.md`, `cores/README.md`) are the detailed contracts; this file is the working map.

Claude Code should start here via [CLAUDE.md](./CLAUDE.md). Official host SDK docs: [plugins.exteragram.app/docs](https://plugins.exteragram.app/docs).

## Layout

| Path | What it is |
| --- | --- |
| `plugin/` | Python loader (`ExitFy.template.plugin`) + Java/DEX runtime + JNI `dlopen` bridge |
| `cores/` | Reproducible Android `arm64-v8a` Xray and exitFy SB (`libexitfy-sb`) builds |
| `.github/workflows/` | Public tree audit + two hardened core publishers |
| `exitfy.plugin` | **Build output only.** Written to the repo root. Never hand-edit, never commit |

Cores are GitHub Releases (`xray-v<upstream>-w<N>`, `sb-v<upstream>-w<N>`). They are never bundled into the plugin. The plugin loads them with `dlopen`.

Run each pipeline **from inside its directory**.

## Non-negotiables

- Never commit `plugin/providers.private.json`, `*.pem`, `*.key`, or `core-signing*`. CI fails if the private catalog is tracked. Maintainers copy `plugin/providers.private.example.json` → `providers.private.json` mode `0600`.
- Never expand `ExitFyBridge`'s public ABI. The seven public methods are `configure`, `load`, `unload`, `updateSettings`, `execute`, `getUiState`, `onAppResume`. Dashboard factory and the direct settings hook stay package-private.
- Never put custom HWID, subscription URLs, node keys, raw proxy URIs, or full custom identifiers into UI state / TextViews. HWID shows “Configured” or the generated default. Subscription User-Agent is visible on purpose (it is a client identity, not a secret).
- Every setting `SettingsModel.fromJson` reads must be sent by `ExitFyPlugin._settings_dict` in `ExitFy.template.plugin`. `verifySettingsReachTheRuntime` exists because this was forgotten twice.
- `plugin/build.gradle` encodes UI and safety contracts as string checks. If you change dashboard/preferences copy, settings keys, or HTTP limits, update those checks in the same change. Do not “temporarily” delete a contract.
- Do not introduce Compose, Material Components, XML layouts, plugin-owned images, or custom Canvas drawing. UI is programmatic Android Views + Telegram ActionBar/dialogs + host theme keys and icons.
- JSON parsing, runtime commands, HTTP and ping stay off the UI thread.
- Fail closed. Corrupt subscription state must not be replaced with empty defaults. Unknown setting keys are rejected. Oversized inputs are bounded, not silently trusted.
- Land plugin work on a branch, or merge it while no core release is running. A core publisher verifies that `main` still points at the wrapper commit it pinned; an unrelated push to `main` can abort a publish.

## exteraGram plugin SDK

Source of truth for the host: [https://plugins.exteragram.app/docs](https://plugins.exteragram.app/docs). Read it when touching `ExitFy.template.plugin`, menu items, settings rows, Java reflection, or Xposed hooks. Do not invent APIs that are not in those docs or in this tree.

exitFy is a **classic single-file** `BasePlugin`, not an [Elyx](https://plugins.exteragram.app/docs/elyx) project. Keep metadata as top-level Python constants. Do not migrate to `metainfo.yml` / `from elyx import ...` unless a human asks.

### Runtime

- Plugins are Python, running inside exteraGram through Chaquopy (docs currently: Python **3.11**, SDK **1.4.4.3**).
- Too-old app builds put the SDK in safe mode and plugin modules refuse to initialize. Treat **exteraGram 12.5.1+** as the baseline.
- exitFy currently declares `__app_version__ = ">=12.5.1"` and `__sdk_version__ = ">=1.4.3.3"`. Do not silently bump those constants; they are a compatibility contract with installed copies.
- Main modules: `base_plugin` (lifecycle, hooks, menus, `MethodHook`), `android_utils` (UI thread, listeners, log, clipboard), `client_utils` (queues, requests, send/edit, fragments, controllers), `file_utils`, `hook_utils` (reflection), `ui.settings` / `ui.bulletin`, `extera_utils` (class proxy). Java interop uses `from java import jclass` and `org.telegram.*`.

### Metadata (AST-parsed)

The loader reads `__id__`, `__name__`, `__description__`, `__author__`, `__version__`, `__icon__`, `__app_version__`, `__sdk_version__`, `__requirements__` with **AST**. They must stay plain top-level constants — no f-strings, no concatenation that the parser cannot see.

- `__id__` and `__name__` are required. `__id__` is 2–32 chars, starts with a letter, only `[A-Za-z0-9_-]`. Changing `__id__` is a **new plugin** (settings, enabled state, hooks, menus).
- `__icon__` is `StickerPackShortName/index` (exitFy uses `exitFy/1`).
- `__app_version__` / `__sdk_version__` take `>=`, `<=`, `==`, `>`, `<`. Legacy `__min_version__` is treated as `>=`.
- `__requirements__` is a PIP list if needed. exitFy does not use it.

### Lifecycle and settings storage

- `on_plugin_load`: enable or restore at app start. Register menus and Java hooks here.
- `on_plugin_unload`: disable or process shutdown. Host removes menus and Java hooks; **you** must stop threads, sockets, observers, DEX runtime.
- `on_app_event(AppEvent)`: `START`, `STOP`, `PAUSE`, `RESUME`. exitFy forwards resume into Java (`onAppResume`).
- Persist with `self.get_setting(key, default)`, `self.set_setting(key, value, reload_settings=False)`, `export_settings` / `import_settings`. Settings are keyed by `__id__` and survive reloads/updates.
- `reload_settings=True` only when the **rows** of `create_settings` must rebuild. A normal value write stays `False` (exitFy does this for HWID, UA, schema markers).

### Host settings UI vs native dashboard

`create_settings()` returns dataclasses from `ui.settings`: `Header`, `Divider`, `Switch`, `Selector`, `Input`, `Text`, `EditText`, `Custom`. exitFy keeps **only inert `Text` rows** so the host still registers a settings entry; the real UI is a Telegram `BaseFragment` opened from those rows and from menus. Do not grow a second settings tree in Python.

Menus: `add_menu_item(MenuItemData(...))` / `remove_menu_item`. Types: `MESSAGE_CONTEXT_MENU`, `DRAWER_MENU`, `MAIN_MENU`, `CHAT_ACTION_MENU`, `PROFILE_ACTION_MENU`. exitFy uses drawer + chat-action with **stable `item_id`s**. Click handlers get a context dict (`fragment`, `account`, …); inspect keys if unsure. Host removes items on unload; exitFy also removes them explicitly.

### Event hooks (TL / outgoing messages)

Register with `add_hook(name)` or `add_on_send_message_hook()`. Implementing `pre_request_hook` / `on_send_message_hook` without registering does nothing.

`HookResult` + `HookStrategy`: `DEFAULT` (leave it), `CANCEL` (stop), `MODIFY` (return the changed object on `request` / `response` / `update` / `updates` / `params`), `MODIFY_FINAL` (modify and stop other plugins).

**Multi-account:** every logged-in account stays connected. Hooks fire for accounts that are **not** on screen. Mutating the hooked object is fine. Anything you *send*, *request*, or *read* in response must use `self.client(account)` or `account=` — otherwise you hit the UI-selected account. `get_hook_account()` exists on SDK 1.4.5.0+; exitFy does not require that yet.

Do not do network or heavy I/O on the UI thread inside a hook. Use `client_utils.run_on_queue(...)` (default `PLUGINS_QUEUE`). UI mutations go through `android_utils.run_on_ui_thread(...)` (exitFy bulletins already do). `run_on_ui_thread` wraps a Python callable; use `R(fn)` only when an API needs a real `java.lang.Runnable`.

### Java reflection and Xposed hooks

- `hook_utils.find_class(fqcn)` returns a Java `Class` or `None`. Do **not** call `.getClass()` on that result. Then `getDeclaredMethod` / `getDeclaredConstructor` + `setAccessible(True)`.
- Field helpers: `get_private_field` / `set_private_field` / static variants. Reflection breaks across app updates — always `try/except` and null-check.
- `from java import jclass` for known classes (`jclass("android.os.Build")`). Nested classes use `$` (`Build$VERSION`).
- `MethodHook`: `before_hooked_method` / `after_hooked_method` on `param` (`thisObject`, `args`, `getResult()`, `setResult()`). `setResult` in **before** skips the original.
- `MethodReplacement.replace_hooked_method` replaces the whole method; return a Java-compatible value (`None` for void).
- Apply with `self.hook_method(method, handler)` or `self.hook_all_methods(clazz, name, handler)` (exitFy call-relay uses this). Unhook with the returned handle; host also unhooks on unload.
- Weak Python callbacks: if Java only holds a weak ref, keep the hook object on `self` (exitFy keeps `_call_hooks` for that reason).
- `from java import jint` (and friends) when reflecting primitive overloads.

User-facing notices: `ui.bulletin.BulletinHelper.show_info` / `show_error`. Open the last screen with `client_utils.get_last_fragment()`.

## Plugin (exitFy)

Runtime lives in `plugin/src/main/java/com/extera/plugins/exitfy`. The Python file is a thin loader and settings bus, not a second implementation of proxy logic.

**Host:** exteraGram ≥ 12.5.1, plugin SDK ≥ 1.4.3.3 (see SDK section), Android 10 / API 29+, 64-bit process, primary ABI `arm64-v8a`. The loader checks all three before creating any exitFy files.

**Telegram source** for compile is `~/work/exteraGram-Dev` (override with `telegramSourceDir` / `EXTERAGRAM_SOURCE_DIR`). Gradle/D8/JNI/core updater/ELF checks all use API 29 and ELF64/`EM_AARCH64`.

### UI

- Drawer, chat-action, and the normal plugin-settings entry all open the native dashboard. Opening the dashboard must only read UI state: no proxy start, subscription fetch, core download, or ping.
- ActionBar is back-only. No about overflow, version in the bar, clipboard import, or Telegram-proxy shortcut there.
- Settings changes (`set_setting`) derive and publish the **complete** `SettingsModel` under one lock. Rebuilding with a short constructor silently drops sibling fields — use the full constructor / `copy(...)`.
- Strings that users see go through `I18n.t("Русский", "English")`.
- Advanced settings include ping type, HWID, **User-Agent**, refresh-on-open, scheduled TCP checks, call relay experiment, failover, component versions, dual-core experiment.

### Subscriptions

Default User-Agent list is `Happ/5.2.0`, then `clash-verge/1.0` if the first answer has no usable nodes. A non-empty `subscription_user_agent` setting **replaces** that list (no fallback). Changing UA does not reconnect; the next subscription refresh uses it.

Device/HWID headers are sent only to the URL the user/provider configured, never to rewritten mirrors or cross-origin redirects.

### Cores at runtime

Selection is adaptive and automatic. The dashboard never names an engine. One Go family may be mapped per process unless the `dual_core` experiment is on (mapping the second family is process-lifetime; turning it off needs an exteraGram restart). `calls_via_proxy` also needs a restart.

TCP ping is the default: it does not steal Telegram's proxy. Proxy GET is the full-path check. Scheduled auto-check is always TCP. `failover` is stored-off; the build must keep it gated by the setting.

### Commands worth knowing

From `plugin/`:

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

Mandatory local artifact pipeline (needs the exteraGram Gradle wrapper, Android SDK, JADX):

```sh
java -classpath ~/work/exteraGram-Dev/gradle/wrapper/gradle-wrapper.jar \
  org.gradle.wrapper.GradleWrapperMain -p "$PWD" clean lintPlugin \
  validateEmbeddedDexConfig unitTests buildDex auditDexWithJadx \
  verifyPluginArtifact
```

`unitTests` is `testDebugUnitTest` + Python template tests. There is no emulator CI; device checks are `plugin/DEVICE_BETA_CHECKLIST.md`.

When `providers.private.json` exists, Gradle regenerates the encrypted catalog. Public/CI builds use the already generated encrypted sources.

## Cores

Two families, two workflows, two Go modules so SB dependencies cannot change libXray. Only Android `arm64-v8a` at API 29. Exported ABI is `StartCore` / `StopCore` only.

- Xray releases: `libxray-arm64-v8a.so` + `manifest.json`
- SB releases: `libexitfy-sb-arm64-v8a.so` + `manifest.json` + corresponding-source bundle

Do not add CLI `Fatal`/`os.Exit` paths to a shared library loaded into Telegram. Do not treat GitHub asset digests as a trust root independent of GitHub (the plugin uses trust-all TLS by policy).

From `cores/`:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/audit_public_tree.py --repo-root .. --path-prefix cores --path-prefix .github
```

External GitHub Actions must stay pinned to full commit SHAs. Publisher jobs are the only ones with `contents: write`.

## Git

### Conventional Commits

Every commit follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

[optional body: why, not a file list]

[optional footer]
```

- **type** (required): `feat` user-visible capability; `fix` bug; `docs` markdown/comments only; `refactor` no intended behavior change; `test` tests only; `build` Gradle/Go/NDK/artifact pipeline; `ci` GitHub Actions; `chore` repo hygiene that is none of the above. Do not use `style` or `perf` unless a human asks.
- **scope** (required when the change is not repo-wide): `plugin`, `cores`, or `ci`. Drop the scope only for root docs / both products in one commit (`docs: …`, `chore: …`).
- **subject**: imperative, lowercase after the colon, no trailing period, about **why / user effect**, not the files. Keep it to ~72 characters.
- **body**: optional, wrap at 72, explain why. Do not paste diffs.
- **breaking change**: `feat(plugin)!: …` or a footer `BREAKING CHANGE: …`. Do not mark a release as breaking unless a human asked — bumping `__id__`, the public `ExitFyBridge` ABI, or core `StartCore`/`StopCore` would be breaking.
- One logical change per commit. Do not mix plugin runtime with a core wrapper bump.
- Do **not** add `Co-authored-by: Cursor <cursoragent@cursor.com>` (or any Cursor agent trailer). If a hook or the environment appends it, strip it before push.

Examples:

```
feat(plugin): let Advanced replace the subscription User-Agent
fix(cores): reject a wrapper tag that moved off the pinned commit
docs: add AGENTS.md for plugin SDK and core pipelines
ci: pin the public-tree audit action to a full commit SHA
```

### Other git rules

- Do not commit `.codegraph/`, `exitfy.plugin`, or provider secrets.
- Prefer a feature branch for plugin work. `main` is also the core-release pin; force-pushing `main` is exceptional and only when the human explicitly asked to rewrite a commit that has no other dependents.

## How to change things safely

1. Prefer tests at the seam you are changing (`SettingsModel`, `SubscriptionManager`, `ExitFyDashboardState`, Python `_settings_dict`) before UI copy.
2. If you add a setting: Java model (`fromJson` / `toJson` / `withSetting` / `equals`) → Python `_settings_dict` → UI row → `recordChangedSettingRevisions` → gradle/python contracts → tests. Carry the new field through every `new SettingsModel(...)`.
3. If you add a user-visible string, add both Russian and English in `I18n.t`.
4. Do not log or put in UI anything that could reconstruct a subscription token or HWID.
5. Verify: Python tests always; Java unit tests when the exteraGram host classes are available; the gradle contracts (`lintPlugin`, `verifySettingsReachTheRuntime`) when touching plugin UI or settings.
6. Host APIs (`BasePlugin`, menus, `ui.settings`, hooks, `find_class`, `MethodHook`) come from [plugins.exteragram.app/docs](https://plugins.exteragram.app/docs), not from memory. Check the docs if the call is not already in this tree.
