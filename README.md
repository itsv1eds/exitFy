# exitFy

Adaptive Telegram proxy plugin for exteraGram, together with the reproducible
Android core builds it downloads at runtime.

| Path | Contents | Licence |
| --- | --- | --- |
| [`plugin/`](plugin/) | the exitFy plugin: a thin Python loader plus the Java/DEX runtime and its JNI bridge | see `plugin/` |
| [`cores/`](cores/) | reproducible Xray and exitFy SB core builds published as GitHub releases | MIT (`cores/LICENSE`); the combined SB shared libraries are GPL-3.0-or-later (`cores/singbox/COPYING`) |

The two parts are released independently. Cores are published as
`xray-v<upstream>-w<N>` and `sb-v<upstream>-w<N>` releases and are downloaded
by the plugin at runtime; they are never bundled into the plugin artifact, and
the plugin loads them through `dlopen`. The installable plugin artifact is
generated at the repository root as `exitfy.plugin`.

Each directory documents its own build and verification pipeline. Run those
pipelines from inside the directory they belong to.

## Continuous integration

`audit-public` audits the exact public Git state of `cores/` and
`.github/`, and fails if the maintainer-only
`plugin/providers.private.json` is ever committed. The two hardened core
publishers build and release each core family; they trigger only on changes
under `cores/` and on their own workflow file.

A core release verifies that `main` still points at the wrapper commit it
pinned. Land plugin work through a branch, or merge it while no core release
is running, so an unrelated push cannot abort a publish in progress.
