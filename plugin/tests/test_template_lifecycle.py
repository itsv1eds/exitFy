import ast
import sys
import threading
import types
import json
import pathlib
import unittest


class FakeBasePlugin:
    def __init__(self):
        self.logs = []
        self.settings = {}
        self.menu_items = []

    def log(self, message):
        self.logs.append(str(message))

    def get_setting(self, key, default=None):
        return self.settings.get(key, default)

    def set_setting(self, key, value, reload_settings=False):
        del reload_settings
        self.settings[key] = value

    def remove_menu_item(self, _item_id):
        return True

    def add_menu_item(self, item):
        self.menu_items.append(item)
        return item.item_id


class FakeValue:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeMenuItemType:
    DRAWER_MENU = "drawer"
    CHAT_ACTION_MENU = "chat"


class FakeDashboard:
    def __init__(self):
        self.current_account = None

    def setCurrentAccount(self, account):
        self.current_account = account


class FakeDexRuntime:
    def __init__(self):
        self.starts = 0
        self.stops = 0
        self.calls = []
        self.dashboard = FakeDashboard()

    def start(self, _bootstrap, _settings):
        self.starts += 1

    def stop(self):
        self.stops += 1

    def call(self, method, *args):
        self.calls.append((method, args))
        if method == "createDashboardFragment":
            return self.dashboard
        if method == "onAppResume":
            return None
        if method == "execute":
            return json.dumps({"ok": True, "message": "", "value": ""})
        raise AssertionError("unexpected bridge call: " + method)


def load_plugin_class(overrides=None):
    template = pathlib.Path(__file__).resolve().parents[1] / "ExitFy.template.plugin"
    tree = ast.parse(template.read_text(encoding="utf-8"), filename=str(template))
    selected = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ExitFyPlugin"
    )
    runtime = FakeDexRuntime()
    errors = []
    infos = []
    opened = []

    class FakeLastFragment:
        @staticmethod
        def getCurrentAccount():
            return 7

        @staticmethod
        def presentFragment(fragment):
            opened.append(fragment)
            return True

    namespace = {
        "BasePlugin": FakeBasePlugin,
        "_DEX_RUNTIME": runtime,
        "_extract_native_bridge": lambda: (
            "/private/exitfy", "/private/bridge.so", "arm64-v8a"
        ),
        "__id__": "exitFy_v2",
        "__version__": "4.0.0-beta.25",
        "PROVIDER_CATALOG_VERSION": 3,
        "CUSTOM_PROVIDER_ID": 3,
        "CUSTOM_V2_ID": 2,
        "SETTINGS_SCHEMA": 6,
        "LEGACY_TRANSIENT_SETTING_KEYS": (
            "ui_add_node", "ui_add_subscription", "ui_hwid_entry", "ui_node_query",
        ),
        "LEGACY_PLUGIN_ID": "exitfy",
        "LEGACY_IMPORT_FLAG": "legacy_import_done",
        "LEGACY_MAX_SUBSCRIPTIONS": 16,
        "LEGACY_MAX_MANUAL_NODES": 200,
        "PLUGIN_ENABLED_PREFIX": "plugin_enabled_",
        "threading": threading,
        "ApplicationLoader": None,
        "_ui_info": infos.append,
        "json": json,
        "_ui_error": errors.append,
        "_t": lambda key: key,
        "run_on_ui_thread": lambda callback: callback(),
        "get_last_fragment": lambda: FakeLastFragment,
        "Text": type("Text", (FakeValue,), {}),
        "MenuItemData": type("MenuItemData", (FakeValue,), {}),
        "MenuItemType": FakeMenuItemType,
    }
    if overrides:
        namespace.update(overrides)
    exec(compile(ast.Module(body=[selected], type_ignores=[]), str(template), "exec"),
         namespace)
    return namespace["ExitFyPlugin"], runtime, errors, opened, infos


SHRIMP, ELIX, SWORKLE, CUSTOM = 0, 1, 2, 3


class TemplateLifecycleTest(unittest.TestCase):
    def test_removed_legacy_provider_selection_falls_back_to_first_source(self):
        plugin_type, *_ = load_plugin_class()
        plugin = plugin_type()
        plugin.settings["provider_id"] = 2

        plugin._migrate_provider_catalog()

        # The removed slot became Elix, which the v3 order puts second.
        self.assertEqual(ELIX, plugin.settings["provider_id"])
        self.assertEqual(3, plugin.settings["provider_catalog_version"])
        self.assertEqual(2, plugin.settings["provider_catalog_legacy_id"])

    def test_v2_selections_follow_their_provider_into_the_v3_order(self):
        for saved, expected in ((0, ELIX), (1, SHRIMP), (2, CUSTOM)):
            plugin_type, *_ = load_plugin_class()
            plugin = plugin_type()
            plugin.settings["provider_id"] = saved
            plugin.settings["provider_catalog_version"] = 2

            plugin._migrate_provider_catalog()

            self.assertEqual(expected, plugin.settings["provider_id"])

    def test_legacy_custom_selection_moves_to_new_custom_slot(self):
        plugin_type, *_ = load_plugin_class()
        plugin = plugin_type()
        plugin.settings["provider_id"] = 3

        plugin._migrate_provider_catalog()
        plugin._migrate_provider_catalog()

        self.assertEqual(CUSTOM, plugin.settings["provider_id"])
        self.assertEqual(3, plugin.settings["provider_catalog_legacy_id"])

    def test_schema_marker_failure_is_nonfatal_after_runtime_start(self):
        plugin_type, runtime, *_ = load_plugin_class()
        plugin = plugin_type()
        plugin._settings_json = lambda: "{}"
        plugin._register_menu = lambda: None
        original = plugin.set_setting

        def fail_schema(key, *args, **kwargs):
            if key == "schema_version":
                raise RuntimeError("preferences unavailable")
            return original(key, *args, **kwargs)

        plugin.set_setting = fail_schema
        plugin.on_plugin_load()

        self.assertTrue(plugin._runtime_ready)
        self.assertEqual(1, runtime.starts)
        self.assertEqual(0, runtime.stops)
        self.assertTrue(any("schema marker" in item for item in plugin.logs))

    def test_runtime_start_failure_is_cleaned_up_and_reaches_host_engine(self):
        plugin_type, runtime, errors, _opened, _infos = load_plugin_class()
        plugin = plugin_type()
        runtime.start = lambda *_args: (_ for _ in ()).throw(
            RuntimeError("native bridge failure")
        )

        with self.assertRaisesRegex(RuntimeError, "native bridge failure"):
            plugin.on_plugin_load()

        self.assertFalse(plugin._runtime_ready)
        self.assertEqual(1, runtime.stops)
        self.assertTrue(errors)

    def test_settings_registry_contains_only_author_placeholder(self):
        plugin_type, *_ = load_plugin_class()
        rows = plugin_type().create_settings()

        self.assertEqual(1, len(rows))
        self.assertEqual("Text", type(rows[0]).__name__)
        self.assertEqual("@exteraPluginsSup", rows[0].text)
        self.assertEqual({"text"}, set(vars(rows[0])))

    def test_both_menu_entries_open_dashboard_directly(self):
        plugin_type, runtime, _errors, opened, _infos = load_plugin_class()
        plugin = plugin_type()
        plugin._runtime_ready = True
        plugin._register_menu()

        self.assertEqual({"drawer", "chat"}, {item.menu_type for item in plugin.menu_items})
        for item in plugin.menu_items:
            item.on_click(None)

        self.assertEqual([runtime.dashboard, runtime.dashboard], opened)
        self.assertEqual(7, runtime.dashboard.current_account)
        self.assertEqual(2, sum(
            method == "createDashboardFragment" for method, _args in runtime.calls
        ))

    def test_legacy_selector_indices_migrate_to_tombstone_and_canonical_ping(self):
        plugin_type, *_ = load_plugin_class()
        plugin = plugin_type()
        plugin.settings.update({"core_policy": 2, "ping_type": 1})

        plugin._normalize_runtime_setting_storage()

        self.assertEqual("auto", plugin.settings["core_policy"])
        self.assertEqual("tcp", plugin.settings["ping_type"])
        self.assertNotIn("core_policy", plugin._settings_dict())
        self.assertEqual("tcp", plugin._settings_dict()["ping_type"])

    def test_string_numeric_and_invalid_core_policies_become_auto_tombstone(self):
        plugin_type, *_ = load_plugin_class()
        for legacy in ("sing_box", "xray", "invalid", 0, 1, 2, 99, None):
            with self.subTest(legacy=legacy):
                plugin = plugin_type()
                plugin.settings.update({
                    "core_policy": legacy,
                    "ping_type": "invalid",
                })

                plugin._normalize_runtime_setting_storage()

                self.assertEqual("auto", plugin.settings["core_policy"])
                self.assertEqual("proxy_get", plugin.settings["ping_type"])
                self.assertNotIn("core_policy", plugin._settings_dict())

    def test_load_clears_obsolete_transient_settings_only(self):
        plugin_type, _runtime, *_ = load_plugin_class()
        plugin = plugin_type()
        plugin.settings.update({
            "ui_add_node": "vless://secret",
            "ui_add_subscription": "https://secret.invalid/sub",
            "ui_hwid_entry": "secret-hwid",
            "custom_hwid": "preserved-hwid",
            "ui_node_query": "obsolete query",
        })
        plugin._settings_json = lambda: "{}"
        plugin._register_menu = lambda: None

        plugin.on_plugin_load()

        self.assertEqual("", plugin.settings["ui_add_node"])
        self.assertEqual("", plugin.settings["ui_add_subscription"])
        self.assertEqual("", plugin.settings["ui_hwid_entry"])
        self.assertEqual("preserved-hwid", plugin.settings["custom_hwid"])
        self.assertEqual("", plugin.settings["ui_node_query"])

class InlineThread:
    def __init__(self, target=None, name=None, daemon=None):
        del name, daemon
        self._target = target

    def start(self):
        if self._target is not None:
            self._target()


class InlineThreading:
    Thread = InlineThread


class LegacyImportTest(unittest.TestCase):
    LEGACY = {
        "custom_hwid": "  legacy-hwid  ",
        "vless_data_custom": {
            "subs": ["https://example.invalid/sub", "", "https://example.invalid/sub"],
            "manual": ["vless://one", "  vless://two  ", 5],
            "active_uri": "vless://one",
        },
    }

    def _run(self, legacy, existing=None):
        module = types.ModuleType("plugin_settings")
        module.get_all_settings = lambda plugin_id: (
            legacy if plugin_id == "exitfy" else {})
        sys.modules["plugin_settings"] = module
        try:
            plugin_type, runtime, _errors, _opened, infos = load_plugin_class({
                "threading": InlineThreading,
                # the real key carries the two counts
                "_t": lambda key: "imported %d/%d" if key == "legacy_imported" else key,
            })
            plugin = plugin_type()
            if existing:
                plugin.settings.update(existing)
            plugin.on_plugin_load()
            return plugin, runtime, infos
        finally:
            sys.modules.pop("plugin_settings", None)

    def test_hand_written_sources_are_imported_once(self) -> None:
        plugin, runtime, infos = self._run(self.LEGACY)
        commands = [json.loads(arguments[0]) for method, arguments in runtime.calls
                    if method == "execute"]
        self.assertEqual(
            [c for c in commands if c["command"] == "add_subscription"],
            [{"command": "add_subscription", "url": "https://example.invalid/sub"}])
        self.assertEqual(
            [c["uri"] for c in commands if c["command"] == "add_node"],
            ["vless://one", "vless://two"])
        self.assertEqual(plugin.settings.get("custom_hwid"), "legacy-hwid")
        self.assertTrue(plugin.settings.get("legacy_import_done"))
        self.assertTrue(infos)

        replay, replay_runtime, _infos = self._run(self.LEGACY, plugin.settings)
        self.assertEqual(
            [m for m, _ in replay_runtime.calls if m == "execute"], [])
        self.assertTrue(replay.settings.get("legacy_import_done"))

    def test_unloading_mid_import_keeps_the_import_pending(self) -> None:
        module = types.ModuleType("plugin_settings")
        module.get_all_settings = lambda plugin_id: (
            self.LEGACY if plugin_id == "exitfy" else {})
        sys.modules["plugin_settings"] = module
        try:
            plugin_type, runtime, _errors, _opened, _infos = load_plugin_class({
                "threading": InlineThreading,
                "_t": lambda key: "imported %d/%d" if key == "legacy_imported" else key,
            })
            plugin = plugin_type()
            original = runtime.call

            def unload_after_first(method, *arguments):
                if method == "execute":
                    plugin._runtime_ready = False
                return original(method, *arguments)

            runtime.call = unload_after_first
            plugin.on_plugin_load()
        finally:
            sys.modules.pop("plugin_settings", None)
        executed = [m for m, _ in runtime.calls if m == "execute"]
        self.assertEqual(1, len(executed))
        self.assertNotIn("legacy_import_done", plugin.settings)

    def test_existing_hwid_is_never_replaced(self) -> None:
        plugin, _runtime, _infos = self._run(
            self.LEGACY, {"custom_hwid": "current"})
        self.assertEqual(plugin.settings.get("custom_hwid"), "current")

    def test_unreachable_storage_leaves_the_import_pending(self) -> None:
        plugin_type, runtime, _errors, _opened, _infos = load_plugin_class(
            {"threading": InlineThreading})
        plugin = plugin_type()
        sys.modules.pop("plugin_settings", None)
        plugin.on_plugin_load()
        self.assertEqual([m for m, _ in runtime.calls if m == "execute"], [])
        self.assertNotIn("legacy_import_done", plugin.settings)

    def test_absent_previous_plugin_marks_import_complete(self) -> None:
        plugin, runtime, _infos = self._run({})
        self.assertEqual([m for m, _ in runtime.calls if m == "execute"], [])
        self.assertTrue(plugin.settings.get("legacy_import_done"))


if __name__ == "__main__":
    unittest.main()
