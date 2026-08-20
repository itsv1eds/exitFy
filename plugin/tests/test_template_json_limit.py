import ast
import pathlib
import textwrap
import unittest


TEMPLATE = pathlib.Path(__file__).resolve().parents[1] / "ExitFy.template.plugin"


def load_template_static_method(name):
    source = TEMPLATE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(TEMPLATE))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "ExitFyPlugin":
            continue
        for member in node.body:
            if isinstance(member, ast.FunctionDef) and member.name == name:
                segment = textwrap.dedent(ast.get_source_segment(source, member))
                namespace = {}
                exec(compile(segment, str(TEMPLATE), "exec"), namespace)
                return namespace[name]
    raise AssertionError("template method not found: " + name)


class TemplateSettingsContractTest(unittest.TestCase):
    def test_settings_ast_contains_only_the_registry_placeholder(self):
        source = TEMPLATE.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(TEMPLATE))
        plugin = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef) and node.name == "ExitFyPlugin")
        methods = {
            node.name: node for node in plugin.body if isinstance(node, ast.FunctionDef)
        }
        settings = methods["create_settings"]
        calls = [node for node in ast.walk(settings) if isinstance(node, ast.Call)]
        self.assertEqual(1, len(calls))
        self.assertIsInstance(calls[0].func, ast.Name)
        self.assertEqual("Text", calls[0].func.id)
        self.assertNotIn("_create_native_settings", methods)
        self.assertNotIn("_create_servers_settings", methods)
        for token in ("Header(", "Switch(", "Selector(", "Custom(", "Divider(",
                      "AlertDialogBuilder", "UItem", "PluginsController"):
            self.assertNotIn(token, source)
        self.assertIn("LEGACY_TRANSIENT_SETTING_KEYS", source)

    def test_dashboard_entry_is_reflected_and_standard_settings_stay_absent(self):
        source = TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("createDashboardFragment", source)
        self.assertIn("def _open_dashboard", source)
        for token in ("UniversalFragment", "ExitFyNativeUi", "ExitFyViews",
                      "def _open_native_settings"):
            self.assertNotIn(token, source)

    def test_runtime_setting_storage_uses_canonical_strings(self):
        source = TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("def _normalize_runtime_setting_storage(self):", source)
        self.assertIn('self.set_setting("core_policy", "auto"', source)
        self.assertNotIn('"core_policy": self._core_policy_value()', source)
        self.assertNotIn("def _core_policy_value(self):", source)
        self.assertIn('"ping_type": self._ping_type_value()', source)
        self.assertNotIn("_normalize_native_selector_storage", source)

    def test_hwid_normalization_matches_java_trim_controls_and_surrogates(self):
        normalize = load_template_static_method("_normalize_hwid")
        malformed = (" \tA" + chr(0x85) + "B" + chr(0xD83D) + "C"
                     + chr(0xDC00) + "D \n")
        self.assertEqual("AB\ufffdC\ufffdD", normalize(malformed))
        explicit_pair = "X" + chr(0xD83D) + chr(0xDE80) + "Y"
        self.assertEqual("X🚀Y", normalize(explicit_pair))
        self.assertEqual("\u00a0value\u00a0", normalize("\u00a0value\u00a0"))
        bounded = normalize("🚀" * 300)
        self.assertEqual(256, len(bounded))
        self.assertEqual(1024, len(bounded.encode("utf-8")))
        boundary = "\u0085" * 4095 + "🚀"
        self.assertEqual("🚀", normalize(boundary))
        explicit_boundary = "\u0085" * 4095 + chr(0xD83D) + chr(0xDE80)
        self.assertEqual("🚀", normalize(explicit_boundary))

    def test_hwid_normalization_bounds_work_before_control_filtering(self):
        normalize = load_template_static_method("_normalize_hwid")
        self.assertEqual("", normalize("\u0085" * 1_000_000 + "visible"))


if __name__ == "__main__":
    unittest.main()
