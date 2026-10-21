import ast
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
JAVA = ROOT / "src/main/java/com/extera/plugins/exitfy"
LITERAL = r'"(?:[^"\\]|\\.)*"'
EXPRESSION = LITERAL + r'(?:\s*\+\s*' + LITERAL + r')*'
MESSAGE = re.compile(r'I18n\.(?:t|format)\(\s*(' + EXPRESSION + r')\s*,\s*(' + EXPRESSION + r')')


class LocalizationTest(unittest.TestCase):
    def test_every_literal_ui_message_has_chinese_and_preserves_format_arguments(self):
        catalog = dict((json.loads(a), json.loads(b)) for a, b in re.findall(
            r'values\.put\((' + LITERAL + r'),\s*(' + LITERAL + r')\);',
            (JAVA / "ChineseStrings.java").read_text()))
        messages = set()
        for source in JAVA.glob("*.java"):
            for match in MESSAGE.finditer(source.read_text()):
                messages.add("".join(json.loads(part) for part in re.findall(LITERAL, match.group(2))))
        self.assertFalse(messages - catalog.keys(), sorted(messages - catalog.keys()))
        for english, chinese in catalog.items():
            self.assertTrue(chinese.strip())
            self.assertEqual(re.findall(r'%(?:\d+\$)?[sdf%]', english),
                             re.findall(r'%(?:\d+\$)?[sdf%]', chinese), english)

    def test_loader_follows_client_locale_and_carries_vpn_preference(self):
        tree = ast.parse((ROOT / "ExitFy.template.plugin").read_text())
        selected = [node for node in tree.body if
                    isinstance(node, ast.FunctionDef) and node.name in ("_language_code", "_is_russian", "_t")
                    or isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_TRANSLATIONS" for t in node.targets)]
        class LocaleInfo:
            shortName = "zh-Hans"
        class Controller:
            getInstance = staticmethod(lambda: Controller())
            getCurrentLocaleInfo = staticmethod(lambda: LocaleInfo())
        namespace = {"LocaleController": Controller}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "loader-locale", "exec"), namespace)
        self.assertEqual("打开 exitFy", namespace["_t"]("open_dashboard"))
        LocaleInfo.shortName = "en"
        self.assertEqual("Open exitFy", namespace["_t"]("open_dashboard"))
        LocaleInfo.shortName = "ru"
        self.assertEqual("Открыть exitFy", namespace["_t"]("open_dashboard"))


if __name__ == "__main__":
    unittest.main()
