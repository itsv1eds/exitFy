import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
GENERATOR = PROJECT / "tools" / "generate_provider_catalog.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("exitfy_provider_generator", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ProviderCatalogGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.generator = _load_generator()
        self.temporary = tempfile.TemporaryDirectory(prefix="exitfy-provider-generator-")
        self.root = Path(self.temporary.name)
        self.private_file = self.root / "providers.private.json"
        self.output_dir = self.root / "java"

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, providers):
        self.private_file.write_text(
            json.dumps({"schema": 1, "providers": providers}), encoding="utf-8"
        )
        os.chmod(self.private_file, 0o600)

    def _sources(self):
        return {
            path.name: path.read_text(encoding="utf-8")
            for path in self.output_dir.glob("*.java")
        }

    def test_replace_regenerates_without_plaintext_and_unchanged_input_is_stable(self):
        first = "https://subscriptions.example/private-token-1234567890"
        replacement = "https://replacement.example/new-private-token-9876543210"
        self._write({"elix": first, "shrimp": None})

        self.generator.generate(self.private_file, self.output_dir)
        generated = self._sources()
        self.assertEqual(
            {"ProviderCatalogData.java", "CatalogMaterialA.java", "CatalogMaterialB.java"},
            set(generated),
        )
        # Elix sits second in the v3 order, so its slot is the enabled one.
        self.assertIn("{false, true, false}", generated["ProviderCatalogData.java"])
        self.assertFalse(any(first in source for source in generated.values()))

        self.generator.generate(self.private_file, self.output_dir)
        self.assertEqual(generated, self._sources())

        self._write({"elix": replacement, "shrimp": None})
        self.generator.generate(self.private_file, self.output_dir)
        replaced = self._sources()
        self.assertNotEqual(generated, replaced)
        self.assertFalse(any(replacement in source for source in replaced.values()))

    def test_missing_or_null_key_disables_a_fixed_slot(self):
        self._write({})
        self.generator.generate(self.private_file, self.output_dir)
        data = self._sources()["ProviderCatalogData.java"]
        self.assertIn("{false, false, false}", data)

        # Shrimp leads the catalog, so only its slot comes back enabled.
        self._write({"shrimp": "https://subscriptions.example/shrimp-token-123456"})
        self.generator.generate(self.private_file, self.output_dir)
        data = self._sources()["ProviderCatalogData.java"]
        self.assertIn("{true, false, false}", data)

    def test_invalid_contract_fails_without_echoing_secret_url(self):
        secret = "http://subscriptions.example/should-not-be-echoed-123456"
        self._write({"elix": secret})
        with self.assertRaises(SystemExit) as captured:
            self.generator.generate(self.private_file, self.output_dir)
        self.assertNotIn(secret, str(captured.exception))

        self.private_file.write_text(
            json.dumps({"schema": True, "providers": {}}), encoding="utf-8"
        )
        os.chmod(self.private_file, 0o600)
        with self.assertRaises(SystemExit):
            self.generator.generate(self.private_file, self.output_dir)


if __name__ == "__main__":
    unittest.main()
