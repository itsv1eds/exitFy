import ast
import hashlib
import os
import pathlib
import tempfile
import unittest


def load_dex_runtime(namespace):
    template = pathlib.Path(__file__).resolve().parents[1] / "ExitFy.template.plugin"
    tree = ast.parse(template.read_text(encoding="utf-8"), filename=str(template))
    selected = []
    names = {"__version__", "ENTRY_CLASS", "DEX_KEEPER_PREFIX", "DEX_KEEPER_NAME"}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in names for target in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.ClassDef) and node.name == "DexRuntime":
            selected.append(node)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(template), "exec"), namespace)
    return namespace["DexRuntime"]


def load_platform_functions(namespace):
    template = pathlib.Path(__file__).resolve().parents[1] / "ExitFy.template.plugin"
    tree = ast.parse(template.read_text(encoding="utf-8"), filename=str(template))
    selected = []
    names = {"SUPPORTED_ABIS", "ELF_MACHINES", "NATIVE_BEGIN", "NATIVE_END"}
    functions = {"_require_supported_platform", "_current_abi",
                 "_matches_file_digest", "_extract_native_bridge"}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in names for target in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(template), "exec"), namespace)
    return namespace


def template_version():
    template = pathlib.Path(__file__).resolve().parents[1] / "ExitFy.template.plugin"
    tree = ast.parse(template.read_text(encoding="utf-8"), filename=str(template))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("template version metadata is absent")


class FakeThread:
    def __init__(self, name, loader):
        self._name = name
        self._loader = loader

    def getName(self):
        return self._name

    def getContextClassLoader(self):
        return self._loader


class FakeThreadSet:
    def __init__(self, threads):
        self._threads = threads

    def toArray(self):
        return list(self._threads)


class FakeThreadMap:
    def __init__(self, threads):
        self._threads = threads

    def keySet(self):
        return FakeThreadSet(self._threads)


class FakeLoader:
    def __init__(self, loaded_class):
        self.loaded_class = loaded_class
        self.calls = 0

    def loadClass(self, _name):
        self.calls += 1
        return self.loaded_class


class DexKeeperTemplateTest(unittest.TestCase):
    def namespace(self, threads, extra_classes=None):
        class ThreadApi:
            @staticmethod
            def getAllStackTraces():
                return FakeThreadMap(threads)

        classes = {"java.lang.Thread": ThreadApi}
        classes.update(extra_classes or {})
        return {
            "BuildVersion": type("BuildVersion", (), {"SDK_INT": 29}),
            "_require_supported_platform": lambda: "arm64-v8a",
            "jclass": lambda name: classes[name],
            "_read_payload": lambda *_args: (_ for _ in ()).throw(
                AssertionError("embedded payload must not be read while reusing keeper")
            ),
            "DEX_BEGIN": "__DEX_BEGIN__",
            "DEX_END": "__DEX_END__",
            "ApplicationLoader": type("ApplicationLoader", (), {"applicationContext": None}),
        }

    def platform_namespace(self, api, abi, is64=True):
        reads = []
        namespace = {
            "hashlib": hashlib,
            "os": os,
            "BuildVersion": type("BuildVersion", (), {"SDK_INT": api}),
            "Build": type("Build", (), {"SUPPORTED_ABIS": [abi]}),
            "Process": type("Process", (), {"is64Bit": staticmethod(lambda: is64)}),
            "_read_payload": lambda *_args: reads.append(True) or b"{}",
        }
        return load_platform_functions(namespace), reads

    def test_existing_bridge_digest_is_streamed_and_size_gated(self):
        namespace, _reads = self.platform_namespace(29, "arm64-v8a")
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "bridge.so"
            value = b"bridge" * 20_000
            path.write_bytes(value)
            digest = hashlib.sha256(value).hexdigest()
            self.assertTrue(namespace["_matches_file_digest"](
                str(path), len(value), digest))
            self.assertFalse(namespace["_matches_file_digest"](
                str(path), len(value) + 1, digest))
            self.assertFalse(namespace["_matches_file_digest"](
                str(path), len(value), "0" * 64))

    def test_api_28_arm64_is_rejected_before_native_payload_read(self):
        namespace, reads = self.platform_namespace(28, "arm64-v8a")
        with self.assertRaisesRegex(RuntimeError, "API 29"):
            namespace["_extract_native_bridge"]()
        self.assertEqual([], reads)

    def test_api_29_non_arm64_is_rejected_before_native_payload_read(self):
        namespace, reads = self.platform_namespace(29, "x86_64")
        with self.assertRaisesRegex(RuntimeError, "arm64-v8a"):
            namespace["_extract_native_bridge"]()
        self.assertEqual([], reads)

    def test_api_29_32_bit_process_is_rejected_before_native_payload_read(self):
        namespace, reads = self.platform_namespace(29, "arm64-v8a", is64=False)
        with self.assertRaisesRegex(RuntimeError, "64-bit"):
            namespace["_extract_native_bridge"]()
        self.assertEqual([], reads)

    def test_api_29_arm64_64_bit_process_passes_platform_gate(self):
        namespace, reads = self.platform_namespace(29, "arm64-v8a")
        self.assertEqual("arm64-v8a", namespace["_require_supported_platform"]())
        self.assertEqual([], reads)

    def test_same_version_keeper_reuses_loader_without_reading_payload(self):
        loaded_class = object()
        loader = FakeLoader(loaded_class)
        keeper_name = "exitfy-dex-keeper:exitFy_v2:" + template_version()
        namespace = self.namespace([FakeThread(keeper_name, loader)])
        runtime_type = load_dex_runtime(namespace)

        runtime = runtime_type()
        runtime.prepare()

        self.assertIs(loader, runtime.class_loader)
        self.assertIs(loaded_class, runtime.clazz)
        self.assertEqual(1, loader.calls)

    def test_other_version_keeper_requires_process_restart_before_new_dex(self):
        loader = FakeLoader(object())
        namespace = self.namespace([
            FakeThread("exitfy-dex-keeper:exitFy_v2:incompatible-version", loader)
        ])
        runtime_type = load_dex_runtime(namespace)

        with self.assertRaisesRegex(RuntimeError, "restart exteraGram"):
            runtime_type().prepare()
        self.assertEqual(0, loader.calls)

    def test_duplicate_same_version_keepers_fail_closed(self):
        loader = FakeLoader(object())
        keeper_name = "exitfy-dex-keeper:exitFy_v2:" + template_version()
        namespace = self.namespace([
            FakeThread(keeper_name, loader),
            FakeThread(keeper_name, loader),
        ])
        runtime_type = load_dex_runtime(namespace)

        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            runtime_type().prepare()
        self.assertEqual(0, loader.calls)

    def test_fresh_process_creates_loader_only_after_no_keeper_is_found(self):
        loaded_class = object()
        loader = FakeLoader(loaded_class)
        payload_reads = []
        parent_loader = object()

        class ByteBuffer:
            @staticmethod
            def wrap(value):
                return ("buffer", value)

        class InMemoryDexClassLoader:
            def __new__(cls, buffer, parent):
                self.assertEqual(("buffer", b"dex"), buffer)
                self.assertIs(parent_loader, parent)
                return loader

        namespace = self.namespace([], {
            "java.nio.ByteBuffer": ByteBuffer,
            "dalvik.system.InMemoryDexClassLoader": InMemoryDexClassLoader,
        })
        namespace["ApplicationLoader"] = type("ApplicationLoader", (), {
            "applicationContext": type("Context", (), {
                "getClassLoader": lambda _self: parent_loader,
            })(),
        })
        namespace["_read_payload"] = lambda *_args: payload_reads.append(True) or b"dex"
        runtime_type = load_dex_runtime(namespace)

        runtime = runtime_type()
        runtime.prepare()

        self.assertEqual([True], payload_reads)
        self.assertIs(loader, runtime.class_loader)
        self.assertIs(loaded_class, runtime.clazz)


if __name__ == "__main__":
    unittest.main()
