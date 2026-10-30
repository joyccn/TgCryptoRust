"""Ensure both Python entry points stay direct, equivalent native exports."""

import unittest

import tgcrypto
import tgcryptors
from tgcryptors import _native


class PythonPackageTests(unittest.TestCase):
    def test_public_operations_are_native_objects(self):
        for name in tgcryptors.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(tgcryptors, name), getattr(_native, name))

    def test_compatibility_module_exports_same_native_api(self):
        self.assertEqual(tgcrypto.__all__, tgcryptors.__all__)
        self.assertEqual(len(tgcryptors.__all__), len(set(tgcryptors.__all__)))
        for name in tgcryptors.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(tgcrypto, name), getattr(tgcryptors, name))

    def test_wildcard_import_includes_version_and_public_api(self):
        for module_name in ("tgcrypto", "tgcryptors"):
            with self.subTest(module=module_name):
                namespace = {}
                exec("from " + module_name + " import *", namespace)
                namespace.pop("__builtins__", None)
                self.assertEqual(set(namespace), set(tgcryptors.__all__))
                self.assertEqual(namespace["__version__"], tgcryptors.__version__)


if __name__ == "__main__":
    unittest.main()
