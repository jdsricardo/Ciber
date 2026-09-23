"""Checks the rules that docs/CODING_STANDARD.md marks as verified on the Python side.

A written standard that nothing enforces drifts away from the code within a few commits. These
tests keep the document honest: if a rule stops being true, the suite says so.
"""
import ast
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).parents[1]
SCANNER = ROOT / "scanner"
LOCAL_PACKAGES = {"engine", "plugins", "support"}


def python_files(directory):
    return sorted(p for p in directory.rglob("*.py") if "__pycache__" not in p.parts)


class DependencyTests(unittest.TestCase):
    def test_scanner_imports_only_the_standard_library(self):
        """The engine must run on a bare Python install: no third-party runtime dependency."""
        external = {}
        for path in python_files(SCANNER):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    modules = [node.module.split(".")[0]]
                else:
                    continue
                for module in modules:
                    if module not in sys.stdlib_module_names and module not in LOCAL_PACKAGES:
                        external.setdefault(module, path.relative_to(ROOT).as_posix())
        self.assertEqual({}, external, f"third-party imports found: {external}")


class PluginContractTests(unittest.TestCase):
    def test_every_plugin_declares_metadata_and_implements_analyze(self):
        """A new check is a ScannerPlugin subclass; the orchestrator holds no check logic."""
        sys.path.insert(0, str(SCANNER))
        from engine.runner import default_active_plugins, default_passive_plugins
        from plugins.base import ScannerPlugin

        active, warnings = default_active_plugins()
        self.assertEqual([], warnings, "a plugin file exists but failed to import")

        for plugin in default_passive_plugins() + active:
            with self.subTest(plugin=type(plugin).__name__):
                self.assertIsInstance(plugin, ScannerPlugin)
                self.assertTrue(plugin.metadata.name)
                self.assertIn(plugin.metadata.kind, ("passive", "safe_active"))
                self.assertTrue(plugin.metadata.checks, "plugin declares no check id")

    def test_check_ids_are_unique_across_the_catalogue(self):
        """Two plugins claiming the same check id would make checks_run meaningless."""
        sys.path.insert(0, str(SCANNER))
        from engine.runner import default_active_plugins, default_passive_plugins

        active, _ = default_active_plugins()
        ids = [check for plugin in default_passive_plugins() + active
               for check in plugin.metadata.checks]
        duplicates = {check for check in ids if ids.count(check) > 1}
        self.assertEqual(set(), duplicates)


class SecureDefaultTests(unittest.TestCase):
    def test_private_targets_are_denied_by_default(self):
        """NFR-04: the shipped configuration never allows scanning private addresses."""
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("ALLOW_PRIVATE_TARGETS=false", example)

    def test_env_file_is_not_versioned(self):
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/.env", ignored)


if __name__ == "__main__":
    unittest.main()
