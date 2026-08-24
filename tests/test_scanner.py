"""End-to-end CLI/runner tests: catalog completeness, scope enforcement, and JSON shape."""
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from engine.models import HttpResponse
from engine.runner import default_passive_plugins, run_passive_scan
from engine.transport import HttpTransport
from plugins.catalog import CATALOG


def fake_response(url):
    headers = {"content-type": "text/html"}
    return HttpResponse(200, url, headers, list(headers.items()), b"<html><body>Hello</body></html>", 15)


class CatalogTests(unittest.TestCase):
    def test_catalog_has_broad_passive_coverage(self):
        self.assertGreaterEqual(len(CATALOG), 30)
        categories = {entry["category"] for entry in CATALOG.values()}
        self.assertTrue({"Transport Security", "Security Headers", "Session Management",
                          "CORS Misconfiguration", "Cache Security", "Information Disclosure",
                          "Secrets Exposure"} <= categories)

    def test_every_entry_declares_taxonomy_fields(self):
        for check_id, entry in CATALOG.items():
            for field in ("title", "category", "cwe", "owasp", "wstg", "description", "developer_impact", "remediation"):
                self.assertTrue(entry.get(field), f"{check_id} is missing {field}")


class PluginRegistrationTests(unittest.TestCase):
    def test_every_catalog_entry_is_claimed_by_exactly_one_plugin(self):
        declared: list[str] = []
        for plugin in default_passive_plugins():
            declared.extend(plugin.metadata.checks)
        self.assertEqual(len(declared), len(set(declared)), "a check id is declared by more than one plugin")
        self.assertEqual(set(CATALOG.keys()), set(declared))


class RunnerTests(unittest.TestCase):
    def test_private_target_is_blocked_by_default(self):
        result = run_passive_scan("http://127.0.0.1/")
        self.assertFalse(result["ok"])
        self.assertIn("error", result)

    def test_clean_site_scan_returns_expected_shape(self):
        with patch.object(HttpTransport, "send", lambda self, request: fake_response(request.url)):
            result = run_passive_scan("https://example.com/")
        self.assertTrue(result["ok"])
        self.assertEqual(200, result["status_code"])
        self.assertEqual(len(default_passive_plugins()), result["plugins_run"])
        self.assertEqual(len(CATALOG), result["checks_run"])
        self.assertIsInstance(result["findings"], list)
        self.assertGreater(len(result["findings"]), 0)  # missing headers on a bare HTML page
        for finding in result["findings"]:
            for field in ("fingerprint", "severity", "confidence", "status", "cwe", "owasp", "wstg",
                          "evidence", "developer_impact", "remediation", "affected_url"):
                self.assertIn(field, finding)


if __name__ == "__main__":
    unittest.main()
