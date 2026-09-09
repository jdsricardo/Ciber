"""Tests for the developer-facing remediation examples layer.

Guarantees that every check a plugin can emit carries a concrete "vulnerable -> fixed"
code example, that examples are well-formed, and that build_finding propagates them into
the serialized finding consumed by the PHP layer.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from engine.models import HttpRequest, HttpResponse, PageContext, ScanContext, ScanLimits, ScanMode
from engine.runner import default_active_plugins, default_passive_plugins
from plugins.catalog import CATALOG
from plugins.headers import SecurityHeadersPlugin
from plugins.remediation_examples import EXAMPLES, get


def _all_owned_check_ids() -> set[str]:
    ids: set[str] = set()
    for plugin in default_passive_plugins():
        ids.update(plugin.metadata.checks)
    active, _ = default_active_plugins()
    for plugin in active:
        ids.update(plugin.metadata.checks)
    return ids


class RemediationExampleCoverageTests(unittest.TestCase):
    def test_every_owned_check_has_an_example(self):
        missing = sorted(cid for cid in _all_owned_check_ids() if cid not in EXAMPLES)
        self.assertEqual(missing, [], f"check ids without a remediation example: {missing}")

    def test_no_example_references_an_unknown_check_id(self):
        known = set(CATALOG) | _all_owned_check_ids()
        orphans = sorted(cid for cid in EXAMPLES if cid not in known)
        self.assertEqual(orphans, [], f"example keys not matching any check id: {orphans}")

    def test_examples_are_well_formed(self):
        for check_id, example in EXAMPLES.items():
            self.assertTrue(example.get("vulnerable"), f"{check_id} has empty 'vulnerable'")
            self.assertTrue(example.get("fixed"), f"{check_id} has empty 'fixed'")
            self.assertNotEqual(example["vulnerable"], example["fixed"], f"{check_id} vulnerable == fixed")

    def test_get_returns_empty_dict_for_unknown(self):
        self.assertEqual(get("does.not.exist"), {})


class RemediationExamplePropagationTests(unittest.TestCase):
    def test_build_finding_carries_example_into_serialized_finding(self):
        request = HttpRequest(method="GET", url="http://x/")
        response = HttpResponse(
            status=200, url="http://x/", headers={"content-type": "text/html"},
            header_pairs=[("content-type", "text/html")],
            body=b"<html><body><form><input type=password></form></body></html>", elapsed_ms=10,
        )
        context = ScanContext(
            target_url="http://x/", mode=ScanMode.PASSIVE, limits=ScanLimits(),
            page=PageContext(is_html=True, has_forms=True, has_password_field=True),
        )
        findings = SecurityHeadersPlugin().analyze(request, [response, response], context)
        self.assertTrue(findings)
        for finding in findings:
            data = finding.to_dict()
            self.assertIn("remediation_example_vulnerable", data)
            self.assertIn("remediation_example_fixed", data)
            expected = get(data["fingerprint"])
            if expected:
                self.assertEqual(data["remediation_example_vulnerable"], expected["vulnerable"])
                self.assertEqual(data["remediation_example_fixed"], expected["fixed"])


if __name__ == "__main__":
    unittest.main()
