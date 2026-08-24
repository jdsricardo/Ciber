"""Integration tests for the SSTI active detector.

Exercises the real engine.runner pipeline (discovery -> baseline -> plugin ->
Finding serialization) against a tiny local HTTP server that simulates three
kinds of template rendering: a naive engine that actually evaluates a narrow
`{{ N * M }}` shape, a properly-escaped/non-evaluating template, and a route
that reflects the raw payload unescaped but still never evaluates it (the
verbatim-markup guard's job is to make sure that last one is NOT flagged as
SSTI, even though it would be fair game for a reflected-XSS detector).
"""
import html
import pathlib
import re
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from engine.runner import run_scan
from support.local_server import serve

# Only recognizes the exact `{{ N * M }}` shape and computes the product with
# plain arithmetic -- never eval() on untrusted input, even in this test fixture.
_TEMPLATE_EXPR = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        name = params.get("name", ["Guest"])[0]

        if parsed.path == "/vuln":
            # Simulates a naive Jinja2-like renderer: the recognized expression
            # shape is actually evaluated and substituted into the output.
            rendered = _TEMPLATE_EXPR.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), name)
            body = f"<html><body>Hello, {rendered}!</body></html>".encode("utf-8")
        elif parsed.path == "/safe":
            # Properly escaped, non-evaluating template: always literal text.
            body = f"<html><body>Hello, {html.escape(name)}!</body></html>".encode("utf-8")
        elif parsed.path == "/reflect_unescaped":
            # Reflects the raw payload verbatim, unescaped, but never evaluates
            # it -- classic reflected-XSS bait, not SSTI.
            body = f"<html><body>Hello, {name}!</body></html>".encode("utf-8")
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _ssti_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("ssti.")]


class TemplateInjectionPluginIntegrationTests(unittest.TestCase):
    def test_vulnerable_route_is_flagged_as_confirmed_ssti(self):
        with serve(_Handler) as base_url:
            result = run_scan(base_url + "/vuln?name=Guest", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"], result)
        findings = _ssti_findings(result)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("name", finding["parameter"])
        self.assertEqual("high", finding["severity"])
        self.assertFalse(finding["manual_review_required"])
        self.assertIn("49", finding["evidence_summary"])
        self.assertIn("{{7*7}}", finding["evidence_summary"])

    def test_safe_escaped_route_produces_no_ssti_finding(self):
        with serve(_Handler) as base_url:
            result = run_scan(base_url + "/safe?name=Guest", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"], result)
        self.assertEqual([], _ssti_findings(result))

    def test_unescaped_but_unevaluated_reflection_is_not_flagged_as_ssti(self):
        # Raw payload markup survives verbatim in the response: this is
        # reflection (an XSS detector's job), not proof of template evaluation.
        with serve(_Handler) as base_url:
            result = run_scan(base_url + "/reflect_unescaped?name=Guest", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"], result)
        self.assertEqual([], _ssti_findings(result))


if __name__ == "__main__":
    unittest.main()
