"""Integration tests for SqlInjectionPlugin against a real local HTTP server."""
import pathlib
import sys
import time
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve
from engine.runner import run_scan


def _param(query, name, default=""):
    return parse_qs(query).get(name, [default])[0]


class ErrorBasedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urlparse(self.path).query
        value = _param(query, "id", "1")
        body = b"<html>Product #1: Widget</html>"
        if "'" in value:
            body = b"<html>Error: You have an error in your SQL syntax near '''</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class BooleanDifferentialHandler(BaseHTTPRequestHandler):
    """Simulates `SELECT * FROM products WHERE id = '<value>'` with no escaping,
    including MySQL-style loose numeric coercion of a string starting with '1' followed
    by non-digit text (so a harmless control suffix still "matches", same as it would on
    a real, vulnerable MySQL-backed app — only an explicit `AND '1'='2'` should break it)."""

    def do_GET(self):
        query = urlparse(self.path).query
        value = _param(query, "id", "1")
        found = self._evaluate(value)
        body = b"<html>Product #1: Widget</html>" if found else b"<html>No product found</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _evaluate(value: str) -> bool:
        lowered = value.lower()
        if "' and '1'='2" in lowered:
            return False
        return value == "1" or value.startswith("1'") or value.startswith("1 ")

    def log_message(self, *args):
        pass


class SafeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html>Product #1: Widget</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SqlInjectionPluginTests(unittest.TestCase):
    def test_error_based_detection(self):
        with serve(ErrorBasedHandler) as base_url:
            result = run_scan(base_url + "/product?id=1", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        fingerprints = {f["fingerprint"] for f in result["findings"]}
        self.assertIn("sqli.error_based", fingerprints)
        finding = next(f for f in result["findings"] if f["fingerprint"] == "sqli.error_based")
        self.assertEqual("critical", finding["severity"])
        self.assertEqual("id", finding["parameter"])

    def test_boolean_differential_detection(self):
        with serve(BooleanDifferentialHandler) as base_url:
            result = run_scan(base_url + "/product?id=1", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        fingerprints = {f["fingerprint"] for f in result["findings"]}
        self.assertIn("sqli.boolean_differential", fingerprints)

    def test_safe_endpoint_produces_no_sqli_finding(self):
        with serve(SafeHandler) as base_url:
            result = run_scan(base_url + "/product?id=1", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        sqli_findings = [f for f in result["findings"] if f["fingerprint"].startswith("sqli.")]
        self.assertEqual([], sqli_findings)


if __name__ == "__main__":
    unittest.main()
