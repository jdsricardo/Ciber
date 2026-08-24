"""Integration tests for ReflectedXssPlugin against a real local HTTP server."""
import html
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve
from engine.runner import run_scan


def _param(query, name, default=""):
    return parse_qs(query).get(name, [default])[0]


class VulnerableTextHandler(BaseHTTPRequestHandler):
    """Reflects the `q` parameter verbatim into HTML text with no escaping."""

    def do_GET(self):
        value = _param(urlparse(self.path).query, "q", "search")
        body = f"<html><body>Você pesquisou por: {value}</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SafeHandler(BaseHTTPRequestHandler):
    """HTML-escapes the reflected value properly."""

    def do_GET(self):
        value = _param(urlparse(self.path).query, "q", "search")
        body = f"<html><body>Você pesquisou por: {html.escape(value)}</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ReflectedXssPluginTests(unittest.TestCase):
    def test_unescaped_reflection_is_flagged(self):
        with serve(VulnerableTextHandler) as base_url:
            result = run_scan(base_url + "/search?q=hello", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        fingerprints = {f["fingerprint"] for f in result["findings"]}
        self.assertIn("xss.reflected_html_text", fingerprints)
        finding = next(f for f in result["findings"] if f["fingerprint"] == "xss.reflected_html_text")
        self.assertEqual("q", finding["parameter"])
        self.assertEqual("high", finding["severity"])

    def test_escaped_reflection_is_not_flagged(self):
        with serve(SafeHandler) as base_url:
            result = run_scan(base_url + "/search?q=hello", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        xss_findings = [f for f in result["findings"] if f["fingerprint"].startswith("xss.")]
        self.assertEqual([], xss_findings)


if __name__ == "__main__":
    unittest.main()
