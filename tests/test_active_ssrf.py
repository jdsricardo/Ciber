"""Integration tests for SsrfPlugin against a real local HTTP server."""
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


class VulnerableFetcherHandler(BaseHTTPRequestHandler):
    """Simulates a server that tries to fetch the `url` parameter server-side."""

    def do_GET(self):
        value = _param(urlparse(self.path).query, "url", "")
        if value.startswith("http://sentinelscope-ssrf-canary.invalid"):
            body = b"Error: curl error: Could not resolve host: sentinelscope-ssrf-canary.invalid"
        elif value.startswith("http://192.0.2.1"):
            time.sleep(0.6)  # simulate a connection attempt timing out (scaled down for tests)
            body = b"Error: connection timed out"
        else:
            body = b"<html>Preview unavailable</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SafeHandler(BaseHTTPRequestHandler):
    """Validates the URL against an allowlist and never fetches arbitrary hosts."""

    def do_GET(self):
        body = b"<html>Invalid URL: only https://cdn.example.test is allowed</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SsrfPluginTests(unittest.TestCase):
    def test_network_error_signature_is_flagged_for_manual_review(self):
        with serve(VulnerableFetcherHandler) as base_url:
            result = run_scan(base_url + "/preview?url=https://cdn.example.test/logo.png", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        fingerprints = {f["fingerprint"] for f in result["findings"]}
        self.assertIn("ssrf.error_signature_suspected", fingerprints)
        finding = next(f for f in result["findings"] if f["fingerprint"] == "ssrf.error_signature_suspected")
        self.assertTrue(finding["manual_review_required"])

    def test_safe_endpoint_produces_no_ssrf_finding(self):
        with serve(SafeHandler) as base_url:
            result = run_scan(base_url + "/preview?url=https://cdn.example.test/logo.png", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        ssrf_findings = [f for f in result["findings"] if f["fingerprint"].startswith("ssrf.")]
        self.assertEqual([], ssrf_findings)


if __name__ == "__main__":
    unittest.main()
