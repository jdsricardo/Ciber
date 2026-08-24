"""Integration tests for the CRLF Injection / HTTP Response Splitting active plugin.

Uses a real local HTTP server (tests/support/local_server.py) with a genuinely
vulnerable route that bypasses BaseHTTPRequestHandler.send_header()'s framework
safety net (which would itself sanitize/reject embedded CR/LF) by hand-writing raw
response bytes -- exactly what a naive application in a language without such
guardrails would do when it splices a URL-decoded parameter into a raw header line.
"""
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qsl, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from engine.runner import run_scan
from support.local_server import serve


def _next_param(path: str) -> str:
    query = urlparse(path).query
    params = dict(parse_qsl(query, keep_blank_values=True))
    return params.get("next", "")


class VulnerableHandler(BaseHTTPRequestHandler):
    """`/vuln` splices the decoded `next` value straight into a raw Location header
    line whenever it contains a real CR/LF (i.e. only when the scanner's
    percent-encoded probe was decoded server-side) -- a genuine response-splitting
    bug. `/safe` always uses the normal, guarded send_header() API."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        next_value = _next_param(self.path)
        body = b"<html><body>hello</body></html>"

        if parsed.path == "/vuln" and ("\r" in next_value or "\n" in next_value):
            head = (
                "HTTP/1.1 302 Found\r\n"
                f"Location: {next_value}\r\n"
                "Content-Type: text/html\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("latin-1", errors="replace")
            self.close_connection = True
            self.wfile.write(head)
            self.wfile.write(body)
            return

        self.send_response(302)
        safe_value = (next_value or "/").replace("\r", "").replace("\n", "")
        self.send_header("Location", safe_value)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class QuirkyHandler(BaseHTTPRequestHandler):
    """Adds a header literally named X-Sentinelscope-Crlf-Test whenever the `next`
    parameter differs at all from its baseline value ("/home"), regardless of
    whether it contains CRLF. This exercises the negative control: a real CRLF
    detector must not be fooled by an app that reacts to any odd suffix."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        next_value = _next_param(self.path)
        body = b"<html><body>quirky</body></html>"
        self.send_response(302)
        safe_value = (next_value or "/").replace("\r", "").replace("\n", "")
        self.send_header("Location", safe_value)
        if next_value != "/home":
            self.send_header("X-Sentinelscope-Crlf-Test", "injected")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def crlf_fingerprints(result):
    return {f["fingerprint"] for f in result["findings"] if f["fingerprint"].startswith("crlf.")}


class CrlfInjectionPluginTests(unittest.TestCase):
    def test_vulnerable_route_produces_a_crlf_finding(self):
        with serve(VulnerableHandler) as base_url:
            result = run_scan(base_url + "/vuln?next=/home", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        found = crlf_fingerprints(result)
        self.assertIn("crlf.header_injection_confirmed", found)
        finding = next(f for f in result["findings"] if f["fingerprint"] == "crlf.header_injection_confirmed")
        self.assertEqual("high", finding["severity"])
        self.assertGreaterEqual(finding["confidence"], 75)
        self.assertEqual("next", finding["parameter"])
        self.assertEqual("query", finding["parameter_location"])

    def test_safe_route_produces_no_crlf_finding(self):
        with serve(VulnerableHandler) as base_url:
            result = run_scan(base_url + "/safe?next=/home", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(set(), crlf_fingerprints(result))

    def test_negative_control_suffix_alone_does_not_trigger_a_finding(self):
        # The quirky server adds the marker header for ANY changed value of `next`,
        # not specifically for CRLF. A correct detector's negative control (a
        # harmless suffix, no CRLF) must catch this and suppress the finding.
        with serve(QuirkyHandler) as base_url:
            result = run_scan(base_url + "/quirky?next=/home", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(set(), crlf_fingerprints(result))


if __name__ == "__main__":
    unittest.main()
