"""Integration tests for the Host Header Injection active plugin, exercised through the
full engine against a real local HTTP server (see tests/support/local_server.py)."""
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve  # noqa: E402

from engine.runner import run_scan  # noqa: E402

CANONICAL_HOST = "app.example.test"


class Handler(BaseHTTPRequestHandler):
    def _send_html(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        host = self.headers.get("Host", "")
        forwarded_host = self.headers.get("X-Forwarded-Host", "")

        if path == "/vuln-redirect":
            # Password-reset-link-style poisoning vector: an absolute Location built
            # verbatim from the (attacker-controllable) Host header.
            self.send_response(302)
            self.send_header("Location", f"http://{host}/dashboard")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/vuln":
            # Vulnerable body reflection: a password-reset link built from Host,
            # rendered inside a page that also has a form (raises relevance/severity).
            body = (
                '<html><body>'
                '<form action="/reset" method="post"><input type="password" name="p"></form>'
                f'<a href="http://{host}/reset-password?token=abc">reset your password</a>'
                '</body></html>'
            ).encode()
            self._send_html(body)
            return

        if path == "/vuln-xfh-only":
            # A weaker case: the app ignores the primary Host header entirely, but
            # trusts X-Forwarded-Host (when present) to build an absolute link.
            link_host = forwarded_host or CANONICAL_HOST
            body = f'<html><body><a href="http://{link_host}/reset-password?token=abc">reset</a></body></html>'.encode()
            self._send_html(body)
            return

        if path == "/safe":
            # Correctly configured app: absolute URLs always use a fixed, server-side
            # canonical hostname and never trust the incoming Host header at all.
            body = f'<html><body><a href="http://{CANONICAL_HOST}/reset-password?token=abc">reset</a></body></html>'.encode()
            self._send_html(body)
            return

        self._send_html(b"<html><body>ok</body></html>")

    def log_message(self, *args):
        pass  # silence request logging during tests


def host_header_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("host_header.")]


class HostHeaderInjectionPluginTests(unittest.TestCase):
    def test_body_reflection_is_flagged_high_severity_with_forms_present(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        findings = host_header_findings(result)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("host_header.reflected_in_body", finding["fingerprint"])
        self.assertEqual("Host", finding["parameter"])
        self.assertEqual("header", finding["parameter_location"])
        self.assertEqual("high", finding["severity"])
        self.assertFalse(finding["manual_review_required"])
        self.assertIn("sentinelscope-host-canary.invalid", finding["evidence"]["probe_response"]["snippet"])

    def test_redirect_reflection_is_flagged(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln-redirect", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        findings = host_header_findings(result)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("host_header.reflected_in_redirect", finding["fingerprint"])
        self.assertEqual("high", finding["severity"])
        self.assertFalse(finding["manual_review_required"])
        location = finding["evidence"]["probe_response"]["headers"].get("location", "")
        self.assertIn("sentinelscope-host-canary.invalid", location)

    def test_xfh_only_reflection_is_reported_as_weaker_signal(self):
        # The app ignores the primary Host header and only trusts X-Forwarded-Host,
        # so the host-only discriminator probe should NOT reproduce the reflection,
        # and the finding must come back flagged for manual review.
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln-xfh-only", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        findings = host_header_findings(result)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("host_header.reflected_in_body", finding["fingerprint"])
        self.assertTrue(finding["manual_review_required"])
        self.assertEqual("X-Forwarded-Host", finding["evidence"]["differences"]["attributed_to"])

    def test_safe_route_with_fixed_canonical_host_produces_no_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/safe", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual([], host_header_findings(result))


if __name__ == "__main__":
    unittest.main()
