"""Integration tests for the Open Redirect active plugin, exercised through the
full engine against a real local HTTP server (see tests/support/local_server.py)."""
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve  # noqa: E402

from engine.runner import run_scan  # noqa: E402

ALLOWED_PATHS = {"/home", "/dashboard"}


class Handler(BaseHTTPRequestHandler):
    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        redirect_value = parse_qs(parsed.query).get("redirect", [""])[0]

        if parsed.path == "/vuln":
            # Classic open redirect: reflect the parameter verbatim into Location.
            self._redirect(redirect_value or "/")
            return

        if parsed.path == "/safe":
            # Correct fix: only ever redirect to an allowlisted internal path.
            self._redirect(redirect_value if redirect_value in ALLOWED_PATHS else "/")
            return

        if parsed.path == "/trap":
            # Always redirects same-site, but echoes the raw value inside an
            # unrelated query string -- never as the actual redirect target.
            # A naive substring check on the Location text would misfire here.
            self._redirect(f"/?note={redirect_value}")
            return

        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence request logging during tests


def open_redirect_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("open_redirect.")]


class OpenRedirectPluginTests(unittest.TestCase):
    def test_vulnerable_route_produces_a_confirmed_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln?redirect=/home", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        findings = open_redirect_findings(result)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("open_redirect.confirmed_header", finding["fingerprint"])
        self.assertEqual("redirect", finding["parameter"])
        self.assertEqual("query", finding["parameter_location"])
        self.assertEqual("medium", finding["severity"])
        location = finding["evidence"]["probe_response"]["headers"].get("location", "")
        self.assertIn("sentinelscope-redirect-canary.invalid", location)

    def test_allowlisted_safe_route_produces_no_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/safe?redirect=/home", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual([], open_redirect_findings(result))

    def test_canary_string_in_unrelated_query_value_is_not_flagged(self):
        # The Location header literally contains the canary domain as text,
        # but never as the actual redirect target host -- a substring check
        # on the header would false-positive here; hostname parsing must not.
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/trap?redirect=/home", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual([], open_redirect_findings(result))


if __name__ == "__main__":
    unittest.main()
