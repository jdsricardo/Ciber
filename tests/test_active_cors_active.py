"""Integration tests for CorsActivePlugin against a real local HTTP server."""
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve
from engine.runner import run_scan


class ReflectingHandler(BaseHTTPRequestHandler):
    """Naively reflects any Origin header, with credentials enabled — a classic misconfiguration."""

    def do_GET(self):
        origin = self.headers.get("Origin")
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class StrictHandler(BaseHTTPRequestHandler):
    """Only ever allows one specific, hardcoded trusted origin."""

    TRUSTED = "https://app.example.test"

    def do_GET(self):
        origin = self.headers.get("Origin")
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if origin == self.TRUSTED:
            self.send_header("Access-Control-Allow-Origin", self.TRUSTED)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CorsActivePluginTests(unittest.TestCase):
    def test_reflected_origin_with_credentials_is_critical(self):
        with serve(ReflectingHandler) as base_url:
            result = run_scan(base_url + "/api/data", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        found = {f["fingerprint"]: f for f in result["findings"]}
        self.assertIn("cors.credentials_with_reflected_origin", found)
        self.assertEqual("critical", found["cors.credentials_with_reflected_origin"]["severity"])

    def test_strict_allowlist_is_not_flagged(self):
        with serve(StrictHandler) as base_url:
            result = run_scan(base_url + "/api/data", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        cors_active_findings = [
            f for f in result["findings"]
            if f["fingerprint"] in ("cors.origin_reflected", "cors.credentials_with_reflected_origin",
                                     "cors.null_origin_allowed", "cors.lookalike_origin_accepted")
        ]
        self.assertEqual([], cors_active_findings)


if __name__ == "__main__":
    unittest.main()
