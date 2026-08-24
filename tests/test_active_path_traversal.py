"""Integration tests for the Path Traversal / LFI active plugin.

Uses a real local HTTP server (tests/support/local_server.py) and drives the
plugin through the full engine (engine.runner.run_scan) so the test exercises
the real HTTP + safety + confidence pipeline end to end, not just the plugin
function in isolation.
"""
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from engine.runner import run_scan  # noqa: E402
from support.local_server import serve  # noqa: E402

UNIX_SIGNATURE = "root:x:0:0:root:/root:/bin/bash"
WINDOWS_SIGNATURE = "[fonts]\r\nfor 16-bit app support"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        file_param = query.get("file", [""])[0]

        if parsed.path == "/vuln":
            # Naive concatenation: any value containing ".." that traverses to
            # "etc/passwd" or "windows\\win.ini" discloses a (fake) OS file.
            lowered = file_param.lower()
            if ".." in file_param and "etc/passwd" in lowered:
                self._respond(200, UNIX_SIGNATURE.encode())
            elif ".." in file_param and "windows" in lowered and "win.ini" in lowered:
                self._respond(200, WINDOWS_SIGNATURE.encode())
            else:
                self._respond(404, b"Arquivo nao encontrado.")

        elif parsed.path == "/safe":
            # Properly sandboxed: identical generic response no matter what is
            # requested, including traversal payloads.
            self._respond(200, b"download not available in this demo")

        elif parsed.path == "/preview":
            # Looks suspicious at first (any non-original value returns text that
            # happens to contain the OS-file signature), but a negative control
            # value ALSO triggers it -- this is not real traversal, just a
            # generic "unknown document" preview page, and must not be flagged.
            if file_param == "report.txt":
                self._respond(200, b"Previa do relatorio original.")
            else:
                self._respond(200, UNIX_SIGNATURE.encode())

        else:
            self._respond(404, b"not found")

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def path_traversal_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("path_traversal.")]


class PathTraversalPluginTests(unittest.TestCase):
    def test_vulnerable_route_discloses_os_file(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln?file=report.txt", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        findings = path_traversal_findings(result)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("path_traversal.file_disclosure", finding["fingerprint"])
        self.assertIn(finding["severity"], ("critical", "high"))
        self.assertEqual("file", finding["parameter"])
        self.assertEqual("query", finding["parameter_location"])

    def test_safe_route_produces_no_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/safe?file=report.txt", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        self.assertEqual([], path_traversal_findings(result))

    def test_generic_preview_page_is_not_a_false_positive(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/preview?file=report.txt", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        self.assertEqual([], path_traversal_findings(result))


if __name__ == "__main__":
    unittest.main()
