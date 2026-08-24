"""Integration tests for the OS Command Injection active plugin.

Uses a real local HTTP server (tests/support/local_server.py) and drives the
plugin through the full engine (engine.runner.run_scan) so the test exercises
the real HTTP + safety + confidence pipeline end to end, not just the plugin
function in isolation.

The handler below NEVER spawns a real shell/subprocess. It only simulates what
a genuinely vulnerable `ping <host>` wrapper's shell would print, by detecting
the exact evaluated commands the plugin injects and computing their result
directly in Python -- e.g. it looks for the literal substring "echo
SENTINELSCOPE_CI_MARKER_7331" and, if present, returns just the marker text
(mimicking the *evaluated* output of a real shell), never the raw command.
"""
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from engine.runner import run_scan  # noqa: E402
from plugins.active.command_injection import MARKER  # noqa: E402
from support.local_server import serve  # noqa: E402

MARKER_COMMAND = f"echo {MARKER}"
# Only the "semicolon" shape (`value; echo MARKER ;`) is honored by the /partial
# route below, simulating a target where only one metacharacter reaches the shell.
SEMICOLON_MARKER = f"; {MARKER_COMMAND} ;"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        host_value = query.get("host", [""])[0]

        if parsed.path == "/vuln":
            self._respond(200, self._simulate_ping(host_value).encode())
        elif parsed.path == "/safe":
            # Parameterized/fixed implementation: never reflects any evaluated
            # content, regardless of what is submitted.
            self._respond(200, b"<html><body>ping result: reachable</body></html>")
        elif parsed.path == "/reflect":
            # Echoes the raw submitted string verbatim, without ever evaluating it
            # -- a plain reflection issue, not command execution.
            body = f"<html><body>ping result: reachable. Voce buscou por: {host_value}</body></html>"
            self._respond(200, body.encode())
        elif parsed.path == "/partial":
            self._respond(200, self._simulate_partial(host_value).encode())
        else:
            self._respond(404, b"not found")

    def _simulate_ping(self, value: str) -> str:
        if MARKER_COMMAND in value:
            return f"<html><body>{MARKER}</body></html>"
        if "expr 7331 + 1" in value or "set /a 7331+1" in value:
            return "<html><body>7332</body></html>"
        return "<html><body>ping result: reachable</body></html>"

    def _simulate_partial(self, value: str) -> str:
        # Only the exact semicolon-wrapped shape is "executed"; every other shape
        # (pipe, &&, backtick, $(), newline) behaves like the safe route.
        if SEMICOLON_MARKER in value:
            return f"<html><body>{MARKER}</body></html>"
        return "<html><body>ping result: reachable</body></html>"

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def ci_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("command_injection.")]


class CommandInjectionPluginTests(unittest.TestCase):
    def test_vulnerable_route_produces_confirmed_critical_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln?host=127.0.0.1", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        findings = ci_findings(result)
        self.assertTrue(findings, "expected at least one command_injection finding")
        confirmed = [f for f in findings if f["fingerprint"] == "command_injection.marker_confirmed"]
        self.assertEqual(1, len(confirmed))
        finding = confirmed[0]
        self.assertEqual("critical", finding["severity"])
        self.assertFalse(finding["manual_review_required"])
        self.assertGreaterEqual(finding["confidence"], 90)
        self.assertEqual("host", finding["parameter"])
        self.assertEqual("query", finding["parameter_location"])

    def test_safe_route_produces_no_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/safe?host=127.0.0.1", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        self.assertEqual([], ci_findings(result))

    def test_raw_reflection_without_evaluation_is_not_confirmed(self):
        # The raw payload text (including "echo " and the marker) is reflected
        # verbatim, so the plugin must recognize this is not real execution and
        # must not produce a confirmed finding.
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/reflect?host=127.0.0.1", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        confirmed = [f for f in ci_findings(result) if f["fingerprint"] == "command_injection.marker_confirmed"]
        self.assertEqual([], confirmed)

    def test_single_shape_signal_is_reported_for_manual_review_only(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/partial?host=127.0.0.1", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        findings = ci_findings(result)
        suspected = [f for f in findings if f["fingerprint"] == "command_injection.marker_suspected"]
        self.assertEqual(1, len(suspected))
        finding = suspected[0]
        self.assertEqual("medium", finding["severity"])
        self.assertTrue(finding["manual_review_required"])
        self.assertLess(finding["confidence"], 90)
        # Only a single shape confirmed the signal, so this must not be reported
        # at the "confirmed" tier.
        self.assertEqual([], [f for f in findings if f["fingerprint"] == "command_injection.marker_confirmed"])


if __name__ == "__main__":
    unittest.main()
