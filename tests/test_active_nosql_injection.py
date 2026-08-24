"""Integration tests for the NoSQL Injection (query-string) active plugin.

Uses a real local HTTP server (tests/support/local_server.py) and drives the plugin
through the full engine (engine.runner.run_scan) so the test exercises the real
HTTP + safety + confidence pipeline end to end, not just the plugin function in
isolation.

The fixture server simulates (in plain Python, no real MongoDB) a single-user
in-memory collection [{"username": "alice"}] behind a naive query-string-to-filter
binding, the classic Express + `qs` + MongoDB operator-injection shape:
  - /vuln  treats a `username[$ne]=<bogus>` key as a real MongoDB "not equal"
    operator: since <bogus> is never "alice", the (only) user is still "found".
    A `username[$eq]=<bogus>` key is treated as plain equality and correctly
    reports "not found" for the same bogus value -- the asymmetry the plugin
    is built to detect.
  - /safe  treats any bracketed/operator-shaped key as malformed input (400),
    simulating a backend that validates parameter types strictly.
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

USERS = ["alice"]
FOUND_BODY = b"user found: alice"
NOT_FOUND_BODY = b"user not found"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/vuln":
            self._handle_vuln(query)
        elif parsed.path == "/safe":
            self._handle_safe(query)
        else:
            self._respond(404, b"not found")

    def _handle_vuln(self, query):
        # Naive query-string-to-filter binding: a literal "[$ne]"/"[$eq]" key is
        # interpreted the way a MongoDB driver would interpret the equivalent
        # operator object once qs/body-parser has parsed the query string.
        ne_key = next((key for key in query if "[$ne]" in key), None)
        if ne_key is not None:
            value = query[ne_key][0]
            self._respond(*((200, FOUND_BODY) if value not in USERS else (404, NOT_FOUND_BODY)))
            return
        eq_key = next((key for key in query if "[$eq]" in key), None)
        if eq_key is not None:
            value = query[eq_key][0]
            self._respond(*((200, FOUND_BODY) if value in USERS else (404, NOT_FOUND_BODY)))
            return
        # Plain form (also covers the `username=...&username[]=...` array-collision
        # probe, since `username[]` is parsed as a distinct key and `username` keeps
        # its original, valid value here).
        value = query.get("username", [""])[0]
        self._respond(*((200, FOUND_BODY) if value in USERS else (404, NOT_FOUND_BODY)))

    def _handle_safe(self, query):
        # Strict input validation: any bracketed/operator-shaped key is rejected
        # outright as malformed, regardless of its value.
        if any("[" in key for key in query):
            self._respond(400, b"invalid parameter")
            return
        value = query.get("username", [""])[0]
        self._respond(*((200, FOUND_BODY) if value in USERS else (404, NOT_FOUND_BODY)))

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def nosql_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("nosql_injection.")]


class NoSqlInjectionPluginTests(unittest.TestCase):
    def test_vulnerable_route_confirms_operator_bypass(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln?username=alice", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        findings = nosql_findings(result)
        by_fingerprint = {f["fingerprint"]: f for f in findings}
        self.assertIn("nosql_injection.operator_bypass_confirmed", by_fingerprint)

        finding = by_fingerprint["nosql_injection.operator_bypass_confirmed"]
        self.assertEqual("username", finding["parameter"])
        self.assertEqual("query", finding["parameter_location"])
        self.assertEqual("critical", finding["severity"])
        self.assertFalse(finding["manual_review_required"])

        # The reason text must reference BOTH the $ne bypass form and the $eq control
        # form, proving the finding is grounded in the asymmetry between the two probes
        # rather than in the $ne probe alone.
        reason = finding["evidence_summary"]
        self.assertIn("$ne", reason)
        self.assertIn("$eq", reason)

        # If an array-collision finding is also present, it must carry the weaker,
        # always-manual-review status the methodology requires for that signal.
        if "nosql_injection.array_type_confusion_suspected" in by_fingerprint:
            array_finding = by_fingerprint["nosql_injection.array_type_confusion_suspected"]
            self.assertTrue(array_finding["manual_review_required"])

    def test_safe_route_produces_no_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/safe?username=alice", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        self.assertEqual([], nosql_findings(result))


if __name__ == "__main__":
    unittest.main()
