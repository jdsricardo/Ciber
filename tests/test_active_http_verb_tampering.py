"""Integration tests for the HTTP Verb / Method Tampering active plugin.

Uses a real local HTTP server (tests/support/local_server.py) and drives the
plugin through the full engine (engine.runner.run_scan) so the test exercises
the real HTTP + safety + confidence pipeline end to end, not just the plugin
function in isolation.
"""
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))
sys.path.insert(0, str(pathlib.Path(__file__).parent))

from engine.runner import run_scan  # noqa: E402
from support.local_server import serve  # noqa: E402

DASHBOARD_HTML = (
    b"<html><body><h1>Painel confidencial</h1>"
    b"<p>Dados sensiveis do usuario autenticado aparecem somente aqui.</p>"
    b"<ul><li>Item A</li><li>Item B</li><li>Item C</li></ul>"
    b"</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/vuln":
            self._respond(200, DASHBOARD_HTML)
        elif self.path == "/safe":
            self._respond(200, DASHBOARD_HTML)
        elif self.path == "/edge":
            self._respond(200, DASHBOARD_HTML)
        elif self.path == "/post-bypass":
            self._respond(200, DASHBOARD_HTML)
        elif self.path == "/trace":
            self._respond(200, DASHBOARD_HTML)
        else:
            self._respond(404, b"not found")

    def do_OPTIONS(self):
        # Deliberately unhelpful Allow header everywhere (only the safe trio),
        # so the plugin must fall back to trying the full candidate set itself.
        self._respond(200, b"", extra_headers={"Allow": "GET, HEAD, OPTIONS"})

    def do_POST(self):
        if self.path == "/post-bypass":
            # Naive filter: only GET is authenticated/authorized; every other
            # method is handed straight to the same handler that serves GET.
            self._respond(200, DASHBOARD_HTML)
        elif self.path == "/edge":
            # Correctly rejects the write, but happens to still answer 200 with
            # a tiny, structurally unrelated JSON body instead of a proper 405.
            # A body-similarity check that is too loose could misread this as
            # "looks like the GET baseline" and would incorrectly flag it.
            self._respond(200, b'{"error":"writes not supported"}', content_type="application/json")
        else:
            self._respond(405, b"POST not allowed", extra_headers={"Allow": "GET, HEAD, OPTIONS"})

    def do_PUT(self):
        self._respond(405, b"PUT not allowed", extra_headers={"Allow": "GET, HEAD, OPTIONS"})

    def do_PATCH(self):
        self._respond(405, b"PATCH not allowed", extra_headers={"Allow": "GET, HEAD, OPTIONS"})

    def do_DELETE(self):
        if self.path == "/vuln":
            # The vulnerability under test: an unauthenticated-looking DELETE is
            # accepted and processed, regardless of any auth/session state.
            self._respond(200, b"resource deleted")
        else:
            self._respond(405, b"DELETE not allowed", extra_headers={"Allow": "GET, HEAD, OPTIONS"})

    def do_TRACE(self):
        if self.path == "/trace":
            marker = self.headers.get("X-Sentinelscope-Trace-Probe", "")
            body = f"TRACE / HTTP/1.1\r\nX-Sentinelscope-Trace-Probe: {marker}\r\n".encode()
            self._respond(200, body, content_type="message/http")
        else:
            self._respond(405, b"TRACE not allowed", extra_headers={"Allow": "GET, HEAD, OPTIONS"})

    def _respond(self, status, body, content_type="text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def verb_tampering_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("http_verb_tampering.")]


class HttpVerbTamperingPluginTests(unittest.TestCase):
    def test_vulnerable_delete_is_flagged_as_destructive_method_accepted(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/vuln", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        findings = verb_tampering_findings(result)
        destructive = [f for f in findings if f["fingerprint"] == "http_verb_tampering.destructive_method_accepted"]
        self.assertEqual(1, len(destructive))
        finding = destructive[0]
        self.assertEqual("critical", finding["severity"])
        self.assertTrue(finding["manual_review_required"])
        self.assertEqual("manual_review_required", finding["status"])
        self.assertIn("DELETE", finding["evidence"]["reason"])
        self.assertIn("nenhuma requisição de confirmação", finding["evidence"]["reason"].lower())

    def test_safe_route_produces_no_verb_tampering_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/safe", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        self.assertEqual([], verb_tampering_findings(result))

    def test_200_with_differently_shaped_post_body_is_not_a_false_positive(self):
        # POST returns 200 (not 405), but with a tiny JSON body that is
        # structurally nothing like the large HTML GET baseline. The
        # similarity gate must reject this as a bypass despite the 2xx status.
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/edge", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        # No POST-bypass finding should be produced for this route at all.
        post_findings = [f for f in verb_tampering_findings(result) if f["method"] == "POST"]
        self.assertEqual([], post_findings)

    def test_post_accepted_like_get_is_flagged_as_method_bypass(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/post-bypass", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        findings = verb_tampering_findings(result)
        post_bypass = [
            f for f in findings
            if f["fingerprint"] == "http_verb_tampering.method_bypass_suspected" and f["method"] == "POST"
        ]
        self.assertEqual(1, len(post_bypass))
        finding = post_bypass[0]
        self.assertEqual("high", finding["severity"])
        self.assertFalse(finding["manual_review_required"])  # reproduced on repeat -> confirmed enough

    def test_trace_reflection_is_flagged(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/trace", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"])
        findings = verb_tampering_findings(result)
        trace_findings = [f for f in findings if f["fingerprint"] == "http_verb_tampering.trace_enabled"]
        self.assertEqual(1, len(trace_findings))
        finding = trace_findings[0]
        self.assertEqual("medium", finding["severity"])
        self.assertTrue(finding["manual_review_required"])
        self.assertIn("Cross-Site Tracing", finding["evidence"]["reason"])


if __name__ == "__main__":
    unittest.main()
