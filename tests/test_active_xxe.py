"""Integration tests for the XXE active detector.

Exercises the real engine.runner pipeline (discovery -> baseline -> plugin ->
Finding serialization) against a tiny local HTTP server that simulates:

  * /api/vuln  -- a naive XML "parser" that textually substitutes a declared
    internal entity into the root element's content, and additionally
    simulates a ~1.5s DNS-resolution-shaped delay (then a generic error) when
    the posted body defines a `SYSTEM "http...` external entity -- mimicking
    a vulnerable parser that attempts to resolve external entities.
  * /api/safe  -- a hardened "parser" that never substitutes any entity value
    into the response and never introduces an artificial delay, regardless of
    what the DOCTYPE declares.
  * /          -- a plain HTML page with no XML content-type and no XML-ish
    path, used to confirm the plugin does not even attempt the XXE probe
    chain when there is no signal the endpoint parses XML.
"""
import pathlib
import re
import sys
import time
import unittest
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve  # noqa: E402

from engine.runner import run_scan  # noqa: E402

MARKER = "SENTINELSCOPE_XXE_PROOF_7331"
ENTITY_DECL = re.compile(r'<!ENTITY\s+(\w+)\s+"([^"]*)"')
ROOT_CONTENT = re.compile(r"<root>(.*?)</root>", re.S)


class Handler(BaseHTTPRequestHandler):
    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        body = self._read_body()
        if self.path.startswith("/api/vuln"):
            self._handle_vuln(body)
        elif self.path.startswith("/api/safe"):
            self._handle_safe(body)
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_vuln(self, body: str) -> None:
        # Simulates a vulnerable parser attempting to resolve an external
        # entity: a DNS-resolution-shaped delay, then a generic failure --
        # never any real network access.
        if 'SYSTEM "http' in body:
            time.sleep(1.5)
            self._respond(502, b"<error>could not resolve host</error>")
            return
        # Naive parser: textually substitute any declared internal entity
        # into the root element's content, mimicking real entity expansion.
        match = ROOT_CONTENT.search(body)
        inner = match.group(1) if match else ""
        for name, value in ENTITY_DECL.findall(body):
            inner = inner.replace(f"&{name};", value)
        self._respond(200, f"<result>{inner}</result>".encode("utf-8"))

    def _handle_safe(self, body: str) -> None:
        # Hardened parser: well-formed XML is accepted, but no entity value
        # -- internal or external -- is ever substituted into the response,
        # and no artificial delay is ever introduced.
        self._respond(200, b"<result>ok</result>")

    def log_message(self, *args):
        pass  # silence request logging during tests


def xxe_findings(result):
    return [f for f in result["findings"] if f["fingerprint"].startswith("xxe.")]


class XxePluginIntegrationTests(unittest.TestCase):
    def test_vulnerable_endpoint_produces_an_xxe_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/api/vuln", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"], result)
        findings = xxe_findings(result)
        fingerprints = {f["fingerprint"] for f in findings}
        # The vulnerable route both expands internal entities and shows a
        # timing differential on the external-entity probe (simulated DNS
        # resolution attempt), so the stronger, escalated finding is expected;
        # accept either fingerprint since a slow/loaded test runner could in
        # principle blur the timing differential on one of the two repeat
        # measurements.
        self.assertTrue(
            {"xxe.internal_entity_expansion", "xxe.external_entity_processing_suspected"} & fingerprints,
            findings,
        )
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertIsNone(finding["parameter"])
        self.assertEqual("body", finding["parameter_location"])
        self.assertTrue(finding["manual_review_required"])
        if finding["fingerprint"] == "xxe.external_entity_processing_suspected":
            self.assertEqual("high", finding["severity"])
            self.assertGreaterEqual(finding["evidence"]["differences"]["timing_delta_ms"], 400)
        else:
            self.assertEqual("medium", finding["severity"])
            self.assertIn(MARKER, finding["evidence"]["probe_response"]["snippet"])

    def test_safe_endpoint_produces_no_xxe_finding(self):
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/api/safe", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"], result)
        self.assertEqual([], xxe_findings(result))

    def test_plain_html_endpoint_is_not_probed(self):
        # No XML content-type and no XML-ish path: the plugin must not even
        # attempt the probe chain, so there must be no XXE finding.
        with serve(Handler) as base_url:
            result = run_scan(base_url + "/", mode="safe_active", allow_private=True)

        self.assertTrue(result["ok"], result)
        self.assertEqual([], xxe_findings(result))


if __name__ == "__main__":
    unittest.main()
