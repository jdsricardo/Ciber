"""Integration tests for two coverage features against a real local HTTP server:

1. Authenticated scanning — auth headers (e.g. a session Cookie) are attached to every
   request and unlock content that is only visible when authenticated.
2. POST/form parameter testing — form fields discovered on the page are probed via POST,
   not only query-string parameters.
"""
import html
import pathlib
import sys
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve
from engine.models import (HttpRequest, InputPoint, ScanContext, ScanLimits, ScanMode)
from engine.runner import run_scan
from engine.transport import HttpTransport
from engine.safety import SafetyController
from plugins.support import build_probe


def _q(query, name, default=""):
    return parse_qs(query).get(name, [default])[0]


# --- Fixtures ---------------------------------------------------------------

class CookieEchoHandler(BaseHTTPRequestHandler):
    """Reflects the received Cookie header into the response body."""

    def do_GET(self):
        cookie = self.headers.get("Cookie", "NO-COOKIE")
        body = f"<html><body>cookie={cookie}</body></html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class AuthGatedXssHandler(BaseHTTPRequestHandler):
    """Only authenticated requests reach the vulnerable, unescaped reflection.

    Unauthenticated requests get a safe login page; authenticated ones (correct Cookie)
    reflect `q` verbatim into HTML text.
    """

    def do_GET(self):
        authenticated = self.headers.get("Cookie", "") == "SESSION=secret-token"
        value = _q(urlparse(self.path).query, "q", "search")
        if authenticated:
            body = f"<html><body>Resultado: {value}</body></html>"
        else:
            body = "<html><body>Faça login para continuar.</body></html>"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class FormPostXssHandler(BaseHTTPRequestHandler):
    """GET serves a POST form with field `q`; POST reflects `q` unescaped (vulnerable)."""

    def do_GET(self):
        body = ('<html><body><form method="post" action="/">'
                '<input name="q" value=""></form></body></html>').encode("utf-8")
        self._send(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length).decode("utf-8")
        value = _q(payload, "q", "")
        body = f"<html><body>Você enviou: {value}</body></html>".encode("utf-8")
        self._send(body)

    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FormPostSafeHandler(FormPostXssHandler):
    """POST reflects `q` HTML-escaped (not vulnerable)."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length).decode("utf-8")
        value = html.escape(_q(payload, "q", ""))
        body = f"<html><body>Você enviou: {value}</body></html>".encode("utf-8")
        self._send(body)


class FormPathTraversalHandler(BaseHTTPRequestHandler):
    """GET serves a POST form with a `file` field; POST discloses an OS file when the
    posted value traverses to etc/passwd (vulnerable), else a not-found message."""

    def do_GET(self):
        body = ('<html><body><form method="post" action="/">'
                '<input name="file" value="home.txt"></form></body></html>').encode("utf-8")
        self._send(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        value = _q(self.rfile.read(length).decode("utf-8"), "file", "")
        if "etc/passwd" in value:
            body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        else:
            body = "Arquivo nao encontrado."
        self._send(body.encode("utf-8"))

    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


# --- Tests ------------------------------------------------------------------

class AuthHeaderTransportTests(unittest.TestCase):
    def test_auth_header_is_attached_to_requests(self):
        with serve(CookieEchoHandler) as base_url:
            context = ScanContext(
                target_url=base_url + "/", mode=ScanMode.PASSIVE, limits=ScanLimits(),
                allow_private=True, auth_headers={"Cookie": "SESSION=secret-token"},
            )
            transport = HttpTransport(SafetyController(context))
            response = transport.send(HttpRequest(method="GET", url=base_url + "/"))
        self.assertIn("cookie=SESSION=secret-token", response.body.decode("utf-8"))

    def test_no_auth_header_when_not_configured(self):
        with serve(CookieEchoHandler) as base_url:
            context = ScanContext(target_url=base_url + "/", mode=ScanMode.PASSIVE,
                                  limits=ScanLimits(), allow_private=True)
            transport = HttpTransport(SafetyController(context))
            response = transport.send(HttpRequest(method="GET", url=base_url + "/"))
        self.assertIn("cookie=NO-COOKIE", response.body.decode("utf-8"))


class AuthenticatedScanTests(unittest.TestCase):
    def test_auth_unlocks_vulnerable_reflection(self):
        with serve(AuthGatedXssHandler) as base_url:
            result = run_scan(base_url + "/app?q=hello", mode="safe_active", allow_private=True,
                              auth_headers={"Cookie": "SESSION=secret-token"})
        self.assertTrue(result["ok"])
        self.assertIn("xss.reflected_html_text", {f["fingerprint"] for f in result["findings"]})

    def test_without_auth_the_reflection_is_not_reached(self):
        with serve(AuthGatedXssHandler) as base_url:
            result = run_scan(base_url + "/app?q=hello", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        self.assertEqual([], [f for f in result["findings"] if f["fingerprint"].startswith("xss.")])


class FormPostProbeTests(unittest.TestCase):
    def test_build_probe_routes_query_to_get_and_form_to_post(self):
        request = HttpRequest(method="GET", url="http://x/app?a=1",
                              inputs=[InputPoint("form", "q", "def"), InputPoint("form", "extra", "keep")])
        query_point = InputPoint("query", "a", "1")
        get_probe = build_probe(request, query_point, "1PAYLOAD")
        self.assertEqual("GET", get_probe.method)
        self.assertIn("a=1PAYLOAD", get_probe.url)
        self.assertEqual(b"", get_probe.body)

        form_point = InputPoint("form", "q", "def")
        post_probe = build_probe(request, form_point, "INJECT")
        self.assertEqual("POST", post_probe.method)
        body = post_probe.body.decode("utf-8")
        self.assertIn("q=INJECT", body)
        self.assertIn("extra=keep", body)  # sibling field preserved at its default
        self.assertEqual("application/x-www-form-urlencoded", post_probe.headers["Content-Type"])

    def test_form_field_xss_is_flagged_via_post(self):
        with serve(FormPostXssHandler) as base_url:
            result = run_scan(base_url + "/", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        xss = [f for f in result["findings"] if f["fingerprint"].startswith("xss.")]
        self.assertTrue(xss, "expected a form-based XSS finding")
        self.assertEqual("q", xss[0]["parameter"])
        self.assertEqual("form", xss[0]["parameter_location"])
        self.assertEqual("POST", xss[0]["method"])

    def test_safe_form_is_not_flagged(self):
        with serve(FormPostSafeHandler) as base_url:
            result = run_scan(base_url + "/", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        self.assertEqual([], [f for f in result["findings"] if f["fingerprint"].startswith("xss.")])

    def test_form_field_path_traversal_is_flagged_via_post(self):
        """Proves the form/POST extension reaches a non-flagship detector (path traversal)."""
        with serve(FormPathTraversalHandler) as base_url:
            result = run_scan(base_url + "/", mode="safe_active", allow_private=True)
        self.assertTrue(result["ok"])
        pt = [f for f in result["findings"] if f["fingerprint"].startswith("path_traversal.")]
        self.assertTrue(pt, "expected a form-based path traversal finding")
        self.assertEqual("file", pt[0]["parameter"])
        self.assertEqual("form", pt[0]["parameter_location"])
        self.assertEqual("POST", pt[0]["method"])


if __name__ == "__main__":
    unittest.main()
