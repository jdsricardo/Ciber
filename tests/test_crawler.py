"""Crawling tests: the scanner must expand a single seed URL into the reachable same-origin
surface and test pages it was never handed directly, while staying read-only (never following
logout or state-changing links) and never leaving the authorized host."""
import pathlib
import sys
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from support.local_server import serve
from engine.crawler import extract_links, is_followable, page_signature, same_scope
from engine.runner import run_scan


class LinkExtractionTests(unittest.TestCase):
    def test_extracts_anchors_and_get_forms_absolutely(self):
        body = ('<a href="/a">a</a><a href="sub/b">b</a>'
                '<form method="get" action="/search"></form>'
                '<form method="post" action="/delete"></form>'
                '<a href="javascript:void(0)">x</a><a href="mailto:z@z">m</a>')
        links = extract_links("http://h/dir/page", body)
        self.assertIn("http://h/a", links)
        self.assertIn("http://h/dir/sub/b", links)
        self.assertIn("http://h/search", links)          # GET form action is navigable
        self.assertNotIn("http://h/delete", links)        # POST form action is not
        self.assertFalse([u for u in links if u.startswith(("javascript", "mailto"))])

    def test_is_followable_blocks_logout_destructive_and_assets(self):
        self.assertTrue(is_followable("http://h/products?id=1"))
        self.assertFalse(is_followable("http://h/account/logout"))
        self.assertFalse(is_followable("http://h/app?action=delete&id=3"))
        self.assertFalse(is_followable("http://h/item?remove=3"))
        self.assertFalse(is_followable("http://h/assets/app.js"))

    def test_page_signature_ignores_query_values_but_not_names(self):
        self.assertEqual(page_signature("http://h/p?id=1"), page_signature("http://h/p?id=2"))
        self.assertNotEqual(page_signature("http://h/p?id=1"), page_signature("http://h/p?cat=1"))

    def test_same_scope_pins_host_and_port(self):
        self.assertTrue(same_scope("http://h:80/x", "h", 80))
        self.assertFalse(same_scope("http://other/x", "h", 80))
        self.assertFalse(same_scope("http://h:8443/x", "h", 80))


class LinkedPage(BaseHTTPRequestHandler):
    """A login-style landing page that links to a *separate* page carrying a reflected-XSS
    parameter — the exact case the user described: the seed is a login screen, but an unlinked-
    from-nowhere-else vulnerable page sits one hop away and must be discovered and tested."""

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/login"):
            body = ('<html><body>Faça login. '
                    '<a href="/search?q=hello">Buscar</a> '
                    '<a href="/logout">Sair</a></body></html>')
        elif self.path.startswith("/search"):
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
            body = f"<html><body>Resultado: {q}</body></html>"   # reflected unescaped
        else:
            body = "<html><body>404</body></html>"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class CrawlReachTests(unittest.TestCase):
    def test_scan_discovers_and_tests_a_linked_page(self):
        with serve(LinkedPage) as base_url:
            result = run_scan(base_url + "/login", mode="safe_active", allow_private=True,
                              max_pages=10, max_depth=2)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["pages_scanned"], 2)
        self.assertTrue(any("/search" in u for u in result["crawled_urls"]),
                        "crawler should have reached /search from the seed")
        self.assertNotIn(base_url + "/logout", result["crawled_urls"])  # logout never followed
        xss = [f for f in result["findings"] if f["fingerprint"].startswith("xss.")]
        self.assertTrue(xss, "reflected XSS on the discovered /search page should be flagged")
        self.assertTrue(any("/search" in f["affected_url"] for f in xss))

    def test_single_page_scan_when_crawl_disabled(self):
        with serve(LinkedPage) as base_url:
            result = run_scan(base_url + "/login", mode="safe_active", allow_private=True,
                              max_pages=1)
        self.assertTrue(result["ok"])
        self.assertEqual(1, result["pages_scanned"])
        self.assertEqual([], [f for f in result["findings"] if f["fingerprint"].startswith("xss.")])

    def test_transient_network_failure_midscan_preserves_findings(self):
        """A timeout while probing a later page must not discard the whole scan: the seed page's
        findings survive and the scan still reports ok."""
        from engine.transport import HttpTransport
        real_send = HttpTransport.send

        def flaky_send(self, request):
            if "/search" in request.url:      # the discovered second page times out mid-crawl
                raise TimeoutError("simulated network timeout")
            return real_send(self, request)

        with serve(LinkedPage) as base_url:
            with unittest.mock.patch.object(HttpTransport, "send", flaky_send):
                result = run_scan(base_url + "/login", mode="passive", allow_private=True,
                                  max_pages=10, max_depth=2)
        self.assertTrue(result["ok"], "a transient timeout must not fail the whole scan")
        self.assertGreaterEqual(result["pages_scanned"], 1)
        self.assertTrue(result["findings"], "seed-page findings must be preserved")


if __name__ == "__main__":
    unittest.main()
