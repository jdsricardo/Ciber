"""Per-plugin unit tests: a vulnerable fixture and a safe fixture for each passive detector."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "scanner"))

from engine.models import FindingStatus, HttpRequest, HttpResponse, PageContext, ScanContext, ScanLimits, ScanMode
from engine.normalization import build_page_context
from plugins.cache import CacheSecurityPlugin
from plugins.cookies import CookieSecurityPlugin
from plugins.cors import CorsPassivePlugin
from plugins.disclosure import InformationDisclosurePlugin
from plugins.headers import SecurityHeadersPlugin
from plugins.secrets import SecretsExposurePlugin
from plugins.transport import TransportSecurityPlugin


def response(url="https://example.com/", status=200, headers=None, body=b"<html><body>Hello</body></html>", elapsed_ms=20, tls_protocol=None, certificate=None):
    headers = {"content-type": "text/html", **(headers or {})}
    pairs = list(headers.items())
    return HttpResponse(status, url, headers, pairs, body, elapsed_ms, headers.get("location"), tls_protocol, certificate or {})


def context_for(primary: HttpResponse) -> ScanContext:
    ctx = ScanContext(target_url=primary.url, mode=ScanMode.PASSIVE, limits=ScanLimits())
    ctx.page = build_page_context(primary)
    return ctx


def request_for(url: str) -> HttpRequest:
    return HttpRequest(method="GET", url=url)


def fingerprints(findings):
    return {f.fingerprint for f in findings}


class TransportSecurityPluginTests(unittest.TestCase):
    plugin = TransportSecurityPlugin()

    def test_http_target_flags_cleartext_transport(self):
        resp = response(url="http://example.com/")
        findings = self.plugin.analyze(request_for("http://example.com/"), [resp, resp], context_for(resp))
        self.assertIn("transport.https", fingerprints(findings))
        self.assertEqual("high", findings[0].severity)

    def test_https_with_strong_hsts_is_clean(self):
        resp = response(headers={"strict-transport-security": "max-age=63072000; includeSubDomains"})
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual(set(), fingerprints(findings))

    def test_https_without_hsts_is_flagged_but_not_confirmed(self):
        resp = response()
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertIn("headers.hsts_missing", fingerprints(findings))
        finding = next(f for f in findings if f.fingerprint == "headers.hsts_missing")
        self.assertNotEqual(FindingStatus.CONFIRMED.value, finding.status)


class SecurityHeadersPluginTests(unittest.TestCase):
    plugin = SecurityHeadersPlugin()

    def test_missing_csp_and_frame_protection_is_flagged(self):
        resp = response()
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        found = fingerprints(findings)
        self.assertIn("headers.csp_missing", found)
        self.assertIn("headers.frame_options_missing", found)

    def test_fully_hardened_headers_produce_no_findings(self):
        resp = response(headers={
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
        })
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)

    def test_non_html_response_is_not_penalized_for_missing_csp(self):
        resp = response(headers={"content-type": "application/json"}, body=b"{}")
        findings = self.plugin.analyze(request_for("https://example.com/api"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)


class CookieSecurityPluginTests(unittest.TestCase):
    plugin = CookieSecurityPlugin()

    def test_insecure_session_cookie_is_flagged(self):
        resp = response(headers={"set-cookie": "session=abc123; Path=/"})
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        found = fingerprints(findings)
        self.assertIn("cookies.missing_secure", found)
        self.assertIn("cookies.missing_httponly", found)
        self.assertIn("cookies.missing_samesite", found)

    def test_hardened_cookie_is_clean(self):
        resp = response(headers={"set-cookie": "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"})
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)

    def test_no_cookies_produces_no_findings(self):
        resp = response()
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)


class CorsPassivePluginTests(unittest.TestCase):
    plugin = CorsPassivePlugin()

    def test_wildcard_with_credentials_is_critical(self):
        resp = response(headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"})
        findings = self.plugin.analyze(request_for("https://example.com/api"), [resp, resp], context_for(resp))
        found = {f.fingerprint: f for f in findings}
        self.assertIn("cors.wildcard_origin", found)
        self.assertIn("cors.credentials_with_wildcard", found)
        self.assertEqual("critical", found["cors.credentials_with_wildcard"].severity)

    def test_restricted_origin_is_clean(self):
        resp = response(headers={"access-control-allow-origin": "https://trusted.example.com"})
        findings = self.plugin.analyze(request_for("https://example.com/api"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)


class CacheSecurityPluginTests(unittest.TestCase):
    plugin = CacheSecurityPlugin()

    def test_session_cookie_without_no_store_is_flagged(self):
        resp = response(headers={"set-cookie": "session=abc123"})
        findings = self.plugin.analyze(request_for("https://example.com/account"), [resp, resp], context_for(resp))
        self.assertIn("cache.sensitive_no_store_missing", fingerprints(findings))

    def test_session_cookie_with_no_store_is_clean(self):
        resp = response(headers={"set-cookie": "session=abc123", "cache-control": "no-store, private"})
        findings = self.plugin.analyze(request_for("https://example.com/account"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)

    def test_static_page_without_cookies_is_not_penalized(self):
        resp = response()
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)


class InformationDisclosurePluginTests(unittest.TestCase):
    plugin = InformationDisclosurePlugin()

    def test_reproducible_stack_trace_is_flagged(self):
        body = b"<html>SQLSTATE[42000]: Syntax error near line 1</html>"
        resp = response(body=body)
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        found = {f.fingerprint: f for f in findings}
        self.assertIn("disclosure.stack_trace", found)
        self.assertFalse(found["disclosure.stack_trace"].manual_review_required)

    def test_one_off_error_text_is_marked_for_manual_review(self):
        body = b"<html>SQLSTATE[42000]: Syntax error near line 1</html>"
        resp_with_error = response(body=body)
        resp_clean = response(body=b"<html>ok</html>")
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp_with_error, resp_clean], context_for(resp_with_error))
        found = {f.fingerprint: f for f in findings}
        self.assertTrue(found["disclosure.stack_trace"].manual_review_required)

    def test_clean_page_has_no_disclosure_findings(self):
        resp = response(body=b"<html><body>Welcome</body></html>")
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)

    def test_server_version_banner_is_low_severity_informational(self):
        resp = response(headers={"server": "Apache/2.4.41 (Ubuntu)"})
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        found = {f.fingerprint: f for f in findings}
        self.assertEqual("low", found["disclosure.server_header"].severity)


class SecretsExposurePluginTests(unittest.TestCase):
    plugin = SecretsExposurePlugin()

    def test_aws_access_key_is_detected_and_masked(self):
        body = b'<script>const key = "AKIAABCDEFGHIJKLMNOP";</script>'
        resp = response(body=body)
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual(1, len(findings))
        self.assertEqual("critical", findings[0].severity)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", findings[0].evidence.probe_response["snippet"])
        self.assertTrue(findings[0].manual_review_required)

    def test_rotating_token_is_not_flagged_as_a_static_secret(self):
        resp_a = response(body=b'<input type="hidden" name="csrf_token" value="k3f8s9a2b7c1d4e6f0a3b5c7d9e1f2a4">')
        resp_b = response(body=b'<input type="hidden" name="csrf_token" value="z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4">')
        findings = self.plugin.analyze(request_for("https://example.com/login"), [resp_a, resp_b], context_for(resp_a))
        self.assertEqual([], findings)

    def test_placeholder_value_is_ignored(self):
        body = b'<div>api_key: changeme</div>'
        resp = response(body=body)
        findings = self.plugin.analyze(request_for("https://example.com/"), [resp, resp], context_for(resp))
        self.assertEqual([], findings)

    def test_stable_high_entropy_secret_is_flagged_for_manual_review(self):
        body = b'<div>connection_string: h4Kx9pQ2mZ7vR1tY8nL3wJ6cF0bE5dS9a</div>'
        resp = response(body=body)
        findings = self.plugin.analyze(request_for("https://example.com/config"), [resp, resp], context_for(resp))
        self.assertEqual(1, len(findings))
        self.assertTrue(findings[0].manual_review_required)


if __name__ == "__main__":
    unittest.main()
