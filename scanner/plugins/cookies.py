"""Cookie attribute analysis: Secure, HttpOnly, SameSite, Domain scope."""
from __future__ import annotations
import re
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from .base import PluginMetadata, ScannerPlugin
from .catalog import CATALOG
from .support import build_finding, consistent, deterministic_confidence

def _cookies(response: HttpResponse) -> list[str]:
    return [value for key, value in response.header_pairs if key.lower() == "set-cookie"]

class CookieSecurityPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Cookie Security",
        category="Session Management",
        cwe="CWE-614,CWE-1004,CWE-352,CWE-284",
        owasp="A07:2025 Authentication Failures",
        wstg="WSTG-SESS-02",
        kind="passive",
        risk="none",
        checks=(
            "cookies.missing_secure", "cookies.missing_httponly", "cookies.missing_samesite",
            "cookies.broad_domain", "cookies.samesite_none_insecure",
        ),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        primary = responses[0]
        cookies = _cookies(primary)
        if not cookies:
            return findings

        def add(check_id: str, failing_predicate, severity: str, evidence: str):
            failing, reproducibility = consistent(responses, lambda r: any(failing_predicate(c) for c in _cookies(r)))
            if failing:
                findings.append(build_finding(
                    check_id=check_id, request=request, response=primary, severity=severity,
                    reason=CATALOG[check_id]["description"],
                    confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=95),
                    parameter_location="cookie",
                    evidence_snippet=evidence,
                ))

        is_https = request.url.startswith("https://")
        if is_https:
            add("cookies.missing_secure", lambda c: "secure" not in c.lower(), "medium",
                next((c for c in cookies if "secure" not in c.lower()), ""))
        add("cookies.missing_httponly", lambda c: "httponly" not in c.lower(), "medium",
            next((c for c in cookies if "httponly" not in c.lower()), ""))
        add("cookies.missing_samesite", lambda c: "samesite=" not in c.lower(), "medium",
            next((c for c in cookies if "samesite=" not in c.lower()), ""))
        add("cookies.broad_domain", lambda c: bool(re.search(r"(?:^|;)\s*domain=", c, re.I)), "low",
            next((c for c in cookies if re.search(r"(?:^|;)\s*domain=", c, re.I)), ""))
        add("cookies.samesite_none_insecure", lambda c: "samesite=none" in c.lower() and "secure" not in c.lower(), "medium",
            next((c for c in cookies if "samesite=none" in c.lower() and "secure" not in c.lower()), ""))
        return findings
