"""Browser-enforced security headers: CSP, framing, sniffing, referrer, permissions, isolation."""
from __future__ import annotations
import re
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from .base import PluginMetadata, ScannerPlugin
from .catalog import CATALOG
from .support import build_finding, consistent, deterministic_confidence

WILDCARD_SOURCE = re.compile(r"(?:^|\s)\*(?:\s|;|$)")

class SecurityHeadersPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Security Headers",
        category="Security Headers",
        cwe="CWE-693,CWE-1021,CWE-200,CWE-116",
        owasp="A02:2025 Security Misconfiguration",
        wstg="WSTG-CONF-12,WSTG-CLNT-09",
        kind="passive",
        risk="none",
        checks=(
            "headers.csp_missing", "headers.csp_report_only", "headers.csp_unsafe_inline",
            "headers.csp_unsafe_eval", "headers.csp_wildcard", "headers.frame_options_missing",
            "headers.nosniff_missing", "headers.referrer_policy_missing", "headers.permissions_policy_missing",
            "headers.coop_missing", "headers.corp_missing", "headers.content_type_missing",
        ),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        primary = responses[0]
        is_html = bool(context.page and context.page.is_html)
        sensitive = bool(context.page and (context.page.has_forms or context.page.has_password_field or context.page.looks_authenticated))

        def add(check_id: str, present_predicate, severity: str, evidence_snippet: str = "", evidence_strength: int = 90):
            missing, reproducibility = consistent(responses, lambda r: not present_predicate(r))
            if missing:
                findings.append(build_finding(
                    check_id=check_id, request=request, response=primary, severity=severity,
                    reason=CATALOG[check_id]["description"],
                    confidence_inputs=deterministic_confidence(reproducibility, evidence_strength),
                    evidence_snippet=evidence_snippet,
                ))

        if not is_html:
            return findings

        csp = primary.headers.get("content-security-policy", "")
        csp_report_only = primary.headers.get("content-security-policy-report-only", "")
        if not csp and not csp_report_only:
            add("headers.csp_missing", lambda r: bool(r.headers.get("content-security-policy")),
                "high" if sensitive else "medium")
        elif not csp and csp_report_only:
            add("headers.csp_report_only", lambda r: bool(r.headers.get("content-security-policy")),
                "medium", csp_report_only)
        if csp:
            csp_lower = csp.lower()
            if "unsafe-inline" in csp_lower:
                add("headers.csp_unsafe_inline", lambda r: "unsafe-inline" not in r.headers.get("content-security-policy", "").lower(),
                    "medium", csp)
            if "unsafe-eval" in csp_lower:
                add("headers.csp_unsafe_eval", lambda r: "unsafe-eval" not in r.headers.get("content-security-policy", "").lower(),
                    "medium", csp)
            if WILDCARD_SOURCE.search(csp_lower):
                add("headers.csp_wildcard", lambda r: not WILDCARD_SOURCE.search(r.headers.get("content-security-policy", "").lower()),
                    "medium", csp)
            framed_ok = "frame-ancestors" in csp_lower
        else:
            framed_ok = False
        if not framed_ok:
            add("headers.frame_options_missing", lambda r: "x-frame-options" in r.headers,
                "high" if sensitive else "medium")

        add("headers.nosniff_missing", lambda r: r.headers.get("x-content-type-options", "").lower() == "nosniff", "low")
        add("headers.referrer_policy_missing", lambda r: "referrer-policy" in r.headers, "low")
        add("headers.permissions_policy_missing", lambda r: "permissions-policy" in r.headers, "low")
        add("headers.coop_missing", lambda r: "cross-origin-opener-policy" in r.headers, "low")
        add("headers.corp_missing", lambda r: "cross-origin-resource-policy" in r.headers, "low")

        if not primary.headers.get("content-type") and len(primary.body) > 0:
            add("headers.content_type_missing", lambda r: bool(r.headers.get("content-type")), "low")

        return findings
