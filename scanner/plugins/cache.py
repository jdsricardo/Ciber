"""Cache-control review for responses that appear to carry session state."""
from __future__ import annotations
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from .base import PluginMetadata, ScannerPlugin
from .catalog import CATALOG
from .support import build_finding, consistent, deterministic_confidence

class CacheSecurityPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Cache Security",
        category="Cache Security",
        cwe="CWE-525",
        owasp="A02:2025 Security Misconfiguration",
        wstg="WSTG-CONF-12",
        kind="passive",
        risk="none",
        checks=("cache.sensitive_no_store_missing",),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext) -> list[Finding]:
        primary = responses[0]
        session_aware = bool(context.page and context.page.sets_cookies) or "authorization" in primary.headers.get("vary", "").lower()
        if not session_aware:
            return []
        missing, reproducibility = consistent(responses, lambda r: "no-store" not in r.headers.get("cache-control", "").lower())
        if not missing:
            return []
        return [build_finding(
            check_id="cache.sensitive_no_store_missing", request=request, response=primary,
            severity="medium",
            reason=CATALOG["cache.sensitive_no_store_missing"]["description"],
            confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=85),
            evidence_snippet=f"Cache-Control: {primary.headers.get('cache-control', '(absent)')}",
        )]
