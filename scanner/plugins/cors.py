"""Passive CORS observation on the baseline (no Origin header) response.

This only reports what the server sends unconditionally. Confirming that an
attacker-controlled Origin is actively reflected requires sending additional
requests with crafted Origin values, which belongs to the active CORS
detector in a later phase. Findings here are deliberately capped below
`confirmed` for that reason.
"""
from __future__ import annotations
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from .base import PluginMetadata, ScannerPlugin
from .support import build_finding, consistent, deterministic_confidence

class CorsPassivePlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="CORS Baseline",
        category="CORS Misconfiguration",
        cwe="CWE-942",
        owasp="A01:2025 Broken Access Control",
        wstg="WSTG-CLNT-07",
        kind="passive",
        risk="none",
        checks=("cors.wildcard_origin", "cors.credentials_with_wildcard"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport=None) -> list[Finding]:
        findings: list[Finding] = []
        primary = responses[0]
        origin = primary.headers.get("access-control-allow-origin", "").strip()
        credentials = primary.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
        if origin != "*":
            return findings

        sensitive = bool(context.page and context.page.looks_authenticated)
        wildcard, reproducibility = consistent(responses, lambda r: r.headers.get("access-control-allow-origin", "").strip() == "*")
        findings.append(build_finding(
            check_id="cors.wildcard_origin", request=request, response=primary,
            severity="high" if sensitive else "medium",
            reason="Access-Control-Allow-Origin: * foi retornado sem um cabeçalho Origin na requisição.",
            confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=90),
            evidence_snippet=f"Access-Control-Allow-Origin: {origin}",
        ))
        if credentials:
            findings.append(build_finding(
                check_id="cors.credentials_with_wildcard", request=request, response=primary,
                severity="critical",
                reason="A resposta combina uma origem coringa com Access-Control-Allow-Credentials: true.",
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=95),
                evidence_snippet="Access-Control-Allow-Credentials: true",
            ))
        return findings
