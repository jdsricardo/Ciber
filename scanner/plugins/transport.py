"""Transport security: HTTPS enforcement, TLS protocol/certificate, HSTS."""
from __future__ import annotations
import re
import ssl
import time
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from .base import PluginMetadata, ScannerPlugin
from .support import build_finding, consistent, deterministic_confidence

HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.I)

class TransportSecurityPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Transport Security",
        category="Transport Security",
        cwe="CWE-319,CWE-326,CWE-298",
        owasp="A04:2025 Cryptographic Failures",
        wstg="WSTG-CRYP-01,WSTG-CONF-07",
        kind="passive",
        risk="none",
        checks=("transport.https", "tls.legacy_protocol", "tls.certificate_expiry", "headers.hsts_missing", "headers.hsts_weak"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport=None) -> list[Finding]:
        findings: list[Finding] = []
        primary = responses[0]
        is_https = request.url.startswith("https://")
        sensitive = bool(context.page and (context.page.has_password_field or context.page.looks_authenticated))

        if not is_https:
            _, reproducibility = consistent(responses, lambda r: True)
            findings.append(build_finding(
                check_id="transport.https", request=request, response=primary,
                severity="critical" if sensitive else "high",
                reason="A URL informada usa o esquema http://.",
                confidence_inputs=deterministic_confidence(reproducibility),
                evidence_snippet=request.url,
            ))
            return findings

        if primary.tls_protocol:
            legacy, reproducibility = consistent(responses, lambda r: r.tls_protocol in ("TLSv1", "TLSv1.1"))
            if legacy:
                findings.append(build_finding(
                    check_id="tls.legacy_protocol", request=request, response=primary,
                    severity="high",
                    reason=f"O protocolo negociado foi {primary.tls_protocol}.",
                    confidence_inputs=deterministic_confidence(reproducibility),
                    evidence_snippet=str(primary.tls_protocol),
                ))
            not_after = (primary.certificate or {}).get("notAfter")
            if not_after:
                try:
                    remaining_days = round((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400)
                except ValueError:
                    remaining_days = None
                if remaining_days is not None and remaining_days < 30:
                    findings.append(build_finding(
                        check_id="tls.certificate_expiry", request=request, response=primary,
                        severity="critical" if remaining_days < 0 else "medium",
                        reason=f"Validade restante do certificado: {remaining_days} dias.",
                        confidence_inputs=deterministic_confidence(100),
                        evidence_snippet=f"notAfter={not_after}",
                    ))

        hsts_present, reproducibility = consistent(responses, lambda r: "strict-transport-security" in r.headers)
        if not hsts_present:
            findings.append(build_finding(
                check_id="headers.hsts_missing", request=request, response=primary,
                severity="high" if sensitive else "medium",
                reason="Strict-Transport-Security está ausente da resposta HTTPS.",
                confidence_inputs=deterministic_confidence(reproducibility),
            ))
        else:
            hsts_value = primary.headers.get("strict-transport-security", "")
            match = HSTS_MAX_AGE.search(hsts_value)
            weak = not match or int(match.group(1)) < 31536000
            if weak:
                findings.append(build_finding(
                    check_id="headers.hsts_weak", request=request, response=primary,
                    severity="low",
                    reason=f"Valor do HSTS: {hsts_value}",
                    confidence_inputs=deterministic_confidence(reproducibility),
                    evidence_snippet=hsts_value,
                ))
        return findings
