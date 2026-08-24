"""Host Header Injection: single endpoint-level active probe.

Methodology (bounded, three requests, stop-on-no-evidence):
  1. Repeat-baseline probe: resend the same GET with the ORIGINAL, correct Host
     header (re-derived from `urlparse(request.url).hostname`). This is a negative
     control — if our reserved canary domain somehow already appears here, it can't
     be attributed to Host manipulation, so we stay silent (normal page dynamism,
     not noise from our own probe).
  2. Combined probe: resend the GET with both `Host` and `X-Forwarded-Host` set to
     a reserved, non-resolvable canary domain (`.invalid` TLD, RFC 2606 — guarantees
     no real host is ever contacted or implicated). `HttpTransport` connects to
     `urlparse(request.url).hostname`/`.port` (the real, authorized target) and sends
     `request.headers` verbatim as the request line's headers, so the TCP/TLS
     connection never leaves scope — only the logical `Host:` header value we send
     changes. `SafetyController.validate_url` also validates `request.url`, not the
     Host header content, so scope is preserved regardless of what we put in Host.
  3. Host-only discriminator probe (only sent if step 2 found the canary): the same
     canary Host, but WITHOUT X-Forwarded-Host. If the canary still reflects, the
     application is driven by the primary Host header (strong, structural evidence).
     If it does NOT reflect here — meaning step 2's reflection depended on
     X-Forwarded-Host being present — the signal is weaker and more ambiguous: many
     apps do not trust X-Forwarded-Host the way they trust the primary Host header,
     so this is still reported, but with `manual_review_required=True` and reduced
     confidence.

Detection looks for the canary reflected into, specifically:
  (a) a `Location` header (an absolute redirect URL built from Host — the classic
      password-reset-link poisoning vector),
  (b) an absolute (or protocol-relative) URL in the response BODY, e.g. a canonical
      link tag, an asset URL, a form action, or a "click here" link built from Host,
  (c) a `Set-Cookie` `Domain=` attribute derived from Host.
Matching is exact hostname/substring matching against the canary domain specifically
(never a generic "did the response change" diff), so every finding has a structural,
explainable reason.

HTTPS note: SNI for the TLS handshake is derived by `http.client.HTTPSConnection`
from the real target hostname (the `host` argument it was constructed with, i.e.
`urlparse(request.url).hostname`), not from the `Host:` header we set — so the TLS
handshake itself will not fail because of our manipulated Host. However, many
virtual-hosting setups and CDNs route purely on the HTTP-level Host header *after*
TLS termination, so a mismatched Host can still yield a default vhost's content, an
error response, or the real site unaffected. That is an expected "not vulnerable"
outcome and must simply produce no finding, not a crash. `transport.send` errors for
these extra probes are handled defensively: `Cancelled`/`BudgetExceeded`/
`ScopeViolation` always propagate (per project convention), but any other, lower-level
connection error (e.g. a TLS handshake reset from strict vhost routing) is treated as
"this probe produced no usable evidence" and the plugin moves on without crashing.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.safety import BudgetExceeded, Cancelled, ScopeViolation
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding

CANARY = "sentinelscope-host-canary.invalid"

CATALOG: dict[str, dict[str, str]] = {
    "host_header.reflected_in_redirect": {
        "title": "Cabeçalho Host é refletido em redirecionamento ou cookie de resposta",
        "category": "Injeção de Host Header",
        "cwe": "CWE-644",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-17",
        "description": (
            "Um valor de Host (ou X-Forwarded-Host) manipulado e reservado para testes foi "
            "refletido verbatim no cabeçalho Location de um redirecionamento ou no atributo "
            "Domain de um Set-Cookie, indicando que a aplicação usa o cabeçalho Host recebido "
            "do cliente para construir URLs absolutas ou escopo de cookies do lado do servidor."
        ),
        "developer_impact": (
            "Um atacante pode manipular o cabeçalho Host para envenenar links de redefinição de "
            "senha, URLs de redirecionamento pós-login/pós-cadastro, ou o domínio de cookies de "
            "sessão, potencialmente levando ao sequestro de conta, envenenamento de cache web ou "
            "vazamento de cookies para um domínio controlado pelo atacante."
        ),
        "remediation": (
            "Nunca construa URLs absolutas, links de redefinição de senha, redirecionamentos ou o "
            "domínio de cookies a partir do cabeçalho Host (ou X-Forwarded-Host) recebido do "
            "cliente. Use um nome de host fixo e configurado no servidor, ou valide o Host recebido "
            "contra uma allowlist estrita antes de confiar nele para qualquer finalidade."
        ),
    },
    "host_header.reflected_in_body": {
        "title": "Cabeçalho Host é refletido em URL absoluta no corpo da resposta",
        "category": "Injeção de Host Header",
        "cwe": "CWE-644",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-17",
        "description": (
            "Um valor de Host (ou X-Forwarded-Host) manipulado e reservado para testes foi "
            "refletido verbatim como o host de uma URL absoluta (ou relativa a protocolo) no corpo "
            "HTML da resposta, por exemplo em um link, em uma action de formulário ou em uma tag "
            "canonical."
        ),
        "developer_impact": (
            "Se essa URL aparecer em um contexto sensível — um link 'clique aqui' de redefinição de "
            "senha, uma tag canonical indexada por mecanismos de busca, ou a action de um formulário "
            "— um atacante pode induzir vítimas a seguir um link malicioso hospedado sob um domínio "
            "que parece pertencer à aplicação legítima."
        ),
        "remediation": (
            "Construa toda URL absoluta exibida no corpo da resposta a partir de um nome de host "
            "fixo e configurado no servidor, nunca a partir do cabeçalho Host ou X-Forwarded-Host "
            "fornecido pelo cliente."
        ),
    },
}

BODY_ABSOLUTE_PATTERN = re.compile(r"(?:https?:)?//" + re.escape(CANARY), re.I)
COOKIE_DOMAIN_PATTERN = re.compile(r"(?i)domain\s*=\s*\.?" + re.escape(CANARY) + r"\b")


def _location_evidence(response: HttpResponse) -> str | None:
    location = response.headers.get("location", "")
    if not location:
        return None
    hostname = urlparse(location).hostname or ""
    if hostname == CANARY or CANARY in location:
        return location
    return None


def _cookie_domain_evidence(response: HttpResponse) -> str | None:
    for key, value in response.header_pairs:
        if key.lower() == "set-cookie" and COOKIE_DOMAIN_PATTERN.search(value):
            return value
    return None


def _body_evidence(response: HttpResponse) -> str | None:
    match = BODY_ABSOLUTE_PATTERN.search(response.body.decode("utf-8", errors="replace"))
    return match.group(0) if match else None


def _any_canary(response: HttpResponse) -> bool:
    return bool(_location_evidence(response) or _cookie_domain_evidence(response) or _body_evidence(response))


class HostHeaderInjectionPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Host Header Injection",
        category="Injeção de Host Header",
        cwe="CWE-644",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-17",
        kind="safe_active",
        risk="low",
        checks=("host_header.reflected_in_redirect", "host_header.reflected_in_body"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        original_host = urlparse(request.url).hostname or ""
        if not original_host:
            return []

        baseline_request, baseline_response = self._send(request, transport, {"Host": original_host})
        if baseline_response is None:
            return []
        if _any_canary(baseline_response):
            # The canary already appears with the correct, unmodified Host: it cannot be
            # attributed to Host manipulation, so treat this as noise and stay silent.
            return []

        combined_request, combined_response = self._send(
            request, transport, {"Host": CANARY, "X-Forwarded-Host": CANARY}
        )
        if combined_response is None or not _any_canary(combined_response):
            return []

        _, host_only_response = self._send(request, transport, {"Host": CANARY})
        host_attributable = host_only_response is not None and _any_canary(host_only_response)

        findings: list[Finding] = []
        findings.extend(self._header_finding(combined_request, combined_response, host_attributable))
        findings.extend(self._body_finding(combined_request, combined_response, host_attributable, context))
        return findings

    def _send(self, template: HttpRequest, transport: HttpTransport, header_overrides: dict[str, str]) -> tuple[HttpRequest, HttpResponse | None]:
        headers = {k: v for k, v in template.headers.items() if k.lower() not in ("host", "x-forwarded-host")}
        headers.update(header_overrides)
        probe_request = HttpRequest(method="GET", url=template.url, headers=headers)
        try:
            return probe_request, transport.send(probe_request)
        except (Cancelled, BudgetExceeded, ScopeViolation):
            raise
        except Exception:
            # Lower-level connection error (e.g. TLS/SNI or vhost-routing rejection of the
            # mismatched Host on an HTTPS target). Expected "not vulnerable" outcome for many
            # real hosts: skip this probe's contribution instead of crashing the plugin.
            return probe_request, None

    def _attribution_note(self, host_attributable: bool) -> str:
        if host_attributable:
            return (
                f", e permaneceu presente ao remover o cabeçalho X-Forwarded-Host — portanto "
                f"atribuível ao cabeçalho Host primário."
            )
        return (
            f", mas desapareceu ao remover o cabeçalho X-Forwarded-Host e manter o Host original — "
            f"sinal mais fraco, dependente apenas de X-Forwarded-Host, que a aplicação pode não "
            f"tratar como confiável da mesma forma que o Host primário."
        )

    def _header_finding(self, request: HttpRequest, response: HttpResponse, host_attributable: bool) -> list[Finding]:
        location_evidence = _location_evidence(response)
        cookie_evidence = _cookie_domain_evidence(response)
        if not location_evidence and not cookie_evidence:
            return []

        if location_evidence and cookie_evidence:
            where = (
                f"no cabeçalho Location ('{location_evidence}') e no atributo Domain de um "
                f"Set-Cookie ('{cookie_evidence}')"
            )
        elif location_evidence:
            where = f"no cabeçalho Location de um redirecionamento ('{location_evidence}')"
        else:
            where = f"no atributo Domain de um cabeçalho Set-Cookie ('{cookie_evidence}')"

        reason = f"O domínio de teste '{CANARY}' enviado via Host foi refletido verbatim {where}" + self._attribution_note(host_attributable)
        evidence_strength = 95 if host_attributable else 70
        ambiguity = 0 if host_attributable else 25
        independent_confirmation = 85 if host_attributable else 30

        return [build_finding(
            check_id="host_header.reflected_in_redirect",
            request=request,
            response=response,
            severity="high",
            reason=reason,
            confidence_inputs=ConfidenceInputs(
                evidence_strength=evidence_strength,
                reproducibility=85,
                differential_quality=90,
                independent_confirmation=independent_confirmation,
                ambiguity=ambiguity,
            ),
            parameter="Host",
            parameter_location="header",
            manual_review_required=not host_attributable,
            evidence_snippet=(location_evidence or cookie_evidence or "")[:200],
            differences={
                "attributed_to": "Host" if host_attributable else "X-Forwarded-Host",
                "location": location_evidence,
                "set_cookie_domain": cookie_evidence,
            },
            catalog=CATALOG,
        )]

    def _body_finding(self, request: HttpRequest, response: HttpResponse, host_attributable: bool, context: ScanContext) -> list[Finding]:
        body_evidence = _body_evidence(response)
        if not body_evidence:
            return []

        has_forms = bool(context.page and context.page.has_forms)
        severity = "high" if has_forms else "medium"
        evidence_strength = 90 if host_attributable else 65
        ambiguity = 5 if host_attributable else 30
        independent_confirmation = 75 if host_attributable else 25

        reason = (
            f"O domínio de teste '{CANARY}' enviado via Host foi refletido verbatim como host de "
            f"uma URL absoluta no corpo da resposta ('{body_evidence}')" + self._attribution_note(host_attributable)
        )

        return [build_finding(
            check_id="host_header.reflected_in_body",
            request=request,
            response=response,
            severity=severity,
            reason=reason,
            confidence_inputs=ConfidenceInputs(
                evidence_strength=evidence_strength,
                reproducibility=85,
                differential_quality=85,
                independent_confirmation=independent_confirmation,
                ambiguity=ambiguity,
            ),
            parameter="Host",
            parameter_location="header",
            manual_review_required=not host_attributable,
            evidence_snippet=body_evidence[:200],
            differences={
                "attributed_to": "Host" if host_attributable else "X-Forwarded-Host",
                "body_match": body_evidence,
                "has_forms": has_forms,
            },
            catalog=CATALOG,
        )]
