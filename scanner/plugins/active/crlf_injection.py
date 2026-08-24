"""CRLF Injection / HTTP Response Splitting: differential detection of user input that
reaches raw HTTP header construction on the server side.

Methodology per parameter (bounded, stop-on-evidence):
  1. Only test query parameters that give a strong signal of flowing into response
     header construction: either the parameter's baseline value is reflected
     somewhere in the baseline response headers (strongest signal), or - as a
     lower-priority fallback used only when no parameter shows header reflection -
     the parameter name looks redirect-related (the same name heuristic used for
     Open Redirect), since redirect targets commonly flow straight into `Location`.
  2. Send one probe: the original value followed by a percent-encoded CRLF sequence
     and a brand new header/cookie line (`X-Sentinelscope-Crlf-Test: injected` and
     `Set-Cookie: sentinelscope_crlf=injected`). The request line/headers this
     scanner actually sends never contain a raw CR/LF - only a vulnerable
     server-side app that URL-decodes the parameter and splices the raw value into
     a hand-built header line, instead of using a proper header-setting API that
     rejects embedded newlines, would ever split it into new header lines.
  3. Detect success structurally, never by fuzzy string matching: a header
     literally named `x-sentinelscope-crlf-test` (absent from the baseline)
     appears in the probe response, or a `Set-Cookie` header carrying
     `sentinelscope_crlf=injected` appears that was not present in baseline.
     Header presence is compared via `header_pairs` (never the collapsed
     `headers` dict, which would silently drop a duplicated `Set-Cookie`) using
     name-set / value-list differencing.
  4. Negative control: resend the same original value with a harmless suffix that
     contains no CRLF at all. If the "new header" signal still appears, this is not
     CRLF injection (the app adds odd headers/cookies for any odd suffix) and no
     finding is reported.
  5. Bonus second confirmation: try a doubled-CRLF variant that attempts to splice
     a whole extra body into the response. If it also lands, that raises
     independent_confirmation further, but it is only ever used as corroborating
     evidence - never to render or execute anything.

Never attempts to actually poison a shared cache, fixate a real session, or chain
this into a further attack; detection stops at proving the header injection itself.
"""
from __future__ import annotations
import re
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, consistent, mutate_query_param

CATALOG: dict[str, dict[str, str]] = {
    "crlf.header_injection_confirmed": {
        "title": "Injeção de cabeçalho HTTP via CRLF confirmada",
        "category": "Injeção de CRLF / HTTP Response Splitting",
        "cwe": "CWE-93",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-15",
        "description": (
            "Um parâmetro de query teve uma sequência CRLF (%0d%0a) codificada em URL aceita "
            "pela aplicação e refletida como uma quebra de linha real dentro dos cabeçalhos de "
            "resposta HTTP, permitindo a injeção de um cabeçalho ou cookie inteiramente novo."
        ),
        "developer_impact": (
            "Um atacante pode injetar cabeçalhos de resposta arbitrários, fixar cookies de "
            "sessão em vítimas via um Set-Cookie forjado, envenenar caches intermediários ou, "
            "em cenários mais graves, dividir a resposta HTTP em duas para conduzir XSS "
            "refletido ou desfiguração via response splitting."
        ),
        "remediation": (
            "Nunca construa cabeçalhos HTTP concatenando entrada do usuário em uma string "
            "bruta. Utilize sempre a API de definição de cabeçalhos/cookies do framework, que "
            "rejeita ou remove caracteres CR/LF automaticamente, e valide ou rejeite qualquer "
            "valor de entrada que contenha '\\r' ou '\\n' antes de usá-lo em um redirecionamento "
            "ou em qualquer outro valor refletido em cabeçalho de resposta."
        ),
    },
}

REDIRECT_NAME_PATTERN = re.compile(r"redirect|url|next|return|dest|continue|target", re.I)
INJECTED_HEADER_NAME = "x-sentinelscope-crlf-test"
INJECTED_HEADER_VALUE = "injected"
INJECTED_COOKIE_MARKER = "sentinelscope_crlf=injected"
CONTROL_SUFFIX = "-control-suffix"
MIN_REFLECTED_VALUE_LENGTH = 3
SPLIT_BODY_MARKER = b"<html>injected body</html>"


def _header_names(response: HttpResponse) -> set[str]:
    return {name.lower() for name, _ in response.header_pairs}


def _cookie_values(response: HttpResponse) -> list[str]:
    return [value for name, value in response.header_pairs if name.lower() == "set-cookie"]


def _value_reflected_in_headers(value: str, response: HttpResponse) -> bool:
    if not value or len(value) < MIN_REFLECTED_VALUE_LENGTH:
        return False
    return any(value in header_value for _, header_value in response.header_pairs)


def _new_injected_header(baseline: HttpResponse, probe: HttpResponse) -> str | None:
    """Returns the probe's injected-header value if a *new* (not present at baseline)
    header literally named INJECTED_HEADER_NAME shows up carrying our marker value."""
    baseline_names = _header_names(baseline)
    if INJECTED_HEADER_NAME in baseline_names:
        return None
    for name, value in probe.header_pairs:
        if name.lower() == INJECTED_HEADER_NAME and INJECTED_HEADER_VALUE in value.lower():
            return value
    return None


def _new_injected_cookie(baseline: HttpResponse, probe: HttpResponse) -> str | None:
    """Returns the probe's injected Set-Cookie value if a *new* cookie carrying our
    marker appears that was not already present in the baseline Set-Cookie list."""
    baseline_cookies = _cookie_values(baseline)
    for cookie in _cookie_values(probe):
        if cookie not in baseline_cookies and INJECTED_COOKIE_MARKER in cookie:
            return cookie
    return None


class CrlfInjectionPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="CRLF Injection",
        category="Injeção de CRLF / HTTP Response Splitting",
        cwe="CWE-93",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-15",
        kind="safe_active",
        risk="low",
        checks=("crlf.header_injection_confirmed",),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        primary = responses[0]
        query_points = [point for point in request.inputs if point.location == "query"]
        reflected = [point for point in query_points if _value_reflected_in_headers(point.value, primary)]
        candidates = reflected if reflected else [point for point in query_points if REDIRECT_NAME_PATTERN.search(point.name)]

        findings: list[Finding] = []
        for point in candidates:
            finding = self._test_parameter(request, point, responses, transport)
            if finding is not None:
                findings.append(finding)
        return findings

    def _send(self, template: HttpRequest, transport: HttpTransport, url: str) -> tuple[HttpRequest, HttpResponse]:
        probe_request = HttpRequest(method=template.method, url=url, headers=dict(template.headers))
        return probe_request, transport.send(probe_request)

    def _test_parameter(self, request: HttpRequest, point, responses: list[HttpResponse], transport: HttpTransport) -> Finding | None:
        baseline = responses[0]
        probe_payload = f"{point.value}\r\nX-Sentinelscope-Crlf-Test: injected\r\nSet-Cookie: {INJECTED_COOKIE_MARKER}"
        probe_url = mutate_query_param(request.url, point.name, probe_payload)
        probe_request, probe_response = self._send(request, transport, probe_url)

        injected_header_value = _new_injected_header(baseline, probe_response)
        injected_cookie_value = _new_injected_cookie(baseline, probe_response)
        if injected_header_value is None and injected_cookie_value is None:
            return None

        control_payload = f"{point.value}{CONTROL_SUFFIX}"
        control_url = mutate_query_param(request.url, point.name, control_payload)
        _, control_response = self._send(request, transport, control_url)
        if _new_injected_header(baseline, control_response) is not None or _new_injected_cookie(baseline, control_response) is not None:
            # The same "new header/cookie" signal also appears for a harmless suffix
            # that contains no CRLF at all: this app reacts to any odd input, not
            # specifically to CRLF, so this is not CRLF injection.
            return None

        second_confirmed = self._confirm_body_split(request, point, transport, responses)

        _, reproducibility = consistent(responses, lambda r: INJECTED_HEADER_NAME not in _header_names(r))

        evidence_bits = []
        if injected_header_value is not None:
            evidence_bits.append(f"o cabeçalho novo '{INJECTED_HEADER_NAME}: {injected_header_value}'")
        if injected_cookie_value is not None:
            evidence_bits.append(f"o Set-Cookie novo '{injected_cookie_value}'")
        evidence_text = " e ".join(evidence_bits)

        reason = (
            f"O parâmetro '{point.name}' aceitou uma sequência CRLF codificada em URL (%0d%0a) e a "
            f"resposta passou a conter {evidence_text}, ausente tanto na linha de base quanto em um "
            f"valor de controle com sufixo inofensivo sem CRLF ('{control_payload}'). "
            + (
                "Uma segunda variante com CRLF duplicado também conseguiu injetar conteúdo adicional no "
                "corpo da resposta, confirmando de forma independente a divisão da resposta HTTP."
                if second_confirmed else
                "A segunda variante com CRLF duplicado (tentativa de divisão do corpo da resposta) não "
                "reproduziu o efeito, mas a injeção do cabeçalho já é evidência estrutural suficiente."
            )
        )

        confidence_inputs = ConfidenceInputs(
            evidence_strength=95,
            reproducibility=reproducibility,
            differential_quality=95,
            independent_confirmation=100 if second_confirmed else 60,
            ambiguity=0,
        )

        return build_finding(
            check_id="crlf.header_injection_confirmed",
            request=probe_request,
            response=probe_response,
            severity="high",
            reason=reason,
            confidence_inputs=confidence_inputs,
            parameter=point.name,
            parameter_location=point.location,
            evidence_snippet=evidence_text,
            differences={
                "injected_header_confirmed": injected_header_value is not None,
                "injected_cookie_confirmed": injected_cookie_value is not None,
                "second_variant_confirmed": second_confirmed,
            },
            catalog=CATALOG,
        )

    def _confirm_body_split(self, request: HttpRequest, point, transport: HttpTransport, responses: list[HttpResponse]) -> bool:
        payload = f"{point.value}\r\n\r\n{SPLIT_BODY_MARKER.decode()}"
        url = mutate_query_param(request.url, point.name, payload)
        _, response = self._send(request, transport, url)
        if SPLIT_BODY_MARKER not in response.body:
            return False
        return not any(SPLIT_BODY_MARKER in baseline.body for baseline in responses)
