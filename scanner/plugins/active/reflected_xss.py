"""Reflected XSS: marker-based reflection discovery, context classification, then a
context-appropriate confirmation probe. Never assumes a reflected marker alone proves
exploitability — HTML/JS escaping is checked explicitly before any finding is raised.
"""
from __future__ import annotations
import re
import secrets
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, send_probe, testable_inputs

CATALOG = {
    "xss.reflected_html_text": {
        "title": "Cross-Site Scripting refletido em contexto de texto HTML",
        "category": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-01",
        "description": "Um marcador contendo caracteres HTML especiais foi refletido sem escaping no corpo da resposta, em uma posição de texto solto no HTML.",
        "developer_impact": "Um atacante pode injetar HTML e JavaScript arbitrário que será executado no navegador de outros usuários que acessem uma URL manipulada, permitindo roubo de sessão, phishing ou desfiguração da página.",
        "remediation": "Codifique (HTML-encode) toda saída de dados controlados pelo usuário antes de inseri-la no HTML. Utilize as funções de escaping automático do seu framework de templates.",
    },
    "xss.reflected_html_attribute": {
        "title": "Cross-Site Scripting refletido em atributo HTML",
        "category": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-01",
        "description": "Um marcador foi refletido dentro do valor de um atributo HTML de forma que permite encerrar o atributo e injetar novos atributos ou tags.",
        "developer_impact": "Um atacante pode escapar do atributo e injetar manipuladores de evento (ex.: onmouseover) ou novas tags, executando JavaScript arbitrário no navegador de outros usuários.",
        "remediation": "Codifique valores de atributos HTML corretamente (HTML attribute encoding) e utilize aspas em todos os atributos.",
    },
    "xss.reflected_script_context": {
        "title": "Cross-Site Scripting refletido em contexto de script",
        "category": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-01",
        "description": "Um marcador foi refletido dentro de um bloco <script> de forma que permite encerrar uma string JavaScript e injetar código arbitrário.",
        "developer_impact": "Um atacante pode injetar JavaScript arbitrário diretamente no contexto de execução da página, o cenário de maior impacto para XSS refletido.",
        "remediation": "Nunca insira dados controlados pelo usuário diretamente em blocos <script>. Utilize atributos data-* com HTML encoding e leia-os via JavaScript, ou serialize com JSON.stringify aplicando escaping de </script>.",
    },
}

MARKER_PREFIX = "sszz"
CONTEXT_TAGS = re.compile(r"<(script|style|textarea|title)\b", re.I)

def _marker() -> str:
    return f"{MARKER_PREFIX}{secrets.token_hex(4)}"

def _find_reflection_context(body: str, marker: str) -> str | None:
    """Returns 'script', 'attribute', 'text', or None based on where the raw marker landed."""
    index = body.find(marker)
    if index == -1:
        return None
    window_start = max(0, index - 400)
    before = body[window_start:index]
    # Determine the nearest enclosing tag context by scanning backwards for the last
    # unmatched '<' before the marker and checking whether we are still inside it (attribute)
    # or past its closing '>' (text/script-body).
    last_open = before.rfind("<")
    last_close = before.rfind(">")
    if last_open > last_close:
        return "attribute"
    open_script = list(CONTEXT_TAGS.finditer(before))
    if open_script:
        tag = open_script[-1].group(1).lower()
        closing = re.search(rf"</{tag}\b", before[open_script[-1].end():], re.I)
        if not closing:
            return "script" if tag == "script" else "text"
    return "text"

class ReflectedXssPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Reflected XSS",
        category="Cross-Site Scripting (XSS)",
        cwe="CWE-79",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-01",
        kind="safe_active",
        risk="low",
        checks=("xss.reflected_html_text", "xss.reflected_html_attribute", "xss.reflected_script_context"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        findings: list[Finding] = []
        for param in testable_inputs(request):
            finding = self._test_parameter(request, param, transport)
            if finding:
                findings.append(finding)
        return findings

    def _test_parameter(self, request, param, transport):
        marker = _marker()
        discovery_value = f"{marker}<{marker}>\"'"
        probe = send_probe(transport, request, param, param.value + discovery_value)
        body = probe.body.decode("utf-8", errors="replace")

        if marker not in body:
            return None  # not reflected at all: nothing to test further

        raw_reflection = discovery_value in body
        if not raw_reflection:
            # The marker landed, but not verbatim: check whether it survived HTML-escaped
            # (safe) or was otherwise altered/stripped (also safe, from an XSS standpoint).
            escaped_forms = ["&lt;", "&#60;", "&#x3c;"]
            if any(f"{marker}{form}" in body.lower() or form in body for form in escaped_forms) or f"{marker}<{marker}>" not in body:
                return None
        context_kind = _find_reflection_context(body, marker)
        if context_kind is None:
            return None

        if context_kind == "text":
            return self._confirm_html_text(request, param, marker, transport)
        if context_kind == "attribute":
            return self._confirm_attribute(request, param, marker, transport)
        if context_kind == "script":
            return self._confirm_script(request, param, marker, transport)
        return None

    def _confirm_html_text(self, request, param, marker, transport):
        payload = f"<{marker} data-x=1>"
        probe = send_probe(transport, request, param, param.value + payload)
        body = probe.body.decode("utf-8", errors="replace")
        if payload not in body:
            return None
        confirm_payload = f"<{marker}b data-y=2>"
        confirm = send_probe(transport, request, param, param.value + confirm_payload)
        reproduced = confirm_payload in confirm.body.decode("utf-8", errors="replace")
        return build_finding(
            check_id="xss.reflected_html_text", request=request, response=probe,
            severity="high",
            reason=f"O parâmetro '{param.name}' refletiu uma tag HTML não escapada ('<{marker} ...>') diretamente no corpo da resposta, em posição de texto solto.",
            confidence_inputs=ConfidenceInputs(
                evidence_strength=85, reproducibility=100 if reproduced else 40,
                differential_quality=70, independent_confirmation=100 if reproduced else 0,
            ),
            parameter=param.name, parameter_location=param.location,
            evidence_snippet=payload,
            manual_review_required=not reproduced,
            catalog=CATALOG,
        )

    def _confirm_attribute(self, request, param, marker, transport):
        payload = f'" data-{marker}="1'
        probe = send_probe(transport, request, param, param.value + payload)
        body = probe.body.decode("utf-8", errors="replace")
        if f"data-{marker}=" not in body:
            return None
        confirm_payload = f"' data-{marker}b='2"
        confirm = send_probe(transport, request, param, param.value + confirm_payload)
        reproduced = f"data-{marker}b=" in confirm.body.decode("utf-8", errors="replace")
        return build_finding(
            check_id="xss.reflected_html_attribute", request=request, response=probe,
            severity="high",
            reason=f"O parâmetro '{param.name}' permitiu encerrar um atributo HTML (aspas duplas ou simples) e injetar um novo atributo ('data-{marker}').",
            confidence_inputs=ConfidenceInputs(
                evidence_strength=80, reproducibility=100 if reproduced else 40,
                differential_quality=70, independent_confirmation=100 if reproduced else 0,
            ),
            parameter=param.name, parameter_location=param.location,
            evidence_snippet=payload,
            manual_review_required=not reproduced,
            catalog=CATALOG,
        )

    def _confirm_script(self, request, param, marker, transport):
        payload = f";window.{marker}=1;"
        probe = send_probe(transport, request, param, param.value + payload)
        body = probe.body.decode("utf-8", errors="replace")
        if payload not in body:
            return None
        confirm_payload = f";window.{marker}b=2;"
        confirm = send_probe(transport, request, param, param.value + confirm_payload)
        reproduced = confirm_payload in confirm.body.decode("utf-8", errors="replace")
        return build_finding(
            check_id="xss.reflected_script_context", request=request, response=probe,
            severity="critical",
            reason=f"O parâmetro '{param.name}' foi refletido dentro de um bloco <script>, permitindo encerrar a string original e injetar uma nova instrução JavaScript ('window.{marker}=1').",
            confidence_inputs=ConfidenceInputs(
                evidence_strength=90, reproducibility=100 if reproduced else 40,
                differential_quality=75, independent_confirmation=100 if reproduced else 0,
            ),
            parameter=param.name, parameter_location=param.location,
            evidence_snippet=payload,
            manual_review_required=not reproduced,
            catalog=CATALOG,
        )
