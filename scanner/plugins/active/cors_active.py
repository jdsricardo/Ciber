"""Active CORS testing: sends crafted Origin headers and checks how the server reflects
them, complementing plugins.cors.CorsPassivePlugin (which only reads the baseline,
no-Origin response). This is what actually confirms whether an attacker-controlled
origin is trusted, rather than just observing a bare wildcard.
"""
from __future__ import annotations
from urllib.parse import urlparse
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding

CATALOG = {
    "cors.origin_reflected": {
        "title": "CORS reflete dinamicamente qualquer origem enviada",
        "category": "Configuração Incorreta de CORS",
        "cwe": "CWE-942",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CLNT-07",
        "description": "O servidor respondeu com Access-Control-Allow-Origin igual, byte a byte, a um valor de Origin arbitrário e não confiável enviado pelo scanner.",
        "developer_impact": "Qualquer site pode ler respostas desta origem via JavaScript no navegador da vítima. Se combinado com Access-Control-Allow-Credentials, dados autenticados de qualquer usuário podem ser lidos por um site malicioso.",
        "remediation": "Nunca reflita o cabeçalho Origin diretamente. Valide contra uma lista de permissões de origens confiáveis e retorne apenas essas.",
    },
    "cors.credentials_with_reflected_origin": {
        "title": "CORS reflete a origem e permite credenciais simultaneamente",
        "category": "Configuração Incorreta de CORS",
        "cwe": "CWE-942",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CLNT-07",
        "description": "A resposta combina a reflexão de uma origem arbitrária com Access-Control-Allow-Credentials: true.",
        "developer_impact": "Qualquer site pode fazer requisições autenticadas (com cookies de sessão) a esta API e ler a resposta, permitindo roubo completo de dados de sessão de qualquer usuário que visite um site malicioso.",
        "remediation": "Nunca combine credenciais com uma origem refletida dinamicamente. Utilize uma lista de permissões estrita de origens confiáveis.",
    },
    "cors.null_origin_allowed": {
        "title": "CORS aceita a origem 'null'",
        "category": "Configuração Incorreta de CORS",
        "cwe": "CWE-942",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CLNT-07",
        "description": "O servidor respondeu com Access-Control-Allow-Origin: null para uma requisição com Origin: null.",
        "developer_impact": "A origem 'null' pode ser forjada por um atacante através de iframes em sandbox, documentos servidos via data:, ou arquivos locais, permitindo contornar a intenção da política de CORS.",
        "remediation": "Nunca inclua 'null' em uma lista de permissões de CORS. Trate-a como qualquer outra origem não confiável.",
    },
    "cors.lookalike_origin_accepted": {
        "title": "CORS aceita uma origem parecida, mas diferente, da origem legítima",
        "category": "Configuração Incorreta de CORS",
        "cwe": "CWE-942",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CLNT-07",
        "description": "O servidor aceitou uma origem que apenas contém ou se assemelha ao domínio legítimo (ex.: um subdomínio ou domínio com prefixo/sufixo diferente), sugerindo validação por substring em vez de comparação exata.",
        "developer_impact": "Um atacante que registre um domínio com nome semelhante (ex.: 'exemplo.com.atacante.com') pode ser tratado como uma origem confiável, permitindo leitura cross-origin de dados autenticados.",
        "remediation": "Compare a origem recebida por igualdade exata contra uma lista de permissões, nunca por substring, prefixo, sufixo ou expressão regular frouxa.",
    },
}

CANARY_ORIGIN = "https://sentinelscope-cors-canary.invalid"

class CorsActivePlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="CORS Active Testing",
        category="Configuração Incorreta de CORS",
        cwe="CWE-942",
        owasp="A01:2025 Broken Access Control",
        wstg="WSTG-CLNT-07",
        kind="safe_active",
        risk="low",
        checks=(
            "cors.origin_reflected", "cors.credentials_with_reflected_origin",
            "cors.null_origin_allowed", "cors.lookalike_origin_accepted",
        ),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        findings: list[Finding] = []

        reflected = self._probe(request, transport, CANARY_ORIGIN)
        if reflected is not None:
            findings.append(reflected)

        null_finding = self._probe_null(request, transport)
        if null_finding is not None:
            findings.append(null_finding)

        host = urlparse(request.url).hostname or ""
        if host:
            lookalike = f"https://{host}.sentinelscope-cors-canary.invalid"
            lookalike_finding = self._probe(request, transport, lookalike, check_id="cors.lookalike_origin_accepted", severity="high")
            if lookalike_finding is not None:
                findings.append(lookalike_finding)

        return findings

    def _get_with_origin(self, transport: HttpTransport, url: str, origin: str) -> HttpResponse:
        return transport.send(HttpRequest(method="GET", url=url, headers={"Accept": "*/*", "Origin": origin}))

    def _probe(self, request, transport, origin, check_id="cors.origin_reflected", severity="high"):
        probe = self._get_with_origin(transport, request.url, origin)
        acao = probe.headers.get("access-control-allow-origin", "").strip()
        if acao != origin:
            return None

        confirm = self._get_with_origin(transport, request.url, origin)
        reproduced = confirm.headers.get("access-control-allow-origin", "").strip() == origin
        acac = probe.headers.get("access-control-allow-credentials", "").strip().lower() == "true"

        if acac and check_id == "cors.origin_reflected":
            return build_finding(
                check_id="cors.credentials_with_reflected_origin", request=request, response=probe,
                severity="critical",
                reason=f"Access-Control-Allow-Origin refletiu exatamente '{origin}' e Access-Control-Allow-Credentials: true foi enviado simultaneamente.",
                confidence_inputs=ConfidenceInputs(
                    evidence_strength=95, reproducibility=100 if reproduced else 40,
                    differential_quality=80, independent_confirmation=100 if reproduced else 0,
                ),
                evidence_snippet=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true",
                manual_review_required=not reproduced,
                catalog=CATALOG,
            )

        return build_finding(
            check_id=check_id, request=request, response=probe,
            severity=severity,
            reason=f"Access-Control-Allow-Origin refletiu exatamente a origem enviada pelo scanner ('{origin}'), que não é uma origem confiável conhecida.",
            confidence_inputs=ConfidenceInputs(
                evidence_strength=90, reproducibility=100 if reproduced else 40,
                differential_quality=75, independent_confirmation=100 if reproduced else 0,
            ),
            evidence_snippet=f"Access-Control-Allow-Origin: {acao}",
            manual_review_required=not reproduced,
            catalog=CATALOG,
        )

    def _probe_null(self, request, transport):
        probe = self._get_with_origin(transport, request.url, "null")
        acao = probe.headers.get("access-control-allow-origin", "").strip()
        if acao.lower() != "null":
            return None
        confirm = self._get_with_origin(transport, request.url, "null")
        reproduced = confirm.headers.get("access-control-allow-origin", "").strip().lower() == "null"
        return build_finding(
            check_id="cors.null_origin_allowed", request=request, response=probe,
            severity="medium",
            reason="Access-Control-Allow-Origin: null foi retornado para uma requisição com Origin: null.",
            confidence_inputs=ConfidenceInputs(
                evidence_strength=90, reproducibility=100 if reproduced else 40,
                differential_quality=70, independent_confirmation=100 if reproduced else 0,
            ),
            evidence_snippet=f"Access-Control-Allow-Origin: {acao}",
            manual_review_required=not reproduced,
            catalog=CATALOG,
        )
