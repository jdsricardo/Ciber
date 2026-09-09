"""SSRF (Server-Side Request Forgery) candidate detection.

Full SSRF confirmation per the project's methodology requires a callback/canary server
the test environment controls, so the target's outbound interaction with it can be
observed directly. This increment does not have such a callback service wired up, so
every finding here is evidence of a *likely* server-side fetch (timing or error-message
differential), never a directly confirmed out-of-band interaction — every finding is
therefore `manual_review_required=True` by design, per the project's rule: when a test
cannot be confirmed safely and generically, report the indicator and ask for a human
look rather than inventing automated certainty.

We never target real private-network or cloud-metadata addresses ourselves — the whole
point is that WE never make that request; we ask the target's own server, via the
tested parameter, to attempt one, and infer the outcome only from its own response.
"""
from __future__ import annotations
import re
import statistics
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, send_probe, testable_inputs

CATALOG = {
    "ssrf.error_signature_suspected": {
        "title": "Possível SSRF: mensagem de erro sugere requisição de rede feita pelo servidor",
        "category": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-19",
        "description": "Um parâmetro que aceita uma URL produziu uma mensagem de erro específica de rede/HTTP ao receber um host inexistente, sugerindo que o servidor tentou buscar a URL diretamente.",
        "developer_impact": "Se confirmado, um atacante pode induzir o servidor a fazer requisições para endereços internos da rede (RFC1918), serviços de metadados de nuvem, ou outros sistemas não expostos publicamente, contornando controles de firewall perimetral.",
        "remediation": "Valide URLs fornecidas pelo usuário contra uma lista de permissões de hosts/esquemas explícitos antes de buscá-las. Bloqueie resolução para endereços privados, loopback e de metadados de nuvem no momento da requisição (não apenas por nome de host).",
    },
    "ssrf.timing_signature_suspected": {
        "title": "Possível SSRF: atraso de resposta sugere tentativa de conexão de rede pelo servidor",
        "category": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-19",
        "description": "Um parâmetro que aceita uma URL apontando para um endereço não roteável (documentação/reservado) produziu um tempo de resposta consistentemente maior que a baseline, reproduzido em uma segunda medição, compatível com uma tentativa real de conexão de rede que expirou por timeout.",
        "developer_impact": "Se confirmado, o servidor realiza requisições de rede server-side a partir de entrada do usuário, o que pode ser abusado para atingir redes internas ou serviços não expostos publicamente.",
        "remediation": "Valide URLs fornecidas pelo usuário contra uma lista de permissões de hosts/esquemas explícitos antes de buscá-las. Utilize um proxy de saída com bloqueio de rede interna para qualquer busca de URL controlada pelo usuário.",
    },
}

URL_LIKE_NAME = re.compile(r"url|uri|link|callback|webhook|image|img|avatar|fetch|src|feed|proxy|target|endpoint", re.I)
URL_LIKE_VALUE = re.compile(r"^https?://", re.I)

CANARY_HOST = "sentinelscope-ssrf-canary.invalid"
# RFC 5737 TEST-NET-1: reserved for documentation, guaranteed to never route to a live
# host, so a connection attempt to it can only ever time out — never succeed or leak data.
UNROUTABLE_HOST = "192.0.2.1"

NETWORK_ERROR_PATTERNS = re.compile(
    r"could not resolve host|name or service not known|getaddrinfo failed|"
    r"connection refused|connection timed out|no route to host|"
    r"curl error|failed to connect|network is unreachable",
    re.I,
)

TIME_DELAY_THRESHOLD_MS = 2500

class SsrfPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="SSRF Candidate Detection",
        category="Server-Side Request Forgery (SSRF)",
        cwe="CWE-918",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-19",
        kind="safe_active",
        risk="low",
        checks=("ssrf.error_signature_suspected", "ssrf.timing_signature_suspected"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        findings: list[Finding] = []
        baseline = responses[0]
        candidates = [
            p for p in testable_inputs(request)
            if URL_LIKE_NAME.search(p.name) or URL_LIKE_VALUE.match(p.value)
        ]
        for param in candidates:
            finding = self._test_parameter(request, baseline, param, transport)
            if finding:
                findings.append(finding)
        return findings

    def _test_parameter(self, request, baseline, param, transport):
        finding = self._error_signature(request, baseline, param, transport)
        if finding:
            return finding
        return self._timing_signature(request, baseline, param, transport)

    def _error_signature(self, request, baseline, param, transport):
        probe_value = f"http://{CANARY_HOST}/sentinelscope-probe"
        probe = send_probe(transport, request, param, probe_value)
        probe_text = probe.body.decode("utf-8", errors="replace")
        baseline_text = baseline.body.decode("utf-8", errors="replace")

        match = NETWORK_ERROR_PATTERNS.search(probe_text)
        if not match or NETWORK_ERROR_PATTERNS.search(baseline_text):
            return None
        # Negative control: a value that is invalid but NOT URL-shaped at all should not
        # produce the same network-specific error if the app is genuinely attempting a
        # fetch of URL-shaped input specifically (rules out a generic "invalid input"
        # error page that happens to mention network-sounding words).
        control = send_probe(transport, request, param, "zzqxNotAUrlAtAll")
        control_text = control.body.decode("utf-8", errors="replace")
        if NETWORK_ERROR_PATTERNS.search(control_text):
            return None

        return build_finding(
            check_id="ssrf.error_signature_suspected", request=request, response=probe,
            severity="high",
            reason=f"O parâmetro '{param.name}' com um host inexistente ({CANARY_HOST}) produziu a mensagem de erro de rede '{match.group(0)}', ausente tanto na baseline quanto no controle com um valor não formatado como URL.",
            confidence_inputs=ConfidenceInputs(
                evidence_strength=65, reproducibility=70, differential_quality=60,
                independent_confirmation=0, ambiguity=20,
            ),
            parameter=param.name, parameter_location=param.location,
            evidence_snippet=match.group(0),
            manual_review_required=True,
            catalog=CATALOG,
        )

    def _timing_signature(self, request, baseline, param, transport):
        baseline_typical_ms = statistics.median([baseline.elapsed_ms, baseline.elapsed_ms])
        threshold_ms = baseline_typical_ms + TIME_DELAY_THRESHOLD_MS

        probe_value = f"http://{UNROUTABLE_HOST}/sentinelscope-probe"
        probe = send_probe(transport, request, param, probe_value)
        if probe.elapsed_ms < threshold_ms:
            return None

        confirm = send_probe(transport, request, param, probe_value)
        control = send_probe(transport, request, param, "zzqxNotAUrlAtAll")
        confirmed = confirm.elapsed_ms >= threshold_ms
        control_clean = control.elapsed_ms < threshold_ms
        if not control_clean:
            # The endpoint is generally slow for any unusual input, not specifically
            # because it attempted to connect to an unroutable address.
            return None

        return build_finding(
            check_id="ssrf.timing_signature_suspected", request=request, response=probe,
            severity="high",
            reason=(
                f"O parâmetro '{param.name}' apontando para um endereço não roteável ({UNROUTABLE_HOST}) "
                f"levou {probe.elapsed_ms}ms (baseline {baseline_typical_ms:.0f}ms). Repetição "
                f"{'confirmou' if confirmed else 'não confirmou'} o atraso; o controle com um valor não "
                f"formatado como URL levou {control.elapsed_ms}ms."
            ),
            confidence_inputs=ConfidenceInputs(
                evidence_strength=60, reproducibility=100 if confirmed else 40,
                differential_quality=65, independent_confirmation=100 if confirmed else 0,
                ambiguity=15,
            ),
            parameter=param.name, parameter_location=param.location,
            evidence_snippet=f"elapsed_ms={probe.elapsed_ms}",
            manual_review_required=True,
            catalog=CATALOG,
        )
