"""HTTP Verb / Method Tampering: authorization bypass through method switching.

This is NOT "does the server support method X" (that alone is not a vulnerability —
a clean 405 Method Not Allowed for PUT is the correct, secure behavior). The signal
this plugin looks for is a state-changing or normally-restricted method being
*processed as if it were a legitimate request*, which typically means a proxy, WAF,
or auth filter that special-cases `method == 'GET'` and lets everything else slip
through underneath to the real application logic.

Methodology (bounded, and deliberately conservative about which verbs get sent):

  1. `responses[0]` is already the GET baseline for the target URL; no extra
     request is needed for it.
  2. Send a single OPTIONS request to the same URL and read the `Allow` header, if
     present, to decide which verbs are worth trying. When `Allow` explicitly lists
     verbs beyond the safe trio (GET, HEAD, OPTIONS), only those declared verbs are
     probed. When `Allow` is absent, or only lists the safe trio (i.e. unhelpful for
     narrowing), fall back to trying the full candidate set: POST, PUT, DELETE,
     PATCH. TRACE is always probed once on its own, independent of `Allow`, since
     many servers implement TRACE at a layer that never advertises it per-route.
  3. For POST, a different status code is expected and not interesting by itself.
     What is interesting is a 2xx response whose body closely resembles the
     authenticated/successful GET baseline (via `engine.normalization.summarize`/
     `compare`), suggesting the write path is not actually gated the way GET is.
     One repeat POST is sent to confirm reproducibility before treating it as
     higher-confidence evidence.
  4. DELETE, PUT, PATCH and TRACE are each sent AT MOST ONCE, ever, for the entire
     scan, and are never repeated for "confirmation" the way other probes in this
     project are — repeating a possibly state-changing request is not safe even
     when the method is nominally idempotent, and this project's architecture
     cannot verify from a single scan pass whether a real state change occurred.
     Any non-rejecting response is therefore treated as sufficient standalone
     evidence: 2xx/3xx for DELETE/PUT/PATCH, or 2xx/header-reflection for TRACE.
     Every finding produced this way sets `manual_review_required=True` and its
     `reason` explicitly states that no confirmation request was sent, for safety.
  5. TRACE responses are additionally inspected for reflection of a unique marker
     header sent with the probe (classic Cross-Site Tracing / XST signal),
     independent of status code.
  6. If `Allow` advertises risky verbs but active probing rejected all of them
     cleanly, that is reported as a low-severity, informational note about
     unnecessary attack surface — not a confirmed bypass.

Never targets any URL other than the one already provided by the engine; never
guesses or enumerates resources.
"""
from __future__ import annotations
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.normalization import compare, summarize
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, consistent

CATALOG: dict[str, dict[str, str]] = {
    "http_verb_tampering.destructive_method_accepted": {
        "title": "Método HTTP potencialmente destrutivo foi aceito sem rejeição",
        "category": "HTTP Verb Tampering",
        "cwe": "CWE-650",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CONF-06",
        "description": "Um método HTTP normalmente restrito e potencialmente destrutivo (DELETE, PUT ou PATCH) foi enviado ao endpoint e a resposta não apresentou nenhum sinal de rejeição, sugerindo que um filtro de autenticação ou autorização verifica apenas o método GET e deixa os demais métodos passarem direto para a lógica de negócio.",
        "developer_impact": "Um atacante pode conseguir criar, alterar ou remover dados sem autenticação ou autorização adequadas, contornando controles de acesso que dependem apenas do verbo HTTP esperado em vez de uma verificação centralizada e independente do método.",
        "remediation": "Aplique a mesma verificação de autenticação e autorização a todos os métodos HTTP no mesmo endpoint, e rejeite explicitamente (405 Method Not Allowed) qualquer método não suportado antes de a requisição alcançar a lógica de negócio.",
    },
    "http_verb_tampering.method_bypass_suspected": {
        "title": "Troca de verbo HTTP pode contornar o controle de acesso",
        "category": "HTTP Verb Tampering",
        "cwe": "CWE-650",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CONF-06",
        "description": "Um método HTTP diferente do esperado (por exemplo, POST em vez de GET) produziu uma resposta que se assemelha ao acesso legítimo, ou o cabeçalho Allow anunciou suporte a métodos além do necessário, ampliando a superfície de ataque disponível.",
        "developer_impact": "Se a camada de autenticação, WAF ou proxy reverso verificar apenas um método específico (geralmente GET), trocar o verbo da requisição pode permitir que a mesma operação sensível seja executada sem os controles de acesso esperados.",
        "remediation": "Centralize a verificação de autenticação e autorização de forma independente do método HTTP, e restrinja explicitamente cada rota apenas aos métodos que ela realmente precisa suportar.",
    },
    "http_verb_tampering.trace_enabled": {
        "title": "Método TRACE está habilitado",
        "category": "HTTP Verb Tampering",
        "cwe": "CWE-650",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CONF-06",
        "description": "O servidor respondeu a uma requisição TRACE sem rejeitá-la, em alguns casos refletindo de volta, no corpo da resposta, cabeçalhos enviados na requisição (Cross-Site Tracing).",
        "developer_impact": "TRACE habilitado, combinado com outra vulnerabilidade do lado do navegador, pode em cenários legados permitir a leitura de cabeçalhos HTTP normalmente inacessíveis a scripts, como cookies HttpOnly.",
        "remediation": "Desabilite o método TRACE (e TRACK) no servidor web ou proxy reverso, permitindo apenas os métodos estritamente necessários para cada rota.",
    },
}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
STANDARD_CANDIDATES = ("POST", "PUT", "DELETE", "PATCH")
TRACE_MARKER = "SentinelScope-Trace-Probe-7f3c1a9d"
SIMILARITY_THRESHOLD = 0.6


def _parse_allow(response: HttpResponse) -> set[str] | None:
    raw = response.headers.get("allow")
    if not raw:
        return None
    methods = {token.strip().upper() for token in raw.split(",") if token.strip()}
    return methods or None


def _decode(response: HttpResponse) -> str:
    return response.body.decode("utf-8", errors="replace")


def _send(transport: HttpTransport, method: str, url: str, headers: dict[str, str]) -> tuple[HttpRequest, HttpResponse]:
    probe_request = HttpRequest(method=method, url=url, headers=dict(headers))
    return probe_request, transport.send(probe_request)


class HttpVerbTamperingPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="HTTP Verb Tampering",
        category="HTTP Verb Tampering",
        cwe="CWE-650",
        owasp="A01:2025 Broken Access Control",
        wstg="WSTG-CONF-06",
        kind="safe_active",
        # Elevated to "medium": probing DELETE/PUT/PATCH is restricted to one
        # attempt each and is never retried, but sending a state-changing verb to
        # a genuinely vulnerable, unauthenticated endpoint still carries inherent
        # residual risk that passive/GET-only checks do not.
        risk="medium",
        checks=(
            "http_verb_tampering.destructive_method_accepted",
            "http_verb_tampering.method_bypass_suspected",
            "http_verb_tampering.trace_enabled",
        ),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        baseline = responses[0]
        baseline_summary = summarize(baseline)
        findings: list[Finding] = []
        stronger_signal_found = False

        options_request, options_response = _send(transport, "OPTIONS", request.url, request.headers)
        allow_methods = _parse_allow(options_response)
        risky_declared = (allow_methods - SAFE_METHODS) if allow_methods else set()

        if allow_methods and risky_declared:
            candidates = [method for method in STANDARD_CANDIDATES if method in risky_declared]
        else:
            candidates = list(STANDARD_CANDIDATES)

        for method in candidates:
            if method == "POST":
                finding = self._test_post(request, baseline, baseline_summary, transport)
            else:
                finding = self._test_destructive(method, request, transport)
            if finding is not None:
                findings.append(finding)
                stronger_signal_found = True

        trace_finding = self._test_trace(request, transport)
        if trace_finding is not None:
            findings.append(trace_finding)

        if allow_methods and risky_declared and not stronger_signal_found:
            findings.append(self._allow_header_finding(options_request, options_response, risky_declared))

        return findings

    def _test_post(self, request: HttpRequest, baseline: HttpResponse, baseline_summary, transport: HttpTransport) -> Finding | None:
        probe_request, probe_response = _send(transport, "POST", request.url, request.headers)

        def looks_like_bypass(response: HttpResponse) -> bool:
            if not (200 <= response.status < 300):
                return False
            return compare(baseline_summary, summarize(response)).similarity >= SIMILARITY_THRESHOLD

        if not looks_like_bypass(probe_response):
            return None

        # POST is not in the single-attempt-only group: one repeat is safe and
        # used purely to confirm reproducibility, same as other detectors.
        repeat_request, repeat_response = _send(transport, "POST", request.url, request.headers)
        _, reproducibility = consistent([probe_response, repeat_response], looks_like_bypass)
        reproduced = reproducibility == 100
        diff = compare(baseline_summary, summarize(probe_response))

        reason = (
            f"O método POST foi enviado para a mesma URL da linha de base GET (que respondeu {baseline.status}, "
            f"{len(baseline.body)} bytes) e recebeu status {probe_response.status} com um corpo estruturalmente "
            f"semelhante ao da resposta GET (similaridade {diff.similarity:.2f} em uma escala de 0 a 1), como se a "
            "requisição de escrita tivesse sido processada da mesma forma que uma leitura autorizada. Uma segunda "
            "tentativa de POST foi enviada apenas para confirmar reprodutibilidade "
            + ("e reproduziu o mesmo comportamento." if reproduced
               else "e NÃO reproduziu exatamente o mesmo comportamento, portanto recomenda-se revisão manual.")
        )
        confidence_inputs = ConfidenceInputs(
            evidence_strength=75,
            reproducibility=reproducibility,
            differential_quality=70,
            independent_confirmation=100 if reproduced else 30,
            ambiguity=0 if reproduced else 20,
        )
        return build_finding(
            check_id="http_verb_tampering.method_bypass_suspected",
            request=probe_request,
            response=probe_response,
            severity="high",
            reason=reason,
            confidence_inputs=confidence_inputs,
            manual_review_required=not reproduced,
            evidence_snippet=_decode(probe_response)[:200],
            differences={
                "method": "POST", "baseline_status": baseline.status, "probe_status": probe_response.status,
                "similarity": diff.similarity, "reproduced": reproduced,
            },
            catalog=CATALOG,
        )

    def _test_destructive(self, method: str, request: HttpRequest, transport: HttpTransport) -> Finding | None:
        # PUT, DELETE, PATCH: exactly one attempt, ever, for the whole scan. No
        # confirmation request is sent, deliberately, because repeating a
        # possibly state-changing request is not safe even if the method is
        # nominally idempotent.
        probe_request, probe_response = _send(transport, method, request.url, request.headers)
        if not (200 <= probe_response.status < 400):
            return None

        reason = (
            f"O método {method} foi enviado uma única vez para a URL alvo e recebeu status {probe_response.status} "
            f"({len(probe_response.body)} bytes de corpo), sem nenhum sinal de rejeição (esperava-se 401, 403, 404 "
            "ou 405 para um método potencialmente destrutivo em um endpoint sem indicação de autorização explícita "
            "para esse verbo). Por segurança, NENHUMA requisição de confirmação foi enviada para este método: "
            "repetir um DELETE/PUT/PATCH não é seguro mesmo quando o método é nominalmente idempotente, portanto "
            "esta constatação baseia-se em uma única observação e exige revisão manual antes de qualquer ação."
        )
        confidence_inputs = ConfidenceInputs(
            evidence_strength=75,
            reproducibility=50,
            independent_confirmation=0,
            ambiguity=10,
        )
        return build_finding(
            check_id="http_verb_tampering.destructive_method_accepted",
            request=probe_request,
            response=probe_response,
            severity="critical",
            reason=reason,
            confidence_inputs=confidence_inputs,
            manual_review_required=True,
            evidence_snippet=_decode(probe_response)[:200],
            differences={"method": method, "probe_status": probe_response.status, "confirmation_sent": False},
            catalog=CATALOG,
        )

    def _test_trace(self, request: HttpRequest, transport: HttpTransport) -> Finding | None:
        # TRACE: exactly one attempt, ever, for the whole scan, same safety
        # rationale as the destructive methods above.
        headers = dict(request.headers)
        headers["X-Sentinelscope-Trace-Probe"] = TRACE_MARKER
        probe_request, probe_response = _send(transport, "TRACE", request.url, headers)
        body_text = _decode(probe_response)
        reflected = TRACE_MARKER in body_text
        accepted = 200 <= probe_response.status < 300
        if not (reflected or accepted):
            return None

        if reflected:
            index = body_text.find(TRACE_MARKER)
            snippet = body_text[max(0, index - 30): index + len(TRACE_MARKER) + 30]
            reflection_note = (
                "O cabeçalho de marcação exclusivo enviado nesta sondagem foi refletido de volta no corpo da "
                f"resposta ('...{snippet}...'), caracterizando Cross-Site Tracing (XST)."
            )
        else:
            snippet = body_text[:200]
            reflection_note = (
                "O cabeçalho de marcação não foi encontrado refletido no corpo, mas o método TRACE foi aceito "
                f"com status de sucesso ({probe_response.status}) em vez de ser rejeitado."
            )

        reason = (
            f"O método TRACE foi enviado uma única vez para a URL alvo e recebeu status {probe_response.status}. "
            f"{reflection_note} Por segurança, NENHUMA requisição de confirmação foi enviada para TRACE: repetir "
            "esta sondagem não traria garantia adicional que justifique o risco, portanto esta constatação "
            "baseia-se em uma única observação e exige revisão manual."
        )
        confidence_inputs = ConfidenceInputs(
            evidence_strength=85 if reflected else 55,
            reproducibility=50,
            independent_confirmation=0,
            ambiguity=5 if reflected else 25,
        )
        return build_finding(
            check_id="http_verb_tampering.trace_enabled",
            request=probe_request,
            response=probe_response,
            severity="medium",
            reason=reason,
            confidence_inputs=confidence_inputs,
            manual_review_required=True,
            evidence_snippet=snippet,
            differences={
                "method": "TRACE", "probe_status": probe_response.status,
                "header_reflected": reflected, "confirmation_sent": False,
            },
            catalog=CATALOG,
        )

    def _allow_header_finding(self, options_request: HttpRequest, options_response: HttpResponse, risky_declared: set[str]) -> Finding:
        methods_text = ", ".join(sorted(risky_declared))
        reason = (
            f"A resposta a uma requisição OPTIONS anunciou, no cabeçalho Allow, suporte aos métodos {methods_text} "
            "além do trio seguro GET/HEAD/OPTIONS, mas a sondagem ativa de cada um desses métodos não obteve "
            "nenhuma resposta que indicasse aceitação indevida (todos foram corretamente rejeitados). Isto é "
            "reportado apenas como exposição informativa de superfície de ataque, sem qualquer bypass confirmado."
        )
        confidence_inputs = ConfidenceInputs(
            evidence_strength=50,
            reproducibility=60,
            independent_confirmation=0,
            ambiguity=20,
        )
        return build_finding(
            check_id="http_verb_tampering.method_bypass_suspected",
            request=options_request,
            response=options_response,
            severity="low",
            reason=reason,
            confidence_inputs=confidence_inputs,
            informational=True,
            evidence_snippet=f"Allow: {options_response.headers.get('allow', '')}",
            differences={"allow_header": options_response.headers.get("allow", ""), "risky_methods": sorted(risky_declared)},
            catalog=CATALOG,
        )
