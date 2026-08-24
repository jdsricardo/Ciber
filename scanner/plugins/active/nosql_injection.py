"""NoSQL Injection (query-string surface): differential detection of MongoDB-operator
injection reachable through bracket-encoded query parameters (`param[$ne]=...`).

Known limitation: real-world NoSQL injection most commonly targets JSON request
bodies (for example a login POST with a JSON payload), which this project cannot
yet actively test -- engine/discovery.py only produces InputPoint.location == "query"
candidates, there is no JSON-body active-testing path in the engine. This detector is
therefore limited to frameworks that also bind query-string arrays/objects into
database filters (classically Express + the `qs` library + MongoDB): an honest but
narrower slice of the vulnerability class than NoSQL injection as a whole.

Methodology per candidate query parameter (bounded, stop-on-evidence):
  1. Build an "operator" probe that REMOVES the plain `name=value` parameter and
     replaces it with `name[$ne]=<bogus>`, where `<bogus>` is a value that never
     matches a real record. A vulnerable backend interprets `$ne` as "not equal to
     bogus", so an exact-match/auth-gate query keeps matching some other record and
     the response keeps looking like the original "found" baseline.
  2. Build a same-shaped control probe using `name[$eq]` with the SAME bogus value.
     `$eq` is a plain equality operator, so this should behave like a normal failed
     lookup -- a "not found" response, structurally different from baseline.
  3. Compare both probes to the baseline with engine.normalization.summarize/compare.
     The vulnerable pattern is the asymmetry: `$ne` looks like baseline ("found"),
     `$eq` looks rejected ("not found") for the exact same bogus value.
  4. Re-send the `$ne` probe once more (idempotent GET, no different from re-running
     any read request) to confirm the "found" response is reproducible and not a
     fluke of a stateful/paginated endpoint.
  5. Only once the operator-bypass pattern is confirmed, additionally try a raw
     array-collision variant (`name=<original>&name[]=<original>`) as a weaker,
     complementary signal. It is reported only as a corroborating,
     always-manual-review finding when it independently shows the same
     "looks like baseline" pattern -- never reported on its own, since many
     frameworks handle repeated/array query parameters with no security
     implication at all.

Never attempts `$where` with JavaScript payloads, `$regex` DoS-shaped payloads, or
record enumeration/dumping -- only the minimum `$ne`/`$eq` comparison needed as
evidence, matching this project's minimum-evidence-necessary rule for active checks.
"""
from __future__ import annotations
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.normalization import ResponseDiff, ResponseSummary, compare, summarize
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding

CATALOG: dict[str, dict[str, str]] = {
    "nosql_injection.operator_bypass_confirmed": {
        "title": "Operador do MongoDB injetável via parâmetro de query",
        "category": "NoSQL Injection",
        "cwe": "CWE-943",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-05",
        "description": (
            "Um parâmetro de query aceitou a sintaxe de operador do MongoDB "
            "(`nome[$ne]=valor`) e o backend passou a interpretar o parâmetro como um "
            "filtro de comparação em vez de um valor literal, alterando a semântica da "
            "consulta original."
        ),
        "developer_impact": (
            "Dependendo de como o resultado é utilizado (por exemplo, em uma verificação "
            "de login ou em um filtro de propriedade de registro), isso pode permitir "
            "contornar autenticação, ler registros pertencentes a outros usuários, ou "
            "obter resultados diferentes dos pretendidos pela consulta original."
        ),
        "remediation": (
            "Nunca vincule diretamente a estrutura bruta da query string (arrays/objetos) "
            "a filtros do banco de dados. Valide e converta explicitamente cada parâmetro "
            "para o tipo primitivo esperado antes de usá-lo em uma consulta, rejeitando "
            "qualquer valor que não seja uma string ou número simples (por exemplo, "
            "recusando arrays e objetos produzidos pelo parser de query string)."
        ),
    },
    "nosql_injection.array_type_confusion_suspected": {
        "title": "Possível confusão de tipo por parâmetro de query em formato de array",
        "category": "NoSQL Injection",
        "cwe": "CWE-943",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-05",
        "description": (
            "Enviar o mesmo parâmetro tanto na forma simples quanto na forma de array "
            "(`nome[]=valor`) produziu uma resposta que se assemelha ao mesmo padrão de "
            "'sucesso' já observado na injeção de operador confirmada para este mesmo "
            "parâmetro, sugerindo que o backend também aceita entrada não-string aqui."
        ),
        "developer_impact": (
            "Isolado, este sinal nem sempre é explorável -- muitos frameworks lidam com "
            "parâmetros repetidos ou em array sem qualquer implicação de segurança -- mas, "
            "correlacionado com a injeção de operador já confirmada no mesmo parâmetro, é "
            "um indício adicional de que a camada de validação de tipos é fraca de forma "
            "mais ampla."
        ),
        "remediation": (
            "Rejeite explicitamente valores de array/objeto para parâmetros que devem ser "
            "um único valor escalar, em vez de confiar no comportamento padrão do parser "
            "de query string."
        ),
    },
}

CANDIDATE_NAME_PATTERN = re.compile(r"user|username|login|email|id|password|token|search|filter|query", re.I)
AUTH_CONTEXT_PATTERN = re.compile(r"login|auth|user|admin", re.I)
BOGUS_VALUE = "zzqxNotARealValue123"
FEW_PARAMS_THRESHOLD = 3
SIMILARITY_HIGH = 0.7
SIMILARITY_LOW = 0.5


def _remove_and_add(url: str, name: str, new_key: str, value: str) -> str:
    """Returns `url` with the plain `name` parameter REMOVED and `new_key=value` added,
    so the operator-encoded form is what actually goes out on the wire in place of the
    original plain parameter, not merely alongside it."""
    parsed = urlparse(url)
    params = [(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True) if key != name]
    params.append((new_key, value))
    return urlunparse(parsed._replace(query=urlencode(params)))


def _add_array_form(url: str, name: str, value: str) -> str:
    """Returns `url` with the original `name=value` kept AND a second `name[]=value`
    parameter added, to probe array/type-confusion handling of the same parameter."""
    parsed = urlparse(url)
    params = list(parse_qsl(parsed.query, keep_blank_values=True))
    params.append((f"{name}[]", value))
    return urlunparse(parsed._replace(query=urlencode(params)))


def _looks_like_baseline(diff: ResponseDiff) -> bool:
    return not diff.status_changed and diff.similarity >= SIMILARITY_HIGH


def _looks_rejected(diff: ResponseDiff, response: HttpResponse) -> bool:
    return diff.status_changed or diff.similarity < SIMILARITY_LOW or response.status in (401, 403, 404)


def _auth_context(url: str, name: str) -> bool:
    return bool(AUTH_CONTEXT_PATTERN.search(url) or AUTH_CONTEXT_PATTERN.search(name))


class NoSqlInjectionPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="NoSQL Injection",
        category="NoSQL Injection",
        cwe="CWE-943",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-05",
        kind="safe_active",
        risk="low",
        checks=(
            "nosql_injection.operator_bypass_confirmed",
            "nosql_injection.array_type_confusion_suspected",
        ),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        query_points = [point for point in request.inputs if point.location == "query"]
        if not query_points:
            return []
        if len(query_points) <= FEW_PARAMS_THRESHOLD:
            candidates = query_points
        else:
            candidates = [point for point in query_points if CANDIDATE_NAME_PATTERN.search(point.name)]

        baseline = responses[0]
        baseline_summary = summarize(baseline)

        findings: list[Finding] = []
        for point in candidates:
            findings.extend(self._test_parameter(request, point, baseline_summary, transport))
        return findings

    def _send(self, template: HttpRequest, transport: HttpTransport, url: str) -> tuple[HttpRequest, HttpResponse]:
        probe_request = HttpRequest(method=template.method, url=url, headers=dict(template.headers))
        return probe_request, transport.send(probe_request)

    def _test_parameter(self, request: HttpRequest, point, baseline_summary: ResponseSummary, transport: HttpTransport) -> list[Finding]:
        ne_key = f"{point.name}[$ne]"
        eq_key = f"{point.name}[$eq]"
        ne_url = _remove_and_add(request.url, point.name, ne_key, BOGUS_VALUE)
        eq_url = _remove_and_add(request.url, point.name, eq_key, BOGUS_VALUE)

        ne_request, ne_response = self._send(request, transport, ne_url)
        eq_request, eq_response = self._send(request, transport, eq_url)

        ne_diff = compare(baseline_summary, summarize(ne_response))
        eq_diff = compare(baseline_summary, summarize(eq_response))

        if not (_looks_like_baseline(ne_diff) and _looks_rejected(eq_diff, eq_response)):
            return []

        # Confirmation: re-send the same $ne probe once more (idempotent, read-only)
        # to rule out a stateful/paginated fluke driving the "looks like baseline" match.
        _, confirm_response = self._send(request, transport, ne_url)
        confirm_diff = compare(baseline_summary, summarize(confirm_response))
        confirmed = _looks_like_baseline(confirm_diff) and confirm_response.status == ne_response.status

        critical_context = _auth_context(request.url, point.name)
        severity = "critical" if (critical_context and confirmed) else "high"

        reason = (
            f"O parâmetro '{ne_key}' com o valor inexistente '{BOGUS_VALUE}' retornou uma resposta com "
            f"formato de sucesso (status {ne_response.status}, similaridade {ne_diff.similarity} em relação "
            f"à linha de base), enquanto '{eq_key}' com o MESMO valor inexistente retornou uma resposta de "
            f"'não encontrado' (status {eq_response.status}, similaridade {eq_diff.similarity} em relação à "
            "linha de base). Essa assimetria indica que o operador MongoDB $ne foi interpretado pelo backend "
            "como um filtro de comparação, contornando a busca por igualdade original, enquanto $eq (uma "
            "comparação de igualdade normal) corretamente não encontrou nenhum registro. "
            + (
                "Repetir o probe $ne reproduziu o mesmo padrão de sucesso."
                if confirmed else
                "Repetir o probe $ne NÃO reproduziu o mesmo padrão, portanto recomenda-se confirmação manual."
            )
        )

        confidence_inputs = ConfidenceInputs(
            evidence_strength=90,
            reproducibility=100 if confirmed else 50,
            differential_quality=90,
            independent_confirmation=100 if confirmed else 30,
            ambiguity=0 if confirmed else 20,
        )

        findings = [build_finding(
            check_id="nosql_injection.operator_bypass_confirmed",
            request=ne_request,
            response=ne_response,
            severity=severity,
            reason=reason,
            confidence_inputs=confidence_inputs,
            parameter=point.name,
            parameter_location=point.location,
            manual_review_required=not confirmed,
            differences={
                "ne_status": ne_response.status, "eq_status": eq_response.status,
                "ne_similarity": ne_diff.similarity, "eq_similarity": eq_diff.similarity,
                "confirmed": confirmed,
            },
            catalog=CATALOG,
        )]

        array_finding = self._test_array_collision(request, point, baseline_summary, transport)
        if array_finding is not None:
            findings.append(array_finding)
        return findings

    def _test_array_collision(self, request: HttpRequest, point, baseline_summary: ResponseSummary, transport: HttpTransport) -> Finding | None:
        # Weaker, complementary signal (methodology step 3): only ever reported when it
        # correlates with the operator-bypass evidence already confirmed above, never on
        # its own -- many frameworks handle repeated/array query params with no security
        # implication whatsoever.
        array_url = _add_array_form(request.url, point.name, point.value)
        array_request, array_response = self._send(request, transport, array_url)
        array_diff = compare(baseline_summary, summarize(array_response))
        if not _looks_like_baseline(array_diff):
            return None

        reason = (
            f"Enviar '{point.name}' tanto na forma simples quanto como array "
            f"('{point.name}[]={point.value}') produziu uma resposta (status {array_response.status}, "
            f"similaridade {array_diff.similarity} em relação à linha de base) com o mesmo formato de "
            "'sucesso' já observado na injeção de operador confirmada para este mesmo parâmetro. Isolado, "
            "este sinal é fraco (muitos frameworks lidam normalmente com parâmetros repetidos/array), mas "
            "correlacionado com a injeção de operador acima sugere uma camada de validação de tipos fraca "
            "de forma mais ampla."
        )
        confidence_inputs = ConfidenceInputs(
            evidence_strength=40, reproducibility=60, differential_quality=40,
            independent_confirmation=0, ambiguity=30,
        )
        return build_finding(
            check_id="nosql_injection.array_type_confusion_suspected",
            request=array_request,
            response=array_response,
            severity="medium",
            reason=reason,
            confidence_inputs=confidence_inputs,
            parameter=point.name,
            parameter_location=point.location,
            manual_review_required=True,
            differences={"array_similarity": array_diff.similarity, "array_status": array_response.status},
            catalog=CATALOG,
        )
