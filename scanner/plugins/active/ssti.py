"""Active detector: Server-Side Template Injection (SSTI).

Methodology (mathematical proof only -- never escalates to file/variable/RCE access):

1. Candidate parameters come only from `request.inputs` with `location == "query"`
   (no POST/form engine exists yet). Parameters whose baseline value is a bare
   numeric id (e.g. `id=42`, `page=3`) are skipped, since template injection is
   about text rendered into a template body, not numeric identifiers -- but any
   parameter we are not confident about is still tried.
2. For each candidate parameter, five arithmetic probes are tried in order, each
   using a DIFFERENT engine syntax so a hit also hints at the engine family:
   `{{7*7}}` (Jinja2/Twig-like), `${7*7}` (EL/Freemarker/Velocity-like),
   `#{7*7}` (Ruby/OGNL/EL-like), `<%= 7*7 %>` (ERB/JSP-like), `*{7*7}`
   (Thymeleaf-like). We stop at the first syntax that evaluates.
3. False-positive guard: a hit only counts when the EVALUATED numeral (`49`)
   appears in the response AND the raw payload markup (`{{7*7}}`, etc.) does
   NOT survive verbatim, and the numeral is absent from the untouched baseline
   responses. If the raw markup is still literally present, the payload was
   echoed, not executed -- that is reflection/XSS, not SSTI, and out of scope
   for this detector.
4. Independent confirmation: once one syntax evaluates, a second, different
   expression in the SAME syntax family (`{{8*8}}` -> `64`) must also evaluate
   before the finding is treated as confirmed. A single unconfirmed hit is
   still reported, but flagged `manual_review_required` at lower confidence.
5. The engine family is named only as a hedged possibility in `reason=`
   ("compatível com engines baseadas em ..."), never asserted with certainty.
6. We never send gadget-chain payloads (`{{config}}`, `__class__.__mro__`,
   command execution, file reads, etc.). Arithmetic evaluation is the maximum
   evidence collected, per the project's minimum-evidence-necessary principle.
"""
from __future__ import annotations
import re
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, InputPoint, ScanContext
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, mutate_query_param

# Own local catalog: this plugin is responsible for its own reference text,
# not the shared scanner/plugins/catalog.py table used by passive checks.
CATALOG: dict[str, dict[str, str]] = {
    "ssti.expression_evaluated": {
        "title": "Injeção de template no lado do servidor (SSTI)",
        "category": "Server-Side Template Injection",
        "cwe": "CWE-1336",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-18",
        "description": (
            "Uma expressão aritmética enviada em um parâmetro de consulta foi avaliada pelo motor de "
            "templates do servidor -- o resultado calculado apareceu na resposta em vez da sintaxe literal "
            "enviada, indicando que a entrada é interpretada como código de template e não apenas como texto."
        ),
        "developer_impact": (
            "Dependendo do motor de templates em uso, a capacidade de avaliar expressões arbitrárias pode "
            "evoluir para leitura de variáveis internas, acesso a objetos do ambiente de execução ou, em "
            "cenários mais graves, execução de código no servidor."
        ),
        "remediation": (
            "Nunca concatene entrada do usuário diretamente no código-fonte de um template; trate-a sempre "
            "como dado de contexto (uma variável), utilize um modo sandboxed ou logic-less do motor de "
            "templates quando disponível, e valide/normalize a entrada antes de qualquer renderização."
        ),
    },
}

# Each family: (syntax key, hedge text for reason=, primary probe, confirmation probe).
# 7*7=49 / 8*8=64 are used consistently across families -- distinct enough not to
# coincidentally match ordinary page content, and cheap to also check against the
# untouched baseline body before trusting a match.
_FAMILIES = (
    {
        "primary": ("{{7*7}}", "49"),
        "confirm": ("{{8*8}}", "64"),
        "hedge": "compatível com engines baseadas em chaves duplas (ex.: Jinja2, Twig)",
    },
    {
        "primary": ("${7*7}", "49"),
        "confirm": ("${8*8}", "64"),
        "hedge": "compatível com engines baseadas em ${ } (ex.: expressões EL/Java, Freemarker, Velocity)",
    },
    {
        "primary": ("#{7*7}", "49"),
        "confirm": ("#{8*8}", "64"),
        "hedge": "compatível com engines baseadas em #{ } (ex.: variantes Ruby/OGNL/EL)",
    },
    {
        "primary": ("<%= 7*7 %>", "49"),
        "confirm": ("<%= 8*8 %>", "64"),
        "hedge": "compatível com engines no estilo ERB/JSP",
    },
    {
        "primary": ("*{7*7}", "49"),
        "confirm": ("*{8*8}", "64"),
        "hedge": "compatível com engines no estilo Thymeleaf",
    },
)

_NUMERIC_ID_NAME = re.compile(r"^(id|page|limit|offset|count|num|number|per_page|qty|quantity|year|month|day)s?$", re.I)


def _looks_like_numeric_id(point: InputPoint) -> bool:
    """Skip bare numeric identifiers: SSTI is about text rendered into a template body."""
    return bool(point.value) and point.value.isdigit() and bool(_NUMERIC_ID_NAME.match(point.name))


def _decode(response: HttpResponse) -> str:
    return response.body.decode("utf-8", errors="replace")


def _evaluated(body: str, raw_payload: str, expected: str, baseline_bodies: list[str]) -> bool:
    """True only when the numeral was computed by the server, not merely echoed.

    Rejects the match if the raw markup survived verbatim (unrendered reflection,
    an XSS detector's job, not ours) or if the expected numeral already appears in
    the untouched baseline (so it cannot be trusted as proof of evaluation).
    """
    if raw_payload in body:
        return False
    if expected not in body:
        return False
    if any(expected in baseline for baseline in baseline_bodies):
        return False
    return True


class TemplateInjectionPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Server-Side Template Injection",
        category="Server-Side Template Injection",
        cwe="CWE-1336",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-18",
        kind="safe_active",
        risk="low",
        checks=("ssti.expression_evaluated",),
    )

    def analyze(
        self,
        request: HttpRequest,
        responses: list[HttpResponse],
        context: ScanContext,
        transport: HttpTransport | None = None,
    ) -> list[Finding]:
        if transport is None:
            # safe_active plugin exercised without a transport (e.g. passive-only
            # mode): nothing to probe with, so stay silent rather than assume.
            return []

        baseline_bodies = [_decode(response) for response in responses]
        findings: list[Finding] = []
        seen_names: set[str] = set()

        for point in request.inputs:
            if point.location != "query" or point.name in seen_names:
                continue
            seen_names.add(point.name)
            if _looks_like_numeric_id(point):
                continue
            finding = self._probe_parameter(point, request, baseline_bodies, transport)
            if finding is not None:
                findings.append(finding)

        return findings

    def _probe_parameter(
        self,
        point: InputPoint,
        request: HttpRequest,
        baseline_bodies: list[str],
        transport: HttpTransport,
    ) -> Finding | None:
        for family in _FAMILIES:
            payload, expected = family["primary"]
            probe_url = mutate_query_param(request.url, point.name, payload)
            probe_request = HttpRequest(method="GET", url=probe_url, headers=dict(request.headers))
            probe_response = transport.send(probe_request)
            body = _decode(probe_response)

            if not _evaluated(body, payload, expected, baseline_bodies):
                continue  # this syntax was not evaluated; try the next engine family

            confirm_payload, confirm_expected = family["confirm"]
            confirm_url = mutate_query_param(request.url, point.name, confirm_payload)
            confirm_request = HttpRequest(method="GET", url=confirm_url, headers=dict(request.headers))
            confirm_response = transport.send(confirm_request)
            confirm_body = _decode(confirm_response)
            confirmed = _evaluated(confirm_body, confirm_payload, confirm_expected, baseline_bodies)

            if confirmed:
                reason = (
                    f"O parâmetro '{point.name}' foi testado com a expressão \"{payload}\" e o servidor "
                    f"respondeu com o resultado avaliado \"{expected}\", sem preservar a sintaxe original -- "
                    f"{family['hedge']}. Uma segunda expressão independente na mesma sintaxe, "
                    f"\"{confirm_payload}\", também foi avaliada para \"{confirm_expected}\", confirmando que "
                    f"o servidor está interpretando a expressão em vez de apenas devolvê-la como texto."
                )
                return build_finding(
                    check_id="ssti.expression_evaluated",
                    request=confirm_request,
                    response=confirm_response,
                    severity="high",
                    reason=reason,
                    confidence_inputs=ConfidenceInputs(
                        evidence_strength=95,
                        reproducibility=100,
                        differential_quality=90,
                        independent_confirmation=90,
                        ambiguity=0,
                    ),
                    parameter=point.name,
                    parameter_location=point.location,
                    verification_count=2,
                    evidence_snippet=expected,
                    catalog=CATALOG,
                )

            reason = (
                f"O parâmetro '{point.name}' foi testado com a expressão \"{payload}\" e o servidor respondeu "
                f"com o resultado avaliado \"{expected}\", sem preservar a sintaxe original -- {family['hedge']}. "
                f"A confirmação independente com \"{confirm_payload}\" não reproduziu o mesmo comportamento "
                f"(esperado \"{confirm_expected}\"), então este achado é reportado como sinal único, pendente "
                f"de revisão manual."
            )
            return build_finding(
                check_id="ssti.expression_evaluated",
                request=probe_request,
                response=probe_response,
                severity="medium",
                reason=reason,
                confidence_inputs=ConfidenceInputs(
                    evidence_strength=70,
                    reproducibility=100,
                    differential_quality=50,
                    independent_confirmation=0,
                    ambiguity=15,
                ),
                parameter=point.name,
                parameter_location=point.location,
                manual_review_required=True,
                verification_count=1,
                evidence_snippet=expected,
                catalog=CATALOG,
            )

        return None
