"""OS Command Injection: differential detection of arbitrary command execution
through query-string parameters, using only non-destructive proof techniques.

SAFETY IS THE PRIORITY HERE. Every probe is deliberately restricted to techniques
with no persistent or destructive side effect on the target: no reverse/bind
shells, no file reads/writes/deletes, no downloads, no user creation. Exactly
three proof techniques are used, tried cheapest-and-least-ambiguous first, and the
chain stops at the first technique that produces usable evidence:

  1. MARKER proof: wrap the parameter's original value with a shell metacharacter
     around `echo <distinctive marker>`. Tried first because `echo` exists
     unchanged on both POSIX shells and cmd.exe, so one payload shape can prove
     execution regardless of the target OS.
  2. MATH proof: same idea using a harmless arithmetic expression
     (`expr 7331 + 1` on POSIX, `set /a 7331+1` on cmd.exe) whose evaluated
     result (7332) is distinctive enough that it will not appear by coincidence.
     Only attempted if the marker produced no usable signal at all.
  3. TIMING proof (last resort only, cautious): inject a bounded delay
     (`sleep 3` / `ping -n 4 127.0.0.1`, ~3s) and compare elapsed time against the
     baseline, requiring one repeat measurement before trusting the signal at all.
     This technique is inherently noisier than the other two, so it is always
     reported as `manual_review_required`, never as a confirmed finding.

Only query-string parameters are tested; there is no HTML-form/POST submission
engine yet (see engine/discovery.py). A verbatim reflection of the raw payload
text is explicitly distinguished from real execution: a hit is only trusted when
the *evaluated* result (the marker text alone, or "7332") is present while the
literal injected command text is absent from the response — see `_probe_shapes`.
A negative control (same metacharacter, no actual command attached) rules out an
application that simply echoes any input containing these characters verbatim.

Elevated `risk="medium"` on the plugin metadata is deliberate: even a purely
harmless marker/math/timing probe still causes the target to execute
attacker-influenced input when the endpoint is genuinely vulnerable. That is an
inherent, unavoidable characteristic of proving this bug class safely, not a
flaw in this implementation.
"""
from __future__ import annotations
import re
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, mutate_query_param

CATALOG: dict[str, dict[str, str]] = {
    "command_injection.marker_confirmed": {
        "title": "Injeção de Comandos do Sistema Operacional confirmada",
        "category": "Injeção de Comandos do Sistema Operacional",
        "cwe": "CWE-78",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-12",
        "description": (
            "Um parâmetro de URL foi manipulado com separadores de comando do shell e o "
            "resultado avaliado (um marcador exclusivo ou uma expressão aritmética) apareceu "
            "na resposta usando pelo menos dois separadores de comando distintos, ausente na "
            "linha de base e em um controle negativo inerte, sem que o texto do comando "
            "injetado fosse apenas refletido."
        ),
        "developer_impact": (
            "Um atacante pode executar comandos arbitrários com os privilégios do processo do "
            "servidor, incluindo leitura, alteração ou exclusão de arquivos, movimentação "
            "lateral na rede interna e comprometimento total do host."
        ),
        "remediation": (
            "Elimine a chamada a um shell do sistema operacional para esta funcionalidade; "
            "utilize APIs nativas da linguagem sem invocar um shell (por exemplo, evite "
            "shell=True) com uma lista fixa de argumentos, valide a entrada com uma lista de "
            "permissões estrita, e execute o processo com o menor privilégio possível."
        ),
    },
    "command_injection.marker_suspected": {
        "title": "Possível Injeção de Comandos do Sistema Operacional",
        "category": "Injeção de Comandos do Sistema Operacional",
        "cwe": "CWE-78",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-12",
        "description": (
            "Um parâmetro de URL mostrou um sinal de avaliação de comando (marcador exclusivo "
            "ou expressão aritmética) para um único separador de comando, ausente na linha de "
            "base e não explicado por reflexão literal, mas uma segunda variação de separador "
            "não reproduziu o mesmo resultado, ou o controle negativo foi ambíguo."
        ),
        "developer_impact": (
            "Se confirmado, um atacante poderia executar comandos arbitrários no servidor; "
            "mesmo sem confirmação total, o comportamento observado é anômalo e merece "
            "investigação manual antes de ser descartado."
        ),
        "remediation": (
            "Revise manualmente o comportamento deste parâmetro; se uma chamada de shell "
            "estiver envolvida, elimine-a em favor de APIs nativas sem shell e valide a "
            "entrada com uma lista de permissões estrita."
        ),
    },
    "command_injection.timing_suspected": {
        "title": "Possível Injeção de Comandos baseada em atraso de tempo",
        "category": "Injeção de Comandos do Sistema Operacional",
        "cwe": "CWE-78",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-12",
        "description": (
            "Um comando de atraso limitado (sleep/ping) injetado em um parâmetro de URL "
            "produziu um atraso na resposta consistente com sua execução pelo sistema "
            "operacional, reproduzido em duas medições consecutivas, mas sem uma prova "
            "determinística (nenhum marcador ou valor avaliado apareceu na resposta)."
        ),
        "developer_impact": (
            "Um atraso reproduzível e correlacionado ao payload injetado é um forte indício "
            "de execução de comando arbitrário, ainda que menos conclusivo que uma prova de "
            "conteúdo; a exploração completa poderia permitir execução de comandos com os "
            "privilégios do servidor."
        ),
        "remediation": (
            "Revise manualmente este endpoint; elimine chamadas a um shell do sistema "
            "operacional para esta funcionalidade e substitua por APIs nativas da linguagem "
            "sem shell, com validação estrita da entrada."
        ),
    },
}

# Query parameter names that plausibly reach a shell command. Only used to prioritize
# which parameters get tested when there are many; with 3 or fewer query parameters,
# every one is tested regardless of name (small surface, worth being thorough).
SIGNAL_NAME_PATTERN = re.compile(r"cmd|command|exec|run|ping|host|hostname|ip|query|search|file|name", re.I)

MARKER = "SENTINELSCOPE_CI_MARKER_7331"
MARKER_COMMAND = f"echo {MARKER}"
MATH_EXPECTED = "7332"
MATH_COMMAND_SH = "expr 7331 + 1"
MATH_COMMAND_WINDOWS = "set /a 7331+1"
TIMING_DELAY_SECONDS = 3
TIMING_THRESHOLD_MS = 2000  # below the nominal ~3000ms delay, to absorb network jitter
MAX_PARAMETERS = 5  # cap total probe volume: each parameter can cost up to ~20 requests
                     # across all three phases in the worst (non-vulnerable) case, so
                     # testing more than a handful risks starving other active plugins'
                     # share of the scan's shared request budget.


def _wrap_semicolon(value: str, command: str) -> str:
    return f"{value}; {command} ;"


def _wrap_pipe(value: str, command: str) -> str:
    return f"{value} | {command}"


def _wrap_and_and(value: str, command: str) -> str:
    return f"{value} && {command}"


def _wrap_backtick(value: str, command: str) -> str:
    return f"{value}`{command}`"


def _wrap_dollar_paren(value: str, command: str) -> str:
    return f"{value}$({command})"


def _wrap_newline(value: str, command: str) -> str:
    return f"{value}\n{command}"


# Shapes are ordered roughly cheapest/most-common-first. `;`, `|`, `&&` are meaningful
# to both POSIX shells and cmd.exe; backtick/`$()` command substitution is POSIX-only;
# a raw newline can act as a statement separator under either interpreter depending on
# how the vulnerable code invokes it.
SHAPES = [
    ("semicolon", _wrap_semicolon),
    ("pipe", _wrap_pipe),
    ("and_and", _wrap_and_and),
    ("backtick", _wrap_backtick),
    ("dollar_paren", _wrap_dollar_paren),
    ("newline", _wrap_newline),
]


def _decode(response: HttpResponse) -> str:
    return response.body.decode("utf-8", errors="replace")


class CommandInjectionPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Command Injection",
        category="Injeção de Comandos do Sistema Operacional",
        cwe="CWE-78",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-12",
        kind="safe_active",
        risk="medium",
        checks=(
            "command_injection.marker_confirmed",
            "command_injection.marker_suspected",
            "command_injection.timing_suspected",
        ),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []

        query_points = [p for p in request.inputs if p.location == "query"]
        if not query_points:
            return []
        if len(query_points) <= 3:
            candidates = query_points
        else:
            candidates = [p for p in query_points if SIGNAL_NAME_PATTERN.search(p.name)] or query_points
        candidates = candidates[:MAX_PARAMETERS]

        baseline_texts = [_decode(response) for response in responses]
        baseline_avg_ms = sum(response.elapsed_ms for response in responses) / len(responses)

        findings: list[Finding] = []
        for point in candidates:
            finding = self._test_parameter(request, point, transport, baseline_texts, baseline_avg_ms)
            if finding is not None:
                findings.append(finding)
        return findings

    def _send(self, template: HttpRequest, transport: HttpTransport, url: str) -> tuple[HttpRequest, HttpResponse]:
        probe_request = HttpRequest(method=template.method, url=url, headers=dict(template.headers))
        return probe_request, transport.send(probe_request)

    def _test_parameter(self, request, point, transport, baseline_texts, baseline_avg_ms) -> Finding | None:
        # 1) Marker proof: cheap, unambiguous, and OS-agnostic (echo exists everywhere).
        hits = self._probe_shapes(request, point, transport, MARKER_COMMAND, lambda text: MARKER in text, baseline_texts)
        finding = self._resolve_hits(
            request, point, transport, hits, evidence_fn=lambda text: MARKER in text,
            inert_payload=MARKER, evidence_label=f"o marcador exclusivo '{MARKER}'", evidence_needle=MARKER,
        )
        if finding is not None:
            return finding

        # 2) Math proof: POSIX shell dialect first, then a single cmd.exe-flavored
        #    attempt, but only if the POSIX dialect produced no signal at all.
        math_hits = self._probe_shapes(request, point, transport, MATH_COMMAND_SH, lambda text: MATH_EXPECTED in text, baseline_texts)
        finding = self._resolve_hits(
            request, point, transport, math_hits, evidence_fn=lambda text: MATH_EXPECTED in text,
            inert_payload="7331 + 1", evidence_label=f"o resultado avaliado '{MATH_EXPECTED}' (de '{MATH_COMMAND_SH}')",
            evidence_needle=MATH_EXPECTED,
        )
        if finding is not None:
            return finding
        if not math_hits:
            windows_hits = self._probe_shapes(request, point, transport, MATH_COMMAND_WINDOWS, lambda text: MATH_EXPECTED in text, baseline_texts)
            finding = self._resolve_hits(
                request, point, transport, windows_hits, evidence_fn=lambda text: MATH_EXPECTED in text,
                inert_payload="7331+1", evidence_label=f"o resultado avaliado '{MATH_EXPECTED}' (de '{MATH_COMMAND_WINDOWS}')",
                evidence_needle=MATH_EXPECTED,
            )
            if finding is not None:
                return finding

        # 3) Timing proof: last resort only, since it is the noisiest of the three.
        return self._test_timing(request, point, transport, baseline_avg_ms)

    def _probe_shapes(self, request, point, transport, command, evidence_fn, baseline_texts):
        """Try each metacharacter shape in turn, stopping once two independent shapes
        confirm the same evaluated result (or the shapes are exhausted).

        A hit requires the evaluated result to be present (`evidence_fn`) while the
        literal injected command text is absent from the body -- this is what tells
        real execution apart from the application simply echoing the raw parameter
        value back verbatim (see module docstring).
        """
        if any(evidence_fn(text) for text in baseline_texts):
            return []  # this evidence already appears with no injection; useless as a signal
        hits = []
        for shape_name, shape_fn in SHAPES:
            probe_value = shape_fn(point.value, command)
            probe_url = mutate_query_param(request.url, point.name, probe_value)
            probe_request, probe_response = self._send(request, transport, probe_url)
            body_text = _decode(probe_response)
            if evidence_fn(body_text) and command not in body_text:
                hits.append((shape_name, shape_fn, probe_request, probe_response, body_text))
                if len(hits) >= 2:
                    break
        return hits

    def _negative_control(self, request, point, transport, shape_fn, inert_payload, evidence_fn) -> bool:
        """Send the same metacharacter shape with an inert payload that has no command
        semantics (e.g. the bare marker text with no `echo`). Returns True ("clean")
        when the evaluated result is absent, ruling out an application that echoes any
        input containing these characters verbatim rather than executing it."""
        control_value = shape_fn(point.value, inert_payload)
        control_url = mutate_query_param(request.url, point.name, control_value)
        _, control_response = self._send(request, transport, control_url)
        return not evidence_fn(_decode(control_response))

    def _snippet(self, body_text: str, needle: str) -> str:
        idx = body_text.find(needle)
        if idx == -1:
            return needle
        return body_text[max(0, idx - 30): idx + len(needle) + 30]

    def _resolve_hits(self, request, point, transport, hits, evidence_fn, inert_payload, evidence_label, evidence_needle) -> Finding | None:
        if not hits:
            return None
        shape_name, shape_fn, probe_request, probe_response, body_text = hits[0]
        control_clean = self._negative_control(request, point, transport, shape_fn, inert_payload, evidence_fn)

        if len(hits) >= 2 and control_clean:
            second_shape_name = hits[1][0]
            reason = (
                f"O parâmetro '{point.name}' teve {evidence_label} presente na resposta ao injetar dois "
                f"separadores de comando distintos ('{shape_name}' e '{second_shape_name}'), ausente na linha "
                "de base e em um controle negativo inerte (mesmo separador, sem o comando), sem que o texto "
                "literal do comando injetado fosse refletido -- evidência de execução real pelo sistema "
                "operacional do servidor alvo."
            )
            return build_finding(
                check_id="command_injection.marker_confirmed",
                request=probe_request, response=probe_response, severity="critical", reason=reason,
                confidence_inputs=ConfidenceInputs(
                    evidence_strength=95, reproducibility=100, differential_quality=90, independent_confirmation=100,
                ),
                parameter=point.name, parameter_location=point.location, manual_review_required=False,
                verification_count=2, evidence_snippet=self._snippet(body_text, evidence_needle),
                differences={"shapes_confirmed": [shape_name, second_shape_name]},
                catalog=CATALOG,
            )

        if control_clean:
            reason = (
                f"O parâmetro '{point.name}' teve {evidence_label} presente na resposta ao injetar o separador "
                f"'{shape_name}', ausente na linha de base e em um controle negativo inerte, sem reflexão "
                "literal do comando. Apenas um separador produziu o sinal -- uma segunda variação de separador "
                "não reproduziu o mesmo resultado -- portanto recomenda-se revisão manual antes de tratar como "
                "confirmado."
            )
            confidence_inputs = ConfidenceInputs(evidence_strength=80, reproducibility=55, differential_quality=35, ambiguity=15)
        else:
            reason = (
                f"O parâmetro '{point.name}' teve {evidence_label} presente na resposta ao injetar o separador "
                f"'{shape_name}', ausente na linha de base, mas um controle negativo inerte (mesmo separador, "
                "sem o comando) também produziu um resultado semelhante, tornando o sinal ambíguo e exigindo "
                "revisão manual."
            )
            confidence_inputs = ConfidenceInputs(evidence_strength=55, reproducibility=45, differential_quality=20, ambiguity=35)

        return build_finding(
            check_id="command_injection.marker_suspected",
            request=probe_request, response=probe_response, severity="medium", reason=reason,
            confidence_inputs=confidence_inputs,
            parameter=point.name, parameter_location=point.location, manual_review_required=True,
            verification_count=len(hits), evidence_snippet=self._snippet(body_text, evidence_needle),
            catalog=CATALOG,
        )

    def _test_timing(self, request, point, transport, baseline_avg_ms) -> Finding | None:
        attempts = (
            ("semicolon", f"sleep {TIMING_DELAY_SECONDS}", _wrap_semicolon),
            ("and_and", "ping -n 4 127.0.0.1", _wrap_and_and),
        )
        for label, command, shape_fn in attempts:
            probe_value = shape_fn(point.value, command)
            probe_url = mutate_query_param(request.url, point.name, probe_value)
            probe_request, first_response = self._send(request, transport, probe_url)
            delta_first = first_response.elapsed_ms - baseline_avg_ms
            if delta_first < TIMING_THRESHOLD_MS:
                continue
            # One repeat before trusting a timing signal: network jitter alone can
            # produce a single slow response.
            _, second_response = self._send(request, transport, probe_url)
            delta_second = second_response.elapsed_ms - baseline_avg_ms
            if delta_second < TIMING_THRESHOLD_MS:
                continue
            reason = (
                f"O parâmetro '{point.name}' apresentou atraso de aproximadamente {delta_first:.0f}ms e "
                f"{delta_second:.0f}ms acima da média da linha de base ({baseline_avg_ms:.0f}ms) ao injetar "
                f"'{command}' com o separador '{label}', reproduzido em duas medições consecutivas. Isto é um "
                "indício de execução de um comando de atraso pelo sistema operacional, mas não uma prova "
                "determinística -- nenhum marcador ou valor avaliado apareceu na resposta -- portanto requer "
                "revisão manual."
            )
            return build_finding(
                check_id="command_injection.timing_suspected",
                request=probe_request, response=second_response, severity="medium", reason=reason,
                confidence_inputs=ConfidenceInputs(evidence_strength=55, reproducibility=100, differential_quality=30, ambiguity=30),
                parameter=point.name, parameter_location=point.location, manual_review_required=True,
                verification_count=2, baseline={"elapsed_ms_avg": round(baseline_avg_ms)},
                evidence_snippet=f"delta1={delta_first:.0f}ms delta2={delta_second:.0f}ms",
                catalog=CATALOG,
            )
        return None
