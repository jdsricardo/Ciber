"""SQL Injection: error-based, boolean-differential, and cautious time-based detection.

Only tests query-string parameters already present on the target URL (there is no
HTML-form/POST submission engine yet). Never enumerates tables, extracts records, or
reads data beyond what is needed to prove the vulnerability exists. Each technique is
tried in increasing cost order (error-based -> boolean-differential -> time-based) and
the chain stops at the first technique that produces confirmed evidence, per the
project's "stop at minimum necessary evidence" principle.
"""
from __future__ import annotations
import re
import statistics
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.normalization import compare, summarize
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, send_probe, testable_inputs

CATALOG = {
    "sqli.error_based": {
        "title": "SQL Injection confirmada por mensagem de erro de banco de dados",
        "category": "Injeção de SQL",
        "cwe": "CWE-89",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-05",
        "description": "Um caractere de controle SQL enviado em um parâmetro produziu uma mensagem de erro de banco de dados ausente na resposta de baseline.",
        "developer_impact": "Um atacante pode manipular a consulta SQL executada pela aplicação, potencialmente lendo, alterando ou apagando dados, ou contornando autenticação.",
        "remediation": "Utilize consultas parametrizadas (prepared statements) ou um ORM com binding de parâmetros em todos os pontos que recebem entrada do usuário. Nunca concatene entrada diretamente em comandos SQL.",
    },
    "sqli.boolean_differential": {
        "title": "SQL Injection confirmada por diferencial booleano",
        "category": "Injeção de SQL",
        "cwe": "CWE-89",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-05",
        "description": "Uma condição SQL logicamente verdadeira produziu uma resposta equivalente à baseline, enquanto uma condição logicamente falsa produziu uma resposta estruturalmente diferente, e um probe de controle inócuo não alterou o comportamento.",
        "developer_impact": "A aplicação avalia a condição booleana injetada diretamente na consulta SQL, confirmando que a entrada do usuário influencia a lógica da consulta sem sanitização.",
        "remediation": "Utilize consultas parametrizadas (prepared statements) ou um ORM com binding de parâmetros em todos os pontos que recebem entrada do usuário. Nunca concatene entrada diretamente em comandos SQL.",
    },
    "sqli.time_based": {
        "title": "SQL Injection provável por atraso de tempo controlado",
        "category": "Injeção de SQL",
        "cwe": "CWE-89",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-05",
        "description": "Uma condição SQL contendo uma função de atraso controlado produziu um tempo de resposta consistentemente maior que a baseline, reproduzido em uma segunda medição, enquanto um probe de controle de complexidade equivalente não produziu o mesmo atraso.",
        "developer_impact": "A aplicação avalia a expressão SQL injetada, incluindo chamadas de função, confirmando que a entrada do usuário influencia a execução da consulta sem sanitização.",
        "remediation": "Utilize consultas parametrizadas (prepared statements) ou um ORM com binding de parâmetros em todos os pontos que recebem entrada do usuário. Nunca concatene entrada diretamente em comandos SQL.",
    },
}

DB_ERROR_PATTERNS = [
    ("MySQL/MariaDB", re.compile(r"sql syntax.*mysql|warning: mysqli?_|you have an error in your sql syntax|sqlstate\[hy000\]", re.I)),
    ("PostgreSQL", re.compile(r"pg_query\(\)|postgresql.*error|invalid input syntax for|org\.postgresql\.util\.psqlexception", re.I)),
    ("MSSQL", re.compile(r"unclosed quotation mark|microsoft sql server|odbc sql server driver|system\.data\.sqlclient", re.I)),
    ("SQLite", re.compile(r"sqlite3?\.operationalerror|near \".*\": syntax error", re.I)),
    ("Oracle", re.compile(r"ora-\d{5}", re.I)),
    ("Generic", re.compile(r"sqlstate\[|syntax error.*(?:query|sql)|unterminated quoted string", re.I)),
]

ERROR_PAYLOAD = "'"
ERROR_CONFIRM_PAYLOAD = '"'
# AND, not OR: the parameter's baseline value already produces a match (it's the value
# actually on the scanned URL), so "OR '1'='1'" would be true regardless of the original
# condition and never diverge from baseline. "AND '1'='1'" is a no-op on an already-true
# condition (stays == baseline) while "AND '1'='2'" forces it false (diverges) — that
# contrast is what actually proves the parameter reaches the query's boolean logic.
BOOLEAN_TRUE_SUFFIX = "' AND '1'='1"
BOOLEAN_FALSE_SUFFIX = "' AND '1'='2"
CONTROL_SUFFIX = " zzqxNotASqlPayload"
TIME_DELAY_SECONDS = 3
TIME_VARIANTS = [
    f"' OR SLEEP({TIME_DELAY_SECONDS})-- -",
    f" OR SLEEP({TIME_DELAY_SECONDS})-- -",
]
TIME_CONTROL_SUFFIX = " zzqxTimingControlNoDelay"

class SqlInjectionPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="SQL Injection",
        category="Injeção de SQL",
        cwe="CWE-89",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-05",
        kind="safe_active",
        risk="low",
        checks=("sqli.error_based", "sqli.boolean_differential", "sqli.time_based"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        findings: list[Finding] = []
        baseline = responses[0]
        baseline_summary = summarize(baseline)
        for param in testable_inputs(request):
            finding = self._test_parameter(request, baseline, baseline_summary, param, transport)
            if finding:
                findings.append(finding)
        return findings

    def _test_parameter(self, request, baseline, baseline_summary, param, transport):
        finding = self._error_based(request, baseline, param, transport)
        if finding:
            return finding
        finding = self._boolean_differential(request, baseline, baseline_summary, param, transport)
        if finding:
            return finding
        return self._time_based(request, baseline, param, transport)

    # --- Error-based -----------------------------------------------------

    def _error_based(self, request, baseline, param, transport):
        probe = send_probe(transport, request, param, param.value + ERROR_PAYLOAD)
        probe_text = probe.body.decode("utf-8", errors="replace")
        baseline_text = baseline.body.decode("utf-8", errors="replace")
        for engine_name, pattern in DB_ERROR_PATTERNS:
            match = pattern.search(probe_text)
            if not match or pattern.search(baseline_text):
                continue
            confirm = send_probe(transport, request, param, param.value + ERROR_CONFIRM_PAYLOAD)
            confirm_text = confirm.body.decode("utf-8", errors="replace")
            reproduced = bool(pattern.search(confirm_text))
            return build_finding(
                check_id="sqli.error_based", request=request, response=probe,
                severity="critical",
                reason=f"O parâmetro '{param.name}' produziu uma mensagem de erro de banco de dados compatível com {engine_name}, ausente na resposta de baseline. Confirmação com um segundo payload ({'reproduzida' if reproduced else 'não reproduzida'}).",
                confidence_inputs=ConfidenceInputs(
                    evidence_strength=90,
                    reproducibility=100 if reproduced else 40,
                    differential_quality=85,
                    independent_confirmation=100 if reproduced else 0,
                ),
                parameter=param.name, parameter_location=param.location,
                evidence_snippet=match.group(0),
                manual_review_required=not reproduced,
                catalog=CATALOG,
            )
        return None

    # --- Boolean differential ---------------------------------------------

    def _boolean_differential(self, request, baseline, baseline_summary, param, transport):
        true_resp = send_probe(transport, request, param, param.value + BOOLEAN_TRUE_SUFFIX)
        false_resp = send_probe(transport, request, param, param.value + BOOLEAN_FALSE_SUFFIX)
        control_resp = send_probe(transport, request, param, param.value + CONTROL_SUFFIX)

        true_summary = summarize(true_resp)
        false_summary = summarize(false_resp)
        control_summary = summarize(control_resp)
        true_diff = compare(baseline_summary, true_summary)
        false_diff = compare(baseline_summary, false_summary)
        control_diff = compare(baseline_summary, control_summary)

        # A vulnerable, injectable parameter: the always-true condition still looks like the
        # baseline (query remains valid and returns the same "found" content), the always-false
        # condition diverges (query becomes valid-but-empty or errors), and a harmless control
        # suffix with no SQL meaning changes nothing at all (rules out a generally noisy/dynamic
        # page or a WAF that reacts to any unusual input regardless of SQL semantics).
        true_matches_baseline = true_resp.status == baseline.status and true_diff.similarity > 0.9
        false_diverges = false_resp.status != baseline.status or false_diff.similarity < 0.85
        control_matches_baseline = control_resp.status == baseline.status and control_diff.similarity > 0.9

        if true_matches_baseline and false_diverges and control_matches_baseline:
            # Independent confirmation: repeat the true/false pair once more to rule out
            # a one-off fluke (pagination, rotating content, transient error).
            true_repeat = summarize(send_probe(transport, request, param, param.value + BOOLEAN_TRUE_SUFFIX))
            false_repeat = summarize(send_probe(transport, request, param, param.value + BOOLEAN_FALSE_SUFFIX))
            reproduced = (
                compare(baseline_summary, true_repeat).similarity > 0.9
                and compare(baseline_summary, false_repeat).similarity < 0.85
            )
            return build_finding(
                check_id="sqli.boolean_differential", request=request, response=true_resp,
                severity="critical",
                reason=(
                    f"Para o parâmetro '{param.name}': a condição sempre-verdadeira produziu uma resposta "
                    f"{true_diff.similarity:.0%} similar à baseline; a condição sempre-falsa produziu uma resposta "
                    f"{false_diff.similarity:.0%} similar; o probe de controle inócuo manteve {control_diff.similarity:.0%} "
                    f"de similaridade. Repetição do par verdadeiro/falso {'confirmou' if reproduced else 'não confirmou'} o padrão."
                ),
                confidence_inputs=ConfidenceInputs(
                    evidence_strength=85,
                    reproducibility=100 if reproduced else 40,
                    differential_quality=90,
                    independent_confirmation=100 if reproduced else 0,
                ),
                parameter=param.name, parameter_location=param.location,
                differences={
                    "true_similarity": true_diff.similarity,
                    "false_similarity": false_diff.similarity,
                    "control_similarity": control_diff.similarity,
                },
                manual_review_required=not reproduced,
                catalog=CATALOG,
            )
        return None

    # --- Time-based (cautious) ---------------------------------------------

    def _time_based(self, request, baseline, param, transport):
        baseline_typical_ms = statistics.median([baseline.elapsed_ms, baseline.elapsed_ms])
        threshold_ms = baseline_typical_ms + TIME_DELAY_SECONDS * 1000 * 0.7

        for variant in TIME_VARIANTS:
            probe = send_probe(transport, request, param, param.value + variant)
            if probe.elapsed_ms < threshold_ms:
                continue
            confirm = send_probe(transport, request, param, param.value + variant)
            control = send_probe(transport, request, param, param.value + TIME_CONTROL_SUFFIX)
            confirmed = confirm.elapsed_ms >= threshold_ms
            control_clean = control.elapsed_ms < threshold_ms
            if not control_clean:
                # The endpoint appears to be generally slow for any long/unusual input,
                # not specifically because of the SLEEP() call. Do not report.
                continue
            return build_finding(
                check_id="sqli.time_based", request=request, response=probe,
                severity="critical" if confirmed else "high",
                reason=(
                    f"O parâmetro '{param.name}' com um atraso SQL de {TIME_DELAY_SECONDS}s levou {probe.elapsed_ms}ms "
                    f"(baseline {baseline_typical_ms:.0f}ms). Repetição {'confirmou' if confirmed else 'não confirmou'} o atraso; "
                    f"o probe de controle, de complexidade equivalente mas sem função de atraso, levou {control.elapsed_ms}ms."
                ),
                confidence_inputs=ConfidenceInputs(
                    evidence_strength=75,
                    reproducibility=100 if confirmed else 40,
                    differential_quality=70,
                    independent_confirmation=100 if confirmed else 0,
                    ambiguity=10,
                ),
                parameter=param.name, parameter_location=param.location,
                evidence_snippet=f"elapsed_ms={probe.elapsed_ms}",
                manual_review_required=not confirmed,
                catalog=CATALOG,
            )
        return None
