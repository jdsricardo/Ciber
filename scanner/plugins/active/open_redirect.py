"""Open Redirect: detects query parameters that control a navigation target and
can be steered toward an attacker-controlled external host (CWE-601).

Only query-string parameters are probed -- there is no POST/form submission
engine yet (see engine/discovery.py). A candidate is a parameter whose name
suggests redirect/navigation intent, or whose baseline value already looks
like a URL or path. Each candidate is probed with a canary domain on the
`.invalid` TLD (IANA-reserved, guaranteed to never resolve or belong to
anyone), escalating through common bypass shapes only if the plain probe is
inconclusive, and stopping as soon as one succeeds.

Detection always parses the Location header (or a client-side navigation
snippet) with urllib.parse and compares the resulting *hostname*, never a
naive substring check on the raw text -- a substring check would misfire on
`notexample.com` containing `example.com`, or on a same-path redirect that
merely echoes the injected value inside an unrelated query string. A second,
structurally identical probe against an unrelated control host confirms the
match tracks the actual value sent rather than being a fluke.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, InputPoint, ScanContext

from ..base import PluginMetadata, ScannerPlugin
from ..support import baseline_summary, build_finding, build_probe, testable_inputs

CANARY_URL = "https://sentinelscope-redirect-canary.invalid/"
CANARY_HOST = "sentinelscope-redirect-canary.invalid"
CONTROL_URL = "https://sentinelscope-control-canary.invalid/"
CONTROL_HOST = "sentinelscope-control-canary.invalid"

NAME_PATTERN = re.compile(
    r"redirect_uri|redirect_url|redirect|return_url|returnto|return|dest|destination|"
    r"continue|target|goto|link|url|next",
    re.I,
)
JS_REDIRECT_PATTERN = re.compile(r"window\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.I)
META_REFRESH_PATTERN = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>]+)', re.I)

# Own local catalog: this plugin owns its Open Redirect reference text end to
# end, following the convention documented in plugins/active/__init__.py.
CATALOG: dict[str, dict[str, str]] = {
    "open_redirect.confirmed_header": {
        "title": "Redirecionamento aberto confirmado via cabeçalho Location",
        "category": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CLNT-04",
        "description": "Um parâmetro de query controla o destino de um redirecionamento HTTP e aceita um host externo arbitrário sem validação.",
        "developer_impact": "Um atacante pode montar um link para este site que, após o clique, redireciona a vítima para um site malicioso, favorecendo phishing e roubo de credenciais sob a aparência de um domínio confiável.",
        "remediation": "Valide o parâmetro de redirecionamento contra uma lista de permissões de caminhos internos, ou use um identificador indireto (por exemplo um índice) em vez de aceitar uma URL completa.",
    },
    "open_redirect.client_side_suspected": {
        "title": "Possível redirecionamento aberto no lado do cliente",
        "category": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-CLNT-04",
        "description": "Um parâmetro de query é refletido dentro de uma navegação client-side (window.location ou meta refresh) apontando para o host canário injetado.",
        "developer_impact": "Se o navegador realmente executar essa navegação, o mesmo efeito de phishing de um redirecionamento aberto no servidor se aplica, mas por meio de JavaScript ou meta tag.",
        "remediation": "Valide o parâmetro no servidor antes de embuti-lo em qualquer script ou meta tag de navegação, restringindo-o a caminhos internos conhecidos.",
    },
}


def _looks_like_url(value: str) -> bool:
    return bool(value) and (value.startswith(("/", "http://", "https://")) or "://" in value)


def _is_candidate(point: InputPoint) -> bool:
    return bool(NAME_PATTERN.search(point.name)) or _looks_like_url(point.value)


def _build_variants(base_url: str) -> list[str]:
    """Plain canary URL plus common open-redirect bypass shapes, in escalation order."""
    host = urlparse(base_url).hostname
    return [
        base_url,
        f"//{host}/",
        f"https:{host}",
        f"/\\/{host}/",
    ]


def _extract_target_host(location: str | None) -> str | None:
    """Parse a Location value the way a browser would for the shapes we probe.

    Never a substring check on the raw header text: `example.com` sitting
    inside `notexample.com`, or a canary string reflected inertly inside an
    unrelated query value on a same-path redirect, must not match.
    """
    if not location:
        return None
    normalized = location.replace("\\", "/")
    normalized = re.sub(r"^/{2,}", "//", normalized)  # collapse the backslash-trick shape to protocol-relative
    parsed = urlparse(normalized)
    if parsed.hostname:
        return parsed.hostname
    if parsed.scheme and not parsed.netloc and parsed.path:
        # "https:host" with no slashes: still authority-like for a special scheme.
        candidate = parsed.path.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        return candidate.lower() or None
    return None


def _client_side_match(body: str, probe_value: str) -> str | None:
    js_match = JS_REDIRECT_PATTERN.search(body)
    if js_match and probe_value in js_match.group(1):
        return js_match.group(0)
    meta_match = META_REFRESH_PATTERN.search(body)
    if meta_match and probe_value in meta_match.group(1):
        return meta_match.group(0)
    return None


class OpenRedirectPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Open Redirect",
        category="Open Redirect",
        cwe="CWE-601",
        owasp="A01:2025 Broken Access Control",
        wstg="WSTG-CLNT-04",
        kind="safe_active",
        risk="low",
        checks=("open_redirect.confirmed_header", "open_redirect.client_side_suspected"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport=None) -> list[Finding]:
        findings: list[Finding] = []
        if transport is None:
            return findings
        primary = responses[0]
        candidates = [point for point in testable_inputs(request) if _is_candidate(point)]
        for point in candidates:
            finding = self._probe_parameter(request, primary, point, context, transport)
            if finding is not None:
                findings.append(finding)
        return findings

    def _send(self, request: HttpRequest, point: InputPoint, value: str, transport) -> tuple[HttpRequest, HttpResponse]:
        probe_request = build_probe(request, point, value)
        return probe_request, transport.send(probe_request)

    def _probe_parameter(self, request: HttpRequest, primary: HttpResponse, point: InputPoint,
                          context: ScanContext, transport) -> Finding | None:
        canary_variants = _build_variants(CANARY_URL)
        control_variants = _build_variants(CONTROL_URL)

        match_kind: str | None = None
        match_variant: str | None = None
        probe_request = probe_response = None
        client_snippet: str | None = None

        for variant in canary_variants:
            probe_request, probe_response = self._send(request, point, variant, transport)
            host = _extract_target_host(probe_response.headers.get("location"))
            if host == CANARY_HOST:
                match_kind, match_variant = "header", variant
                break
            if probe_response.status == 200:
                body_text = probe_response.body.decode("utf-8", errors="replace")
                snippet = _client_side_match(body_text, variant)
                if snippet:
                    match_kind, match_variant, client_snippet = "client", variant, snippet
                    break

        if match_kind is None or match_variant is None:
            return None

        # Structurally identical probe against an unrelated host: confirms the
        # match tracks the value we sent rather than being a coincidence.
        control_value = control_variants[canary_variants.index(match_variant)]
        _, control_response = self._send(request, point, control_value, transport)
        if match_kind == "header":
            control_confirmed = _extract_target_host(control_response.headers.get("location")) == CONTROL_HOST
        else:
            control_body = control_response.body.decode("utf-8", errors="replace")
            control_confirmed = bool(_client_side_match(control_body, control_value))

        # Original baseline value, already exercised by the runner's baseline
        # requests: makes sure a legitimate same-site redirect on every request
        # doesn't get misread as evidence of anything.
        baseline_host = _extract_target_host(primary.headers.get("location")) if 300 <= primary.status < 400 else None
        baseline_data = baseline_summary(primary)
        baseline_data["redirect_host"] = baseline_host

        sensitive = bool(context.page and context.page.looks_authenticated)
        severity = "high" if sensitive else "medium"

        if match_kind == "header":
            location_value = probe_response.headers.get("location", "")
            confirmation_clause = (
                f"também foi refletida para '{CONTROL_HOST}', confirmando"
                if control_confirmed
                else "não foi refletida da mesma forma, mas a correspondência exata de host com o canário permanece confirmando"
            )
            reason = (
                f"O parâmetro '{point.name}' foi alterado para '{match_variant}' e a resposta retornou "
                f"{probe_response.status} com o cabeçalho Location apontando para o host externo "
                f"'{CANARY_HOST}' (Location: {location_value}). Uma sonda de controle idêntica para "
                f"'{CONTROL_HOST}' {confirmation_clause} "
                f"que o destino do redirecionamento é controlado pelo valor do parâmetro, e não por acaso."
            )
            confidence_inputs = ConfidenceInputs(
                evidence_strength=95,
                reproducibility=100,
                differential_quality=90 if control_confirmed else 60,
                independent_confirmation=90 if control_confirmed else 0,
                ambiguity=0,
            )
            manual_review = False
            evidence_snippet = f"Location: {location_value}"
        else:
            confirmation_clause = (
                f"também apareceu na navegação client-side para '{CONTROL_HOST}', reforçando"
                if control_confirmed
                else "não apareceu da mesma forma, mas ainda assim reforça"
            )
            reason = (
                f"O parâmetro '{point.name}' foi alterado para '{match_variant}' e a resposta 200 contém "
                f"navegação client-side apontando exatamente para essa URL canário (trecho: {client_snippet}). "
                f"Uma sonda de controle idêntica {confirmation_clause} "
                f"a suspeita de redirecionamento aberto no lado do cliente; confirmação manual é recomendada."
            )
            confidence_inputs = ConfidenceInputs(
                evidence_strength=55,
                reproducibility=100,
                differential_quality=70 if control_confirmed else 40,
                independent_confirmation=60 if control_confirmed else 0,
                ambiguity=25,
            )
            manual_review = True
            evidence_snippet = client_snippet or ""

        check_id = "open_redirect.confirmed_header" if match_kind == "header" else "open_redirect.client_side_suspected"

        return build_finding(
            check_id=check_id,
            request=probe_request,
            response=probe_response,
            severity=severity,
            reason=reason,
            confidence_inputs=confidence_inputs,
            parameter=point.name,
            parameter_location=point.location,
            manual_review_required=manual_review,
            differences={
                "variant_used": match_variant,
                "baseline_redirect_host": baseline_host,
                "control_probe_confirmed": control_confirmed,
            },
            evidence_snippet=evidence_snippet,
            baseline=baseline_data,
            catalog=CATALOG,
        )
