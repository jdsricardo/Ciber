"""Shared helpers for passive plugins: evidence assembly and Finding construction.

Centralized here so individual plugins only decide *whether* something is
wrong and *how confident* they are, never how an Evidence/Finding object is shaped.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from engine.confidence import ConfidenceInputs, score, status_for
from engine.models import Evidence, Finding, HttpRequest, HttpResponse
from engine.safety import redact_headers
from .catalog import CATALOG
from .remediation_examples import get as remediation_example

def mutate_query_param(url: str, name: str, value: str, already_encoded: bool = False) -> str:
    """Returns `url` with query parameter `name` replaced by `value` (added if absent).

    `already_encoded=True` sends `value` verbatim after the `=` instead of running it
    through `urlencode`, which otherwise double-encodes a literal `%0d%0a`-style payload
    into `%250d%250a` — wrong for detectors (CRLF, command injection) that need the exact
    percent-escapes a real attacker would send on the wire.
    """
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if already_encoded:
        params.pop(name, None)
        other = urlencode(params)
        pair = f"{quote(name, safe='')}={value}"
        query = f"{other}&{pair}" if other else pair
        return urlunparse(parsed._replace(query=query))
    params[name] = value
    return urlunparse(parsed._replace(query=urlencode(params)))

PROBE_ACCEPT = "text/html,application/json,*/*;q=0.5"

def form_fields(request: HttpRequest) -> dict[str, str]:
    """Default name->value map of every discovered form field on the page."""
    return {point.name: point.value for point in request.inputs if point.location == "form"}

def build_probe(request: HttpRequest, param, value: str, *, already_encoded: bool = False) -> HttpRequest:
    """Build a probe request that sets input point `param` to `value`, choosing the channel by
    the point's location: a query parameter rides on the URL (GET); a form field is submitted in
    an application/x-www-form-urlencoded body (POST), preserving the other discovered fields at
    their default values. This lets a plugin test a parameter without knowing where it lives.

    Note: form probes are POSTed to the scanned page URL. Forms whose `action` targets a
    different path are a known limitation of this version.
    """
    if getattr(param, "location", "query") == "form":
        fields = form_fields(request)
        fields[param.name] = value
        return HttpRequest(
            method="POST", url=request.url,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": PROBE_ACCEPT},
            body=urlencode(fields).encode("utf-8"),
        )
    return HttpRequest(
        method="GET",
        url=mutate_query_param(request.url, param.name, value, already_encoded),
        headers={"Accept": PROBE_ACCEPT},
    )

def send_probe(transport, request: HttpRequest, param, value: str, *, already_encoded: bool = False) -> HttpResponse:
    """Send a probe built by build_probe and return the response."""
    return transport.send(build_probe(request, param, value, already_encoded=already_encoded))

def testable_inputs(request: HttpRequest) -> list:
    """Input points an active parameter test should exercise: query-string and form fields."""
    return [point for point in request.inputs if point.location in ("query", "form")]

def sanitize_request(request: HttpRequest) -> dict[str, Any]:
    return {"method": request.method, "url": request.url, "headers": redact_headers(request.headers)}

def sanitize_response(response: HttpResponse, snippet: str = "") -> dict[str, Any]:
    return {
        "status": response.status,
        "headers": redact_headers(response.headers),
        "elapsed_ms": response.elapsed_ms,
        "snippet": snippet[:400],
    }

def baseline_summary(response: HttpResponse) -> dict[str, Any]:
    return {"status": response.status, "length": len(response.body), "elapsed_ms": response.elapsed_ms}

def consistent(responses: list[HttpResponse], predicate) -> tuple[bool, int]:
    """Evaluate `predicate` against every baseline response.

    Returns the primary (first-response) result plus a reproducibility score:
    100 when every baseline response agrees, 40 when the page is flaky.
    """
    results = [predicate(response) for response in responses]
    reproducibility = 100 if len(set(results)) == 1 else 40
    return results[0], reproducibility

def contextual_severity(sensitive: bool, if_sensitive: str, if_static: str) -> str:
    return if_sensitive if sensitive else if_static

def deterministic_confidence(reproducibility: int, evidence_strength: int = 100, ambiguity: int = 0) -> ConfidenceInputs:
    """Confidence for a directly-observed fact (a header/cookie attribute is present or absent).

    Agreement across repeated baseline requests doubles as an independent
    confirmation, but passive observation alone is capped below `confirmed`
    (reserved for active differential detectors with a control probe).
    """
    return ConfidenceInputs(
        evidence_strength=evidence_strength,
        reproducibility=reproducibility,
        independent_confirmation=reproducibility,
        ambiguity=ambiguity,
    )

def build_finding(
    *,
    check_id: str,
    request: HttpRequest,
    response: HttpResponse,
    severity: str,
    reason: str,
    confidence_inputs: ConfidenceInputs,
    parameter: str | None = None,
    parameter_location: str | None = None,
    manual_review_required: bool = False,
    informational: bool = False,
    verification_count: int = 1,
    differences: dict[str, Any] | None = None,
    evidence_snippet: str = "",
    baseline: dict[str, Any] | None = None,
    catalog: dict[str, dict[str, str]] | None = None,
) -> Finding:
    entry = (catalog or CATALOG)[check_id]
    example = remediation_example(check_id)
    confidence = score(confidence_inputs)
    status = status_for(confidence, manual_review_required, informational)
    evidence = Evidence(
        reason=reason,
        baseline=baseline or baseline_summary(response),
        probe_request=sanitize_request(request),
        probe_response=sanitize_response(response, evidence_snippet),
        differences=differences or {},
        verification_count=verification_count,
    )
    return Finding(
        fingerprint=check_id,
        title=entry["title"],
        category=entry["category"],
        cwe=entry["cwe"],
        owasp=entry["owasp"],
        wstg=entry["wstg"],
        endpoint=response.url,
        # A form parameter is submitted via POST (see build_probe); a query parameter rides on
        # the URL with the base method. Reflect the channel actually used to reach the finding.
        method="POST" if parameter_location == "form" else request.method,
        parameter=parameter,
        parameter_location=parameter_location,
        severity=severity,
        confidence=confidence,
        status=status.value,
        description=entry["description"],
        evidence=evidence,
        developer_impact=entry["developer_impact"],
        remediation=entry["remediation"],
        manual_review_required=manual_review_required,
        remediation_example_vulnerable=example.get("vulnerable", ""),
        remediation_example_fixed=example.get("fixed", ""),
        remediation_example_language=example.get("language", ""),
        remediation_example_note=example.get("note", ""),
    )
