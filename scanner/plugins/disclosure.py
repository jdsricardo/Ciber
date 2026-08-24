"""Information disclosure: version fingerprints, error details, directory listings, source maps, mixed content."""
from __future__ import annotations
import re
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from .base import PluginMetadata, ScannerPlugin
from .catalog import CATALOG
from .support import build_finding, consistent, deterministic_confidence

ERROR_PATTERN = re.compile(
    r"traceback \(most recent call last\)|fatal error:|uncaught (?:exception|error)|"
    r"stack trace:|sqlstate\[|at [\w.$]+\([\w.]+:\d+\)|django\.core\.exceptions|"
    r"org\.springframework|System\.NullReferenceException",
    re.I,
)
DIRECTORY_INDEX = re.compile(r"<title>\s*index of\s*/|<h1>\s*index of\s*/", re.I)
SOURCE_MAP_REFERENCE = re.compile(r"sourceMappingURL\s*=", re.I)
HTTP_RESOURCE = re.compile(r'(?:src|href|action)\s*=\s*["\']http://', re.I)
PASSWORD_INPUT = re.compile(r'type=["\']?password', re.I)

class InformationDisclosurePlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Information Disclosure",
        category="Information Disclosure",
        cwe="CWE-200,CWE-209,CWE-548,CWE-540,CWE-319",
        owasp="A02:2025 Security Misconfiguration",
        wstg="WSTG-INFO-02,WSTG-INFO-05,WSTG-INFO-08,WSTG-ERRH-01,WSTG-CONF-04",
        kind="passive",
        risk="none",
        checks=(
            "disclosure.server_header", "disclosure.powered_by_header", "disclosure.stack_trace",
            "disclosure.directory_listing", "disclosure.source_map", "disclosure.mixed_content",
            "disclosure.password_over_http",
        ),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport=None) -> list[Finding]:
        findings: list[Finding] = []
        primary = responses[0]
        body = primary.body.decode("utf-8", errors="replace")
        is_https = request.url.startswith("https://")

        if primary.headers.get("server"):
            present, reproducibility = consistent(responses, lambda r: bool(r.headers.get("server")))
            findings.append(build_finding(
                check_id="disclosure.server_header", request=request, response=primary, severity="low",
                reason=CATALOG["disclosure.server_header"]["description"],
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=90),
                evidence_snippet=f"Server: {primary.headers['server']}",
            ))
        if primary.headers.get("x-powered-by"):
            _, reproducibility = consistent(responses, lambda r: bool(r.headers.get("x-powered-by")))
            findings.append(build_finding(
                check_id="disclosure.powered_by_header", request=request, response=primary, severity="low",
                reason=CATALOG["disclosure.powered_by_header"]["description"],
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=90),
                evidence_snippet=f"X-Powered-By: {primary.headers['x-powered-by']}",
            ))

        match = ERROR_PATTERN.search(body)
        if match:
            _, reproducibility = consistent(responses, lambda r: bool(ERROR_PATTERN.search(r.body.decode("utf-8", errors="replace"))))
            reproduced = reproducibility == 100
            findings.append(build_finding(
                check_id="disclosure.stack_trace", request=request, response=primary,
                severity="high" if reproduced else "medium",
                reason=f"Padrão encontrado próximo de: ...{body[max(0, match.start() - 30):match.end() + 30]}...",
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=70, ambiguity=15),
                manual_review_required=not reproduced,
                evidence_snippet=match.group(0),
            ))
        if DIRECTORY_INDEX.search(body):
            _, reproducibility = consistent(responses, lambda r: bool(DIRECTORY_INDEX.search(r.body.decode("utf-8", errors="replace"))))
            findings.append(build_finding(
                check_id="disclosure.directory_listing", request=request, response=primary, severity="medium",
                reason=CATALOG["disclosure.directory_listing"]["description"],
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=80, ambiguity=10),
            ))
        if "sourcemap" in primary.headers or "x-sourcemap" in primary.headers or SOURCE_MAP_REFERENCE.search(body):
            _, reproducibility = consistent(responses, lambda r: "sourcemap" in r.headers or "x-sourcemap" in r.headers or bool(SOURCE_MAP_REFERENCE.search(r.body.decode("utf-8", errors="replace"))))
            findings.append(build_finding(
                check_id="disclosure.source_map", request=request, response=primary, severity="low",
                reason=CATALOG["disclosure.source_map"]["description"],
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=90),
            ))
        if is_https and HTTP_RESOURCE.search(body):
            _, reproducibility = consistent(responses, lambda r: bool(HTTP_RESOURCE.search(r.body.decode("utf-8", errors="replace"))))
            findings.append(build_finding(
                check_id="disclosure.mixed_content", request=request, response=primary, severity="medium",
                reason=CATALOG["disclosure.mixed_content"]["description"],
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=85),
                evidence_snippet=HTTP_RESOURCE.search(body).group(0),
            ))
        if not is_https and PASSWORD_INPUT.search(body):
            _, reproducibility = consistent(responses, lambda r: bool(PASSWORD_INPUT.search(r.body.decode("utf-8", errors="replace"))))
            findings.append(build_finding(
                check_id="disclosure.password_over_http", request=request, response=primary, severity="critical",
                reason=CATALOG["disclosure.password_over_http"]["description"],
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=95),
            ))
        return findings
