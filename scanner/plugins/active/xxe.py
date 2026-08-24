"""XML External Entity (XXE) injection: endpoint-level probe for XML entity processing.

Unlike the parameter-fuzzing detectors in this package, XXE is a property of the
*endpoint* -- does it parse attacker-supplied XML at all, and if so, does it resolve
external entities -- not of any individual query/form parameter. This plugin therefore
runs at most one small, fixed chain of probes against the target URL itself, only when
there is some signal the endpoint might parse XML:

  1. a well-formed XML body with no DOCTYPE, to confirm the endpoint accepts XML at all
     (a 404/405/415 here means there is no XML endpoint to test, so we stop);
  2. a body defining and referencing a harmless internal entity, to confirm the parser
     processes DOCTYPE declarations and substitutes entities -- this alone is not
     dangerous (most parsers do this safely) but narrows down whether escalating is
     even worth it;
  3. only if (2) shows substitution, a body defining an external SYSTEM entity that
     points at a reserved, always-NXDOMAIN `.invalid` host, to see whether the response
     timing or error text differs from the internal-only probe in a way that suggests
     the parser attempted to resolve/contact the external entity.

Because `.invalid` never resolves, step 3 can never succeed in actually fetching
anything -- the differential itself (a DNS-resolution-shaped delay or a reflected
resolution error) is the evidence, not the content of any fetched resource. No
file:// or PHP-wrapper payloads are ever sent, and a timing differential is only
reported after a repeat measurement confirms it, in the same spirit as this
project's time-based SQLi caution.
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from engine.confidence import ConfidenceInputs
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from ..base import PluginMetadata, ScannerPlugin
from ..support import baseline_summary, build_finding

MARKER = "SENTINELSCOPE_XXE_PROOF_7331"
CANARY_HOST = "sentinelscope-xxe-canary.invalid"

XML_PATH_HINT = re.compile(r"/api/|/xml|/soap|/rest|\.xml$", re.I)
DNS_FAILURE_TEXT = re.compile(
    r"could not resolve|getaddrinfo|name or service not known|"
    r"name resolution|resolve host|timed out|timeout",
    re.I,
)

TIMING_DELTA_THRESHOLD_MS = 400
REJECTED_STATUSES = {404, 405, 415}

CONTROL_BODY = b'<?xml version="1.0"?>\n<root>sentinelscope-control</root>'
INTERNAL_ENTITY_BODY = (
    '<?xml version="1.0"?>\n'
    f'<!DOCTYPE root [ <!ENTITY sentinelscope_marker "{MARKER}"> ]>\n'
    '<root>&sentinelscope_marker;</root>'
).encode()
EXTERNAL_ENTITY_BODY = (
    '<?xml version="1.0"?>\n'
    f'<!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://{CANARY_HOST}/probe"> ]>\n'
    '<root>&xxe;</root>'
).encode()

CATALOG: dict[str, dict[str, str]] = {
    "xxe.internal_entity_expansion": {
        "title": "Processamento de entidades XML internas detectado",
        "category": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-07",
        "description": (
            "O endpoint aceita XML enviado via POST e substitui pelo valor declarado uma "
            "entidade interna definida em uma seção DOCTYPE, confirmando que o parser XML "
            "processa DOCTYPE e entidades."
        ),
        "developer_impact": (
            "Isoladamente, a expansão de entidades internas não expõe dados, mas é uma "
            "pré-condição necessária para uma falha de XXE mais grave (leitura de arquivos, "
            "SSRF ou negação de serviço) caso a resolução de entidades externas também "
            "esteja habilitada no mesmo parser."
        ),
        "remediation": (
            "Desabilite o processamento de DOCTYPE e a resolução de entidades externas no "
            "parser XML (por exemplo, defusedxml em Python, "
            "`libxml_disable_entity_loader(true)` em PHP, ou a opção equivalente do parser "
            "utilizado)."
        ),
    },
    "xxe.external_entity_processing_suspected": {
        "title": "Possível resolução de entidade externa (XXE) habilitada",
        "category": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "owasp": "A05:2025 Injection",
        "wstg": "WSTG-INPV-07",
        "description": (
            "Uma entidade externa SYSTEM apontando para um domínio reservado e inexistente "
            "(.invalid) produziu uma resposta com tempo ou texto de erro observavelmente "
            "diferente da sonda apenas com entidade interna, sugerindo uma tentativa do "
            "servidor de resolver ou contatar a entidade externa."
        ),
        "developer_impact": (
            "Se a resolução de entidades externas estiver habilitada, um atacante pode usar "
            "XXE para ler arquivos locais, forjar requisições internas (SSRF) ou exfiltrar "
            "dados fora de banda através do parser XML do servidor."
        ),
        "remediation": (
            "Desabilite explicitamente a resolução de entidades externas e o processamento "
            "de DOCTYPE no parser XML em uso, e valide que apenas entidades predefinidas do "
            "XML sejam aceitas."
        ),
    },
}


def _post_xml(transport, url: str, body: bytes) -> tuple[HttpRequest, HttpResponse]:
    probe = HttpRequest(method="POST", url=url, headers={"Content-Type": "application/xml"}, body=body)
    return probe, transport.send(probe)


def _differs_from_baseline(baseline_elapsed_ms: int, candidate: HttpResponse) -> tuple[bool, int]:
    delta = candidate.elapsed_ms - baseline_elapsed_ms
    body_text = candidate.body.decode("utf-8", errors="replace")
    return (delta >= TIMING_DELTA_THRESHOLD_MS or bool(DNS_FAILURE_TEXT.search(body_text))), delta


class XxePlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="XML External Entity",
        category="XML External Entity (XXE)",
        cwe="CWE-611",
        owasp="A05:2025 Injection",
        wstg="WSTG-INPV-07",
        kind="safe_active",
        risk="low",
        checks=("xxe.internal_entity_expansion", "xxe.external_entity_processing_suspected"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport=None) -> list[Finding]:
        findings: list[Finding] = []
        if transport is None:
            return findings

        primary = responses[0]
        content_type = primary.headers.get("content-type", "")
        path = urlparse(request.url).path or "/"
        looks_like_xml_endpoint = "xml" in content_type.lower() or bool(XML_PATH_HINT.search(path))
        if not looks_like_xml_endpoint:
            # No signal at all that this endpoint parses XML: XXE is an endpoint-level
            # property, not a per-parameter one, so we do not fuzz blindly here.
            return findings

        _, control_response = _post_xml(transport, request.url, CONTROL_BODY)
        if control_response.status in REJECTED_STATUSES:
            # Endpoint flatly rejects a POST XML body: nothing to test here.
            return findings

        internal_probe, internal_response = _post_xml(transport, request.url, INTERNAL_ENTITY_BODY)
        internal_body = internal_response.body.decode("utf-8", errors="replace")
        if MARKER not in internal_body:
            # Parser is well-formed-only / hardened: it never substituted the internal
            # entity, so there is no basis for escalating to the external-entity probe.
            return findings

        internal_elapsed = internal_response.elapsed_ms
        _, external_response_1 = _post_xml(transport, request.url, EXTERNAL_ENTITY_BODY)
        differs_1, delta_1 = _differs_from_baseline(internal_elapsed, external_response_1)

        confirmed_external = False
        external_probe_2 = external_response_2 = None
        delta_2 = delta_1
        if differs_1:
            # Timing/error-based evidence needs a repeat measurement before it is
            # trusted, the same caution this project applies to time-based SQLi.
            external_probe_2, external_response_2 = _post_xml(transport, request.url, EXTERNAL_ENTITY_BODY)
            confirmed_external, delta_2 = _differs_from_baseline(internal_elapsed, external_response_2)

        if confirmed_external:
            findings.append(build_finding(
                check_id="xxe.external_entity_processing_suspected",
                request=external_probe_2,
                response=external_response_2,
                severity="high",
                reason=(
                    "O endpoint substituiu a entidade interna, confirmando que DOCTYPE/entidades "
                    f"são processados. Em duas medições consecutivas, a sonda com entidade externa "
                    f"SYSTEM para um host .invalid levou {external_response_2.elapsed_ms}ms contra "
                    f"{internal_elapsed}ms da sonda somente-interna (Δ={delta_2}ms), sugerindo uma "
                    "tentativa de resolução ou contato de rede para a entidade externa."
                ),
                confidence_inputs=ConfidenceInputs(
                    evidence_strength=70, reproducibility=100,
                    differential_quality=60, independent_confirmation=50, ambiguity=15,
                ),
                parameter=None,
                parameter_location="body",
                manual_review_required=True,
                baseline=baseline_summary(internal_response),
                differences={
                    "internal_entity_elapsed_ms": internal_elapsed,
                    "external_entity_elapsed_ms_first": external_response_1.elapsed_ms,
                    "external_entity_elapsed_ms_second": external_response_2.elapsed_ms,
                    "timing_delta_ms": delta_2,
                },
                evidence_snippet=external_response_2.body.decode("utf-8", errors="replace"),
                catalog=CATALOG,
            ))
        else:
            findings.append(build_finding(
                check_id="xxe.internal_entity_expansion",
                request=internal_probe,
                response=internal_response,
                severity="medium",
                reason=(
                    f"O endpoint substituiu a entidade interna &sentinelscope_marker; pelo valor "
                    f"declarado ({MARKER}), confirmando que DOCTYPE/entidades são processados. A "
                    "sonda de acompanhamento com entidade externa SYSTEM para um host .invalid não "
                    "apresentou uma diferença de tempo ou erro consistente em relação à sonda "
                    "somente-interna, portanto não há evidência suficiente de resolução de entidade "
                    "externa."
                ),
                confidence_inputs=ConfidenceInputs(evidence_strength=80, reproducibility=70, ambiguity=10),
                parameter=None,
                parameter_location="body",
                manual_review_required=True,
                baseline=baseline_summary(control_response),
                differences={
                    "internal_entity_elapsed_ms": internal_elapsed,
                    "external_entity_elapsed_ms": external_response_1.elapsed_ms,
                    "timing_delta_ms": delta_1,
                },
                evidence_snippet=internal_body,
                catalog=CATALOG,
            ))
        return findings
