"""Path Traversal / Local File Inclusion: differential detection of OS-file disclosure
through query-string parameters that plausibly reference a file, path, or template.

Methodology per parameter (bounded, stop-on-evidence):
  1. The baseline response for the parameter's original value is already `responses[0]`
     (or `responses[1]`); no extra request is needed for it.
  2. Send one OS-appropriate traversal probe using only well-known, harmless files
     (`/etc/passwd`, `windows\\win.ini`). If the OS cannot be guessed from response
     headers, try Unix first, then Windows, stopping as soon as one hits.
  3. If a probe's response contains the file's content signature and the baseline
     responses never do, send a negative control (a similarly-shaped but nonexistent
     filename, no traversal) to rule out a route that echoes the same content for
     any input.
  4. If the control does not also match, send a second, independently-encoded probe
     (here: extra traversal depth) to confirm. Both probes agreeing -> confirmed,
     critical. Only the first agreeing -> reported but manual_review_required.
  5. If no OS-file signature is ever found but the traversal payload behaves
     differently from the negative control (status code differs), report a lower
     severity, manual-review "suspicious behavior" finding instead of staying silent.

Never targets `.env`, credentials, private keys, SSH keys, or application source —
only generic, low-sensitivity OS files whose signatures are unambiguous.
"""
from __future__ import annotations
import re
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.transport import HttpTransport
from ..base import PluginMetadata, ScannerPlugin
from ..support import build_finding, consistent, mutate_query_param
from engine.confidence import ConfidenceInputs

CATALOG: dict[str, dict[str, str]] = {
    "path_traversal.file_disclosure": {
        "title": "Divulgação de arquivo do sistema operacional via travessia de diretório",
        "category": "Path Traversal / Inclusão de Arquivo",
        "cwe": "CWE-22",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-ATHZ-01",
        "description": "Um parâmetro que referencia um arquivo aceitou uma sequência de travessia de diretório e a resposta passou a conter o conteúdo de um arquivo do sistema operacional.",
        "developer_impact": "Um atacante pode ler arquivos arbitrários do sistema de arquivos do servidor, incluindo arquivos de configuração e, dependendo das permissões do processo, arquivos ainda mais sensíveis.",
        "remediation": "Nunca monte caminhos de arquivo diretamente a partir de entrada do usuário; resolva o caminho canônico e valide, por allowlist, que ele permanece dentro do diretório base permitido, rejeitando qualquer valor que contenha sequências de travessia ('..') ou que resolva para fora do diretório esperado.",
    },
    "path_traversal.suspicious_behavior": {
        "title": "Parâmetro de arquivo reage de forma diferente a sequências de travessia",
        "category": "Path Traversal / Inclusão de Arquivo",
        "cwe": "CWE-22",
        "owasp": "A01:2025 Broken Access Control",
        "wstg": "WSTG-ATHZ-01",
        "description": "Um parâmetro que referencia um arquivo produziu uma resposta claramente diferente para uma sequência de travessia de diretório em comparação com um valor de controle inexistente, mas nenhum conteúdo de arquivo do sistema operacional foi confirmado.",
        "developer_impact": "O comportamento diferenciado sugere que a entrada influencia a resolução de caminho no servidor. Isso pode indicar uma travessia de diretório parcialmente mitigada, que merece confirmação manual.",
        "remediation": "Revise manualmente como o parâmetro é utilizado para acessar o sistema de arquivos e aplique validação por allowlist do caminho já resolvido.",
    },
}

CANDIDATE_NAME_PATTERN = re.compile(r"file|page|path|doc|template|include|lang|view|download", re.I)
UNIX_SIGNATURE = re.compile(r"root:.*?:0:0:")
WINDOWS_SIGNATURE = re.compile(r"\[fonts\]|for 16-bit app support", re.I)
CONTROL_VALUE = "nonexistent-file-zzqx.txt"

PROBES = {
    "unix": {
        "probe": "../" * 6 + "etc/passwd",
        "confirm": "../" * 10 + "etc/passwd",
        "signature": UNIX_SIGNATURE,
        "label": "/etc/passwd",
    },
    "windows": {
        "probe": "..\\" * 6 + "windows\\win.ini",
        "confirm": "..\\" * 10 + "windows\\win.ini",
        "signature": WINDOWS_SIGNATURE,
        "label": "windows\\win.ini",
    },
}


def _looks_like_file_path(value: str) -> bool:
    if not value:
        return False
    if "/" in value or "\\" in value:
        return True
    return bool(re.search(r"\.[A-Za-z0-9]{1,5}$", value))


def _os_order(responses: list[HttpResponse]) -> list[str]:
    primary = responses[0]
    hints = f"{primary.headers.get('server', '')} {primary.headers.get('x-powered-by', '')}".lower()
    if any(token in hints for token in ("iis", "asp.net", "win32", "windows")):
        return ["windows", "unix"]
    return ["unix", "windows"]


def _decode(response: HttpResponse) -> str:
    return response.body.decode("utf-8", errors="replace")


class PathTraversalPlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Path Traversal / LFI",
        category="Path Traversal / Inclusão de Arquivo",
        cwe="CWE-22",
        owasp="A01:2025 Broken Access Control",
        wstg="WSTG-ATHZ-01",
        kind="safe_active",
        risk="low",
        checks=("path_traversal.file_disclosure", "path_traversal.suspicious_behavior"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext, transport: HttpTransport | None = None) -> list[Finding]:
        if transport is None:
            return []
        findings: list[Finding] = []
        for point in request.inputs:
            if point.location != "query":
                continue
            if not (CANDIDATE_NAME_PATTERN.search(point.name) or _looks_like_file_path(point.value)):
                continue
            finding = self._test_parameter(request, point, responses, transport)
            if finding is not None:
                findings.append(finding)
        return findings

    def _send(self, template: HttpRequest, transport: HttpTransport, url: str) -> tuple[HttpRequest, HttpResponse]:
        probe_request = HttpRequest(method=template.method, url=url, headers=dict(template.headers))
        return probe_request, transport.send(probe_request)

    def _test_parameter(self, request: HttpRequest, point, responses: list[HttpResponse], transport: HttpTransport) -> Finding | None:
        order = _os_order(responses)
        matched_os = None
        matched_request = matched_response = None
        matched_match = None
        last_request = last_response = None
        last_payload = None

        for os_name in order:
            payload = PROBES[os_name]["probe"]
            url = mutate_query_param(request.url, point.name, payload)
            probe_request, probe_response = self._send(request, transport, url)
            last_request, last_response, last_payload = probe_request, probe_response, payload
            match = PROBES[os_name]["signature"].search(_decode(probe_response))
            if match:
                matched_os, matched_request, matched_response, matched_match = os_name, probe_request, probe_response, match
                break

        if matched_os is None:
            return self._suspicious_behavior_finding(request, point, responses, transport, last_request, last_response, last_payload)

        signature = PROBES[matched_os]["signature"]
        baseline_has_signature, reproducibility = consistent(
            responses, lambda r: bool(signature.search(_decode(r)))
        )
        if baseline_has_signature:
            # The signature already appears with the parameter's original value: it
            # cannot be used as distinguishing evidence of traversal for this endpoint.
            return None

        control_url = mutate_query_param(request.url, point.name, CONTROL_VALUE)
        _, control_response = self._send(request, transport, control_url)
        if signature.search(_decode(control_response)):
            # A similarly-shaped, nonexistent value produces the same signature: the
            # app returns this content regardless of input, not a real traversal.
            return None

        confirm_payload = PROBES[matched_os]["confirm"]
        confirm_url = mutate_query_param(request.url, point.name, confirm_payload)
        confirm_request, confirm_response = self._send(request, transport, confirm_url)
        confirmed = bool(signature.search(_decode(confirm_response)))

        body = _decode(matched_response)
        snippet = body[max(0, matched_match.start() - 20): matched_match.end() + 20]
        label = PROBES[matched_os]["label"]
        reason = (
            f"O parâmetro '{point.name}' recebeu o payload de travessia '{last_payload if matched_os else ''}' "
            f"e a resposta passou a conter a assinatura de conteúdo de '{label}' ('{matched_match.group(0)}'), "
            f"ausente tanto na linha de base quanto em um valor de controle inexistente. "
            + (
                "Um segundo payload com profundidade adicional de travessia confirmou o mesmo padrão."
                if confirmed else
                "Um segundo payload com profundidade adicional de travessia NÃO reproduziu o padrão, "
                "portanto recomenda-se confirmação manual."
            )
        )

        confidence_inputs = ConfidenceInputs(
            evidence_strength=95,
            reproducibility=reproducibility,
            differential_quality=95,
            independent_confirmation=100 if confirmed else 25,
            ambiguity=0 if confirmed else 25,
        )

        return build_finding(
            check_id="path_traversal.file_disclosure",
            request=matched_request,
            response=matched_response,
            severity="critical",
            reason=reason,
            confidence_inputs=confidence_inputs,
            parameter=point.name,
            parameter_location=point.location,
            manual_review_required=not confirmed,
            evidence_snippet=snippet,
            differences={"confirmed_with_second_payload": confirmed, "os_guess": matched_os},
            catalog=CATALOG,
        )

    def _suspicious_behavior_finding(self, request, point, responses, transport, last_request, last_response, last_payload) -> Finding | None:
        if last_response is None:
            return None
        control_url = mutate_query_param(request.url, point.name, CONTROL_VALUE)
        control_request, control_response = self._send(request, transport, control_url)
        baseline = responses[0]

        status_diff = last_response.status != control_response.status
        probe_len, control_len = len(last_response.body), len(control_response.body)
        relative_diff = abs(probe_len - control_len) / max(1, control_len)
        baseline_matches_control_status = baseline.status == control_response.status

        if not (status_diff and baseline_matches_control_status) and relative_diff <= 0.5:
            return None

        reason = (
            f"O parâmetro '{point.name}' respondeu de forma diferente a um payload de travessia de diretório "
            f"('{last_payload}': status {last_response.status}, {probe_len} bytes) em comparação com um valor de "
            f"controle inexistente e sem sequência de travessia ('{CONTROL_VALUE}': status {control_response.status}, "
            f"{control_len} bytes). Nenhuma assinatura de arquivo do sistema operacional foi encontrada, portanto "
            "isto é reportado como comportamento suspeito, não como divulgação confirmada."
        )
        confidence_inputs = ConfidenceInputs(
            evidence_strength=40,
            reproducibility=60,
            differential_quality=60 if status_diff else 40,
            independent_confirmation=0,
            ambiguity=30,
        )
        return build_finding(
            check_id="path_traversal.suspicious_behavior",
            request=last_request,
            response=last_response,
            severity="medium",
            reason=reason,
            confidence_inputs=confidence_inputs,
            parameter=point.name,
            parameter_location=point.location,
            manual_review_required=True,
            differences={
                "status_probe": last_response.status, "status_control": control_response.status,
                "length_probe": probe_len, "length_control": control_len,
            },
            catalog=CATALOG,
        )
