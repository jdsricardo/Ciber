"""Secrets exposure detection. Detects, masks, and reports — never uses a discovered credential."""
from __future__ import annotations
import math
import re
from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.safety import mask
from .base import PluginMetadata, ScannerPlugin
from .catalog import CATALOG
from .support import build_finding, consistent, deterministic_confidence

# High-signature formats: specific enough that a match is almost never a false positive.
HIGH_CONFIDENCE_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
]

# Generic heuristic: a well-known field name assigned a long, high-entropy value.
HEURISTIC_PATTERN = re.compile(
    r'(?i)\b(api[_-]?key|secret|access[_-]?token|client[_-]?secret|password|passwd|connection[_-]?string)'
    r'["\'\s:=]+([A-Za-z0-9+/_.\-]{16,80})',
)
PLACEHOLDER_VALUES = {"changeme", "your_api_key_here", "xxxxxxxx", "example", "replace_with_a_strong_password"}

def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

class SecretsExposurePlugin(ScannerPlugin):
    metadata = PluginMetadata(
        name="Secrets Exposure",
        category="Secrets Exposure",
        cwe="CWE-798",
        owasp="A02:2025 Security Misconfiguration",
        wstg="WSTG-INFO-05",
        kind="passive",
        risk="none",
        checks=("secrets.high_confidence_pattern", "secrets.heuristic_pattern"),
    )

    def analyze(self, request: HttpRequest, responses: list[HttpResponse], context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        primary = responses[0]
        body = primary.body.decode("utf-8", errors="replace")
        seen: set[str] = set()

        for name, pattern in HIGH_CONFIDENCE_PATTERNS:
            match = pattern.search(body)
            if not match or match.group(0) in seen:
                continue
            seen.add(match.group(0))
            _, reproducibility = consistent(responses, lambda r: bool(pattern.search(r.body.decode("utf-8", errors="replace"))))
            findings.append(build_finding(
                check_id="secrets.high_confidence_pattern", request=request, response=primary,
                severity="critical",
                reason=f"Matched the {name} format.",
                confidence_inputs=deterministic_confidence(reproducibility, evidence_strength=95),
                manual_review_required=True,
                evidence_snippet=f"{name}: {mask(match.group(0))}",
            ))

        for match in HEURISTIC_PATTERN.finditer(body):
            value = match.group(2)
            if value in seen or value.lower() in PLACEHOLDER_VALUES or len(set(value)) < 6:
                continue
            entropy = _shannon_entropy(value)
            if entropy < 3.2:
                continue
            seen.add(value)
            # A value that changes between baseline requests is very likely a per-request
            # nonce/CSRF/session token rather than a static hard-coded secret.
            if not all(value in r.body.decode("utf-8", errors="replace") for r in responses):
                continue
            findings.append(build_finding(
                check_id="secrets.heuristic_pattern", request=request, response=primary,
                severity="high",
                reason=f"Field name '{match.group(1)}' is followed by a {len(value)}-character, high-entropy value (entropy={entropy:.2f}) that is stable across repeated requests.",
                confidence_inputs=deterministic_confidence(100, evidence_strength=55, ambiguity=25),
                manual_review_required=True,
                evidence_snippet=f"{match.group(1)}: {mask(value)}",
            ))
        return findings
