from __future__ import annotations
from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any

class ScanMode(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    AUTHENTICATED = "authenticated"

class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    HIGH_CONFIDENCE = "high_confidence"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    INFORMATIONAL = "informational"
    MANUAL_REVIEW = "manual_review_required"

@dataclass(frozen=True)
class InputPoint:
    location: str
    name: str
    value: str
    data_type: str = "string"
    @property
    def identifier(self) -> str:
        return sha256(f"{self.location}:{self.name}".encode()).hexdigest()[:16]

@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    inputs: list[InputPoint] = field(default_factory=list)

@dataclass
class HttpResponse:
    status: int
    url: str
    headers: dict[str, str]
    header_pairs: list[tuple[str, str]]
    body: bytes
    elapsed_ms: int
    redirect_url: str | None = None
    tls_protocol: str | None = None
    certificate: dict[str, Any] = field(default_factory=dict)

@dataclass
class ResponseSummary:
    status: int
    length: int
    normalized_hash: str
    normalized_text: str
    structure: list[str]
    elapsed_ms: int

@dataclass
class ResponseDiff:
    similarity: float
    status_changed: bool
    length_delta: int
    added_headers: list[str]
    removed_headers: list[str]
    structure_changed: bool
    timing_delta_ms: int

@dataclass
class Evidence:
    reason: str
    baseline: dict[str, Any]
    probe_request: dict[str, Any]
    probe_response: dict[str, Any]
    differences: dict[str, Any]
    verification_count: int = 1

@dataclass
class Finding:
    fingerprint: str
    title: str
    category: str
    cwe: str
    owasp: str
    wstg: str
    endpoint: str
    method: str
    parameter: str | None
    parameter_location: str | None
    severity: str
    confidence: int
    status: str
    description: str
    evidence: Evidence
    developer_impact: str
    remediation: str
    manual_review_required: bool = False
    remediation_example_vulnerable: str = ""
    remediation_example_fixed: str = ""
    remediation_example_language: str = ""
    remediation_example_note: str = ""
    def to_dict(self) -> dict[str, Any]:
        """The JSON shape PHP stores. The two aliases exist because the database and the UI
        name these fields after what they mean to a developer, not after the engine internals."""
        data = asdict(self)
        data["affected_url"] = self.endpoint
        data["evidence_summary"] = self.evidence.reason
        return data

@dataclass
class ScanLimits:
    max_requests: int = 40
    max_requests_per_endpoint: int = 12
    max_response_bytes: int = 262_144
    request_timeout_seconds: float = 10.0
    global_timeout_seconds: float = 60.0
    min_request_interval_seconds: float = 0.15
    max_redirects: int = 3
    # Crawl bounds: max_pages caps how many distinct pages a single scan visits; max_depth caps
    # how far (in links followed) the crawler travels from the seed URL. Both are enforced in the
    # runner's breadth-first walk. A default of 1 means "scan only the URL given" — the passive
    # and active profiles raise it so a scan explores the whole reachable, same-origin surface.
    max_pages: int = 1
    max_depth: int = 2
    max_attempts_per_parameter: int = 4

@dataclass
class PageContext:
    """Contextual signals used to keep severity/confidence proportionate instead of flat rules."""
    has_forms: bool = False
    has_password_field: bool = False
    sets_cookies: bool = False
    is_html: bool = False
    is_json: bool = False
    looks_authenticated: bool = False

@dataclass
class ScanContext:
    target_url: str
    mode: ScanMode
    limits: ScanLimits
    allow_private: bool = False
    cancel_file: str | None = None
    log_file: str | None = None
    page: PageContext | None = None
    # Headers attached to every request (e.g. an authenticated session Cookie or a
    # Bearer token), enabling scans of authenticated areas. Only ever sent to the pinned,
    # authorized host/port (scope enforcement guarantees this) and redacted in logs.
    auth_headers: dict[str, str] = field(default_factory=dict)
