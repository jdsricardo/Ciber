"""Comparison-ready views of an HTTP response.

Two requests to the same page are never byte-identical: timestamps, UUIDs, CSRF tokens and
nonces change on every render. Every comparison in the engine therefore runs on the normalized
text produced here, so a detector measures the difference its probe caused and not the noise
the application produces on its own.
"""
from __future__ import annotations

import json
import re
from difflib import SequenceMatcher
from hashlib import sha256
from html.parser import HTMLParser

from .models import HttpResponse, PageContext, ResponseDiff, ResponseSummary

# Content that legitimately changes between two identical requests, and the placeholder each
# is collapsed to before anything is compared.
VOLATILE = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+Z-]+\b"), "<TIMESTAMP>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I), "<UUID>"),
    (re.compile(r"\b[0-9a-f]{24,}\b", re.I), "<HEX>"),
    (re.compile(r'(?i)(csrf|nonce|token)(["\'\s:=]+)[A-Za-z0-9_./+-]{8,}'), r"\1\2<VOLATILE>"),
]


class StructureParser(HTMLParser):
    """Collects the tag sequence of a document: its shape, independent of its text."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag.lower())


def normalize_text(body: bytes, content_type: str = "") -> str:
    """Decode, canonicalize and strip volatile content, so two renders become comparable."""
    text = body.decode("utf-8", errors="replace")
    if "json" in content_type:
        try:
            text = json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))
        except (ValueError, TypeError):
            pass
    for pattern, replacement in VOLATILE:
        text = pattern.sub(replacement, text)
    return re.sub(r"\s+", " ", text).strip()


def summarize(response: HttpResponse) -> ResponseSummary:
    """The comparable form of one response: normalized text, its hash, and its tag structure."""
    content_type = response.headers.get("content-type", "")
    normalized = normalize_text(response.body, content_type)

    parser = StructureParser()
    if "html" in content_type or normalized.startswith("<"):
        try:
            parser.feed(normalized)
        except Exception:
            pass

    return ResponseSummary(
        response.status,
        len(response.body),
        sha256(normalized.encode()).hexdigest(),
        normalized,
        parser.tags,
        response.elapsed_ms,
    )


def compare(
    left: ResponseSummary,
    right: ResponseSummary,
    left_headers: dict[str, str] | None = None,
    right_headers: dict[str, str] | None = None,
) -> ResponseDiff:
    """Everything a detector needs to judge whether a probe changed the response."""
    left_keys = set((left_headers or {}).keys())
    right_keys = set((right_headers or {}).keys())
    similarity = SequenceMatcher(None, left.normalized_text, right.normalized_text).ratio()

    return ResponseDiff(
        round(similarity, 4),
        left.status != right.status,
        right.length - left.length,
        sorted(right_keys - left_keys),
        sorted(left_keys - right_keys),
        left.structure != right.structure,
        right.elapsed_ms - left.elapsed_ms,
    )


def build_page_context(response: HttpResponse) -> PageContext:
    """Signals used to keep severity proportionate: a missing cookie flag matters more on a
    page that actually sets a session than on a static page that sets nothing."""
    content_type = response.headers.get("content-type", "")
    body_lower = response.body.decode("utf-8", errors="replace").lower()
    has_session_cookie = any(
        key.lower() == "set-cookie" and re.search(r"(?i)(sess|auth|token|logged)", value)
        for key, value in response.header_pairs
    )

    return PageContext(
        has_forms="<form" in body_lower,
        has_password_field=bool(re.search(r'type=["\']?password', body_lower)),
        sets_cookies=any(key.lower() == "set-cookie" for key, _ in response.header_pairs),
        is_html="html" in content_type,
        is_json="json" in content_type,
        looks_authenticated=has_session_cookie or "authorization" in response.headers,
    )


def baseline_stability(summaries: list[ResponseSummary]) -> float:
    """How alike the independent baseline responses were, from 0.0 to 1.0.

    A page that differs from itself cannot support a differential conclusion, so detectors use
    this to hold back confidence instead of reporting noise as a finding.
    """
    if len(summaries) < 2:
        return 1.0
    scores = [
        SequenceMatcher(None, summaries[i - 1].normalized_text, summaries[i].normalized_text).ratio()
        for i in range(1, len(summaries))
    ]
    return round(sum(scores) / len(scores), 4)
