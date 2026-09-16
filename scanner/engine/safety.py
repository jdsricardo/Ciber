"""Scope, budget and rate enforcement — the guard every request passes through.

Nothing in the engine opens a socket without first calling `SafetyController.before_request`,
which is what makes the scanner's promises checkable in one place: the scan stays on the
authorized host and port, never exceeds its request or time budget, and can be cancelled.
"""
from __future__ import annotations

import json
import os
import socket
import time
from collections import Counter
from ipaddress import ip_address
from threading import Lock
from urllib.parse import urljoin, urlparse

from .models import HttpRequest, ScanContext

SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


class Cancelled(RuntimeError):
    """The operator asked for the scan to stop."""


class BudgetExceeded(RuntimeError):
    """The scan reached its global request or time budget."""


class EndpointBudgetExceeded(BudgetExceeded):
    """One endpoint reached its own probe cap.

    A per-endpoint cap is a local limit: it means "stop probing THIS endpoint", not "abort the
    whole scan". It subclasses BudgetExceeded so existing broad handlers still catch it, while
    the crawl loop can tell it apart from a global budget and simply move to the next page.
    """


class ScopeViolation(ValueError):
    """A request tried to leave the authorized host, port or scheme."""


def mask(value: str) -> str:
    """Enough of a secret to correlate log lines, never enough to reuse it."""
    if len(value) < 8:
        return "***"
    return value[:3] + "***" + value[-2:]


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: (mask(value) if key.lower() in SENSITIVE_HEADERS else value)
        for key, value in headers.items()
    }


class SafetyController:
    """Owns the scan's scope and budget. One instance is shared by crawling and probing."""

    def __init__(self, context: ScanContext) -> None:
        self.context = context
        self.started = time.monotonic()
        self.total = 0
        self.per_endpoint: Counter[str] = Counter()
        self.last_request = 0.0
        self.lock = Lock()

        parsed = urlparse(context.target_url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if self.scheme not in ("http", "https") or not self.host:
            raise ScopeViolation("Only absolute HTTP(S) targets are supported")
        self.pinned_addresses = self._resolve(self.host)

    def _resolve(self, host: str) -> set[str]:
        addresses = {item[4][0].split("%")[0] for item in socket.getaddrinfo(host, None)}
        if not addresses:
            raise ScopeViolation("Target did not resolve")
        if not self.context.allow_private and any(not ip_address(x).is_global for x in addresses):
            raise ScopeViolation("Private, loopback, link-local, and reserved targets are blocked")
        return addresses

    def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
            raise ScopeViolation("Unsafe URL scheme or embedded credentials")
        if parsed.hostname != self.host or port != self.port:
            raise ScopeViolation("Request attempted to leave the authorized host and port")
        # Re-resolving on every request is what closes the DNS-rebinding window: a name that
        # pointed at the authorized address when the scan started must still point there now.
        if self._resolve(parsed.hostname) != self.pinned_addresses:
            raise ScopeViolation("DNS resolution changed during the scan")

    def before_request(self, request: HttpRequest) -> None:
        """Authorize one request, or raise. Charges the budget and applies the rate limit."""
        with self.lock:
            self.validate_url(request.url)
            if self.context.cancel_file and os.path.exists(self.context.cancel_file):
                raise Cancelled("Scan cancelled")
            if time.monotonic() - self.started > self.context.limits.global_timeout_seconds:
                raise BudgetExceeded("Global scan timeout reached")
            if self.total >= self.context.limits.max_requests:
                raise BudgetExceeded("Global request budget reached")

            endpoint = f"{request.method}:{urlparse(request.url).path}"
            if self.per_endpoint[endpoint] >= self.context.limits.max_requests_per_endpoint:
                raise EndpointBudgetExceeded("Endpoint request budget reached")

            wait = self.context.limits.min_request_interval_seconds - (time.monotonic() - self.last_request)
            if wait > 0:
                time.sleep(wait)

            self.total += 1
            self.per_endpoint[endpoint] += 1
            self.last_request = time.monotonic()
            self.log({
                "event": "request",
                "number": self.total,
                "method": request.method,
                "url": request.url,
                "headers": redact_headers(request.headers),
                "body_bytes": len(request.body),
            })

    def log(self, event: dict) -> None:
        if not self.context.log_file:
            return
        event["timestamp"] = time.time()
        with open(self.context.log_file, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")


def safe_redirect(base: str, location: str, controller: SafetyController) -> str:
    """Resolve a Location header against the current URL, refusing anything out of scope."""
    target = urljoin(base, location)
    controller.validate_url(target)
    return target
