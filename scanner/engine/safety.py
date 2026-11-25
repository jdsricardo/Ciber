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

# The messages of the exceptions below reach the user as the reason an analysis failed
# (docs/INTEGRATION_CONTRACT.md §3.3), so they are written in Portuguese like every other
# interface text (docs/CODING_STANDARD.md §1).


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
        # The page being analysed (see begin_page): requests to its path are budgeted per page.
        self.page_path = ""
        self.page_key = ""

        parsed = urlparse(context.target_url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if self.scheme not in ("http", "https") or not self.host:
            raise ScopeViolation("Apenas alvos HTTP(S) absolutos são suportados.")
        self.pinned_addresses = self._resolve(self.host)

    def _resolve(self, host: str) -> set[str]:
        addresses = {item[4][0].split("%")[0] for item in socket.getaddrinfo(host, None)}
        if not addresses:
            raise ScopeViolation("O endereço do alvo não pôde ser resolvido.")
        if not self.context.allow_private and any(not ip_address(x).is_global for x in addresses):
            raise ScopeViolation("Alvos em rede privada, loopback, link-local ou endereços reservados são bloqueados por padrão.")
        return addresses

    def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
            raise ScopeViolation("Esquema de URL inseguro ou credenciais embutidas na URL.")
        if parsed.hostname != self.host or port != self.port:
            raise ScopeViolation("A requisição tentou sair do host e da porta autorizados.")
        # Re-resolving on every request is what closes the DNS-rebinding window: a name that
        # pointed at the authorized address when the scan started must still point there now.
        if self._resolve(parsed.hostname) != self.pinned_addresses:
            raise ScopeViolation("A resolução DNS do alvo mudou durante a análise.")

    def begin_page(self, url: str, key: str) -> None:
        """Mark the page whose analysis starts now. `key` identifies the page among the pages
        of the same path (the crawler's page signature)."""
        with self.lock:
            self.page_path = urlparse(url).path
            self.page_key = key

    def before_request(self, request: HttpRequest) -> None:
        """Authorize one request, or raise. Charges the budget and applies the rate limit."""
        with self.lock:
            self.validate_url(request.url)
            if self.context.cancel_file and os.path.exists(self.context.cancel_file):
                raise Cancelled("Análise cancelada.")
            if time.monotonic() - self.started > self.context.limits.global_timeout_seconds:
                raise BudgetExceeded("Tempo máximo global da análise atingido.")
            if self.total >= self.context.limits.max_requests:
                raise BudgetExceeded("Limite global de requisições da análise atingido.")

            path = urlparse(request.url).path
            endpoint = f"{request.method}:{path}"
            if self.page_key and path == self.page_path:
                # One script that serves many screens (`index.php?p=12`, `?p=14`): each screen
                # is its own endpoint, or the first screens would spend the budget of all others.
                endpoint += "#" + self.page_key
            if self.per_endpoint[endpoint] >= self.context.limits.max_requests_per_endpoint:
                raise EndpointBudgetExceeded("Limite de requisições por endpoint atingido.")

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
