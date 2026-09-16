"""The contract every check implements. One class per vulnerability family, nothing else."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from engine.models import Finding, HttpRequest, HttpResponse, ScanContext
from engine.transport import HttpTransport


@dataclass(frozen=True)
class PluginMetadata:
    """Identity and taxonomy of one plugin, declared by the plugin itself.

    `checks` lists the check ids the plugin owns; the runner sums them to report how many
    checks an analysis ran, so a plugin that gains a check is counted without touching the core.
    """

    name: str
    category: str
    cwe: str
    owasp: str
    wstg: str
    kind: str
    risk: str
    checks: tuple[str, ...] = ()


class ScannerPlugin(ABC):
    """Base class of every check.

    `kind` is 'passive' (baseline-only, never sends extra requests) or 'safe_active' (may use
    `transport` to send additional, budget- and scope-controlled requests). `transport` is None
    for passive-only scans, so a safe_active plugin must not assume it is present without
    checking — that is what lets the same plugin be exercised in either mode.
    """

    metadata: PluginMetadata

    @abstractmethod
    def analyze(
        self,
        request: HttpRequest,
        responses: list[HttpResponse],
        context: ScanContext,
        transport: HttpTransport | None = None,
    ) -> list[Finding]:
        """Return the findings this plugin observed on one page. Never raises for a negative."""
