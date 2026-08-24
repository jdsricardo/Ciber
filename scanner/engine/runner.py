"""Orchestrates a scan: baseline requests, page context, plugin execution, JSON serialization."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from .discovery import discover
from .models import HttpRequest, ScanContext, ScanLimits, ScanMode
from .normalization import baseline_stability, build_page_context, summarize
from .safety import Cancelled, BudgetExceeded, SafetyController, ScopeViolation
from .transport import HttpTransport

BASELINE_REQUESTS = 2

class ScanRunner:
    """Runs a set of plugins against one authorized target and returns a JSON-serializable result."""

    def __init__(self, plugins: list, limits: ScanLimits | None = None) -> None:
        self.plugins = plugins
        self.limits = limits or ScanLimits()

    def rule_count(self) -> int:
        return sum(len(plugin.metadata.checks) for plugin in self.plugins)

    def run(
        self,
        target_url: str,
        mode: ScanMode = ScanMode.PASSIVE,
        allow_private: bool = False,
        cancel_file: str | None = None,
        log_file: str | None = None,
    ) -> dict[str, Any]:
        context = ScanContext(
            target_url=target_url, mode=mode, limits=self.limits,
            allow_private=allow_private, cancel_file=cancel_file, log_file=log_file,
        )
        safety = SafetyController(context)
        transport = HttpTransport(safety)
        request = HttpRequest(method="GET", url=target_url, headers={"Accept": "text/html,application/json,*/*;q=0.5"})

        responses = [transport.send(request) for _ in range(BASELINE_REQUESTS)]
        primary = responses[0]
        summaries = [summarize(response) for response in responses]
        context.page = build_page_context(primary)
        request.inputs = discover(target_url, primary.body.decode("utf-8", errors="replace"))

        findings = []
        for plugin in self.plugins:
            findings.extend(plugin.analyze(request, responses, context))

        return {
            "ok": True,
            "status_code": primary.status,
            "duration_ms": primary.elapsed_ms,
            "plugins_run": len(self.plugins),
            "checks_run": self.rule_count(),
            "baseline_stability": baseline_stability(summaries),
            "requests_made": safety.total,
            "findings": [finding.to_dict() for finding in findings],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

def default_passive_plugins() -> list:
    from plugins.cache import CacheSecurityPlugin
    from plugins.cookies import CookieSecurityPlugin
    from plugins.cors import CorsPassivePlugin
    from plugins.disclosure import InformationDisclosurePlugin
    from plugins.headers import SecurityHeadersPlugin
    from plugins.secrets import SecretsExposurePlugin
    from plugins.transport import TransportSecurityPlugin
    return [
        TransportSecurityPlugin(),
        SecurityHeadersPlugin(),
        CookieSecurityPlugin(),
        CorsPassivePlugin(),
        CacheSecurityPlugin(),
        InformationDisclosurePlugin(),
        SecretsExposurePlugin(),
    ]

def run_passive_scan(
    target_url: str,
    allow_private: bool = False,
    cancel_file: str | None = None,
    log_file: str | None = None,
    limits: ScanLimits | None = None,
) -> dict[str, Any]:
    runner = ScanRunner(default_passive_plugins(), limits)
    try:
        return runner.run(target_url, ScanMode.PASSIVE, allow_private, cancel_file, log_file)
    except (ScopeViolation, BudgetExceeded, Cancelled) as error:
        return {"ok": False, "error": str(error)}
