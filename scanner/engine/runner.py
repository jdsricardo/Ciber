"""Orchestrates a scan: baseline requests, page context, plugin execution, JSON serialization."""
from __future__ import annotations
import importlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .discovery import discover
from .models import HttpRequest, ScanContext, ScanLimits, ScanMode
from .normalization import baseline_stability, build_page_context, summarize
from .safety import Cancelled, BudgetExceeded, SafetyController, ScopeViolation
from .transport import HttpTransport

BASELINE_REQUESTS = 2

# Passive checks read one baseline; active checks send additional, per-parameter probe
# requests, so they need a larger — but still explicitly bounded — request and time budget.
PASSIVE_LIMITS = ScanLimits()
ACTIVE_LIMITS = ScanLimits(
    max_requests=200,
    max_requests_per_endpoint=80,
    max_response_bytes=262_144,
    request_timeout_seconds=10.0,
    global_timeout_seconds=240.0,
    min_request_interval_seconds=0.1,
    max_redirects=3,
    max_depth=2,
    max_attempts_per_parameter=8,
)

class ScanRunner:
    """Runs a set of plugins against one authorized target and returns a JSON-serializable result."""

    def __init__(self, plugins: list, limits: ScanLimits | None = None, plugin_warnings: list[str] | None = None) -> None:
        self.plugins = plugins
        self.limits = limits or ScanLimits()
        self.plugin_warnings = plugin_warnings or []

    def rule_count(self) -> int:
        return sum(len(plugin.metadata.checks) for plugin in self.plugins)

    def run(
        self,
        target_url: str,
        mode: ScanMode = ScanMode.PASSIVE,
        allow_private: bool = False,
        cancel_file: str | None = None,
        log_file: str | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        context = ScanContext(
            target_url=target_url, mode=mode, limits=self.limits,
            allow_private=allow_private, cancel_file=cancel_file, log_file=log_file,
            auth_headers=auth_headers or {},
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
        stopped_early = None
        for plugin in self.plugins:
            try:
                findings.extend(plugin.analyze(request, responses, context, transport))
            except Cancelled:
                stopped_early = "cancelled"
                break
            except BudgetExceeded:
                # Budget ran out mid-plugin: keep everything found so far and stop cleanly
                # rather than losing the whole scan to one greedy detector.
                stopped_early = "budget_exceeded"
                break
            except ScopeViolation:
                stopped_early = "scope_violation"
                break

        result = {
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
        if stopped_early:
            result["stopped_early"] = stopped_early
        if self.plugin_warnings:
            result["plugin_warnings"] = self.plugin_warnings
        return result

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

# (module filename stem, expected class name). Registering here is the only integration step
# a new safe_active plugin needs; a file that doesn't exist yet is silently skipped (still being
# built), but a file that exists and fails to import is a real bug and is surfaced as a warning
# instead of silently vanishing — a plugin that "loads" but contributes zero findings and zero
# errors is much harder to notice than one that leaves a visible warning in the scan result.
ACTIVE_PLUGIN_SPECS = [
    ("sql_injection", "SqlInjectionPlugin"),
    ("reflected_xss", "ReflectedXssPlugin"),
    ("path_traversal", "PathTraversalPlugin"),
    ("open_redirect", "OpenRedirectPlugin"),
    ("command_injection", "CommandInjectionPlugin"),
    ("ssti", "TemplateInjectionPlugin"),
    ("xxe", "XxePlugin"),
    ("crlf_injection", "CrlfInjectionPlugin"),
    ("host_header", "HostHeaderInjectionPlugin"),
    ("http_verb_tampering", "HttpVerbTamperingPlugin"),
    ("nosql_injection", "NoSqlInjectionPlugin"),
    ("cors_active", "CorsActivePlugin"),
    ("ssrf", "SsrfPlugin"),
]

def default_active_plugins() -> tuple[list, list[str]]:
    """safe_active plugins: bounded, non-destructive probes against discovered parameters.

    Returns (plugins, warnings) — warnings list plugins whose file exists but failed to load.
    """
    plugins: list = []
    warnings: list[str] = []
    active_dir = Path(__file__).resolve().parent.parent / "plugins" / "active"
    for module_stem, class_name in ACTIVE_PLUGIN_SPECS:
        if not (active_dir / f"{module_stem}.py").is_file():
            continue
        try:
            module = importlib.import_module(f"plugins.active.{module_stem}")
            plugins.append(getattr(module, class_name)())
        except Exception as error:
            warnings.append(f"plugins.active.{module_stem}.{class_name} falhou ao carregar: {error}")
    return plugins, warnings

def plugins_for_mode(mode: str) -> tuple[list, list[str]]:
    plugins = default_passive_plugins()
    warnings: list[str] = []
    if mode == ScanMode.SAFE_ACTIVE.value:
        active_plugins, warnings = default_active_plugins()
        plugins += active_plugins
    return plugins, warnings

def run_scan(
    target_url: str,
    mode: str = ScanMode.PASSIVE.value,
    allow_private: bool = False,
    cancel_file: str | None = None,
    log_file: str | None = None,
    limits: ScanLimits | None = None,
    auth_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    scan_mode = ScanMode.SAFE_ACTIVE if mode == ScanMode.SAFE_ACTIVE.value else ScanMode.PASSIVE
    resolved_limits = limits or (ACTIVE_LIMITS if scan_mode is ScanMode.SAFE_ACTIVE else PASSIVE_LIMITS)
    plugins, warnings = plugins_for_mode(mode)
    runner = ScanRunner(plugins, resolved_limits, plugin_warnings=warnings)
    try:
        return runner.run(target_url, scan_mode, allow_private, cancel_file, log_file, auth_headers)
    except (ScopeViolation, BudgetExceeded, Cancelled) as error:
        return {"ok": False, "error": str(error)}
    except OSError as error:
        # Network-level failure reaching the target (connection refused, DNS failure,
        # timeout): an expected operational condition, not a bug — report it as a failed
        # scan instead of letting it crash a library caller (e.g. the evaluation harness).
        return {"ok": False, "error": f"Falha de rede ao acessar o alvo: {error}"}

def run_passive_scan(
    target_url: str,
    allow_private: bool = False,
    cancel_file: str | None = None,
    log_file: str | None = None,
    limits: ScanLimits | None = None,
    auth_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Kept for direct passive-only callers; run_scan(mode=...) is the general entry point."""
    return run_scan(target_url, ScanMode.PASSIVE.value, allow_private, cancel_file, log_file, limits, auth_headers)
