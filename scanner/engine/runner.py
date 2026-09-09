"""Orchestrates a scan: crawls the reachable same-origin surface, then for each discovered page
runs baseline requests, page context, plugin execution, and JSON serialization."""
from __future__ import annotations
import importlib
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from .crawler import extract_links, is_followable, page_signature, same_scope
from .discovery import discover
from .models import HttpRequest, ScanContext, ScanLimits, ScanMode
from .normalization import baseline_stability, build_page_context, summarize
from .safety import Cancelled, BudgetExceeded, EndpointBudgetExceeded, SafetyController, ScopeViolation
from .transport import HttpTransport

BASELINE_REQUESTS = 2

# Findings for these check families describe a server-/site-wide condition (a missing transport
# or response header, a cookie or CORS misconfiguration) rather than a per-page defect. When the
# crawler visits many pages the same condition would otherwise be reported once per page, so they
# are de-duplicated by fingerprint alone. Everything else (injection, disclosure, secrets, ...) is
# genuinely per-endpoint and is de-duplicated by (fingerprint, endpoint, parameter).
SITE_WIDE_PREFIXES = ("transport.", "headers.", "cookies.", "cache.", "cors.")
# Individual disclosure checks that reflect a server-wide banner rather than a per-page defect
# (the rest — directory listing, stack traces, mixed content, source maps — are page-specific).
SITE_WIDE_FINGERPRINTS = frozenset({"disclosure.server_header", "disclosure.powered_by_header"})

# Passive checks read one baseline per page; active checks also send per-parameter probe
# requests, so they need a larger — but still explicitly bounded — request and time budget. Both
# profiles crawl: they expand the seed URL into the reachable same-origin surface (max_pages) up
# to a link distance of max_depth, so a scan covers unlinked-from-the-seed pages too (e.g. an
# unprotected page reachable past a login screen), not only the URL the user typed.
PASSIVE_LIMITS = ScanLimits(
    max_requests=300,
    global_timeout_seconds=180.0,
    max_pages=30,
    max_depth=3,
)
ACTIVE_LIMITS = ScanLimits(
    max_requests=2500,
    max_requests_per_endpoint=120,
    max_response_bytes=262_144,
    request_timeout_seconds=10.0,
    global_timeout_seconds=600.0,
    min_request_interval_seconds=0.1,
    max_redirects=3,
    max_pages=20,
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

        # Breadth-first crawl of the reachable same-origin surface. Each visited page is fully
        # scanned (baseline requests + every plugin) as it is dequeued; its links are then
        # enqueued for later visits. A shared SafetyController budget covers crawling and probing
        # alike, so the scan can never exceed its request/time envelope regardless of site size.
        queue: list[tuple[str, int]] = [(target_url, 0)]
        enqueued: set[str] = {page_signature(target_url)}
        crawled_urls: list[str] = []
        findings: list = []
        stopped_early = None
        seed_primary = None
        seed_summaries = None

        while queue and len(crawled_urls) < self.limits.max_pages:
            url, depth = queue.pop(0)
            request = HttpRequest(method="GET", url=url,
                                  headers={"Accept": "text/html,application/json,*/*;q=0.5"})
            try:
                responses = [transport.send(request) for _ in range(BASELINE_REQUESTS)]
            except Cancelled:
                stopped_early = "cancelled"
                break
            except EndpointBudgetExceeded:
                # This page's own GET endpoint is capped; skip it and keep crawling others.
                continue
            except BudgetExceeded:
                stopped_early = "budget_exceeded"
                break
            except ScopeViolation:
                # A queued link that turned out to leave scope (e.g. DNS re-pinned): skip the
                # page and keep crawling the rest rather than aborting the whole scan.
                continue
            except OSError:
                # This one page could not be fetched (reset, timeout). Skip it; other pages
                # (and the findings already gathered) are unaffected.
                continue

            primary = responses[0]
            crawled_urls.append(url)
            context.page = build_page_context(primary)
            body = primary.body.decode("utf-8", errors="replace")
            request.inputs = discover(url, body)
            if seed_primary is None:
                seed_primary, seed_summaries = primary, [summarize(r) for r in responses]

            stopped_early = self._run_plugins(request, responses, context, transport, findings)
            if stopped_early:
                break

            # Enqueue same-origin, followable, not-yet-seen destinations for later depths:
            # links parsed from the HTML plus this page's own redirect target (a page that 3xx's
            # to the real content, e.g. after a login gate). Everything is filtered through the
            # same scope + read-only rules before being queued.
            if depth < self.limits.max_depth:
                candidates = []
                if "html" in primary.headers.get("content-type", ""):
                    candidates.extend(extract_links(url, body))
                if primary.redirect_url:
                    candidates.append(urljoin(url, primary.redirect_url))
                for link in candidates:
                    signature = page_signature(link)
                    if (signature not in enqueued and same_scope(link, safety.host, safety.port)
                            and is_followable(link)):
                        enqueued.add(signature)
                        queue.append((link, depth + 1))

        # A total failure to fetch even the seed page is an error, not an empty scan.
        if seed_primary is None:
            return {"ok": False, "error": stopped_early or "Nenhuma página pôde ser acessada no alvo."}

        result = {
            "ok": True,
            "status_code": seed_primary.status,
            "duration_ms": seed_primary.elapsed_ms,
            "plugins_run": len(self.plugins),
            "checks_run": self.rule_count(),
            "baseline_stability": baseline_stability(seed_summaries),
            "requests_made": safety.total,
            "pages_scanned": len(crawled_urls),
            "crawled_urls": crawled_urls,
            "findings": [finding.to_dict() for finding in self._deduplicate(findings)],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
        if stopped_early:
            result["stopped_early"] = stopped_early
        if self.plugin_warnings:
            result["plugin_warnings"] = self.plugin_warnings
        return result

    def _run_plugins(self, request, responses, context, transport, findings: list) -> str | None:
        """Run every plugin against one page, appending findings. Returns a stop reason if the
        request/time budget was hit (so the crawl stops cleanly), else None."""
        for plugin in self.plugins:
            try:
                findings.extend(plugin.analyze(request, responses, context, transport))
            except Cancelled:
                return "cancelled"
            except EndpointBudgetExceeded:
                # This endpoint's probe budget is spent: stop testing this page but let the crawl
                # continue to the next page (which has its own endpoint budget). Returning None
                # keeps everything found so far without ending the whole scan.
                return None
            except BudgetExceeded:
                # The global request/time budget ran out: keep everything found so far and stop
                # the whole scan cleanly rather than losing it to one greedy detector.
                return "budget_exceeded"
            except ScopeViolation:
                return "scope_violation"
            except OSError:
                # A transient network failure (timeout, reset) while this plugin was probing.
                # Skip only this plugin and let the remaining plugins on the page still run, so
                # one blip mid-scan neither discards the whole scan nor silently drops every
                # later detector on the page. If the target is genuinely unreachable, each
                # remaining plugin fails the same way and the crawl then drains cleanly.
                continue
        return None

    @staticmethod
    def _deduplicate(findings: list) -> list:
        """Collapse repeats across crawled pages: site-wide conditions (headers, transport,
        cookies, cache, CORS) once per fingerprint; everything else per (fingerprint, endpoint,
        parameter). Preserves first-seen order so the seed page's findings lead the report."""
        seen: set = set()
        unique: list = []
        for finding in findings:
            if finding.fingerprint.startswith(SITE_WIDE_PREFIXES) or finding.fingerprint in SITE_WIDE_FINGERPRINTS:
                key: tuple = (finding.fingerprint,)
            else:
                key = (finding.fingerprint, finding.endpoint, finding.parameter)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

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
    max_pages: int | None = None,
    max_depth: int | None = None,
) -> dict[str, Any]:
    scan_mode = ScanMode.SAFE_ACTIVE if mode == ScanMode.SAFE_ACTIVE.value else ScanMode.PASSIVE
    resolved_limits = limits or (ACTIVE_LIMITS if scan_mode is ScanMode.SAFE_ACTIVE else PASSIVE_LIMITS)
    # Let a caller (CLI, evaluation harness) tighten or widen the crawl without redefining a
    # whole ScanLimits profile — useful to keep a run short, or to reach deeper on a large target.
    if max_pages is not None or max_depth is not None:
        resolved_limits = replace(
            resolved_limits,
            max_pages=max_pages if max_pages is not None else resolved_limits.max_pages,
            max_depth=max_depth if max_depth is not None else resolved_limits.max_depth,
        )
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
