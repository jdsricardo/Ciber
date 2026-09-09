# Architecture

SentinelScope uses a layered, local deployment. The browser sends requests to a pure PHP application. PHP validates input, orchestrates analyses, renders results, and persists data through PDO prepared statements. A separately invoked Python process performs the bounded HTTP request and returns JSON. MariaDB stores applications, analyses, and findings.

## Main flow

1. The developer registers an authorized target.
2. PHP creates a `running` analysis and invokes the Python scanner (`scanner/scanner.py`) with escaped arguments.
3. The Python engine (`scanner/engine/`) validates the URL and resolved addresses, sends two independent baseline requests through a safety-controlled transport, builds a page context, and runs every registered passive plugin (`scanner/plugins/`) — 34 checks across transport security, security headers, cookies, CORS, cache, information disclosure, and secrets exposure — emitting structured JSON findings with severity, confidence, status, CWE/OWASP/WSTG references, and sanitized evidence.
4. PHP stores the findings in a transaction, calculates the score, and marks the analysis complete.
5. The UI presents each issue as observation, developer impact, fix, a concrete "vulnerable vs. fixed" code/config example (`scanner/plugins/remediation_examples.py`, keyed by check id and merged into every finding by `build_finding`), a confidence/status badge, and a collapsible technical panel with the raw evidence. Historical fingerprints support comparisons.

## Scanner engine internals

The engine is deliberately layered so that adding a new check never touches the core:

- `engine/models.py` — typed request/response/finding/evidence data model shared by every plugin.
- `engine/safety.py` + `engine/transport.py` — scope enforcement (host/port pinning, DNS re-resolution check, private-network denial), rate limiting, budgets, and the only code path allowed to make an HTTP request. The transport retries once on a transient TCP reset (charging the request budget a single time); a persistent network failure surfaces as a failed scan (`ok:false`) rather than a crash.
- `engine/normalization.py` — strips volatile content (timestamps, UUIDs, CSRF/nonce tokens) before any comparison, and derives page context (has forms, has a password field, looks authenticated) used to keep severity proportionate.
- `engine/confidence.py` — the single place that turns evidence strength, reproducibility, and ambiguity into a 0–100 confidence score and a finding status, kept independent from severity.
- `engine/runner.py` — orchestrates baseline collection and plugin execution; owns no vulnerability-specific logic.
- `plugins/*.py` — one class per vulnerability family (`ScannerPlugin` subclasses), each declaring its own CWE/OWASP/WSTG metadata and the check ids it owns; `plugins/catalog.py` centralizes the static reference text so it is authored once.
- `plugins/support.py` `build_probe`/`send_probe` — a parameter-source-agnostic probe helper: query parameters are tested on the URL (GET), form fields are submitted in a POST body (with sibling fields preserved). Active plugins iterate `testable_inputs` (query + form) instead of query-only. Form/POST testing is wired into every value-injection detector — SQL injection, reflected XSS, path traversal, open redirect, command injection, SSTI, and SSRF. CRLF (header-reflection) and NoSQL (`name[$ne]` key mutation) remain query-only because their probe construction is channel-specific.
- Authenticated scanning: `ScanContext.auth_headers` (a session cookie or bearer token) is attached to every request by the transport, so it covers passive and active checks alike without touching any plugin. It is only ever sent to the pinned host/port, is redacted in logs, and is passed transiently by the web app (never persisted).

This structure is what later phases (active SQL injection, XSS, IDOR, etc.) will extend: new plugins register against the same `ScannerPlugin` interface and reuse the same baseline/diff/confidence machinery instead of each reimplementing comparison logic.

## Security boundaries

- Private, loopback, link-local, and reserved destinations are blocked by default.
- The scanner accepts only HTTP(S), rejects URL credentials, follows no redirects, limits response size, and uses a timeout.
- Mutations require a session-bound CSRF token. Output encoding mitigates stored XSS. PDO native prepared statements prevent SQL injection.
- The current academic version assumes a trusted single-user local installation. Authentication and role-based access are recommended before shared deployment.

## Data model

`applications 1—N analyses 1—N findings`. Indexed application/date and analysis/fingerprint paths support history and comparison. Foreign keys preserve consistency.
