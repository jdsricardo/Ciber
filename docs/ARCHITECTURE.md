# Architecture

SentinelScope uses a layered, local deployment. The browser sends requests to a pure PHP application. PHP validates input, orchestrates analyses, renders results, and persists data through PDO prepared statements. A separately invoked Python process performs the bounded HTTP requests and returns JSON. MariaDB stores applications, analyses, and findings.

## Layers and dependency direction

```
                        public/index.php
                               |
       Presentation ---+--- UseCase ---> Domain <--- Infrastructure
       (Views,             (RegisterApplication,  (Model,        (PDO repositories,
        Layout,             RunAnalysis,           Contract,      PythonScannerGateway,
        FindingPresenter,   CompareAnalyses,       Service,       Config, Database, Csrf)
        Html)               ExportAnalysis)        Exception)
```

Every arrow points at `app/src/Domain/`, which depends on nothing outside itself — a rule
enforced by a test in `tests/php_test.php` that fails if a domain file references
`App\Infrastructure`, `App\Presentation`, `App\UseCase` or `PDO` in code.

| Layer | Directory | Responsibility | May depend on |
|---|---|---|---|
| Domain | `app/src/Domain/` | Entities (`Application`, `Analysis`, `Finding`), value objects (`TargetUrl`, `SecurityScore`, `Severity`, `ScanMode`, `AnalysisStatus`, `RemediationExample`, `ScanResult`), the comparison service, the contracts and the error convention. Validates in the constructor, so an invalid object cannot exist. | nothing |
| UseCase | `app/src/UseCase/` | One class per application operation: `RegisterApplication`, `RunAnalysis`, `CompareAnalyses`, `ExportAnalysis`. Orchestrates the domain through the contracts and owns the transaction boundary. | Domain |
| Infrastructure | `app/src/Infrastructure/` | Implements the domain contracts: `PdoApplicationRepository`, `PdoAnalysisRepository`, `PdoFindingRepository`, `PdoTransactionManager`, `PythonScannerGateway`, plus `Config`, `Database` and `Csrf`. The only place SQL and the Python invocation exist. | Domain |
| Presentation | `app/src/Presentation/` | `Views` (one method per screen), `Layout`, `FindingPresenter`, `Html`. Reads entities, produces markup, decides nothing. | Domain, UseCase |

`public/index.php` is the front controller: it constructs the adapters, wires them into the use
cases, dispatches one request, and maps a `DomainError` to its HTTP status. It holds no rules.

### Contracts declared by the domain

| Interface | Implemented by (production) | Implemented by (tests) |
|---|---|---|
| `Domain\Contract\ApplicationRepository` | `PdoApplicationRepository` | `Tests\Php\InMemoryApplicationRepository` |
| `Domain\Contract\AnalysisRepository` | `PdoAnalysisRepository` | `Tests\Php\InMemoryAnalysisRepository` |
| `Domain\Contract\FindingRepository` | `PdoFindingRepository` | `Tests\Php\InMemoryFindingRepository` |
| `Domain\Contract\ScannerGateway` | `PythonScannerGateway` | `Tests\Php\FakeScannerGateway` |
| `Domain\Contract\TransactionManager` | `PdoTransactionManager` | `Tests\Php\ImmediateTransactionManager` |

### Error convention

The domain throws only `DomainError` subclasses — `InvalidInput` (400), `NotFound` (404),
`ScannerUnavailable` (502) — carrying a message already written for the developer using the
application. Infrastructure failures are wrapped by the adapter that produced them. Anything
reaching the front controller as a plain `Throwable` is a defect: it is logged in full and the
user sees a generic message. See [CODING_STANDARD.md](CODING_STANDARD.md) §6.

## Main flow

1. The developer registers an authorized target.
2. PHP creates a `running` analysis and invokes the Python scanner (`scanner/scanner.py`) with escaped arguments.
3. The Python engine (`scanner/engine/`) validates the URL and resolved addresses, then crawls the reachable same-origin surface breadth-first (`engine/crawler.py`): starting from the seed URL it follows `<a>` links, GET form actions, and same-origin redirects up to a page and depth budget, so a scan covers pages the user never typed — e.g. an unprotected page reachable one hop past a login screen. For each discovered page it sends two independent baseline requests through a safety-controlled transport, builds a page context, and runs every registered plugin (`scanner/plugins/`) — 34 passive checks across transport security, security headers, cookies, CORS, cache, information disclosure, and secrets exposure, plus the active detectors in `safe_active` mode — emitting structured JSON findings with severity, confidence, status, CWE/OWASP/WSTG references, and sanitized evidence. Crawling is deliberately read-only: logout/sign-out links and state-changing links (`?action=delete`, `?remove=`, …) are never followed, so an authenticated session survives the crawl and the scanner triggers no destructive side effect.
4. PHP stores the findings in a transaction, calculates the score, and marks the analysis complete.
5. The UI presents each issue as observation, developer impact, fix, a concrete "vulnerable vs. fixed" code/config example (`scanner/plugins/remediation_examples.py`, keyed by check id and merged into every finding by `build_finding`), a confidence/status badge, and a collapsible technical panel with the raw evidence. Historical fingerprints support comparisons.

## Scanner engine internals

The engine is deliberately layered so that adding a new check never touches the core:

- `engine/models.py` — typed request/response/finding/evidence data model shared by every plugin.
- `engine/safety.py` + `engine/transport.py` — scope enforcement (host/port pinning, DNS re-resolution check, private-network denial), rate limiting, budgets, and the only code path allowed to make an HTTP request. The transport retries once on a transient TCP reset (charging the request budget a single time); a persistent network failure surfaces as a failed scan (`ok:false`) rather than a crash.
- `engine/normalization.py` — strips volatile content (timestamps, UUIDs, CSRF/nonce tokens) before any comparison, and derives page context (has forms, has a password field, looks authenticated) used to keep severity proportionate.
- `engine/confidence.py` — the single place that turns evidence strength, reproducibility, and ambiguity into a 0–100 confidence score and a finding status, kept independent from severity.
- `engine/discovery.py` — turns a URL and an HTML document into the `InputPoint` list the
  active detectors probe: query-string parameters plus the fields of every form, collapsed by
  a location-aware identifier so the same name in two places is not tested twice.
- `engine/matchers.py` — a small composable predicate vocabulary over a response (status,
  header, text, length, similarity, timing, redirect) with `&`, `|` and `~`. It is available
  to detectors that prefer declarative conditions; the current plugins express their
  conditions directly, so it is exercised by the engine tests rather than by a plugin.
- `engine/crawler.py` — same-origin link/redirect discovery: parses `<a>` targets and GET form actions, keeps only in-scope HTTP(S) URLs on the pinned host/port, and enforces the read-only navigation rules (skip logout/sign-out, skip state-changing `?action=delete`-style links, skip static assets). Pages are collapsed by *signature* (path + set of query-parameter names, ignoring values) so `/product?id=1` and `/product?id=2` count as one page.
- `engine/runner.py` — orchestrates the breadth-first crawl and, per discovered page, baseline collection and plugin execution; owns no vulnerability-specific logic. It de-duplicates findings across pages (server-wide header/transport/cookie/CORS conditions once per fingerprint; injection/disclosure findings per fingerprint+endpoint+parameter) and shares one SafetyController budget across crawling and probing, so a scan can never exceed its request/time envelope regardless of site size. The crawl is bounded by `max_pages` and `max_depth` (overridable per run via `--max-pages`/`--max-depth`); setting `max_pages=1` reproduces the original single-page behavior.
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

`applications 1—N analyses 1—N findings`. Indexed application/date and analysis/fingerprint paths support history and comparison. Foreign keys preserve consistency, and `findings` cascades on delete so an analysis never leaves orphaned rows.

| Table | Predominant operation | Index that serves it |
|---|---|---|
| `applications` | list, and look up by primary key | primary key |
| `analyses` | insert, then read the history of one application by date | `idx_analysis_application_date (application_id, started_at)` |
| `findings` | bulk insert per analysis, then read every finding of one analysis | `idx_finding_analysis (analysis_id)`, `idx_finding_fingerprint (analysis_id, fingerprint)` |

## Measured decisions

Four structural choices in this architecture were made because they were measured, not because
they were expected to be faster. Each was compared against the alternative the problem
statement naturally suggests, at the input sizes the system really reaches and two orders of
magnitude beyond.

| Decision | Alternative rejected | Structure adopted | Where |
|---|---|---|---|
| Crawl frontier | list + `pop(0)` (O(n) shift per visit) | `collections.deque` | `scanner/engine/runner.py` |
| Pages already enqueued | list membership (O(n)) | `set` (O(1) average) | `scanner/engine/runner.py` |
| Finding de-duplication | pairwise scan (O(n²)) | `set` of keys + ordered list | `ScanRunner._deduplicate()` |
| Comparison between analyses | pairwise scan (O(n²)) | map keyed by fingerprint | `app/src/Domain/Service/AnalysisComparison.php` |

The comparison decision is the one that matters for NFR-01: at 1,000 findings the pairwise
version costs 94.8 ms against 0.2 ms for the keyed map, and it degrades to roughly 10 s at
10,000 findings while the keyed map stays under 3 ms. The crawl-frontier decision is recorded
as what it is — no measurable gain at the size a scan actually reaches (`max_pages` of 30),
adopted because it removes the only quadratic term from the crawl loop.

Full results, method and environment are in
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md); they are reproduced with
`python evaluation/benchmark_structures.py` and `php evaluation/benchmark_comparison.php`.

---

**Repository.** The source, the tests and the engineering documentation described in the six
sections above are versioned at https://github.com/jdsricardo/Ciber.git
