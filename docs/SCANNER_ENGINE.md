# Scanner Engine — Phase 1 Foundation (complete)

## Implemented foundation

- Typed common models for requests, responses, input points, summaries, differences, evidence, findings, scan modes, page context, and limits (`engine/models.py`).
- Stable input identifiers by location and name; query-string and HTML-form discovery (`engine/discovery.py`).
- Central normalization for timestamps, UUIDs, long random values, nonce, CSRF, and token fields, plus page-context inference (forms, password fields, session cookies) (`engine/normalization.py`).
- Central response summaries and comparison across status, length, normalized content, HTML structure, headers, and timing.
- Composable positive/negative matchers with AND, OR, and NOT plus status, header, text/regex, length, similarity, timing, and redirect primitives (`engine/matchers.py`).
- Reusable regex and JSON-path extractors.
- Same-host-and-port scope enforcement, dangerous-scheme rejection, URL credential rejection, private-network denial, DNS pinning, request budgets, endpoint budgets, rate limiting, request/global timeouts, cancellation file, response-size limits, and JSONL request logging with secret headers redacted (`engine/safety.py`).
- A central confidence-scoring model, kept independent from severity (`engine/confidence.py`): `confidence = 0.35*evidence_strength + 0.25*reproducibility + 0.2*differential_quality + 0.2*independent_confirmation - 0.3*instability - 0.2*ambiguity`, mapped to `confirmed / high_confidence / probable / possible / informational / manual_review_required`.
- A plugin interface declaring category, CWE, OWASP, WSTG, kind, operational risk, and the set of check ids it owns (`plugins/base.py`).
- Seven object-oriented passive plugins (`plugins/transport.py`, `headers.py`, `cookies.py`, `cors.py`, `cache.py`, `disclosure.py`, `secrets.py`) covering 34 individual checks, including a new Secrets Exposure detector (high-signature credential formats plus an entropy-based heuristic that ignores per-request/rotating tokens).
- `engine/runner.py` orchestrates two independent baseline requests through `HttpTransport`/`SafetyController`, builds page context, runs every registered plugin, and serializes results to the JSON shape consumed by `app/bootstrap.php`.

## Migration status

Complete. `scanner/scanner.py` is now a thin CLI wrapper around `engine.runner.run_passive_scan`. `database.sql` was extended (additive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) with `category, cwe, owasp, wstg, method, parameter, parameter_location, confidence, status, description, evidence_summary, manual_review_required`, and `app/bootstrap.php`/`public/index.php` persist and render them (severity and confidence are shown as separate badges; the full structured evidence is available as JSON in the finding's technical-context panel). Active probes (Phase 2) must not be enabled before their own controlled vulnerable/safe test fixtures pass.

## Confidence vs. severity

Every finding carries both independently. Severity is the potential impact if the finding is real; confidence is how sure the detector is. A critical finding can have low confidence — it stays `Critical / possible`, never silently downgraded to a lower severity. Purely passive, single-observation checks are capped below `confirmed` by construction (no `differential_quality` or true independent method contributes to their score), which is reserved for future active detectors that reproduce a result via an independent second technique (e.g. an error-based and a boolean-differential SQLi probe agreeing).

## Reference baseline

Mappings use OWASP Top 10:2025. WSTG identifiers should use the stable, versioned v4.2 form in persisted evidence, while development work may consult the latest WSTG 5.0 content. CWE identifiers remain weakness-specific and must not be inferred from a generic anomaly.

## Coverage increments: form/POST testing and authenticated scanning

- Parameter tests are parameter-source-agnostic: `plugins/support.build_probe`/`send_probe` route a probe to the right channel — a query parameter is tested on the URL (GET), a form field is submitted in an `application/x-www-form-urlencoded` body (POST) with sibling fields preserved. Active plugins iterate `testable_inputs` (query + form). Form/POST testing is enabled for every value-injection detector (SQL injection, reflected XSS, path traversal, open redirect, command injection, SSTI, SSRF); CRLF and NoSQL stay query-only because their probe construction is channel-specific. Form probes POST to the scanned page URL; forms whose `action` targets a different path are a known limitation.
- Authenticated scanning: `ScanContext.auth_headers` is merged into every outgoing request by the transport, covering passive and active checks at once without touching any plugin. Auth headers reach only the pinned host/port (scope enforcement), are redacted in logs (`SENSITIVE_HEADERS`), and are supplied via the CLI (`--cookie`, repeatable `--header`) or transiently by the web app (never persisted).

## Coverage increment: same-origin crawling

- `engine/crawler.py` expands a single seed URL into the reachable same-origin surface. `engine/runner.py` runs a breadth-first walk: it dequeues a page, scans it in full (two baseline requests + every plugin), then enqueues its `<a>` links, GET form actions, and redirect target for later depths. This closes the gap where a scan of a login page (or any landing page) would previously miss an unprotected page sitting one hop away — the scanner now discovers and tests it on its own.
- Bounds and safety: the crawl is capped by `max_pages` and `max_depth` (profiles: passive 30 pages / depth 3, active 20 pages / depth 2; both overridable with `--max-pages`/`--max-depth`, and `max_pages=1` restores single-page scanning). Navigation is read-only — logout/sign-out links and state-changing links (`?action=delete`, `?remove=`, …) are never followed, so an authenticated crawl does not tear down its own session or mutate server state. All requests share one `SafetyController` budget, so crawling plus probing stays inside the same request/time envelope, and every URL is still re-validated against the pinned host/port before it is fetched.
- Resilience: a per-endpoint budget hit (`EndpointBudgetExceeded`) ends only that endpoint and the crawl moves on; a transient network failure (`OSError`: timeout/reset) while a plugin probes skips just that plugin, and a page that cannot be fetched at all is skipped — so one blip never discards findings already gathered. Only a global request/time budget or a cancellation stops the whole scan, and in every case the findings collected so far are returned.
- Pages are de-duplicated by signature (path + query-parameter *names*), so a catalog of `/item?id=1..N` is visited once; findings are de-duplicated across pages so a server-wide missing header is reported once, while per-endpoint injection/disclosure findings are kept per URL and parameter. The result JSON gains `pages_scanned` and `crawled_urls`.
