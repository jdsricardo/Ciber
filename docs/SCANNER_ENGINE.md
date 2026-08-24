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
