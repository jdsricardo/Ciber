# Scanner Engine — Phase 1 Foundation

## Implemented foundation

- Typed common models for requests, responses, input points, summaries, differences, evidence, findings, scan modes, and limits.
- Stable input identifiers by location and name.
- Central normalization for timestamps, UUIDs, long random values, nonce, CSRF, and token fields.
- Central response summaries and comparison across status, length, normalized content, HTML structure, headers, and timing.
- Composable positive/negative matchers with AND, OR, and NOT plus status, header, text/regex, length, similarity, timing, and redirect primitives.
- Reusable regex and JSON-path extractors.
- Same-host-and-port scope enforcement, dangerous-scheme rejection, URL credential rejection, private-network denial, DNS pinning, request budgets, endpoint budgets, rate limiting, request/global timeouts, cancellation file, response-size limits, and JSONL request logging with secret headers redacted.
- A plugin interface declaring category, CWE, OWASP, WSTG, kind, and operational risk.

## Migration status

The production CLI remains on the existing passive implementation while the new foundation is tested. The next increment will route repeated baselines through `HttpTransport`, migrate each passive rule behind the plugin contract, and enrich MariaDB persistence without breaking the current PHP JSON fields. Active probes must not be enabled before that migration and its controlled vulnerable/safe test fixtures pass.

## Reference baseline

Mappings use OWASP Top 10:2025. WSTG identifiers should use the stable, versioned v4.2 form in persisted evidence, while development work may consult the latest WSTG 5.0 content. CWE identifiers remain weakness-specific and must not be inferred from a generic anomaly.
