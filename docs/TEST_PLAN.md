# Test Plan and Results

## Strategy

Unit tests cover the engine foundation (`tests/test_engine.py`), per-plugin vulnerable/safe fixtures (`tests/test_plugins.py`), catalog/runner integration (`tests/test_scanner.py`), and PHP rendering/config smoke tests (`tests/php_test.php`). Integration tests use an explicitly authorized laboratory server. Acceptance testing follows CA-01 through CA-07 from the project charter.

Each passive plugin is tested with at minimum: a vulnerable fixture, a hardened/safe fixture, and one context-sensitive edge case (e.g. a non-HTML response is not penalized for a missing CSP; a stack-trace pattern seen in only one of two baseline requests is downgraded to `manual_review_required` instead of a confirmed finding; a high-entropy value that changes between baseline requests is treated as a rotating token, not a static secret).

| Case | Expected result | Current result |
|---|---|---|
| TC-01 Register a valid target | Application is persisted | Ready for manual execution |
| TC-02 Reject invalid URL/missing authorization | Clear validation error | Ready for manual execution |
| TC-03 Scan controlled response | 34 passive checks complete and findings persist with severity, confidence, and status | Automated scanner test supplied |
| TC-04 Verify each finding | Category, CWE, OWASP, WSTG, severity, confidence, evidence, impact, remediation present | Automated scanner and plugin tests supplied |
| TC-05 Compare before/after scans | New, persistent, fixed groups are correct | Ready for integration execution |
| TC-06 Print report | Identity, date, score, findings included | Ready for manual execution |
| TC-07 Load 1,000 findings | History renders under three seconds | Benchmark procedure pending environment run |
| TC-08 SSRF protection | Private target denied by default | Automated test supplied |
| TC-09 False-positive reduction | A flaky/one-off signal (error text in only one of two baselines, a rotating token) is downgraded or excluded rather than confirmed | Automated plugin tests supplied |
| TC-10 Plugin/catalog consistency | Every catalog entry is declared by exactly one plugin, and every plugin declares complete CWE/OWASP/WSTG metadata | Automated test supplied |

Final measured results should be recorded with date, environment specifications, evidence, and tester name before academic delivery.
