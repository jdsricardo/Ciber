# Software Requirements and Traceability

Each requirement carries a priority, the **item of the Termo de Referência (section 3.2) it
originates from**, the interview answer that produced that item, and the acceptance criterion
that verifies it. The origin column is the one the E1 checklist requires: no requirement is
justified by "the team decided", every one points at an item of the Termo.

Non-functional requirements additionally carry the measurable condition under which they are
considered met.

## Functional requirements

| ID | Requirement | Priority | Origin (TR 3.2) | Interview source | Acceptance criterion |
|---|---|---|---|---|---|
| FR-01 | Register an application name and HTTP(S) base URL with authorization confirmation. | High | 1 | RF-001 (B1, G1) | CA-01 |
| FR-02 | Execute the enabled check catalogue on demand: 34 passive check ids across 7 plugin families, plus 30 active check ids across 13 safe-active families (64 in complete mode), each implemented as an independent, object-oriented plugin. | High | 2 | RF-002 (B2, C1, G1) | CA-01 |
| FR-03 | Store target, category, CWE, OWASP Top 10:2025, WSTG reference, structured evidence, severity, confidence, status, and remediation. | High | 3 | RF-005 (F1, D3) | CA-02 |
| FR-04 | Calculate a 0–100 score from weighted findings. | Medium | 4 | RF-007 (E2, F3) | CA-03 |
| FR-05 | Explain developer impact and an actionable fix for every finding, including a concrete "vulnerable vs. fixed" code (or server-config) example. | High | 5 | RF-006 (D1, F1, F2) | CA-02 |
| FR-06 | Display analysis history per application. | High | 6 | RF-008 (E2, F3) | CA-05 |
| FR-07 | Compare two analyses as new, persistent, and fixed. | High | 7 | RF-008 (E2, F3) | CA-04 |
| FR-08 | Generate a complete printable report of one analysis. | Medium | 12 | RF-009 (F3, H1) | CA-06 |
| FR-09 | Report a confidence score separate from severity for every finding, and flag findings that require manual review. | High | 4 | RF-005 (F1, D3) | CA-02 |
| FR-10 | Test discovered form fields via POST (not only query-string parameters) in the value-injection active detectors (SQLi, XSS, path traversal, open redirect, command injection, SSTI, SSRF). | High | 2 | RF-003 (H1) | CA-01 |
| FR-11 | Optionally attach a session credential (cookie/bearer header) to every request to assess authenticated areas, sent only to the authorized target and never persisted. | Medium | 10 | RF-004 (G2, H1) | CA-01 |
| FR-12 | Export a completed analysis as machine-readable JSON, and let the developer filter findings by severity on the results page. | Medium | 8, 11 | RF-009 (F3, H1) | CA-06 |
| FR-13 | Expand the submitted URL into the reachable same-origin surface and scan each discovered page, following read-only navigation only: logout and state-changing links are never followed. | High | 9 | RF-010 (C1, G1) | CA-01 |

## Non-functional requirements

| ID | Requirement | Measurable condition | Priority | Origin (TR 3.2) | Interview source | Acceptance criterion |
|---|---|---|---|---|---|---|
| NFR-01 | A history of 1,000 findings is presented within three seconds in the defined test environment. | Elapsed time < 3,000 ms for 1,000 findings. | High | 6, 7 | RNF-004 (E2) | CA-05 |
| NFR-02 | User-supplied content is escaped; writes use prepared SQL statements; POST actions use CSRF tokens. | Zero unescaped outputs, zero concatenated SQL statements, and every POST route rejecting a request without a valid token. | High | 1, 2 | RNF-002 (G1) | CA-02 |
| NFR-03 | The scanner sends two independent bounded GET baseline requests per page, reads at most 256 KiB per response, times out after ten seconds per request, and does not exploit findings. | `BASELINE_REQUESTS = 2`; `max_response_bytes = 262144`; `request_timeout_seconds = 10.0`. | High | 2 | RNF-001 (G1) | CA-01 |
| NFR-04 | Private, loopback, link-local and reserved targets are denied by default. | A scan of a non-global address fails with `ScopeViolation` while `ALLOW_PRIVATE_TARGETS=false`. | High | 2 | RNF-001 (G1) | CA-01 |
| NFR-05 | Installation is reproducible from the supplied manual. | A person outside the team installs and runs the system using only the manual. | Medium | — | — | CA-07 |
| NFR-06 | User-facing content is authored in Brazilian Portuguese; CWE/OWASP/WSTG identifiers keep their standard English form; source code and engineering documentation are in English. | Inspection of finding texts and of the interface. | Medium | 5 | — | CA-02 |
| NFR-07 | Sensitive request headers (Cookie, Authorization, API keys) are masked in the execution log and never persisted. | The log contains no complete credential value, and no persisted column stores one. | High | 10 | RNF-005 (G2) | CA-02 |
| NFR-08 | A new check is added as a plugin implementing `ScannerPlugin`, without changing the orchestrator's logic. | A registered plugin runs with no vulnerability-specific code added to `engine/runner.py`. | Medium | 2 | RNF-003 (G2) | CA-01 |

Requirement count: 13 functional and 8 non-functional, above the minimum of 12 and 5 set for
the E1 delivery.

## Architecture traceability

Every high-priority requirement is mapped to the component that realises it in
[ARCHITECTURE.md](ARCHITECTURE.md) and in section 6.1 of the Fase 3 document. The measured
basis for the data-structure decisions behind NFR-01 is in
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md).

## Score rule

The score begins at 100. Each critical, high, medium, or low finding deducts 30, 15, 7, or 2 points respectively. The result is clamped to 0–100. This intentionally simple, deterministic rule is appropriate for comparison; it is not a universal measure of application security.
