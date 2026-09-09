# Software Requirements and Traceability

## Functional requirements

| ID | Requirement | Acceptance criterion |
|---|---|---|
| FR-01 | Register an application name and HTTP(S) base URL with authorization confirmation. | CA-01 |
| FR-02 | Execute 34 predefined, passive checks on demand across transport, TLS, headers, cookies, CORS, caching, information disclosure, and secrets exposure, each implemented as an independent, object-oriented plugin. | CA-01 |
| FR-03 | Store target, category, CWE, OWASP Top 10:2025, WSTG reference, structured evidence, severity, confidence, status, and remediation. | CA-02 |
| FR-04 | Calculate a 0–100 score from weighted findings. | CA-03 |
| FR-05 | Explain developer impact and an actionable fix for every finding, including a concrete "vulnerable vs. fixed" code (or server-config) example. | CA-02 |
| FR-06 | Display analysis history per application. | CA-05 |
| FR-07 | Compare two analyses as new, persistent, and fixed. | CA-04 |
| FR-08 | Generate a complete printable report. | CA-06 |
| FR-09 | Report a confidence score separate from severity for every finding, and flag findings that require manual review. | CA-02 |
| FR-10 | Test discovered form fields via POST (not only query-string parameters) in the value-injection active detectors (SQLi, XSS, path traversal, open redirect, command injection, SSTI, SSRF). | CA-01 |
| FR-11 | Optionally attach a session credential (cookie/bearer header) to every request to assess authenticated areas, sent only to the authorized target and never persisted. | CA-01 |
| FR-12 | Export a completed analysis as machine-readable JSON, and let the developer filter findings by severity on the results page. | CA-06 |

## Non-functional requirements

- NFR-01: A query over 1,000 indexed findings must render within three seconds in the defined test environment.
- NFR-02: User-supplied content is escaped; writes use prepared SQL statements; POST actions use CSRF tokens.
- NFR-03: The scanner performs two independent, bounded GET baseline requests (to measure response stability and reduce false positives), reads at most 256 KiB per response, times out after ten seconds per request, and does not exploit findings.
- NFR-04: Private and reserved network targets are denied by default to reduce SSRF risk.
- NFR-05: Installation must be reproducible using the supplied manual.
- NFR-06: User-facing content (finding titles, descriptions, developer impact, remediation, and code examples) is authored in Brazilian Portuguese, since the target audience is a Brazilian development team; CWE/OWASP/WSTG identifiers remain in their standard English form. Source code, code comments, and engineering documentation are in English.

## Score rule

The score begins at 100. Each critical, high, medium, or low finding deducts 30, 15, 7, or 2 points respectively. The result is clamped to 0–100. This intentionally simple, deterministic rule is appropriate for comparison; it is not a universal measure of application security.
