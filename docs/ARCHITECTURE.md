# Architecture

SentinelScope uses a layered, local deployment. The browser sends requests to a pure PHP application. PHP validates input, orchestrates analyses, renders results, and persists data through PDO prepared statements. A separately invoked Python process performs the bounded HTTP request and returns JSON. MariaDB stores applications, analyses, and findings.

## Main flow

1. The developer registers an authorized target.
2. PHP creates a `running` analysis and invokes the Python scanner with escaped arguments.
3. Python validates the URL and resolved addresses, requests one document, evaluates 32 passive response-level checks, and emits JSON.
4. PHP stores the findings in a transaction, calculates the score, and marks the analysis complete.
5. The UI presents each issue as observation, developer impact, and fix. Historical fingerprints support comparisons.

## Security boundaries

- Private, loopback, link-local, and reserved destinations are blocked by default.
- The scanner accepts only HTTP(S), rejects URL credentials, follows no redirects, limits response size, and uses a timeout.
- Mutations require a session-bound CSRF token. Output encoding mitigates stored XSS. PDO native prepared statements prevent SQL injection.
- The current academic version assumes a trusted single-user local installation. Authentication and role-based access are recommended before shared deployment.

## Data model

`applications 1—N analyses 1—N findings`. Indexed application/date and analysis/fingerprint paths support history and comparison. Foreign keys preserve consistency.
