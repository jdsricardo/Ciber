# Integration Contract — Web Application ⇄ Scanner Engine

| | |
|---|---|
| Contract version | **1.1** |
| Status | Normative. A change to any rule below requires a new version and an entry in the change log at the end of this document. |
| Producer | Scanner engine — `scanner/scanner.py` (Python 3.10+, standard library only) |
| Consumer | `App\Infrastructure\Scanner\PythonScannerGateway` → `App\Domain\Model\ScanResult` (PHP 8.2+) |
| Conformance tests | `tests/test_integration_contract.py` (producer side) and the *Integration contract* group in `tests/php_test.php` (consumer side). Both read the same captured payload, `tests/fixtures/scan_result.sample.json`. |

This document is the single agreement between the two halves of SentinelScope. The PHP
application never imports Python code and the engine never reads the database; everything that
crosses the boundary is described here: how the engine is started, what it receives, what it
prints, and what the consumer must do with each possible answer.

---

## 1. Transport

| Aspect | Rule |
|---|---|
| Mechanism | One child process per analysis. The consumer starts it, waits for it to exit, and reads its standard output. There is no socket, queue or shared file. |
| Direction | Request: command-line arguments. Response: **one JSON document** on standard output. |
| Encoding | Standard output is UTF-8, regardless of platform or console code page. The engine forces this with `stream.reconfigure(encoding="utf-8")`. |
| Framing | The whole standard output is the document. The consumer trims surrounding whitespace and decodes it with `json_decode`. There is no delimiter or length prefix: **anything else printed on standard output — a warning, a debug line, a traceback — is a contract violation**. |
| Standard error | Not part of the response. The consumer must not mix it into the document it decodes. |
| Exit code | `0` when the document has `"ok": true`; `1` when it has `"ok": false`. Any other code, or no document at all, means the engine did not run to completion. |

## 2. Request

### 2.1 Command line

```
<PYTHON_BINARY> <ROOT>/scanner/scanner.py <target-url> --mode=<mode> [--allow-private] [--cookie=<value>]
```

| Argument | Type | Required | Rule |
|---|---|---|---|
| `<target-url>` | string | yes | The application's base URL, already validated by `Domain\Model\TargetUrl` (HTTP/HTTPS, ≤ 2,048 characters, no embedded credentials). |
| `--mode` | `passive` \| `safe_active` | yes | `safe_active` is sent only when the user requested the full analysis **and** confirmed the separate active authorization (`RunAnalysis`). |
| `--allow-private` | flag | no | Sent only when `ALLOW_PRIVATE_TARGETS=true` in `.env`. Without it the engine refuses private, loopback, link-local and reserved destinations. |
| `--cookie` | string | no | Session credential for authenticated areas (FR-11). Sent only when the user supplied one for this analysis. |

Other options the engine accepts (`--header`, `--max-pages`, `--max-depth`, `--log-file`,
`--cancel-file`) are for command-line and evaluation use and are not sent by the web application.

### 2.2 Rules on the request

- **R1 — Arguments arrive intact.** The target URL and the session cookie must reach the engine
  byte-for-byte as the user entered them. Characters such as `%`, `!`, `"`, `&` and spaces are
  legitimate in both (percent-encoded URLs; cookie values) and must not be altered, dropped or
  interpreted by a shell.
- **R2 — No shell injection.** No user-supplied value may extend the command line.
- **R3 — The credential is transient.** The session cookie exists only in the child process's
  arguments for the duration of that analysis. It is never written to the database, to a file or
  to a log (NFR-07). The engine redacts `Cookie`, `Authorization` and API-key headers in its own
  request log (`SENSITIVE_HEADERS` in `scanner/engine/safety.py`).

## 3. Response

### 3.1 Success document (`"ok": true`)

| Field | Type | Meaning |
|---|---|---|
| `ok` | `true` | The scan ran and the findings below are its complete result. |
| `status_code` | int | HTTP status of the seed page's first baseline response. |
| `duration_ms` | int ≥ 0 | **Wall-clock duration of the whole scan**, from the first request to the last, in milliseconds. Shown to the user as the analysis duration. |
| `plugins_run` | int | Number of plugin families executed (7 passive; 20 in `safe_active`). |
| `checks_run` | int | Number of check identifiers declared by those plugins (34 passive; 64 in `safe_active`). |
| `baseline_stability` | float 0–1 | Similarity of the two baseline responses of the seed page. |
| `requests_made` | int | Requests sent, crawling and probing together. |
| `pages_scanned` | int | Distinct pages visited by the crawler. |
| `crawled_urls` | list of string | Those pages, in visiting order. |
| `findings` | list of *Finding* | Every finding, already de-duplicated across pages. May be empty. |
| `scanned_at` | string | ISO-8601 UTC timestamp. |
| `stopped_early` | string, optional | `budget_exceeded` or `cancelled` when the scan ended before exhausting the crawl. The findings gathered up to that point are still valid. |
| `plugin_warnings` | list of string, optional | Plugins that could not be loaded. |

The consumer currently reads `ok`, `findings`, `checks_run`, `duration_ms` and `status_code`;
the remaining fields are informational and may be ignored.

### 3.2 Finding

Every element of `findings` has the fields below. The **limit** column is the width of the
column that stores the field (`database.sql`); the producer must not exceed it, because a value
that does not fit is either rejected (strict SQL mode) or silently truncated (permissive mode),
and neither is acceptable.

| Field | Type | Required | Limit | Rule |
|---|---|---|---|---|
| `fingerprint` | string | yes | 120 | Check identifier, `<family>.<check>` (e.g. `xss.reflected_html_text`). Its prefix before the first dot is the vulnerability family. |
| `title` | string | yes | 180 | Short Portuguese title, from `plugins/catalog.py`. |
| `category` | string | yes | 80 | Category name. |
| `cwe` / `owasp` / `wstg` | string | yes | 120 each | Taxonomy identifiers in their standard English form (NFR-06). |
| `severity` | string | yes | enum | One of `critical`, `high`, `medium`, `low`. **No other value is valid.** |
| `confidence` | int | yes | 0–100 | Independent from severity (FR-09). |
| `status` | string | yes | 30 | One of `confirmed`, `high_confidence`, `probable`, `possible`, `informational`, `manual_review_required`. |
| `affected_url` | string | yes | 2,048 | URL where the finding was observed. For an active finding it is the probe URL and therefore includes the probe value. |
| `endpoint` | string | yes | — | Same value as `affected_url` (engine-internal name, not stored). |
| `method` | string | yes | 10 | HTTP method used to reach the finding (`POST` for form fields). |
| `parameter` | string \| null | yes | 180 | Name of the tested input, or `null` for page-level findings. |
| `parameter_location` | string \| null | yes | 40 | `query`, `form`, `cookie` (a finding about a cookie the page sets), or `null`. |
| `description` | string | yes | text | What the check looks for. |
| `evidence_summary` | string | yes | 500 | One-sentence statement of what was observed. |
| `evidence` | object | yes | 64 KiB serialized | Structured evidence: `reason`, `baseline`, `probe_request`, `probe_response`, `differences`, `verification_count`. Secrets are already redacted. |
| `developer_impact` | string | yes | text | Why it matters to the developer. |
| `remediation` | string | yes | text | How to fix it. |
| `manual_review_required` | bool | yes | — | The detector asks for human confirmation. |
| `remediation_example_vulnerable` / `_fixed` | string | yes (may be empty) | text | The "vulnerable vs. fixed" example (FR-05). |
| `remediation_example_language` | string | yes (may be empty) | 60 | Language of the example. |
| `remediation_example_note` | string | yes (may be empty) | 500 | Short note on the example. |

### 3.3 Failure document (`"ok": false`)

```json
{"ok": false, "error": "Falha de rede ao acessar o alvo: [WinError 10061] ..."}
```

| Field | Type | Rule |
|---|---|---|
| `ok` | `false` | The scan did not produce a usable result. |
| `error` | string, non-empty | Human-readable reason in Portuguese, shown to the user as the reason the analysis failed. |

Typical causes: target unreachable, scope violation (private destination without
`--allow-private`), no page could be fetched, global budget or time exhausted before the seed
page answered.

## 4. Consumer obligations

| Rule | Obligation |
|---|---|
| **C1 — Record before calling.** | The analysis row exists with status `running` before the engine is started, so an interrupted run leaves a trace. |
| **C2 — Every analysis is closed.** | Whatever happens after C1 — success, `ok:false`, unreadable output, engine crash, time limit, or a failure while storing the result — the analysis ends as `completed` or `failed` with a reason. **An analysis must never remain `running` after the request that started it has ended.** |
| **C3 — All or nothing.** | Findings and the `completed` status are written in one transaction. A failure while writing them leaves no partial findings. |
| **C4 — Validate, don't trust.** | The document is validated on reading (`ScanResult::fromEnginePayload`, `Finding::fromRow`, `Severity::fromString`). An invalid document — not JSON, unknown severity, missing fingerprint/title/URL, confidence outside 0–100 — fails the analysis with a clear reason; it is never stored partially and never reported as an empty scan. |
| **C5 — Deadline.** | The consumer allows the engine its full time budget (180 s passive, 600 s safe-active, `global_timeout_seconds` in `scanner/engine/runner.py`) plus a margin, and must still satisfy C2 if that deadline is exceeded. |
| **C6 — Escaping is the consumer's job.** | Every string in the document — including evidence copied from the target, which is attacker-controllable — is escaped on output (`Presentation\Html::escape`). |

## 5. Finding identity across analyses

Comparing two analyses (FR-07, CA-04) requires knowing when a finding of the older analysis is
"the same" as one of the newer analysis. The identity of a finding is the tuple:

```
( fingerprint,  scheme://host:port/path of affected_url (query string removed),  parameter_location,  parameter )
```

- The **query string is removed** because, for active findings, `affected_url` contains the
  random marker of the probe that revealed the issue, which differs on every run.
- The **path and parameter are kept** because the same check can fail independently on two
  endpoints or two parameters, and fixing one of them must show as *fixed* while the other
  stays *persistent*.
- Site-wide findings (headers, transport, cookies, cache, CORS) are reported once by the engine,
  at the first page where they were observed, which is the seed page whenever the condition holds
  there; their identity is therefore stable between runs of the same application.

## 6. Versioning policy

- Adding an optional response field is a **minor** change (1.x): consumers ignore fields they do
  not read.
- Removing or renaming a field, changing a type, adding a severity, or changing the meaning of a
  field is a **major** change (2.0) and requires the consumer to be changed in the same commit.
- Every change is recorded below, and the shared sample payload is regenerated with
  `python tests/test_integration_contract.py --regenerate-fixture`.

## 7. Change log

| Version | Date | Change |
|---|---|---|
| 1.1 | 2026-10-14 | `parameter_location` also takes `cookie`, which the cookie plugin has always emitted (`cookies.missing_httponly`, `cookies.missing_samesite`, …). Version 1.0 omitted it; the producer conformance test revealed the omission (defect D-08). Documentation correction — no code changed on either side. |
| 1.0 | 2026-10-14 | First written version of the contract that had been implicit in `ScanResult::fromEnginePayload` and `ScanRunner.run()` since Phase 1. Adds the explicit rules R1–R3, C1–C6, the column limits of §3.2, the meaning of `duration_ms` and the identity rule of §5. |
