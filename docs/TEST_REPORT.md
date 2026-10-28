# Test Report

| | |
|---|---|
| Product | SentinelScope 1.0.1 — the code after the fixes of D-01…D-10 (run 3) |
| Plan | [TEST_PLAN.md](TEST_PLAN.md) 2.0, written **before** the first execution; 2.1 adds the dated revisions of its §8 |
| Executed | 2026-10-14 (runs 1, 1b, 2) and 2026-10-28 (runs 3a, 3), with the automated driver; MT-04 pending (§6) |
| Environment | As in plan §2: Windows 11 Pro 10.0.26200, XAMPP Apache 2.4 + PHP 8.2.12, MariaDB 10.4.32, Python 3.12.2 |
| Raw evidence | `docs/test-evidence/2026-10-14_run1`, `…_run1-failure`, `…_run1b-confirm`, `…_run2`, `2026-10-28_run3a-before`, `…_run3` (per-case `results.md`/`results.json`, laboratory request logs, JSON exports, HTML responses, suite outputs) |

## 1. Summary

| Run | Code · started (UTC) | AT-01 Python | AT-02 PHP | System (ST) | Failure injection (FI) |
|---|---|---|---|---|---|
| 1 | before fixes · 2026-10-14 23:00 | 108 / 113 | 129 / 133 | 20 / 23 | 6 / 10 ¹ |
| 1b — confirmation | before fixes · 2026-10-14 23:05 | — | — | ST-24: 0 / 1 | FI-02, 03: pass; FI-08, 09: fail |
| 2 — re-execution | after fixes D-01…D-08 · 2026-10-14 23:13 | 113 / 113 | 140 / 140 | 24 / 24 | 10 / 10 |
| 3a — new cases, before D-09/D-10 | before D-09/D-10 · 2026-10-28 22:32 | — | — | ST-25, ST-26: 0 / 2; browser 2 / 3 ² | — |
| **3 — final re-execution** | **final code · 2026-10-28 22:36** | **113 / 113** | **153 / 153** | **26 / 26 + browser 3 / 3** | **10 / 10** |

¹ Of the four run-1 failures, two (FI-02, FI-03) were false positives of the driver and one
(FI-09) did not provoke the failure it was meant to provoke; see §4. They were re-run in 1b
before any product code changed.

² MT-01 failed in run 3a because of the driver, not the product (TW-04, §4).

**Outcome:** 10 defects found (1 blocker, 6 high, 2 medium, 1 low); **all 10 fixed and verified by
re-executing the cases that revealed them** (§3). No defect remains open. Every planned case was
executed except **MT-04** — installation by a person outside the team — on which CA-07 depends.

Run 3 is the reference result: the whole battery executed on the final code on 2026-10-28.

### 1.1 Acceptance criteria

| Criterion | Verdict | Evidence (run 2) |
|---|---|---|
| CA-01 — the catalogue runs and completion is recorded | **Met** | ST-06 (34 checks, passive), ST-08 (64 checks, complete mode), AT-01 |
| CA-02 — every finding has severity, confidence, status, taxonomy, evidence and fix | **Met** | ST-09 (all 14 findings of ST-08 complete), ST-11, ST-19 |
| CA-03 — score 0–100 by the 30/15/7/2 rule | **Met** | ST-10: page and export equal the manual calculation for both analyses |
| CA-04 — comparison shows new, persistent and fixed | **Met after D-01** | ST-13, ST-14 (failed in run 1) |
| CA-05 — 1,000 findings in under 3 s | **Met** | ST-22: worst of 20 timed responses 129.1 ms in run 3 (89.5 ms in run 2; limit 3,000 ms) |
| CA-06 — JSON export complete and equal to storage and screen | **Met after D-10** | ST-16, ST-24, ST-26 |
| CA-07 — installation by an outsider using only the manual | **Not yet verified** | MT-04 pending (§6) |
| CA-08 — high-priority requirements traced to the Termo | **Met** | Inspection TR-01 (§5) |

## 2. Results by case (run 2)

### 2.1 System tests

Observed values are those of run 2; run 3 repeated every case with the same verdict and adds ST-25 and ST-26.

| Case | Covers | Verdict | Observed |
|---|---|---|---|
| ST-01 | FR-01 | PASS | 302 → dashboard, notice shown, row with `authorization_confirmed_at`. |
| ST-02 | FR-01 *(inv)* | PASS | 400, authorization message, no row. |
| ST-03 | FR-01 *(inv)* | PASS | 400 with the specific message for each of the 5 invalid URLs; no row. |
| ST-04 | FR-01 *(inv)* | PASS | 400 for empty, blank and 121-character names; no row. |
| ST-05 | NFR-02 *(inv)* | PASS | 400 "token de sessão expirou" for missing and wrong token, on create and run; nothing created. |
| ST-06 | FR-02, FR-13, NFR-03 | PASS | Completed, 34 checks; `/`, `/search`, `/profile`, `/about` each received exactly 2 GET; **0 requests to `/logout` and `/item`**; no XSS in passive mode. |
| ST-07 | FR-02 *(inv)* | PASS | 400, no analysis created. |
| ST-08 | FR-02, FR-10 | PASS | Completed in 14.8 s, 64 checks; XSS on `/search` (q) and `/profile` (name). |
| ST-09 | FR-03/05/09 | PASS | All 14 findings complete and shown. |
| ST-10 | FR-04 | PASS | Scores equal to the manual calculation. |
| ST-11 | NFR-02 *(inv)* | PASS | `<script>` name escaped on the dashboard; no raw probe tag on the result page. |
| ST-12 | FR-06 | PASS | Both analyses listed, newest first, with mode, status and score. |
| ST-13 | FR-07, CA-04 | PASS | *Corrigidos*: XSS at `/search · parâmetro q`; *Ainda presentes*: XSS at `/profile · parâmetro name`; no new finding. |
| ST-14 | FR-07, CA-04 | PASS | Both XSS and the four header findings in *Corrigidos*; no new finding; score improved. |
| ST-15 | FR-07 *(inv)* | PASS | 400 "Escolha duas análises da mesma aplicação." |
| ST-16 | FR-12, CA-06 | PASS | JSON attachment; counts and fingerprints equal in export, database and page. |
| ST-17 | FR-08 | PASS | Report with name, score, metrics, every title and remediation, print button, no export link. |
| ST-18 | FR-12 | PASS | Chip counts equal to the export per severity. |
| ST-19 | FR-11, NFR-07 | PASS | `/account/notes` reached with the cookie; the secret is absent from a full database dump, the Apache access log and the error log. |
| ST-20 | Contract R1 | PASS | Cookie `lab_session=s3cr%3D!x` received byte for byte; first request `GET /search?q=a%20b`. |
| ST-21 | errors *(inv)* | PASS | 404 with the right message on all four routes. |
| ST-22 | NFR-01, CA-05 | PASS | Result page 60–76 ms, report 46–90 ms, export 41–85 ms, comparison of 1,000 × 1,000 59–80 ms; 1,000 findings rendered. |
| ST-23 | step 23 | PASS | `data-busy`, `role="status"` and the submit handler present. |
| ST-24 | FR-06, CA-06 | PASS | History date within the run's UTC window; `started_at ≤ completed_at`, 2 s apart. |
| ST-25 | FR-06, Termo item 6 | PASS (run 3; failed in 3a — D-09) | No period: 3 analyses; February: 1; 15/02–20/03: 2 (both ends inclusive); open end: 2; reversed range and `31/02/2026`: 400 with their messages; the form shows the period applied. |
| ST-26 | FR-12, Termo item 8 | PASS (run 3; failed in 3a — D-10) | `summary` = 14 findings, `by_severity` {critical 0, high 3, medium 5, low 6}, `manual_review_required` 0, `security_score` 8 — each equal to the findings and the analysis. |

### 2.2 Failure injection (roadmap step 28) — observed behaviour

| Case | Failure provoked | Observed behaviour (run 2) | Verdict |
|---|---|---|---|
| FI-01 | `.env` absent | 503 with the configuration guidance. | PASS |
| FI-02 | MariaDB stopped | 500 with the generic message; no SQLSTATE, path or stack trace in the response; full exception in Apache's `error.log`; the password appears nowhere (PHP 8.2 logs it as `Object(SensitiveParameterValue)`). | PASS |
| FI-03 | Wrong DB password | Same as FI-02; the wrong password is neither shown nor logged. | PASS |
| FI-04 | Target unreachable | `failed` with "Falha de rede ao acessar o alvo…", reason shown, no findings. | PASS |
| FI-05 | Loopback with private targets denied | `failed` with "Private, loopback, link-local, and reserved targets are blocked"; **0 requests** reached the target. | PASS |
| FI-06 | Python binary absent | `failed` with "O scanner retornou uma resposta inválida…"; not left running. | PASS |
| FI-07 | Engine answers `severity: "info"` | `failed` with "Severidade desconhecida: info."; no findings stored. | PASS |
| FI-08 | `INSERT` on `findings` revoked | 500 generic page; analysis `failed` with "Falha ao gravar o resultado da análise…"; no partial findings. | PASS (failed in run 1 — D-02) |
| FI-09 | Scan longer than PHP's 120 s | Complete-mode scan of 228.6 s finished; 302 to the result; analysis `completed`, score 8, 64 checks. | PASS (failed in run 1b — D-04) |
| FI-10 | 300-char field name, strict SQL mode | `completed`; the form finding stored with a 180-character parameter. | PASS (failed in run 1 — D-06, D-02) |

### 2.3 Automated suites

| Suite | Run 2 | Duration |
|---|---|---|
| AT-01 `python -m unittest discover -s tests -v` | 113 tests, OK (runs 2 and 3) | 266.3 s |
| AT-02 `php tests/php_test.php` | 140 checks (run 2); 153 checks, 0 failed (run 3: + period and export summary) | < 2 s |

## 3. Defect register

Severity per plan §3.1. "Verified" means the case that revealed the defect was re-executed on
the fixed code and passed (run 2) — not merely that the code was changed.

| ID | Severity | Title | Found by | Root cause | Fix | Verified |
|---|---|---|---|---|---|---|
| D-01 | High | Comparison merges the same check found on two endpoints; fixing one endpoint is not shown | ST-13, ST-14, AT-02 (§5 identity) | The engine's `fingerprint` is the check id; `AnalysisComparison` keyed by it. The full URL cannot be used either: it carries the random probe marker. | `Finding::identity()` = check + endpoint without query + parameter location + name; comparison keyed by identity; comparison page shows page and parameter. Contract §5. | ST-13, ST-14, AT-02 ✔ |
| D-02 | **Blocker** | A failure while storing the result leaves the analysis `running` forever | FI-08, FI-10, AT-02 (C2) | `RunAnalysis` closed the analysis on scanner failures but not when the findings transaction threw. | Catch around the transaction: close as `failed` with a reason, rethrow for logging. | FI-08, FI-10, AT-02 ✔ |
| D-03 | High | `%`, `!` and `"` in the target URL or session cookie become spaces before reaching the engine (Windows) | ST-20 | `escapeshellarg()` on Windows replaces those characters; a percent-encoded URL failed, a cookie arrived altered. | Engine started with `proc_open` from an argument list, no shell (contract R1/R2). Unit checks of the argument list added to AT-02. | ST-20, AT-02 ✔ |
| D-04 | High | A scan longer than 120 s dies with *Fatal error: Maximum execution time … in C:\xampp\…\PythonScannerGateway.php*, HTTP 200, analysis left `running` | FI-09 (run 1b) | On Windows `max_execution_time` counts wall-clock time, including the wait for the engine; `display_errors=On` in XAMPP showed the path. | Gateway raises the request's limit to its own deadline (210 s / 630 s, aligned with the engine budget), terminates the engine at the deadline with a reason, ignores client aborts; bootstrap forces `display_errors=0`. | FI-09 ✔ |
| D-05 | Medium | Analysis *Duração* shows ~0 ms for a 14 s scan | AT-01 (contract) | `duration_ms` carried the seed page's response time. | Wall-clock duration of the whole scan. | AT-01 ✔ |
| D-06 | High | A value longer than its column (300-char form field name) is rejected by a strict database, losing the analysis; silently truncated by a permissive one | AT-01 (contract), FI-10 | The engine copies target-controlled names and URLs into findings without bounds. | `FINDING_FIELD_LIMITS` applied in `Finding.to_dict()` (contract §3.2). | AT-01, FI-10 ✔ |
| D-07 | Medium | History labelled "UTC" shows server-local time; an analysis appears to last 3 h | Observed in run 1 (database), then ST-24 written before the fix | `started_at` from a column default in the session's local zone (America/Sao_Paulo), `completed_at` from `UTC_TIMESTAMP()`. | Connection sets `time_zone = '+00:00'`. | ST-24 ✔ |
| D-09 | High | The history cannot be consulted by period, as Termo item 6 requires ("consultar o histórico … por período") | Cross-check of the Termo against the product; ST-25 (run 3a) | Not implemented: the dashboard always listed the whole history. | `Domain\Model\Period`; `AnalysisRepository::listByApplication()` takes an optional period, a range on the `(application_id, started_at)` index; *Histórico por período* form on the dashboard. | ST-25, AT-02 ✔ |
| D-10 | High | The JSON export has no real summary, as Termo item 8 requires ("resumo, Pontuação de Segurança, metadados e relação dos achados") | Cross-check of the Termo against the product; ST-26 (run 3a) | `summary` carried only the number of findings. | `summary` with `by_severity`, `manual_review_required` and `security_score`. | ST-26, AT-02 ✔ |
| D-08 | Low | Contract v1.0 did not list `cookie` as a `parameter_location` | AT-01 (contract) | Documentation omission; the producer always emitted it. | Contract v1.1; producer test updated. | AT-01 ✔ |

### 3.1 Reproduction steps (on the code before the fixes)

- **D-01** Register `http://127.0.0.1:8765/`; run a complete analysis with `lab_target.py --variant vulnerable`; restart the lab with `--variant partial`; run again; compare. *Corrigidos* is empty although `/search` was fixed.
- **D-02** `REVOKE` `INSERT` on `sentinelscope.findings` from the application user; run any analysis. HTTP 500, and the dashboard shows the analysis `running` indefinitely.
- **D-03** Run with the cookie `lab_session=s3cr%3D!x`; the lab log shows `Cookie: lab_session=s3cr 3D x`. Register `http://127.0.0.1:8765/search?q=a%20b`; the analysis fails.
- **D-04** Start the lab with `--delay 2`; run a complete analysis. After 120 s the browser shows the fatal error with the server path; the analysis stays `running`.
- **D-05** `python scanner/scanner.py http://127.0.0.1:8765/ --mode=safe_active --allow-private` → `"duration_ms": 0` after ~14 s.
- **D-06** `SET GLOBAL sql_mode='STRICT_TRANS_TABLES'`; complete analysis of `lab_target.py --variant edge`. Apache log: `Data too long for column 'parameter'`; analysis `running`.
- **D-07** Run any analysis on a server whose time zone is not UTC; `SELECT TIMESTAMPDIFF(SECOND, started_at, completed_at)` returns 10,800 for a 2-second run.
- **D-09** Open the dashboard: nothing restricts the history to a period; `index.php?from=2026-02-01&to=2026-02-28` lists every analysis.
- **D-10** Export any analysis: `"summary": {"findings": N}` and nothing else.
- **D-08** Run `tests/test_integration_contract.py` with contract v1.0: `cookies.missing_httponly.parameter_location must be query, form or null`.

### 3.2 Residual observations (not defects)

- **Rows left by the old code.** Analyses 15, 17, 19 and 20 of the test database were left
  `running` by runs 1 and 1b, before D-02/D-04 were fixed. The fix prevents new occurrences; it
  does not rewrite history. An installation that ran the old version can close such rows with
  `UPDATE analyses SET status='failed', error_message='Interrompida antes da correção D-02/D-04', completed_at=UTC_TIMESTAMP() WHERE status='running';`
  while no analysis is in progress.
- **Deadline termination not exercised end to end.** FI-09 proves that a scan longer than PHP's
  120 s now completes. The branch that terminates the engine at the gateway's own deadline (630 s
  in complete mode) was not provoked, because the engine's own 600 s budget ends the scan first;
  that branch is verified by code review only.
- **Pre-existing timestamps.** Rows written before D-07 keep their local-time `started_at`.

## 4. Test-ware issues

Problems of the tests themselves, kept apart from product defects so the product's numbers are
not inflated or hidden.

| ID | Issue | Effect | Resolution |
|---|---|---|---|
| TW-01 | The "no technical detail" check treated `.php` as a leak, but every page links to `index.php`. | False FAIL in FI-02, FI-03, FI-08 (run 1). | The responses were inspected by hand (generic message only); marker list corrected; re-run in 1b. |
| TW-02 | The driver read `php/logs/php_error_log`, which XAMPP does not create; PHP logs to Apache's `error.log`. | False FAIL "detail logged" in FI-02. | Path corrected; the manual and developer guide point to the right log. |
| TW-03 | FI-09 with 1 s per response finished in 115.8 s, under the 120 s it was meant to exceed. | A **false PASS** in run 1: the failure was not provoked. Recorded as void. | Delay raised to 2 s (plan revision §8); run 1b then reproduced D-04. |
| TW-04 | MT-01 read the button through DevTools after the click; once a form is submitted the browser answers DevTools only after the next page has loaded. | False FAIL in run 3a: the driver read the result page instead of the button. | Checked by hand with submission blocked (the button is locked and shows "Analisando…"); the state is now recorded inside the page (MutationObserver → `sessionStorage`) and read after the navigation. |

The expected results of these cases did not change; plan §8 records each revision and its date.

## 5. Inspection

| ID | Item | Result |
|---|---|---|
| TR-01 | CA-08: every high-priority requirement of [REQUIREMENTS.md](REQUIREMENTS.md) points to an item of the Termo's included scope (§3.2). | 14 of 14 high-priority requirements carry an origin item (1, 2, 3, 4, 5, 6, 7, 9 or 10). Met. |
| TR-02 | Every high-priority requirement has at least one test case. | Plan §7: all 14 covered. Met. |
| TR-03 | The battery includes invalid-input cases. | ST-02, 03, 04, 05, 07, 11, 15, 21 and all FI cases. Met. |

## 6. Browser and manual cases

MT-01…MT-03 need a real browser engine, not a person: since run 3 they are executed by the
`browser` suite of the driver, in a headless Chrome driven through the DevTools protocol
(`tests/e2e/cdp.py`). MT-04 needs a person outside the team and is the only case not executed.

| ID | Result (run 3) | Verdict |
|---|---|---|
| MT-01 | After a real double click the button was disabled with the text "Analisando…", `aria-busy=true`, the progress message visible; the result page opened and **exactly one** analysis was created. | PASS |
| MT-02 | Result with 12 findings (1 high, 5 medium, 6 low): each chip left visible only the findings of its severity, in the right number; *Todos* showed the 12 again. | PASS |
| MT-03 | Report printed to PDF (`2026-10-28_run3/MT-03-report.pdf`): application name, score, metrics and every finding title present; navigation and buttons absent. | PASS |
| MT-04 | Outsider installs using only the manual and runs one analysis; record every question. | **Pending — to be executed by the team** |

## 7. How to reproduce

```bash
php tests/php_test.php
python -m unittest discover -s tests -v
python tests/e2e/run_system_tests.py --run-name <name>   # Apache + MariaDB running, ALLOW_PRIVATE_TARGETS=true; Chrome or Edge for MT-01…03
```
