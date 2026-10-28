# Test Plan

| | |
|---|---|
| Product | SentinelScope 1.0 |
| Plan version | 2.1 (2.0 of 2026-10-14 plus the dated revisions of §8; replaces the 1.x plan, whose cases TC-01…TC-18 are kept as automated tests in §5) |
| Written | 2026-10-14, **before** any case below was executed — the expected result of every case is fixed here first (roadmap step 29, "golden rule"). Execution results go to [TEST_REPORT.md](TEST_REPORT.md), never into this file. |
| Basis | Acceptance criteria CA-01…CA-08 of the Termo de Referência (§5), requirements in [REQUIREMENTS.md](REQUIREMENTS.md), integration rules in [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md). |

## 1. Scope and approach

| Level | What it verifies | How | Where |
|---|---|---|---|
| Unit / component | Domain invariants, use cases, presentation, score, comparison, every scanner plugin against vulnerable and safe fixtures | Automated, no database, no network beyond 127.0.0.1 | `tests/php_test.php`, `tests/test_*.py` |
| Contract | Both sides of the PHP ⇄ Python boundary obey [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) | Automated; both sides read the same captured payload | `tests/test_integration_contract.py`, *Integration contract* group of `tests/php_test.php` |
| System (end-to-end) | The complete flow, from the browser request to the database and back, through Apache + PHP + MariaDB + the Python engine, against a controllable laboratory target | Automated HTTP driver, black-box through the web interface; database read only to confirm what the interface shows | `tests/e2e/run_system_tests.py`, `tests/e2e/lab_target.py` |
| Failure injection | Behaviour under each foreseeable failure (roadmap step 28) | Same driver, with the environment deliberately broken and restored | `tests/e2e/run_system_tests.py --suite failure` |
| Manual | What needs a human, a real browser or an outsider | Protocol in §6, executed and signed by a tester | [TEST_REPORT.md](TEST_REPORT.md) §6 |

Every requirement of high priority has at least one case, and every functional area has cases
with **invalid input**, not only the success path (roadmap §9, checklist before E4).

## 2. Test environment

| Item | Value |
|---|---|
| Machine | Windows 11 Pro 10.0.26200, single developer workstation |
| Web server | XAMPP Apache 2.4 with mod_php, PHP 8.2.12 (`max_execution_time=120`) |
| Database | MariaDB 10.4.32 (XAMPP), schema from `database.sql`, application user `sentinelscope_app` with `SELECT, INSERT, UPDATE, DELETE` only |
| Engine | Python 3.12, standard library only |
| Application URL | `http://localhost/www/Ciber/public/` |
| Laboratory target | `tests/e2e/lab_target.py` on `http://127.0.0.1:8765/`; `.env` has `ALLOW_PRIVATE_TARGETS=true` because the target is on loopback |
| Test data | Created by the cases themselves; every application name carries the run tag so runs never collide. CA-05 seeds 1,000 findings with a script (ST-22). |

### 2.1 Laboratory target

The target is a deliberately vulnerable application whose state is chosen at start-up, so a case
can scan it, "deploy a fix" by restarting it with another variant, and scan again. It logs every
request it receives, which lets a case prove what the scanner did **not** do.

| Variant | `/search?q=` | `/profile?name=` | Security headers | Extra |
|---|---|---|---|---|
| `vulnerable` | reflects unescaped (XSS) | reflects unescaped (XSS) | none | cookie without flags; links to `/logout` and `/item?id=7&action=delete` |
| `partial` | **escaped** | reflects unescaped | none | — |
| `fixed` | escaped | escaped | CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy | — |
| `edge` | as `vulnerable` | as `vulnerable` | none | `/feedback` form with a 300-character field name |

`/account` and `/account/notes?n=` answer only to the cookie `lab_session=<secret>`; otherwise they
redirect to `/`.

## 3. Entry and exit criteria

- **Entry:** the two automated suites pass; Apache and MariaDB are running; the schema is imported.
- **Exit:** every case executed; every *blocker* and *high* defect fixed **and verified by
  re-executing the case that revealed it** (roadmap step 31); every open defect of lower severity
  recorded with its justification.

### 3.1 Defect severity

| Severity | Meaning |
|---|---|
| Blocker | Prevents a main flow or corrupts/loses data; no workaround. |
| High | A requirement or acceptance criterion is not met, or a security rule is broken. |
| Medium | Wrong or misleading information to the user; a workaround exists. |
| Low | Cosmetic or documentation divergence. |

## 4. Test cases

Notation: **Pre** = precondition, **Steps** = what the driver does, **Expected** = the result
that makes the case pass. *(inv)* marks a case built on invalid input or a broken environment.

### 4.1 System tests — registration and input validation

| ID | Covers | Pre | Steps | Expected |
|---|---|---|---|---|
| ST-01 | FR-01, CA-01 | Dashboard reachable | POST `create` with a name, `http://127.0.0.1:8765/` and the authorization box ticked | HTTP 302 to `index.php`; the dashboard shows the notice "Aplicação registrada." and a card with the name and URL; the `applications` row has a non-null `authorization_confirmed_at`. |
| ST-02 *(inv)* | FR-01 | — | POST `create` without the authorization box | HTTP 400; page shows "Confirme que você possui autorização para analisar este alvo."; no row created. |
| ST-03 *(inv)* | FR-01 | — | POST `create` with each URL: empty, `ftp://example.com/`, `javascript:alert(1)`, `http://user:pw@example.com/`, `nota-uma-url` | HTTP 400 for each, with the matching message (`Informe a URL da aplicação.`, `A URL deve usar o esquema HTTP ou HTTPS.` or `Informe uma URL válida.`, `A URL não pode conter credenciais embutidas.`); no row created. |
| ST-04 *(inv)* | FR-01 | — | POST `create` with name empty, only spaces, and 121 characters | HTTP 400 for each; no row created. |
| ST-05 *(inv)* | NFR-02 | An application exists | POST `create` and POST `run` without the `csrf` field, and with a wrong one | HTTP 400 with "Seu token de sessão expirou. Atualize a página e tente novamente."; no application and no analysis created. |

### 4.2 System tests — analysis

| ID | Covers | Pre | Steps | Expected |
|---|---|---|---|---|
| ST-06 | FR-02, FR-13, NFR-03, CA-01 | Lab `vulnerable`; application registered (ST-01) | POST `run` in passive mode | 302 to `page=result&id=N`; analysis `completed`; *Verificações executadas* = **34**; lab log shows `/`, `/search`, `/profile`, `/about` requested, **each page exactly 2 GET** (two baselines), **zero requests to `/logout` and `/item`**; findings include `headers.csp_missing`; **no `xss.*` finding** (passive mode sends no probe). |
| ST-07 *(inv)* | FR-02 | Application registered | POST `run` with active mode but without the active authorization | HTTP 400 "Autorize o envio de payloads de teste ativos para usar a análise completa."; the number of analyses of the application does not change. |
| ST-08 | FR-02, FR-10, CA-01 | Lab `vulnerable` | POST `run` with active mode and active authorization | Analysis `completed`; *Verificações executadas* = **64**; findings include `xss.reflected_html_text` with parameter `q` on `/search` **and** with parameter `name` on `/profile`; still zero requests to `/logout` and `/item`. |
| ST-09 | FR-03, FR-05, FR-09, CA-02 | ST-08 done | Read the JSON export and the result page of ST-08 | **Every** finding has non-empty severity, confidence in 0–100, status, category, CWE, OWASP, WSTG, evidence with a `reason`, developer impact and remediation; the result page shows each finding's title and severity label. |
| ST-10 | FR-04, CA-03 | ST-06 and ST-08 done | For each, compute `max(0, min(100, 100 − 30·critical − 15·high − 7·medium − 2·low))` from the exported findings | The computed value equals the score on the result page and the `security_score` of the export. |
| ST-11 *(inv)* | NFR-02 | — | Register an application named `<script>alert("st11")</script>`; open the dashboard; open the result page of ST-08 (its evidence contains the HTML tag the probe injected) | The dashboard contains `&lt;script&gt;alert(&quot;st11&quot;)&lt;/script&gt;` and **not** the raw tag; the result page contains no raw probe tag `<sszz`. |
| ST-12 | FR-06 | ST-06 and ST-08 done | Open the dashboard | The application's card lists both analyses, the most recent first, each with mode, status `completed` and score. |
| ST-19 | FR-11, NFR-07, R3 | Lab `vulnerable` with secret `st19-<tag>` | POST `run` (passive) with the session cookie `lab_session=st19-<tag>` | Analysis completed; the lab log shows `/account/notes` requested **with** that cookie (the authenticated area was reached; without the cookie `/account` only redirects); the secret appears **nowhere** in the database (full dump of `sentinelscope`), in the Apache access log or in the PHP error log. |
| ST-20 | Contract R1 | Lab `vulnerable` with secret `s3cr%3D!x` | (a) POST `run` with cookie `lab_session=s3cr%3D!x`; (b) register `http://127.0.0.1:8765/search?q=a%20b` and run it | (a) the Cookie header received by the lab is exactly `lab_session=s3cr%3D!x` and `/account/notes` is reached; (b) the first request received by the lab is `GET /search?q=a%20b`. |

### 4.3 System tests — comparison, history, export, report

| ID | Covers | Pre | Steps | Expected |
|---|---|---|---|---|
| ST-13 | FR-07, CA-04 | New application; active analysis **A** of lab `vulnerable`; then lab restarted as `partial`; active analysis **B** | Open `compare&old=A&new=B` | *Corrigidos* contains the XSS of `/search`; *Ainda presentes* contains the XSS of `/profile`; *Novos problemas* is empty. |
| ST-14 | FR-07, CA-04 | A from ST-13; lab restarted as `fixed`; active analysis **C** | Open `compare&old=A&new=C` | *Corrigidos* contains both XSS findings and the four header findings the fixed variant now sends (`csp`, `frame_options`, `nosniff`, `referrer_policy`); *Novos problemas* is empty; the score of C is higher than that of A. |
| ST-15 *(inv)* | FR-07 | Analyses of two different applications | Open `compare` with one of each | HTTP 400 "Escolha duas análises da mesma aplicação." |
| ST-16 | FR-12, CA-06 | ST-08 done | GET `export&id=<ST-08>` | HTTP 200, `Content-Type: application/json`, `Content-Disposition: attachment`; the document has the application name, `started_at`, `security_score`; the number of findings equals the number in the database **and** the number shown on the result page; the multiset of fingerprints equals the database's. |
| ST-17 | FR-08 | ST-08 done | GET `report&id=<ST-08>` | HTTP 200; contains the application name, the score, the four run metrics, every finding title and its remediation, the print button; does **not** contain the *Exportar JSON* link. |
| ST-18 | FR-12 | ST-08 done | Read the severity chips of the result page | One chip per severity present, each count equal to the number of exported findings of that severity; *Todos* equals the total. |
| ST-21 *(inv)* | Error convention | — | GET `result&id=999999`, `export&id=999999`, `compare&old=999999&new=999999`; POST `run` with `application_id=999999` | HTTP 404 for each, with "Análise não encontrada." or "Aplicação não encontrada." |
| ST-22 | NFR-01, CA-05 | An analysis seeded with **1,000** findings (mixed severities) and a second one with 1,000 for comparison | GET result page, report, export and comparison, 5 times each, timing the full HTTP response | Every one of the 20 responses completes in **< 3,000 ms**; the result page renders 1,000 findings. |
| ST-23 | Roadmap step 23 | Application registered | GET dashboard and `assets/app.js` | The run form carries `data-busy` and a `role="status"` element; the script contains the submit handler that shows it and locks the button. (Interactive behaviour: MT-01.) |
| ST-24 | FR-06, CA-06 | Lab `vulnerable`; UTC time noted before and after one passive run | Read the dashboard row and the JSON export of that analysis | The date shown in the history column *Data (UTC)* lies between the two noted UTC instants (± 5 s); in the export `started_at ≤ completed_at` and the difference is under 60 s. *(Added 2026-10-14 after run 1 — see §8.)* |
| ST-25 | FR-06, Termo 3.2 item 6 | New application with three completed analyses whose `started_at` is 2026-01-10, 2026-02-15 and 2026-03-20 (set by the driver in the database) | GET the dashboard (a) without a period; (b) `from=2026-02-01&to=2026-02-28`; (c) `from=2026-02-15&to=2026-03-20`; (d) `from=2026-02-01` only; *(inv)* (e) `from=2026-03-01&to=2026-02-01`; *(inv)* (f) `from=31/02/2026` | (a) the card lists the 3 analyses; (b) only the February one; (c) February and March — both ends inclusive; (d) February and March; (e) HTTP 400 "A data inicial deve ser anterior ou igual à data final."; (f) HTTP 400 "Informe as datas no formato AAAA-MM-DD.". The filter form shows the period applied. *(Added 2026-10-28 — see §8.)* |
| ST-26 | FR-12, Termo 3.2 item 8 | ST-08 done | GET `export&id=<ST-08>` and read `summary` | `summary.findings` = number of findings; `summary.by_severity` has the four severities and each count equals the findings of that severity; `summary.security_score` = `analysis.security_score`; `summary.manual_review_required` = number of findings flagged for manual review. *(Added 2026-10-28 — see §8.)* |

### 4.4 Failure injection (roadmap step 28)

Each case breaks one thing, records the observed behaviour, and restores the environment. The
expected behaviour is the one the contract and the error convention require.

| ID | Failure provoked | Expected behaviour |
|---|---|---|
| FI-01 | `.env` absent | HTTP 503 with "Configuração necessária: copie .env.example para .env e importe database.sql." |
| FI-02 | MariaDB stopped | HTTP 500 with the generic "Ocorreu um erro inesperado. Consulte o log do servidor."; the response contains no `SQLSTATE`, stack trace, file path or credential; the detail is written to the PHP error log, without the database password. |
| FI-03 | Wrong database password in `.env` | Same as FI-02; the wrong password appears neither in the response nor in the log. |
| FI-04 | Target unreachable (lab not running) | Analysis `failed`; the result page shows the reason; no findings; dashboard row `failed`. |
| FI-05 | Loopback target with `ALLOW_PRIVATE_TARGETS=false` | Analysis `failed` with the scope reason; **the lab receives zero requests**. |
| FI-06 | `PYTHON_BINARY` points to a program that does not exist | Analysis `failed` with "O scanner retornou uma resposta inválida. Verifique a configuração do Python."; never left `running`. |
| FI-07 | The engine answers a document that breaks the contract (`severity: "info"`) | Analysis `failed` with "Severidade desconhecida: info."; no findings stored. |
| FI-08 | The database refuses the write of findings (`INSERT` on `findings` revoked) | The user gets an error page; the analysis is `failed` with a reason, **not** left `running`; no findings stored (contract C2, C3). |
| FI-09 | The scan outlives PHP's `max_execution_time` (lab answering each request after 2 s, active mode ≈ 140 requests ⇒ ≈ 280 s; 1 s in plan 2.0, see §8) | The request ends with a page for the user and the analysis is `completed` or `failed` with a reason — **never left `running`** (contract C2, C5). |
| FI-10 | A value longer than its column (lab `edge`: a 300-character field name) with MariaDB in strict mode (`STRICT_TRANS_TABLES`, the MariaDB default outside XAMPP) | The analysis is `completed`; the form finding is stored with a `parameter` of at most 180 characters (contract §3.2). |

## 5. Automated suites (regression)

| ID | Suite | Expected |
|---|---|---|
| AT-01 | `python -m unittest discover -s tests -v` — 106 pre-existing tests (engine, every plugin against vulnerable/safe fixtures, crawler, transport, remediation examples, coding standard, evaluation harness) plus the 7 producer-side contract tests | All pass. |
| AT-02 | `php tests/php_test.php` — 115 pre-existing checks (layering, coding standard, domain invariants, score, presentation, comparison, use cases, export, 1,000-finding render) plus the consumer-side contract checks | All pass. |

The 1.x cases are still covered by these suites: TC-03/04/09/10/11/15/16/17 by AT-01 and
TC-12/13/14/18 by AT-02; TC-01/02/05/06/07/08 are superseded by ST-01/02-04/13/17/22/FI-05.

## 6. Manual tests

These need a real browser. MT-01, MT-02 and MT-03 are executed by `tests/e2e/browser_tests.py`,
which drives a real headless Chrome/Edge through the DevTools protocol (click, double-click, read
the visible state, print to PDF); their expected results below are unchanged. MT-04 needs a person
outside the team and cannot be automated.

| ID | Covers | Steps | Expected |
|---|---|---|---|
| MT-01 | Step 23 | In a browser, start an analysis and double-click *Executar análise* | The button turns into "Analisando…" and is disabled, the progress message appears, and only **one** analysis is created. |
| MT-02 | FR-12 | On a result page with several severities, click each chip | Only findings of that severity remain visible; *Todos* shows all again. |
| MT-03 | FR-08 | Open the printable report and use *Imprimir / Salvar como PDF* | The PDF contains the header, metrics and every finding; navigation and buttons are not printed. |
| MT-04 | CA-07, NFR-05 | A person who did not take part in development installs the system on a machine without the project, using only [INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md), and runs one analysis | Installation and first analysis succeed; every question the person asks is recorded as a gap of the manual and fixed. |

## 7. Traceability — acceptance criteria to cases

| Criterion | Cases |
|---|---|
| CA-01 — the catalogue runs and the completion is recorded | ST-01, ST-06, ST-08, AT-01 |
| CA-02 — every finding has severity, confidence, status, taxonomy, evidence, remediation | ST-09, ST-11, ST-19, AT-01, AT-02 |
| CA-03 — score 0–100 by the 30/15/7/2 rule | ST-10, AT-02 |
| CA-04 — comparison shows new, persistent and fixed | ST-13, ST-14, ST-15, AT-02 |
| CA-05 — 1,000 findings in under 3 s | ST-22, AT-02 |
| CA-06 — JSON export complete and equal to what is stored and shown | ST-16, ST-24, ST-26 |
| CA-07 — installation by an outsider using only the manual | MT-04 |
| CA-08 — every high-priority requirement traced to the Termo | Inspection of [REQUIREMENTS.md](REQUIREMENTS.md) (TR-01 in the report) |

| High-priority requirement | Cases |
|---|---|
| FR-01 | ST-01, ST-02, ST-03, ST-04 |
| FR-02 | ST-06, ST-07, ST-08 |
| FR-03 | ST-09 |
| FR-05 | ST-09 |
| FR-06 | ST-12, ST-25 |
| FR-07 | ST-13, ST-14, ST-15 |
| FR-09 | ST-09 |
| FR-10 | ST-08, AT-01 |
| FR-13 | ST-06 |
| NFR-01 | ST-22 |
| NFR-02 | ST-05, ST-11 |
| NFR-03 | ST-06 |
| NFR-04 | FI-05, AT-01 |
| NFR-07 | ST-19 |

## 8. Plan revisions

| Date | Change | Reason |
|---|---|---|
| 2026-10-14 | Plan 2.0 written before any execution (run 1 started at 23:00 UTC). | Step 29 golden rule. |
| 2026-10-14 | ST-24 added, **before** the fix of the defect it covers. | During run 1 the database showed analyses lasting 10,800 s: `started_at` is written in the server's local time and `completed_at` in UTC. No planned case looked at timestamps, so the defect was registered (D-07) and a case with its expected result was written before the fix. |
| 2026-10-14 | FI-09 delay raised from 1 s to 2 s. | In run 1 the scan finished in 115.8 s, under the 120 s limit, so the failure was **not provoked** and the run-1 verdict is void (recorded as *inconclusive*, not as a pass). The expected behaviour is unchanged. |
| 2026-10-14 | Driver: the "no technical detail" check no longer treats `.php` as a leak; the PHP log is read from Apache's `error.log`. | Run 1 false positives: every page links to `index.php`, and with `C:\xampp\php\logs\` absent PHP writes to Apache's error log. Both were checked by hand (test-evidence run 1) before the driver was changed; the expected results are unchanged. |
| 2026-10-28 | ST-25 and ST-26 added, **before** the code they verify was written. | A cross-check of the Termo de Referência against the product found two items of the included scope not fully realised: item 6 asks to consult the history *by period* (no period filter existed), and item 8 asks the JSON export to contain a *summary* (it carried only the number of findings). |
| 2026-10-28 | MT-01, MT-02 and MT-03 automated with a headless browser (`tests/e2e/browser_tests.py`). | They need a real browser engine, not a person; automating them makes them repeatable. Expected results unchanged. MT-04 stays manual. |
| 2026-10-28 | MT-01 driver: the button state is recorded inside the page (MutationObserver → `sessionStorage`) instead of being read through DevTools after the click. | First automated execution (run 3a): once the form is submitted, the browser answers DevTools only after the next page has loaded, so the driver read the result page instead of the button. Checked by hand with submission blocked: the button does turn into "Analisando…" and is disabled. Expected result unchanged. |
