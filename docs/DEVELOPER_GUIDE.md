# Developer Guide

Everything a developer needs to read, run, change and test SentinelScope's code. The *why* of
the structure is in [ARCHITECTURE.md](ARCHITECTURE.md); the rules every change follows are in
[CODING_STANDARD.md](CODING_STANDARD.md); the boundary between the PHP application and the Python
engine is specified in [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md).

## 1. Repository layout

```
app/
  autoload.php            App\ → app/src/ (no session, no .env: what tests load)
  bootstrap.php           web runtime: autoload + .env + UTC + session + display_errors=0
  src/
    Domain/               entities, value objects, contracts, comparison service, errors
      Contract/           interfaces the outer layers implement (5)
      Exception/          DomainError and its three subclasses
      Model/              Application, Analysis, Finding, TargetUrl, SecurityScore, …
      Service/            AnalysisComparison
    UseCase/              one class per operation (4)
    Infrastructure/       PDO repositories, Python gateway, Config, Database, Csrf
    Presentation/         Views, Layout, FindingPresenter, Html
public/
  index.php               front controller (the only PHP entry point)
  assets/app.css, app.js  styles; progressive-enhancement script
scanner/
  scanner.py              CLI entry point the gateway starts
  engine/                 crawl, transport, safety, normalization, confidence, runner
  plugins/                one class per vulnerability family; plugins/active/ for probes
database.sql              schema, indexes, additive migrations (safe to re-run)
tests/
  php_test.php, php/      PHP suite and its in-memory test doubles
  test_*.py, support/     Python suite and the local HTTP server helper
  fixtures/               payload shared by both sides of the contract tests
  e2e/                    laboratory target and the system/failure-injection driver
evaluation/               empirical evaluation harness and benchmarks
docs/                     engineering documentation (this file and its siblings)
docs/test-evidence/       raw evidence of each test-battery run
```

## 2. Local environment

Requirements and the step-by-step installation are in
[INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md). For development the short
version is:

```bash
# MariaDB and Apache from XAMPP running; then, from the project root:
mysql -u root < database.sql
cp .env.example .env            # set DB_PASSWORD; ALLOW_PRIVATE_TARGETS=true for the lab
python -m unittest discover -s tests      # Python suite (~4-5 min: real sockets)
php tests/php_test.php                    # PHP suite (seconds; no database needed)
```

### 2.1 Configuration (`.env`)

| Key | Default | Used by | Meaning |
|---|---|---|---|
| `DB_HOST`, `DB_PORT`, `DB_NAME` | `127.0.0.1`, `3306`, `sentinelscope` | `Infrastructure\Database` | MariaDB location. |
| `DB_USER`, `DB_PASSWORD` | — | `Infrastructure\Database` | A dedicated user with `SELECT, INSERT, UPDATE, DELETE` on the schema only. |
| `PYTHON_BINARY` | `python` | `PythonScannerGateway` | Executable that runs `scanner/scanner.py`; a full path when Apache's `PATH` does not contain Python. |
| `ALLOW_PRIVATE_TARGETS` | `false` | `PythonScannerGateway` → `--allow-private` | Lets the engine scan loopback/private addresses. Laboratory use only. |
| `APP_ENV` | `development` | — | Informational. |

`.env` is read on every request, so a change takes effect immediately; it is ignored by Git.

## 3. Request lifecycle

`public/index.php` is the only entry point. One request is handled like this:

1. `app/bootstrap.php` registers the autoloader, loads `.env` (HTTP 503 with guidance when it is
   missing), sets PHP to UTC, starts a hardened session and turns `display_errors` off.
2. The front controller builds the PDO adapters and the gateway and injects them into the use
   cases — this is the only place where concrete classes are chosen.
3. A POST is accepted only with the session CSRF token (`Infrastructure\Security\Csrf`).
4. The `page` parameter selects one route:

| Route | Method | Use case / view | Result |
|---|---|---|---|
| *(none)* | GET | `ApplicationRepository::all`, `AnalysisRepository::listByApplication`, `Views::dashboard` | Dashboard with every application and its history; optional `from` / `to` (`YYYY-MM-DD`, inclusive) restrict the history to a period (400 when malformed or reversed). |
| `add` | GET | `Views::addApplication` | Registration form. |
| `create` | POST | `RegisterApplication` | 302 to the dashboard, or 400 with the reason. |
| `run` | POST | `RunAnalysis` | 302 to the result (completed or failed), or 400/404. |
| `result` / `report` | GET | `Views::analysisResult` | Result page / printable report. |
| `export` | GET | `ExportAnalysis` | JSON attachment. |
| `compare` | GET | `CompareAnalyses`, `Views::comparison` | New / persistent / fixed. |
| `about` | GET | `Views::about` | Static page. |

5. A `DomainError` becomes its HTTP status (`InvalidInput` 400, `NotFound` 404,
   `ScannerUnavailable` 502) with its message; any other `Throwable` is logged in full and the user
   gets HTTP 500 with a generic message. Both paths roll back an open transaction first.

## 4. Module reference — PHP

### 4.1 Domain (`app/src/Domain/`)

| Type | Kind | Responsibility |
|---|---|---|
| `Model\Application` | entity | A registered target: name (1–120 chars), `TargetUrl`, authorization instant. |
| `Model\Analysis` | entity | One run: mode, status, score, metrics, timestamps, failure reason. Rejects a completed analysis without score and a failed one without reason. |
| `Model\Finding` | entity | One observed issue with taxonomy, severity, confidence, evidence and the fix example. `identity()` and `endpoint()` implement the contract's identity rule (§5). |
| `Model\TargetUrl` | value object | HTTP(S) only, ≤ 2,048 chars, no embedded credentials. |
| `Model\Period` | value object | A range of whole days in UTC for the history-by-period query; either end may be open; rejects a malformed date (including impossible ones such as 2026-02-31) and a reversed range. |
| `Model\SecurityScore` | value object | 0–100; `fromFindings()` applies the 30/15/7/2 rule. |
| `Model\Severity`, `ScanMode`, `AnalysisStatus` | enums | Closed vocabularies; `fromString()` rejects unknown values. |
| `Model\RemediationExample` | value object | The "vulnerable vs. fixed" pair. |
| `Model\ScanResult` | value object | What the engine answered: findings and metrics, or the failure reason. `fromEnginePayload()` is the consumer-side validation of the contract (rule C4). |
| `Service\AnalysisComparison` | service | Classifies findings of two analyses as new/persistent/fixed with hash maps keyed by identity. |
| `Contract\*` | interfaces | `ApplicationRepository`, `AnalysisRepository`, `FindingRepository`, `ScannerGateway`, `TransactionManager`. |
| `Exception\*` | errors | `DomainError` (abstract, carries the HTTP status) and `InvalidInput`, `NotFound`, `ScannerUnavailable`. |

### 4.2 Use cases (`app/src/UseCase/`)

| Class | Does | Notes |
|---|---|---|
| `RegisterApplication` | Validates and stores an application. | Refuses without the explicit authorization. |
| `RunAnalysis` | Creates the `running` analysis, calls the gateway, stores findings and score in one transaction. | Guarantees contract C2: every exit path — engine failure, invalid document, gateway exception, defect, database refusing the write — closes the analysis as `completed` or `failed`. The safe-active mode needs the second authorization. |
| `CompareAnalyses` | Loads two analyses of the same application and diffs them. | Rows carry identity, endpoint and parameter so the view can say *where* each finding is. |
| `ExportAnalysis` | Builds the JSON document of one analysis: `tool`, `analysis` (metadata), `summary` (findings, `by_severity`, `manual_review_required`, `security_score`) and `findings`. | Pure: returns an array; the controller writes it. |

### 4.3 Infrastructure (`app/src/Infrastructure/`)

| Class | Implements | Notes |
|---|---|---|
| `Persistence\PdoApplicationRepository`, `PdoAnalysisRepository`, `PdoFindingRepository` | the three repositories | The only files with SQL. Prepared statements only. |
| `Persistence\PdoTransactionManager` | `TransactionManager` | Maps "all or nothing" to a database transaction with automatic rollback. |
| `Scanner\PythonScannerGateway` | `ScannerGateway` | Starts the engine with `proc_open` from an argument list (no shell), stdout/stderr to temporary files, polls until exit or deadline (210 s passive, 630 s safe-active) and terminates the engine at the deadline. Raises the request's time limit accordingly and ignores client aborts, so the analysis is always closed. |
| `Database` | — | Lazy PDO connection: exceptions, native prepares, **session time zone UTC**. |
| `Config` | — | Reads `.env`; 503 when it is missing. |
| `Security\Csrf` | — | Session-bound token checked on every POST. |

### 4.4 Presentation (`app/src/Presentation/`)

`Views` has one static method per screen and builds markup only; `Layout` wraps it in the page
shell; `FindingPresenter` renders one finding (observation → impact → fix → example → technical
panel); `Html::escape` is the single output-encoding function. Every dynamic value passes through
it, including evidence copied from the target (contract C6).

The dashboard carries the *Histórico por período* form (a GET form: it changes nothing).

`public/assets/app.js` adds conveniences without being required: copy-to-clipboard of the fixed
example, the toggle of the active-mode authorization, the severity filter chips, and the
"analysis in progress" indicator that also locks the submit button against a duplicate run.

## 5. Module reference — Python engine

| Module | Responsibility |
|---|---|
| `scanner.py` | CLI: parses arguments, forces UTF-8 stdout, prints exactly one JSON document, exit code 0/1. |
| `engine/runner.py` | `run_scan()` and `ScanRunner`: breadth-first crawl (deque + set of page signatures), two baselines per page, every plugin per page, cross-page de-duplication, the result document. Owns no vulnerability logic. `PASSIVE_LIMITS` / `ACTIVE_LIMITS` are the request and time budgets. |
| `engine/safety.py` | `SafetyController`: scope (host/port pinning, DNS re-check, private-network denial), budgets, rate limit, cancellation, redaction of sensitive headers in the log. |
| `engine/transport.py` | `HttpTransport`: the only code path that sends HTTP; bounded reads; one retry on a transient reset. |
| `engine/crawler.py` | Same-origin link extraction and the read-only navigation rules (no logout, no state-changing links). |
| `engine/discovery.py` | Input points: query parameters and form fields. |
| `engine/normalization.py` | Removes volatile content before comparisons; builds the page context. |
| `engine/confidence.py` | The confidence formula and its mapping to a status. |
| `engine/matchers.py` | Composable response predicates. |
| `engine/models.py` | Dataclasses crossing module boundaries; `Finding.to_dict()` is the serialization of contract §3.2, including fitting text fields to their column widths. |
| `plugins/base.py` | `ScannerPlugin` and `PluginMetadata`. |
| `plugins/*.py` | 7 passive families, 34 checks. |
| `plugins/active/*.py` | 13 safe-active families, 30 checks. |
| `plugins/catalog.py`, `remediation_examples.py` | Authored texts (Portuguese) and fix examples per check id. |
| `plugins/support.py` | `build_finding()`, probe construction and sending for query and form inputs. |

### 5.1 Check catalogue

| Plugin | Mode | Checks | CWE | WSTG |
|---|---|---:|---|---|
| TransportSecurityPlugin | passive | 5 | CWE-319, 326, 298 | CRYP-01, CONF-07 |
| SecurityHeadersPlugin | passive | 12 | CWE-693, 1021, 200, 116 | CONF-12, CLNT-09 |
| CookieSecurityPlugin | passive | 5 | CWE-614, 1004, 352, 284 | SESS-02 |
| CorsPassivePlugin | passive | 2 | CWE-942 | CLNT-07 |
| CacheSecurityPlugin | passive | 1 | CWE-525 | CONF-12 |
| InformationDisclosurePlugin | passive | 7 | CWE-200, 209, 548, 540, 319 | INFO-02/05/08, ERRH-01, CONF-04 |
| SecretsExposurePlugin | passive | 2 | CWE-798 | INFO-05 |
| SqlInjectionPlugin | safe_active | 3 | CWE-89 | INPV-05 |
| ReflectedXssPlugin | safe_active | 3 | CWE-79 | INPV-01 |
| PathTraversalPlugin | safe_active | 2 | CWE-22 | ATHZ-01 |
| OpenRedirectPlugin | safe_active | 2 | CWE-601 | CLNT-04 |
| CommandInjectionPlugin | safe_active | 3 | CWE-78 | INPV-12 |
| TemplateInjectionPlugin | safe_active | 1 | CWE-1336 | INPV-18 |
| XxePlugin | safe_active | 2 | CWE-611 | INPV-07 |
| CrlfInjectionPlugin | safe_active | 1 | CWE-93 | INPV-15 |
| HostHeaderInjectionPlugin | safe_active | 2 | CWE-644 | INPV-17 |
| HttpVerbTamperingPlugin | safe_active | 3 | CWE-650 | CONF-06 |
| NoSqlInjectionPlugin | safe_active | 2 | CWE-943 | INPV-05 |
| CorsActivePlugin | safe_active | 4 | CWE-942 | CLNT-07 |
| SsrfPlugin | safe_active | 2 | CWE-918 | INPV-19 |
| **Total** | | **64** (34 + 30) | | |

## 6. Common changes

### 6.1 Add a check

1. Write the plugin as a `ScannerPlugin` subclass in `scanner/plugins/` (passive) or
   `scanner/plugins/active/` (safe-active), declaring its `PluginMetadata` and check ids.
2. Add the texts of each check id to `plugins/catalog.py` and its example to
   `plugins/remediation_examples.py`.
3. Register it in `default_passive_plugins()` / `default_active_plugins()` in `engine/runner.py`.
4. Add a test with a **vulnerable** and a **safe** fixture served by `tests/support/local_server.py`.
   `tests/test_plugins.py` and `tests/test_remediation_examples.py` then check catalogue and
   example coverage automatically.
5. Update the counts in [REQUIREMENTS.md](REQUIREMENTS.md) (FR-02) and in §5.1 above.

No PHP change is needed: the new findings travel through the existing contract.

### 6.2 Change the contract

Follow [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) §6: change both sides in the same
commit, bump the version, add a change-log line, run
`python tests/test_integration_contract.py --regenerate-fixture`, and run both suites.

### 6.3 Change the schema

Append an additive statement to `database.sql` (`ADD COLUMN IF NOT EXISTS`, never a destructive
change), so re-importing over an existing database is safe; if the new column stores a finding
field, add its width to the contract (§3.2) and to `FINDING_FIELD_LIMITS` in `engine/models.py`.

## 7. Testing

| What | Command | Needs |
|---|---|---|
| PHP suite | `php tests/php_test.php` | PHP only |
| Python suite (incl. producer contract tests) | `python -m unittest discover -s tests -v` | Python only |
| One Python test file | `python -m unittest tests.test_integration_contract -v` | Python only |
| System + failure injection | `python tests/e2e/run_system_tests.py [--suite system\|failure] [--only ST-13 …]` | Apache, MariaDB, `.env` with `ALLOW_PRIVATE_TARGETS=true`, port 8765 free |
| Browser cases (MT-01…03) | `python tests/e2e/run_system_tests.py --suite browser` | as above, plus Chrome or Edge (driven headless through `tests/e2e/cdp.py`) |
| Laboratory target alone | `python tests/e2e/lab_target.py --variant vulnerable --log lab.jsonl` | Python only |

The system driver writes `docs/test-evidence/<run>/results.md` and `results.json` plus the raw
evidence. Failure-injection cases change the environment (stop MariaDB, revoke a privilege, set
strict SQL mode, rewrite `.env`) and restore it in a `finally` block; run them on a development
machine only. The plan is [TEST_PLAN.md](TEST_PLAN.md) and the results are in
[TEST_REPORT.md](TEST_REPORT.md).

## 8. Debugging

| Symptom | Where to look |
|---|---|
| Generic "erro inesperado" page | Apache `logs/error.log` (XAMPP's `php/logs/` does not exist, so PHP logs there): every line starts with `SentinelScope:` and has the full exception. |
| Analysis failed with "resposta inválida" | Run the engine by hand: `python scanner/scanner.py <url> --mode=passive [--allow-private]` and check that it prints one JSON document. |
| Analysis failed with "excedeu o tempo máximo" | The engine did not finish within its deadline; the target is slow or very large. Use `--max-pages` from the CLI to scope it. |
| Private target blocked | Expected SSRF protection; `ALLOW_PRIVATE_TARGETS=true` only in a laboratory. |
| Engine request log | `python scanner/scanner.py <url> --log-file scan.jsonl` (secrets redacted). |
