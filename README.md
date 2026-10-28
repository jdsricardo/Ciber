# SentinelScope

SentinelScope is a developer-first web application security assessment platform created as a Software Engineering capstone project. It crawls an authorized target, runs a fixed catalogue of 34 passive checks — plus 30 safe-active, non-destructive probes in the complete mode — and turns the observations into understandable impact and remediation guidance.

## Technology

- PHP 8.2+ without a framework
- Python 3.10+ without external packages
- MariaDB 10.4+
- HTML and CSS without a frontend framework

## Quick start with XAMPP

1. Start Apache and MySQL in XAMPP.
2. Import `database.sql` using phpMyAdmin and create the application's database user
   (statements in the manual, step A.4).
3. Copy `.env.example` to `.env` and enter that user's credentials. `.env` is ignored by Git.
4. Open `http://localhost/<folder under htdocs>/public/` — for this repository checked out at
   `C:\xampp\htdocs\www\Ciber`, that is `http://localhost/www/Ciber/public/`.
5. For an isolated local laboratory target, set `ALLOW_PRIVATE_TARGETS=true`. Keep it `false` for normal use.

The web-server account must be allowed to execute the configured Python binary. Never submit a target without explicit authorization.
The complete, step-by-step procedure is the [installation and user manual](docs/INSTALLATION_AND_USER_MANUAL.md).

## Tests

| Suite | Command | Needs |
|---|---|---|
| Python (engine, plugins, producer side of the contract) | `python -m unittest discover -s tests -v` | Python only |
| PHP (domain, use cases, presentation, consumer side of the contract) | `php tests/php_test.php` | PHP only — in-memory repositories, no `.env` |
| System and failure injection (end to end: Apache + MariaDB + engine) | `python tests/e2e/run_system_tests.py` | the running installation, `ALLOW_PRIVATE_TARGETS=true` |

The plan is [docs/TEST_PLAN.md](docs/TEST_PLAN.md); the results, the defects and their
verification are in [docs/TEST_REPORT.md](docs/TEST_REPORT.md); raw evidence is under
`docs/test-evidence/`.

## Engineering documents

- [Coding standard](docs/CODING_STANDARD.md) — the rules this codebase follows.
- [Developer guide](docs/DEVELOPER_GUIDE.md) — layout, request lifecycle, module reference, how to add a check.
- [Architecture](docs/ARCHITECTURE.md) — layers, contracts, the scanner engine and the data model.
- [Integration contract](docs/INTEGRATION_CONTRACT.md) — the versioned agreement between the PHP
  application and the Python engine.
- [Algorithm measurements](docs/ALGORITHM_MEASUREMENTS.md) — the measured basis for each
  data-structure decision, reproducible with `evaluation/benchmark_structures.py` and
  `evaluation/benchmark_comparison.php`.
- [Requirements](docs/REQUIREMENTS.md), [test plan](docs/TEST_PLAN.md),
  [test report](docs/TEST_REPORT.md), [scanner engine](docs/SCANNER_ENGINE.md).
- [Roadmap compliance](docs/ROADMAP_COMPLIANCE.md) — status of every step of Fases 4 and 5, the
  precedence rules and the pre-delivery checklists, each with its evidence.
- [Changelog](CHANGELOG.md).

## Empirical evaluation

`evaluation/` contains a reproducible harness that measures detection precision/recall/F1
against deliberately vulnerable targets (DVWA, OWASP Juice Shop, WebGoat) in an authorized
laboratory. See [evaluation/README.md](evaluation/README.md).

## Coursework documents

`docs/docsAula/` holds the documents delivered for the course: the roadmap being followed
(`Roteiro_de_Execucao_do_Projeto.pdf`), the terms of reference, the requirements interview, the
data-structure activity, and the Fase 2 and Fase 3 documents that consolidate the technical
decisions and the architecture.

See [the installation and user manual](docs/INSTALLATION_AND_USER_MANUAL.md) for complete instructions.
