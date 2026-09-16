# SentinelScope

SentinelScope is a developer-first web application security assessment platform created as a Software Engineering capstone project. It performs a fixed set of passive, non-destructive HTTP checks and turns the observations into understandable impact and remediation guidance.

## Technology

- PHP 8.2+ without a framework
- Python 3.10+ without external packages
- MariaDB 10.4+
- HTML and CSS without a frontend framework

## Quick start with XAMPP

1. Start Apache and MySQL in XAMPP.
2. Import `database.sql` using phpMyAdmin.
3. Copy `.env.example` to `.env` and enter the local credentials. A development `.env` is already present in this workspace and is ignored by Git.
4. Open `http://localhost/Ciberseguran%C3%A7a/public/`.
5. For an isolated local laboratory target, set `ALLOW_PRIVATE_TARGETS=true`. Keep it `false` for normal use.

The web-server account must be allowed to execute the configured Python binary. Never submit a target without explicit authorization.

## Tests

Run `python -m unittest discover -s tests -v` and `php tests/php_test.php` from the project
directory. Neither suite needs a database or a `.env`: the PHP tests load `app/autoload.php`
and drive the use cases through the in-memory repositories in `tests/php/`.

## Engineering documents

- [Coding standard](docs/CODING_STANDARD.md) — the rules this codebase follows.
- [Architecture](docs/ARCHITECTURE.md) — layers, contracts, the scanner engine and the data model.
- [Algorithm measurements](docs/ALGORITHM_MEASUREMENTS.md) — the measured basis for each
  data-structure decision, reproducible with `evaluation/benchmark_structures.py` and
  `evaluation/benchmark_comparison.php`.
- [Requirements](docs/REQUIREMENTS.md), [test plan](docs/TEST_PLAN.md),
  [scanner engine](docs/SCANNER_ENGINE.md).

## Empirical evaluation

`evaluation/` contains a reproducible harness that measures detection precision/recall/F1
against deliberately vulnerable targets (DVWA, OWASP Juice Shop, WebGoat) in an authorized
laboratory. See [evaluation/README.md](evaluation/README.md).

## Capstone article

`docs/TCC_ARTIGO_ABNT.md` (and its generated `docs/TCC_ARTIGO_ABNT.docx`) hold the ABNT
scientific article describing and evaluating the platform.

See [the installation and user manual](docs/INSTALLATION_AND_USER_MANUAL.md) for complete instructions.
