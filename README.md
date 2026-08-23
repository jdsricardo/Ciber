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

Run `python -m unittest discover -s tests -v` and `php tests/php_test.php` from the project directory.

See [the installation and user manual](docs/INSTALLATION_AND_USER_MANUAL.md) for complete instructions.
