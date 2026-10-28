# Changelog

All notable changes to SentinelScope. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.1] — 2026-10-28 · Final cross-check against the Termo de Referência

### Added
- History by period on the dashboard (*Histórico por período*: from / to, both inclusive) —
  Termo item 6 asked for it and it did not exist (**D-09**). `Domain\Model\Period`;
  `AnalysisRepository::listByApplication()` takes an optional period, served by the existing
  `(application_id, started_at)` index.
- JSON export `summary` now carries findings per severity, findings needing manual review and the
  score — Termo item 8 asked for a summary and the export carried only a count (**D-10**).
- Browser cases MT-01…MT-03 automated in a real headless Chrome/Edge (`tests/e2e/cdp.py`).
- Test cases ST-25 and ST-26.

## [1.0.0] — 2026-10-14 · Fases 4 and 5 (construction, integration and verification)

### Added
- Progress indicator on the run form, with the submit button locked after the first click so a
  double click cannot start a duplicate analysis (roadmap step 23).
- [Integration contract](docs/INTEGRATION_CONTRACT.md) v1.1 between the PHP application and the
  Python engine, with conformance tests on both sides sharing one captured payload.
- System and failure-injection test driver (`tests/e2e/run_system_tests.py`) and a controllable
  laboratory target (`tests/e2e/lab_target.py`).
- [Test plan](docs/TEST_PLAN.md) 2.0, [test report](docs/TEST_REPORT.md), raw evidence in
  `docs/test-evidence/`, [developer guide](docs/DEVELOPER_GUIDE.md) and
  [roadmap compliance](docs/ROADMAP_COMPLIANCE.md).
- The comparison page shows the page and parameter of each finding.

### Fixed
- **D-01** Comparison merged the same check found on two endpoints; findings are now compared by
  identity (check, endpoint, parameter).
- **D-02** A failure while storing the result left the analysis `running` forever; it is now
  closed as `failed`.
- **D-03** On Windows, `%`, `!` and `"` in the target URL or session cookie were replaced with
  spaces before reaching the engine; the engine is now started without a shell.
- **D-04** Analyses longer than PHP's 120 s limit died with a fatal error showing a server path
  and stayed `running`; the gateway now owns the deadline and the error display is off.
- **D-05** The analysis duration showed the response time of one request; it is now the duration
  of the whole scan.
- **D-06** Values longer than their database column (e.g. a 300-character form field name) made a
  strict database reject the analysis; the engine fits each field to its column.
- **D-07** `started_at` was stored in the server's local time and `completed_at` in UTC; every
  timestamp is now UTC.
- **D-08** Contract v1.0 did not list `cookie` as a `parameter_location` (documentation only).

### Changed
- Installation and user manual rewritten: database user creation, `.env` reference, first-access
  checks, laboratory verification, troubleshooting.

## [0.3.0] — 2026-09-23 · Fase 3 (architecture)
- Layered architecture (Domain, UseCase, Infrastructure, Presentation) with contracts declared by
  the domain and in-memory test doubles.

## [0.2.0] — 2026-09-16 · Fase 2 (technical decisions)
- Coding standard, algorithm and data-structure measurements, domain model.

## [0.1.0] — 2026-08-23 · Baseline
- Scanner engine with passive and safe-active plugins, web application, schema.
