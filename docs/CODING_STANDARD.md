# Coding Standard

The rules this codebase follows. Each one is written so a reviewer can decide, without
discussion, whether a change complies — and the rules marked **verificada** are checked
automatically by the test suite, so they cannot silently rot.

Etapa 9 of the project roadmap asks for a repository with history and a coding-standard
document. This is that document; it describes the code as it is, not as it might be.

## 1. Language and audience

| Artifact | Language | Reason |
|---|---|---|
| Source code, identifiers, comments, docstrings | English | The code is read by engineers and by tooling; one language avoids mixed identifiers. |
| Finding titles, descriptions, developer impact, remediation, example notes | Brazilian Portuguese | The audience is a Brazilian development team (NFR-06). |
| Interface text and error messages shown in the browser | Brazilian Portuguese | Same audience. |
| CWE / OWASP / WSTG identifiers | Standard English form | They are external identifiers, not prose. |
| Engineering documentation under `docs/` | English | The coursework documents under `docs/docsAula/` are in Portuguese. |

## 2. Comments

A comment explains **why**, never **what**. A comment that restates the line below it means the
line is the problem.

```python
# Bad — restates the code
# increment the counter
self.total += 1

# Good — states the reason the code cannot be simpler
# Re-resolving on every request is what closes the DNS-rebinding window: a name that
# pointed at the authorized address when the scan started must still point there now.
if self._resolve(parsed.hostname) != self.pinned_addresses:
```

Every module, class and non-obvious function carries a docstring or docblock stating its
responsibility in one sentence. A swallowed exception is never written without a comment naming
which failure is being tolerated and why continuing is safe.

## 3. PHP

- `declare(strict_types=1);` as the first statement after `<?php`. **Verificada.**
- One class, interface or enum per file, in a namespace mirroring its directory under
  `app/src/`, loaded by `app/autoload.php`. **Verificada.**
- Classes are `final` unless something extends them. The only non-final type is the abstract
  `DomainError`. **Verificada.**
- Every method declares a return type, and every parameter and property declares its type.
  `mixed` is used only where the value genuinely is unconstrained (`Html::escape`,
  `TransactionManager::transactional`). **Verificada.**
- Properties are `readonly` when the value does not change after construction.
- 4 spaces, braces on their own line for classes and methods, `UpperCamelCase` types,
  `lowerCamelCase` methods and variables, `UPPER_SNAKE` constants.
- SQL exists only inside `app/src/Infrastructure/Persistence/`, always through PDO prepared
  statements with bound parameters — never string concatenation. **Verificada.**
- `public/index.php` wires adapters, dispatches one request and maps errors to responses. It
  holds no business rule.
- All output reaching the browser passes through `App\Presentation\Html::escape` (or `e()`).

## 4. Python

- The scanner depends only on the Python standard library. No third-party package is imported
  at runtime. **Verificada.**
- `from __future__ import annotations` first, then standard-library imports, then local
  imports.
- Type hints on every public function signature and on every dataclass field.
- Data crossing a module boundary is a dataclass from `engine/models.py`, never a loose dict.
- `snake_case` functions, `UpperCamelCase` classes, 4 spaces.
- A line is broken when it stops being readable, not at a fixed column. Two things are
  deliberately left on one line even when long: the Portuguese finding texts
  (`description`, `developer_impact`, `remediation`), because they are reviewed as prose and a
  concatenated literal makes their diff unreadable; and regex signature tables, because
  breaking a pattern hides what it matches.

## 5. Structure and dependency direction

```
Presentation ─┐
              ├─► UseCase ─► Domain ◄─ Infrastructure
              └──────────────────┘
```

- `app/src/Domain/` depends on nothing outside itself. **Verificada:** a test in
  `tests/php_test.php` strips comments with `token_get_all` and fails if any domain file
  references `App\Infrastructure`, `App\Presentation`, `App\UseCase` or `PDO` in code.
- Interfaces between layers live in `app/src/Domain/Contract/`, declared by the domain and
  implemented outside it, so the dependency arrow always points inwards.
- A class has one responsibility. When a request handler starts making decisions, the decision
  moves to a use case or to the domain.
- In the scanner, a new check is a new `ScannerPlugin` subclass. The orchestrator holds no
  vulnerability-specific logic.

## 6. Errors

- The domain throws only `App\Domain\Exception\DomainError` subclasses — `InvalidInput` (400),
  `NotFound` (404), `ScannerUnavailable` (502). It never returns `null` or `false` to signal a
  broken rule. **Verificada.**
- The message is written for the developer using the application: Portuguese, no stack trace,
  no SQL, no internal identifier.
- Infrastructure failures are wrapped by the adapter that produced them into the matching
  `DomainError`. Anything reaching the front controller as a plain `Throwable` is a defect: it
  is logged in full and the user gets a generic message.
- A use case that has already created a record closes it before giving up, so a failure never
  leaves a row stuck in an intermediate state. **Verificada** for `RunAnalysis`.
- In Python, `engine/safety.py` defines the engine's failure vocabulary (`Cancelled`,
  `BudgetExceeded`, `EndpointBudgetExceeded`, `ScopeViolation`). A detector never invents a new
  exception type for a situation the runner already handles.
- A network failure is an expected operational condition, not a crash: `run_scan` reports it as
  `{"ok": false, "error": ...}`.

## 7. Tests

- Every behaviour change ships with a test. Python: `tests/test_*.py`, standard `unittest`.
  PHP: `tests/php_test.php`, a dependency-free harness.
- PHP tests load `app/autoload.php`, never `app/bootstrap.php`, so the suite needs no `.env`
  and no database; persistence and the scanner are replaced by the in-memory implementations in
  `tests/php/`. **Verificada** — the suite runs on a machine with no MariaDB.
- Tests assert on behaviour, not on internal structure.
- The full suite passes before a commit: `python -m unittest discover -s tests` and
  `php tests/php_test.php`.

## 8. Commits and repository

- One commit per coherent change; a commit mixing a refactor with a behaviour change is split.
- Message: a short imperative subject describing the effect, then the reason when it is not
  obvious from the diff.
- `master` always has a passing suite.
- Secrets never enter the repository: `.env` is ignored, `.env.example` carries placeholders,
  and `ALLOW_PRIVATE_TARGETS` defaults to `false`. **Verificada.**

## 9. Performance decisions

A data-structure or algorithm choice made for performance is measured, not asserted. The
harnesses are `evaluation/benchmark_structures.py` and `evaluation/benchmark_comparison.php`;
the results and the decisions they support are in
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md). A measurement that does not confirm the
expectation is recorded as such.
