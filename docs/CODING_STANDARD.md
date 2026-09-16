# Coding Standard

The rules the SentinelScope codebase actually follows. Each one is written so that a reviewer
can decide, without discussion, whether a change complies.

## 1. Language and audience

| Artifact | Language | Reason |
|---|---|---|
| Source code, identifiers, comments, docstrings | English | The code is read by engineers and by tooling; keeping one language avoids mixed identifiers. |
| Finding titles, descriptions, developer impact, remediation, code-example notes | Brazilian Portuguese | The audience is a Brazilian development team (NFR-06). |
| User interface text and error messages shown in the browser | Brazilian Portuguese | Same audience. |
| CWE / OWASP / WSTG identifiers | Standard English form | They are external identifiers, not prose. |
| Engineering documentation under `docs/` | English | Companion academic documents (`docs/docsAula/`) are in Portuguese. |

## 2. Comments

A comment explains **why**, never **what**. If a comment restates the line below it, the line is
the problem, not the missing comment.

```python
# Bad — restates the code
# increment the counter
self.total += 1

# Good — states the reason the code could not be simpler
# Re-resolving on every request is what closes the DNS-rebinding window: a name that
# pointed at the authorized address when the scan started must still point there now.
if self._resolve(parsed.hostname) != self.pinned_addresses:
```

Every module, class and non-obvious function carries a docstring/docblock stating its
responsibility in one sentence. `except Exception: pass` is never written without a comment
saying which failure is being tolerated and why it is safe to continue.

## 3. PHP

- `declare(strict_types=1);` in every file, first statement after `<?php`.
- PSR-12 formatting: 4 spaces, one class per file, braces on their own line for classes and
  methods, `UpperCamelCase` classes, `lowerCamelCase` methods and variables, `UPPER_SNAKE`
  constants.
- Namespace mirrors the directory under `app/src/`, loaded by `app/autoload.php`.
- Classes are `final` unless a subclass exists. Properties are `readonly` when the value does
  not change after construction.
- Every parameter, property and return has a declared type. `mixed` only where the value truly
  is unconstrained (`Html::escape`, `TransactionManager::transactional`).
- Lines stay within 120 columns.
- No business logic in `public/index.php`: it wires adapters, dispatches, and handles errors.
- SQL is written only inside `app/src/Infrastructure/Persistence/`, always through PDO
  prepared statements with bound parameters — never string concatenation.
- All output is escaped through `App\Presentation\Html::escape` (or `e()` in views).

## 4. Python

- PEP 8, 4 spaces, lines within 110 columns, `snake_case` functions, `UpperCamelCase` classes.
- `from __future__ import annotations` at the top, then standard-library imports, then local
  imports, each group separated by a blank line and alphabetically ordered within the group.
- One statement per line. Semicolon-joined statements and one-line `if x: return y` bodies are
  not used (they were removed from `engine/safety.py` and `engine/normalization.py`).
- Type hints on every public function signature and dataclass field.
- Data passed between modules is a dataclass from `engine/models.py`, never a loose dict.
- The engine depends only on the standard library. No third-party runtime dependency is added.

## 5. Structure and dependency direction

```
Presentation ─┐
              ├─► UseCase ─► Domain ◄─ Infrastructure
              └──────────────────┘
```

- `app/src/Domain/` depends on nothing outside itself. This is enforced by a test in
  `tests/php_test.php`, which fails if a domain file references `App\Infrastructure`,
  `App\Presentation`, `App\UseCase` or `PDO` in code.
- Interfaces between layers (`Domain/Contract/`) are declared by the domain and implemented
  outside it, so the dependency arrow always points inwards.
- A class has one responsibility. When a request handler starts making decisions, the decision
  moves to a use case or to the domain.

## 6. Errors

- The domain throws only `App\Domain\Exception\DomainError` subclasses — `InvalidInput` (400),
  `NotFound` (404), `ScannerUnavailable` (502). It never returns `null`/`false` to signal a
  broken rule.
- The message is written for the developer using the application: Portuguese, no stack trace,
  no SQL, no internal identifier.
- Infrastructure failures are wrapped by the adapter that produced them into the matching
  `DomainError`. Anything that reaches the front controller as a plain `Throwable` is a defect:
  it is logged in full and the user sees a generic message.
- In Python, `engine/safety.py` defines the engine's failure vocabulary (`Cancelled`,
  `BudgetExceeded`, `EndpointBudgetExceeded`, `ScopeViolation`). A detector never invents a new
  exception type for a control-flow situation the runner already knows how to handle.
- A network failure is an expected operational condition, not a crash: `run_scan` reports it as
  `{"ok": false, "error": ...}`.

## 7. Tests

- Every behaviour change ships with a test. Python: `tests/test_*.py`, standard `unittest`.
  PHP: `tests/php_test.php`, a dependency-free harness.
- PHP tests load `app/autoload.php`, never `app/bootstrap.php`, so the suite needs no `.env`
  and no database; persistence and the scanner are replaced by the in-memory implementations
  in `tests/php/`.
- Tests assert on behaviour, not on internal structure. A test that only re-states the
  implementation is deleted.
- The full suite must pass before a commit: `python -m unittest discover -s tests` and
  `php tests/php_test.php`.

## 8. Commits and repository

- One commit per coherent change; a commit that mixes a refactor with a behaviour change is
  split.
- Message: a short imperative subject line describing the effect, then the reason if it is not
  obvious from the diff.
- `main`/`master` always has a passing suite.
- Secrets never enter the repository: `.env` is ignored, `.env.example` carries placeholders.
  The default of `ALLOW_PRIVATE_TARGETS` is `false` and stays that way.

## 9. Performance decisions

A data-structure or algorithm choice made for performance is measured, not asserted. The
measurement harnesses are `evaluation/benchmark_structures.py` and
`evaluation/benchmark_comparison.php`; the results and the decisions they support are recorded
in [ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md).
