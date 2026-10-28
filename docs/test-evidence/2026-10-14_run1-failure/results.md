# System test run 2026-10-14_run1-failure

- Started: 2026-10-14T23:01:36+00:00
- Finished: 2026-10-14T23:04:03+00:00
- Application: http://localhost/www/Ciber/public/
- Passed: 6 / 10

| Case | Title | Verdict | Duration (s) |
|---|---|---|---|
| FI-01 | .env absent | **PASS** | 0.0 |
| FI-02 | MariaDB stopped | **FAIL** | 3.3 |
| FI-03 | Wrong database password | **FAIL** | 0.0 |
| FI-04 | Target unreachable | **PASS** | 2.7 |
| FI-05 | Loopback target with private targets denied | **PASS** | 1.0 |
| FI-06 | Python binary misconfigured | **PASS** | 0.6 |
| FI-07 | Engine answers a document that breaks the contract | **PASS** | 0.4 |
| FI-08 | Database refuses the write of findings | **FAIL** | 2.4 |
| FI-09 | Scan outlives PHP's max_execution_time | **PASS** | 116.4 |
| FI-10 | Value longer than its column, strict SQL mode | **FAIL** | 20.2 |

## FI-01 — .env absent — PASS

- [x] HTTP status
- [x] guidance message

## FI-02 — MariaDB stopped — FAIL

- [x] database stopped
- [x] database restarted
- [x] HTTP status
- [x] generic message
- [ ] no technical detail in the response — observed: `['.php']`
- [ ] detail logged — observed: ``
- [x] password not logged

## FI-03 — Wrong database password — FAIL

- [x] HTTP status
- [x] generic message
- [ ] no technical detail in the response — observed: ``
- [x] wrong password not in the response
- [x] wrong password not logged

## FI-04 — Target unreachable — PASS

- [x] status
- [x] reason recorded and shown
- [x] findings

## FI-05 — Loopback target with private targets denied — PASS

- [x] status
- [x] scope reason recorded
- [x] requests received by the target

## FI-06 — Python binary misconfigured — PASS

- [x] status
- [x] reason

## FI-07 — Engine answers a document that breaks the contract — PASS

- [x] status
- [x] reason
- [x] findings

## FI-08 — Database refuses the write of findings — FAIL

- [x] the user gets an answer (error page or result)
- [ ] no technical detail in the response — observed: ``
- [ ] status — observed: `expected 'failed', got 'running'`
- [ ] reason recorded — observed: ``
- [x] findings

## FI-09 — Scan outlives PHP's max_execution_time — PASS

- [x] the user gets an answer (after 115.8 s)
- [x] no technical detail in the response
- [x] analysis not left running
- [x] a failure carries a reason

## FI-10 — Value longer than its column, strict SQL mode — FAIL

- [ ] status — observed: `expected 'completed', got 'running'`
- [ ] form finding stored — observed: `[]`
- [x] parameter within 180 characters
