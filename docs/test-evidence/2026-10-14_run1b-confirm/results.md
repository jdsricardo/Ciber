# System test run 2026-10-14_run1b-confirm

- Started: 2026-10-14T23:05:47+00:00
- Finished: 2026-10-14T23:09:47+00:00
- Application: http://localhost/www/Ciber/public/
- Passed: 2 / 5

| Case | Title | Verdict | Duration (s) |
|---|---|---|---|
| ST-24 | Analysis timestamps share one clock (FR-06, CA-06) | **FAIL** | 2.3 |
| FI-02 | MariaDB stopped | **PASS** | 3.2 |
| FI-03 | Wrong database password | **PASS** | 0.0 |
| FI-08 | Database refuses the write of findings | **FAIL** | 2.5 |
| FI-09 | Scan outlives PHP's max_execution_time | **FAIL** | 231.4 |

## ST-24 — Analysis timestamps share one clock (FR-06, CA-06) — FAIL

- [ ] history date (UTC) within the run — observed: `2026-10-14 23:05:48.137583 <= 2026-10-14 20:05:48 <= 2026-10-14 23:05:49.865182`
- [ ] export: started_at <= completed_at, under 60 s apart — observed: `2026-10-14 20:05:48 -> 2026-10-14 23:05:49`

## FI-02 — MariaDB stopped — PASS

- [x] database stopped
- [x] database restarted
- [x] HTTP status
- [x] generic message
- [x] no technical detail in the response
- [x] detail logged
- [x] password not logged

## FI-03 — Wrong database password — PASS

- [x] HTTP status
- [x] generic message
- [x] no technical detail in the response
- [x] wrong password not in the response
- [x] wrong password not logged

## FI-08 — Database refuses the write of findings — FAIL

- [x] the user gets an answer (error page or result)
- [x] no technical detail in the response
- [ ] status — observed: `expected 'failed', got 'running'`
- [ ] reason recorded — observed: ``
- [x] findings

## FI-09 — Scan outlives PHP's max_execution_time — FAIL

- [ ] the user gets an answer (after 230.8 s) — observed: `200`
- [ ] no technical detail in the response — observed: ` 
 Fatal error :  Maximum execution time of 120 seconds exceeded in  C:\xampp\htdocs\www\Ciber\app\src\Infrastructure\Scanner\PythonScannerGateway.php  on line  37  
`
- [ ] analysis not left running — observed: `{'status': 'running', 'error': '', 'score': '', 'checks_run': ''}`
- [x] a failure carries a reason
