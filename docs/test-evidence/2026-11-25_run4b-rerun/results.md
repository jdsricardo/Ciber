# System test run execucao-5b-reexecucao

- Started: 2026-11-25T14:47:42+00:00
- Finished: 2026-11-25T14:47:57+00:00
- Application: http://localhost/www/Ciber/public/
- Passed: 4 / 4

| Case | Title | Verdict | Duration (s) |
|---|---|---|---|
| FI-02 | MariaDB stopped | **PASS** | 3.3 |
| MT-01 | Double click on 'Executar análise' starts one analysis, with progress shown | **PASS** | 8.6 |
| MT-02 | Severity chips filter the findings | **PASS** | 0.3 |
| MT-03 | Printable report saved as PDF | **PASS** | 2.0 |

## FI-02 — MariaDB stopped — PASS

- [x] database stopped
- [x] database restarted
- [x] HTTP status
- [x] generic message
- [x] no technical detail in the response
- [x] detail logged
- [x] password not logged

## MT-01 — Double click on 'Executar análise' starts one analysis, with progress shown — PASS

- [x] button disabled
- [x] button says 'Analisando…'
- [x] progress message visible
- [x] result page reached
- [x] analyses created by the double click

## MT-02 — Severity chips filter the findings — PASS

- [x] at least two severities to filter
- [x] 'high' chip shows only its 1 finding(s)
- [x] 'medium' chip shows only its 5 finding(s)
- [x] 'low' chip shows only its 6 finding(s)
- [x] 'Todos' shows every finding again

## MT-03 — Printable report saved as PDF — PASS

- [x] a PDF was produced
- [x] header: application name
- [x] header: score
- [x] metrics
- [x] every finding title printed
- [x] navigation not printed
- [x] buttons not printed
