# System test run 2026-10-28_run3a-before

- Started: 2026-10-28T22:32:41+00:00
- Finished: 2026-10-28T22:33:10+00:00
- Application: http://localhost/www/Ciber/public/
- Passed: 5 / 8

| Case | Title | Verdict | Duration (s) |
|---|---|---|---|
| ST-01 | Register a valid application | **PASS** | 0.2 |
| ST-06 | Passive analysis of the vulnerable laboratory | **PASS** | 3.0 |
| ST-08 | Active analysis of the vulnerable laboratory | **PASS** | 15.2 |
| ST-25 | History consulted by period (FR-06, Termo item 6) | **FAIL** | 0.4 |
| ST-26 | JSON export carries a summary (FR-12, Termo item 8) | **FAIL** | 0.0 |
| MT-01 | Double click on 'Executar análise' starts one analysis, with progress shown | **FAIL** | 7.8 |
| MT-02 | Severity chips filter the findings | **PASS** | 0.3 |
| MT-03 | Printable report saved as PDF | **PASS** | 2.1 |

## ST-01 — Register a valid application — PASS

- [x] HTTP status
- [x] redirect target
- [x] notice shown
- [x] card shows the name
- [x] card shows the URL
- [x] row persisted
- [x] authorization_confirmed_at recorded

## ST-06 — Passive analysis of the vulnerable laboratory — PASS

- [x] redirects to the result
- [x] status
- [x] checks run shown
- [x] baseline GETs to /
- [x] baseline GETs to /search?q=livros
- [x] baseline GETs to /profile?name=ana
- [x] baseline GETs to /about
- [x] requests to logout/destructive links
- [x] headers.csp_missing reported
- [x] no xss finding in passive mode

## ST-08 — Active analysis of the vulnerable laboratory — PASS

- [x] status
- [x] checks run shown
- [x] XSS on /search, parameter q
- [x] XSS on /profile, parameter name
- [x] requests to logout/destructive links

## ST-25 — History consulted by period (FR-06, Termo item 6) — FAIL

- [x] (a) no period: all three
- [ ] (b) February only — observed: `expected [42], got [43, 42, 41]`
- [ ] (b) the form shows the period applied — observed: ``
- [ ] (c) inclusive ends — observed: `expected [43, 42], got [43, 42, 41]`
- [ ] (d) open end — observed: `expected [43, 42], got [43, 42, 41]`
- [ ] (e) reversed period: status — observed: `expected 400, got 200`
- [ ] (e) reversed period: message — observed: ``
- [ ] (f) malformed date: status — observed: `expected 400, got 200`
- [ ] (f) malformed date: message — observed: ``

## ST-26 — JSON export carries a summary (FR-12, Termo item 8) — FAIL

- [x] summary.findings
- [ ] summary.by_severity — observed: `expected {'critical': 0, 'high': 3, 'medium': 5, 'low': 6}, got None`
- [ ] summary.security_score — observed: `expected 8, got None`
- [ ] summary.manual_review_required — observed: `expected 0, got None`

## MT-01 — Double click on 'Executar análise' starts one analysis, with progress shown — FAIL

- [ ] button disabled — observed: `None`
- [ ] button says 'Analisando…' — observed: `None`
- [ ] progress message visible — observed: `None`
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
