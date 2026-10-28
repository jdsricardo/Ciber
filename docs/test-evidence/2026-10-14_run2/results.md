# System test run 2026-10-14_run2

- Started: 2026-10-14T23:13:36+00:00
- Finished: 2026-10-14T23:19:10+00:00
- Application: http://localhost/www/Ciber/public/
- Passed: 34 / 34

| Case | Title | Verdict | Duration (s) |
|---|---|---|---|
| ST-01 | Register a valid application | **PASS** | 0.1 |
| ST-02 | Registration without authorization is refused | **PASS** | 0.1 |
| ST-03 | Invalid URLs are refused | **PASS** | 0.2 |
| ST-04 | Invalid names are refused | **PASS** | 0.1 |
| ST-05 | POST without a valid CSRF token is refused | **PASS** | 0.2 |
| ST-06 | Passive analysis of the vulnerable laboratory | **PASS** | 2.2 |
| ST-07 | Active analysis without the active authorization is refused | **PASS** | 0.1 |
| ST-08 | Active analysis of the vulnerable laboratory | **PASS** | 14.8 |
| ST-09 | Every finding carries the minimum information (CA-02) | **PASS** | 0.1 |
| ST-10 | Score equals the manual 30/15/7/2 calculation (CA-03) | **PASS** | 0.1 |
| ST-11 | User-supplied and target-supplied content is escaped (NFR-02) | **PASS** | 0.1 |
| ST-12 | History lists every analysis, most recent first (FR-06) | **PASS** | 0.0 |
| ST-19 | Authenticated scan reaches the private area; the credential is never kept (FR-11, NFR-07) | **PASS** | 2.7 |
| ST-20 | Arguments reach the engine intact (contract R1) | **PASS** | 4.8 |
| ST-13 | Comparison after a partial fix (CA-04) | **PASS** | 29.5 |
| ST-14 | Comparison after the complete fix (CA-04) | **PASS** | 14.5 |
| ST-15 | Comparison across applications is refused | **PASS** | 0.0 |
| ST-16 | JSON export is complete and equal to what is stored and shown (CA-06) | **PASS** | 0.1 |
| ST-17 | Printable report (FR-08) | **PASS** | 0.1 |
| ST-18 | Severity filter counts (FR-12) | **PASS** | 0.0 |
| ST-21 | Unknown identifiers answer 404 | **PASS** | 0.1 |
| ST-22 | 1,000 findings presented in under 3 seconds (CA-05, NFR-01) | **PASS** | 1.6 |
| ST-23 | Loading indicator is present (roadmap step 23) | **PASS** | 0.0 |
| ST-24 | Analysis timestamps share one clock (FR-06, CA-06) | **PASS** | 2.3 |
| FI-01 | .env absent | **PASS** | 0.0 |
| FI-02 | MariaDB stopped | **PASS** | 3.2 |
| FI-03 | Wrong database password | **PASS** | 0.1 |
| FI-04 | Target unreachable | **PASS** | 2.5 |
| FI-05 | Loopback target with private targets denied | **PASS** | 0.9 |
| FI-06 | Python binary misconfigured | **PASS** | 0.6 |
| FI-07 | Engine answers a document that breaks the contract | **PASS** | 0.9 |
| FI-08 | Database refuses the write of findings | **PASS** | 2.5 |
| FI-09 | Scan outlives PHP's max_execution_time | **PASS** | 229.2 |
| FI-10 | Value longer than its column, strict SQL mode | **PASS** | 20.0 |

## ST-01 — Register a valid application — PASS

- [x] HTTP status
- [x] redirect target
- [x] notice shown
- [x] card shows the name
- [x] card shows the URL
- [x] row persisted
- [x] authorization_confirmed_at recorded

## ST-02 — Registration without authorization is refused — PASS

- [x] HTTP status
- [x] message
- [x] rows created

## ST-03 — Invalid URLs are refused — PASS

- [x] HTTP status for ''
- [x] message for ''
- [x] HTTP status for 'ftp://example.com/'
- [x] message for 'ftp://example.com/'
- [x] HTTP status for 'javascript:alert(1)'
- [x] message for 'javascript:alert(1)'
- [x] HTTP status for 'http://user:pw@example.com/'
- [x] message for 'http://user:pw@example.com/'
- [x] HTTP status for 'nota-uma-url'
- [x] message for 'nota-uma-url'
- [x] rows created

## ST-04 — Invalid names are refused — PASS

- [x] HTTP status for empty name
- [x] an explanation for empty name
- [x] HTTP status for spaces name
- [x] an explanation for spaces name
- [x] HTTP status for 121 characters name
- [x] an explanation for 121 characters name
- [x] rows created

## ST-05 — POST without a valid CSRF token is refused — PASS

- [x] create with missing token: status
- [x] create with missing token: message
- [x] run with missing token: status
- [x] run with missing token: message
- [x] create with wrong token: status
- [x] create with wrong token: message
- [x] run with wrong token: status
- [x] run with wrong token: message
- [x] applications created
- [x] analyses created

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

## ST-07 — Active analysis without the active authorization is refused — PASS

- [x] HTTP status
- [x] message
- [x] analyses created

## ST-08 — Active analysis of the vulnerable laboratory — PASS

- [x] status
- [x] checks run shown
- [x] XSS on /search, parameter q
- [x] XSS on /profile, parameter name
- [x] requests to logout/destructive links

## ST-09 — Every finding carries the minimum information (CA-02) — PASS

- [x] there are findings to inspect
- [x] transport.https @ -: complete
- [x] transport.https @ -: shown with title and severity
- [x] xss.reflected_html_text @ q: complete
- [x] xss.reflected_html_text @ q: shown with title and severity
- [x] xss.reflected_html_text @ name: complete
- [x] xss.reflected_html_text @ name: shown with title and severity
- [x] cookies.missing_samesite @ -: complete
- [x] cookies.missing_samesite @ -: shown with title and severity
- [x] cookies.missing_httponly @ -: complete
- [x] cookies.missing_httponly @ -: shown with title and severity
- [x] headers.csp_missing @ -: complete
- [x] headers.csp_missing @ -: shown with title and severity
- [x] headers.frame_options_missing @ -: complete
- [x] headers.frame_options_missing @ -: shown with title and severity
- [x] cache.sensitive_no_store_missing @ -: complete
- [x] cache.sensitive_no_store_missing @ -: shown with title and severity
- [x] headers.permissions_policy_missing @ -: complete
- [x] headers.permissions_policy_missing @ -: shown with title and severity
- [x] disclosure.server_header @ -: complete
- [x] disclosure.server_header @ -: shown with title and severity
- [x] headers.coop_missing @ -: complete
- [x] headers.coop_missing @ -: shown with title and severity
- [x] headers.nosniff_missing @ -: complete
- [x] headers.nosniff_missing @ -: shown with title and severity
- [x] headers.corp_missing @ -: complete
- [x] headers.corp_missing @ -: shown with title and severity
- [x] headers.referrer_policy_missing @ -: complete
- [x] headers.referrer_policy_missing @ -: shown with title and severity

## ST-10 — Score equals the manual 30/15/7/2 calculation (CA-03) — PASS

- [x] passive: score on the page
- [x] passive: score in the export
- [x] active: score on the page
- [x] active: score in the export

## ST-11 — User-supplied and target-supplied content is escaped (NFR-02) — PASS

- [x] registered
- [x] raw tag absent from dashboard
- [x] escaped form present
- [x] no raw probe tag on the result page

## ST-12 — History lists every analysis, most recent first (FR-06) — PASS

- [x] both analyses listed
- [x] most recent first
- [x] #22 shows mode, completed status and score
- [x] #21 shows mode, completed status and score

## ST-19 — Authenticated scan reaches the private area; the credential is never kept (FR-11, NFR-07) — PASS

- [x] status
- [x] /account/notes reached
- [x] cookie sent to the target
- [x] database dump obtained
- [x] secret absent from the database
- [x] secret absent from the Apache access log
- [x] secret absent from the PHP error log

## ST-20 — Arguments reach the engine intact (contract R1) — PASS

- [x] cookie received exactly as typed
- [x] /account/notes reached with it
- [x] first request received
- [x] analysis status

## ST-13 — Comparison after a partial fix (CA-04) — PASS

- [x] XSS of /search is in 'Corrigidos'
- [x] XSS of /profile is in 'Ainda presentes'
- [x] 'Novos problemas' is empty

## ST-14 — Comparison after the complete fix (CA-04) — PASS

- [x] both XSS findings in 'Corrigidos'
- [x] headers.csp_missing in 'Corrigidos'
- [x] headers.frame_options_missing in 'Corrigidos'
- [x] headers.nosniff_missing in 'Corrigidos'
- [x] headers.referrer_policy_missing in 'Corrigidos'
- [x] 'Novos problemas' is empty
- [x] score improved

## ST-15 — Comparison across applications is refused — PASS

- [x] HTTP status
- [x] message

## ST-16 — JSON export is complete and equal to what is stored and shown (CA-06) — PASS

- [x] HTTP status
- [x] JSON content type
- [x] downloaded as attachment
- [x] application identified
- [x] analysis date present
- [x] score present
- [x] count export = database
- [x] count export = page
- [x] fingerprints export = database

## ST-17 — Printable report (FR-08) — PASS

- [x] HTTP status
- [x] application name
- [x] score
- [x] metric Verificações executadas
- [x] metric Achados
- [x] metric Status HTTP
- [x] metric Duração
- [x] every finding title and remediation
- [x] print button
- [x] no export link

## ST-18 — Severity filter counts (FR-12) — PASS

- [x] 'Todos' chip
- [x] 'high' chip
- [x] 'medium' chip
- [x] 'low' chip
- [x] no chip for absent severities

## ST-21 — Unknown identifiers answer 404 — PASS

- [x] page=result&id=999999: status
- [x] page=result&id=999999: message
- [x] page=export&id=999999: status
- [x] page=export&id=999999: message
- [x] page=compare&old=999999&new=999999: status
- [x] page=compare&old=999999&new=999999: message
- [x] run unknown application: status
- [x] run unknown application: message

## ST-22 — 1,000 findings presented in under 3 seconds (CA-05, NFR-01) — PASS

- [x] findings seeded
- [x] result page: 5 runs under 3,000 ms
- [x] report: 5 runs under 3,000 ms
- [x] export: 5 runs under 3,000 ms
- [x] comparison: 5 runs under 3,000 ms
- [x] result page renders 1,000 findings

## ST-23 — Loading indicator is present (roadmap step 23) — PASS

- [x] run form marked data-busy
- [x] status element with role=status
- [x] script handles submit, locks the button and shows the status

## ST-24 — Analysis timestamps share one clock (FR-06, CA-06) — PASS

- [x] history date (UTC) within the run
- [x] export: started_at <= completed_at, under 60 s apart

## FI-01 — .env absent — PASS

- [x] HTTP status
- [x] guidance message

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

## FI-08 — Database refuses the write of findings — PASS

- [x] the user gets an answer (error page or result)
- [x] no technical detail in the response
- [x] status
- [x] reason recorded
- [x] findings

## FI-09 — Scan outlives PHP's max_execution_time — PASS

- [x] the user gets an answer (after 228.6 s)
- [x] no technical detail in the response
- [x] analysis not left running
- [x] a failure carries a reason

## FI-10 — Value longer than its column, strict SQL mode — PASS

- [x] status
- [x] form finding stored
- [x] parameter within 180 characters
