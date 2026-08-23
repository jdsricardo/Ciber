# Test Plan and Results

## Strategy

Unit tests cover target validation, check count, finding schema, and score calculation. Integration tests use an explicitly authorized laboratory server. Acceptance testing follows CA-01 through CA-07 from the project charter.

| Case | Expected result | Current result |
|---|---|---|
| TC-01 Register a valid target | Application is persisted | Ready for manual execution |
| TC-02 Reject invalid URL/missing authorization | Clear validation error | Ready for manual execution |
| TC-03 Scan controlled response | 32 passive checks complete and findings persist | Automated scanner test supplied |
| TC-04 Verify each finding | Severity, evidence, impact, remediation present | Automated scanner test supplied |
| TC-05 Compare before/after scans | New, persistent, fixed groups are correct | Ready for integration execution |
| TC-06 Print report | Identity, date, score, findings included | Ready for manual execution |
| TC-07 Load 1,000 findings | History renders under three seconds | Benchmark procedure pending environment run |
| TC-08 SSRF protection | Private target denied by default | Automated test supplied |

Final measured results should be recorded with date, environment specifications, evidence, and tester name before academic delivery.
