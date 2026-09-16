# Algorithm and Data-Structure Measurements

Every structural choice below was made because it was measured, not because it was expected to
be faster. Each decision names the alternative that was rejected and the input sizes at which
the two were compared.

## Measurement environment

| Item | Value |
|---|---|
| CPU | Intel64 Family 6 Model 140 (11th gen mobile), AMD64 |
| OS | Windows 11 Pro 10.0.26200 |
| Python | 3.12.2 (CPython, 64-bit) |
| PHP | 8.2.12, ZTS, 64-bit |
| Method | Median of 5 runs per case, wall clock, same process |
| Date | 2026-09-16 |

The median — not the mean — is reported, so a single scheduling hiccup on the measuring machine
cannot move a result. Absolute times depend on the machine; the ratio between the two
implementations does not, and the ratio is what the decision rests on.

## How to reproduce

```
python evaluation/benchmark_structures.py     # scanner engine (Python)
php   evaluation/benchmark_comparison.php     # analysis comparison (PHP)
```

Both accept `--json` for a machine-readable result.

## Decision 1 — Crawl frontier: `deque`, not a list

`ScanRunner.run` walks the reachable same-origin surface breadth-first, taking the next page
from the front of the frontier. Removing from the front of a Python list shifts every remaining
element; `collections.deque.popleft()` is constant time.

| n (pages in the frontier) | list + `pop(0)` | deque + `popleft()` | Gain |
|---|---|---|---|
| 30 | 0.0102 ms | 0.0107 ms | 1.0× |
| 1 000 | 0.4311 ms | 0.3390 ms | 1.3× |
| 10 000 | 228.0680 ms | 4.0594 ms | 56.2× |

**Decision: `deque`.** At the size a scan really reaches — `max_pages` is 30 (passive) and 20
(active) — the two are indistinguishable, and the honest reading of the measurement is that
this change buys nothing today. It was adopted anyway because it costs one import and removes
the only quadratic term in the crawl loop, so raising `max_pages` later is a configuration
change rather than a performance investigation. Implemented in `scanner/engine/runner.py`.

## Decision 2 — Pages already enqueued: hash set, not a list

Before enqueueing a link, the crawler asks whether that page signature has been seen. The
question is asked once per discovered link, so its cost multiplies by the number of links on
the site, not by the number of pages scanned.

| n (distinct signatures) | list + `in` | set + `in` | Gain |
|---|---|---|---|
| 30 | 0.0194 ms | 0.0114 ms | 1.7× |
| 1 000 | 13.5200 ms | 0.3538 ms | 38.2× |
| 10 000 | 618.4438 ms | 2.1607 ms | 286.2× |

**Decision: `set`.** Membership is the only operation performed on this collection and it is
performed for every link on every page, so average O(1) is the property that matters; order is
irrelevant because the frontier already preserves visit order. Implemented as `enqueued` in
`scanner/engine/runner.py`.

## Decision 3 — De-duplicating findings: set of keys, not a pairwise scan

A crawl of many pages reports the same site-wide condition (a missing header, an insecure
cookie) once per page. `ScanRunner._deduplicate` collapses them, keeping first-seen order.

| n (findings before de-duplication) | pairwise scan | set of keys | Gain |
|---|---|---|---|
| 30 | 0.0151 ms | 0.0114 ms | 1.3× |
| 1 000 | 3.4437 ms | 0.4951 ms | 7.0× |
| 10 000 | 474.9044 ms | 6.3865 ms | 74.4× |

**Decision: set of keys.** An active scan over 20 pages with 64 checks produces findings in the
hundreds before de-duplication, where the pairwise scan is already measurably worse and gets
worse quadratically. The list of unique findings is kept alongside the set, because report order
is part of the output and a set has none.

## Decision 4 — Comparing two analyses: map keyed by fingerprint, not a pairwise scan

`AnalysisComparison::diff` classifies every finding of two analyses as new, persistent or fixed.
The natural phrasing — "for each finding, look for it in the other analysis" — is O(n²). Keying
both sides by fingerprint first makes each classification a hash lookup, and lets PHP's
`array_diff_key` / `array_intersect_key` do the work in C.

| n (findings per analysis) | pairwise scan | keyed by fingerprint | Gain |
|---|---|---|---|
| 100 | 0.4590 ms | 0.0141 ms | 32.6× |
| 1 000 | 94.8329 ms | 0.2000 ms | 474.2× |
| 10 000 | 9 950.7170 ms | 2.8598 ms | 3 479.5× |

**Decision: map keyed by fingerprint.** This is the one case where the measurement changes
whether an acceptance criterion is met. CA-05 / NFR-01 requires a history of 1 000 findings to
be usable within three seconds; the pairwise version spends 95 ms of that budget on the
comparison alone and degrades to roughly 10 s at 10 000 findings, while the keyed version stays
under 3 ms. Implemented in `app/src/Domain/Service/AnalysisComparison.php`.

## Decision 5 — Persistence: B-tree indexes, not in-memory structures

The three collections that grow — `applications`, `analyses`, `findings` — are not held in
memory between requests, so the structure that decides their access cost is the index InnoDB
builds, not a PHP array. The indexes exist for the two access paths the application actually
uses:

| Index | Serves |
|---|---|
| `idx_analysis_application_date (application_id, started_at)` | the history of one application, already ordered, with no filesort |
| `idx_finding_analysis (analysis_id)` | loading the findings of one analysis |
| `idx_finding_fingerprint (analysis_id, fingerprint)` | locating one finding by identity when comparing analyses |

A B-tree, not a hash index: the history query is a range scan ordered by date, which a hash
index cannot serve. Each lookup is O(log n) rather than the O(1) average of an in-memory hash
map, and that is the correct trade — durability and ordered access are requirements here, speed
of a single lookup is not the binding constraint.

Loading 1 000 findings and rendering them is measured directly by the PHP suite
(`tests/php_test.php`, CA-05): rendering completes in well under the three-second budget.
