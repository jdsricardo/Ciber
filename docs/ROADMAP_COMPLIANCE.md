# Roadmap Compliance — Fases 4 and 5

Status of every step of Fase 4 (Construção, steps 20–25) and Fase 5 (Integração e verificação,
steps 26–32) of the *Roteiro de Execução do Projeto* (`docs/docsAula/Roteiro_de_Execucao_do_Projeto.pdf`),
followed by the precedence rules of its section 8 and the pre-delivery checklists of its
section 9. Each statement points at evidence that can be checked in the repository; where a step
was not met, or met only by adaptation, this document says so.

Assessed on 2026-10-14 after run 2, and re-assessed on 2026-10-28 after a
cross-check of the product against the Termo de Referência (defects D-09 and D-10, run 3).

**Legend:** ✅ met · 🔄 met by documented adaptation · ⏳ pending (needs a person) · ⚠️ not met in the order the roadmap asks (historical)

## 1. Why some steps are adapted

The roadmap is written for a mobile application that may talk to a physical module (emulator,
airplane mode, offline sync queue, embedded circuit). SentinelScope is a **server-side web
application** whose purpose is to send HTTP requests to a target: it has no offline client, no
local store to synchronize and no hardware. Steps 23, 24 and 25 are therefore met by their
**intent** — the interface does not freeze, connectivity loss is handled without corrupting or
duplicating data, and the external artefact the product depends on (a validation base) exists
and is registered — with the reasoning below. This is a reading of the roadmap, not a scope cut:
no functionality of the Termo de Referência was removed.

## 2. Fase 4 — Construção

| Step | Expected output | Status | Evidence |
|---|---|---|---|
| 20 — Environment and project with packages per layer | Project compiling, structure reflecting the architecture | ✅ | `app/src/{Domain,UseCase,Infrastructure,Presentation}` = the four layers of [ARCHITECTURE.md](ARCHITECTURE.md). All 49 PHP files pass `php -l`; all 67 Python files compile (`python -m compileall`). The layering rule is executable (AT-02, "domain references no outer layer"). Environment reproduced from the manual on XAMPP 8.2 / MariaDB 10.4 / Python 3.12. |
| 21 — Screens and navigation, without business rules | High-priority screens navigable | ✅ | Routes in [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) §3. `Presentation\Views` only builds markup; every decision lives in a use case or the domain. Navigation exercised by ST-01…ST-26 and MT-01…MT-03 in a real browser. |
| 22 — Local repository, screens on real data | Persistence working through the contract declared in E2 | ✅ | `Pdo*Repository` implement the domain contracts. **Fase 3 recorded that the PDO adapters had never run against MariaDB; this cycle closes that gap:** every system test runs on a real MariaDB with a least-privilege user (TEST_REPORT §2). |
| 23 — Data and network operations off the UI path, with a loading indicator | Interface without freezing, loading indication | 🔄 ✅ | The network work (the scan) runs in a separate Python process started by the server; the browser never executes it, so the page cannot freeze. Missing before this cycle: any indication that work was in progress, and protection against a second click. Added on 2026-10-14 (progress message with `role="status"`, button locked → no duplicate analysis). Verified: ST-23 (markup and script); MT-01 in a real headless browser — after a double click the button is locked, the progress message is shown and exactly one analysis is created. |
| 24 — Sync queue, tested without connection (airplane mode, no duplication on reconnect) | Offline operation verified | 🔄 | No offline mode exists to queue for: an analysis *is* network access to the target. The step's intent — losing connectivity must neither corrupt nor duplicate data — is verified as: target unreachable → analysis `failed` with reason, no findings (FI-04); transient TCP reset retried once without double-charging the budget (AT-01, `test_transport.py`); database unreachable → generic error, nothing half-written (FI-02, FI-08, contract C3); no duplicate analysis on resubmission (step 23 lock; MT-01). |
| 25 — External module / validation base | Artefact ready and documented | 🔄 ✅ | No hardware. The artefact the product depends on is its **validation base**, and it exists and is registered: the controllable laboratory target `tests/e2e/lab_target.py` (4 variants, request log), the per-plugin vulnerable/safe fixtures in `tests/`, and the empirical evaluation harness with ground truth in `evaluation/` (results in [EVALUATION_RESULTS.md](EVALUATION_RESULTS.md)). |

## 3. Fase 5 — Integração e verificação

| Step | Expected output | Status | Evidence |
|---|---|---|---|
| 26 — Write and version the integration contract | Format, fields, delimiters, validation rules | ✅ | [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) v1.0 written on 2026-10-14 before the end-to-end battery, v1.1 the same day after it: transport and framing, arguments, every response field with type and column limit, failure document, consumer obligations C1–C6, identity rule, versioning policy and change log. Enforced by conformance tests on both sides reading one shared payload. |
| 27 — Integrate end to end without bypassing layers | Complete flow from the data origin to the screen | ✅ | The system driver acts only through HTTP on the real interface (Apache → front controller → use case → domain → PDO / gateway → engine → laboratory target), and reads the database only to confirm what the screen shows. ST-06/08 (scan to screen), ST-13/14 (comparison), ST-16/17 (export, report). |
| 28 — Provoke and handle foreseeable failures | Behaviour observed in each failure | ✅ | FI-01…FI-10, with the behaviour observed in each one recorded in [TEST_REPORT.md](TEST_REPORT.md) §2.2. Three of them revealed defects (D-02, D-04, D-06), all fixed. |
| 29 — One test case per acceptance criterion, expected result written before execution | Cases with precondition and expected result | ✅ | [TEST_PLAN.md](TEST_PLAN.md) 2.0 written **before** the first execution (run 1, 2026-10-14 23:00 UTC, evidence in `docs/test-evidence/2026-10-14_run1`). Cases added later were written before the code they verify: ST-24 before the fix of D-07, ST-25 and ST-26 before D-09 and D-10 were implemented (plan §8, dated revisions). Invalid-input cases included. Traceability CA → cases in plan §7. |
| 30 — Execute and register defects | Result per case; defects with reproduction steps | ✅ | Run 1 evidence in `docs/test-evidence/2026-10-14_run1*`, run 3a in `2026-10-28_run3a-before`; defect register with root cause and reproduction in TEST_REPORT §3. Test-ware errors kept apart (§4), including one false PASS that was voided. |
| 31 — Fix blockers and highs, re-execute | Defects verified by re-execution, not only fixed | ✅ | All 10 defects fixed, including the medium and low ones. Run 2 re-executed the whole battery after D-01…D-08 (113/113, 140/140, 24/24, 10/10); run 3 re-executed it again on the final code, after D-09/D-10: 113/113, 153/153, 26/26 system, 10/10 failure injection, 3/3 browser. Each defect's revealing case is named in the register's *Verified* column. |
| 32 — Consolidate the five technical documents | Documentation complete and consistent with the product | ✅ | See §3.1. |

### 3.1 The five technical documents (step 32)

Step 32 takes as input steps 6 (Termo), 19 (architecture), 25 (module) and 31 (tests). The
five documents are therefore read as:

| # | Document | Updated in this cycle to match the product |
|---|---|---|
| 1 | Requirements specification — [REQUIREMENTS.md](REQUIREMENTS.md) (with the Termo de Referência) | FR-06 and FR-12 reworded to say what Termo items 6 and 8 require (period, export summary); traceability verified by inspection TR-01/TR-02. |
| 2 | Architecture — [ARCHITECTURE.md](ARCHITECTURE.md) | Gateway without shell and with deadline, the "no analysis left running" rule, finding identity, UTC, link to the contract. |
| 3 | Integration contract — [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) (the module/integration document) | New, v1.1. |
| 4 | Test plan and results — [TEST_PLAN.md](TEST_PLAN.md), [TEST_REPORT.md](TEST_REPORT.md) | New plan 2.0 and report. |
| 5 | Installation and user manual — [INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md) | Rewritten: the previous version pointed at a wrong URL and did not explain how to create the database user. |

Supporting code documentation: [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) (new),
[CODING_STANDARD.md](CODING_STANDARD.md), [SCANNER_ENGINE.md](SCANNER_ENGINE.md),
[ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md), [README](../README.md),
[CHANGELOG](../CHANGELOG.md).

## 4. Precedence rules (roadmap §8)

For Fases 1–3 the git history (`git log --reverse --stat`) is the evidence. The project started
from an artefact that already existed (first commits on 2026-08-23); the roadmap was adopted
while the work was under way and Fases 1–3 were consolidated **retroactively**. Fases 4 and 5
were executed in the roadmap's order; for them the evidence is the dated revision table of the
test plan (its §8) and the time-stamped results of every run in `docs/test-evidence/`.

| Do not … | … before | Status | Evidence |
|---|---|---|---|
| Write requirements | having a source of elicitation | ⚠️ partially | Termo v1.0 (19/08/2026) cites the observation of the team's routine as source; the first `REQUIREMENTS.md` is in the baseline commit of 23/08; the interview is dated 09/09 (simulated). On 23/09 every requirement's origin was re-pointed to an item of the Termo and to the interview answer (inspection TR-01). The source exists now; it did not precede the first version. |
| Choose the technology | closing the Termo | ⚠️ partially | Termo v1.0 is dated 19/08, before the first code (23/08); the technology was, however, inherited from the pre-existing artefact rather than chosen after the Termo. |
| Choose the data structure | estimating the volume | ⚠️ partially | Volumes estimated and structures measured in Fase 2 (16/09, `docs/ALGORITHM_MEASUREMENTS.md`); some structures existed earlier in code and were confirmed — or, for the crawl frontier, recorded as without measurable gain — by that measurement. |
| Draw the architecture | having the domain model | ⚠️ partially | `ARCHITECTURE.md` existed from 23/08 describing the earlier structure; the domain model and the layered architecture arrived together in `1aa5598` (16/09) and were consolidated in `2dcbc8f` (23/09). |
| Open the screen editor | having the repository contracts declared | ⚠️ not met historically | `public/index.php` (screens) is in the baseline of 23/08; `app/src/Domain/Contract/` appears on 16/09. The cost the roadmap warns about (rules inside screens) did occur and was **paid in Fase 3**: rules moved into use cases and the domain, and `Views` now decides nothing. |
| Implement the integration | writing the message contract | ⚠️ not met historically · ✅ remedied | The PHP ⇄ Python integration exists since 23/08; the contract was only implicit in code until it was written on 14/10. Writing it down immediately exposed four integration defects (D-03, D-05, D-06, D-08) — exactly the "trial and error between the two ends" the roadmap predicts. |
| Execute the test | writing the expected result | ✅ | Plan 2.0 written before run 1 (2026-10-14 23:00 UTC); ST-24, ST-25 and ST-26 written before the code they verify; plan revisions dated (plan §8). |
| Close a defect | re-executing the case that revealed it | ✅ | D-01…D-08 closed only after run 2 (2026-10-14 23:13 UTC), D-09 and D-10 only after run 3 (2026-10-28 22:36 UTC); TEST_REPORT §3 *Verified* column. |
| Write the documentation | — (document along the way) | ✅ | Documentation was updated in every phase; in Fases 4–5 the contract and the plan were written before execution, the evidence recorded after each run, and the documents consolidated together with the fixes. |

## 5. Checklists before each delivery (roadmap §9)

### Before E3 — Application and module

| Condition | Status | Evidence |
|---|---|---|
| The application compiles and runs in an emulator or physical device | 🔄 ✅ | Web application: runs on the target environment (XAMPP on Windows 11) and was exercised end to end by the 39 system, failure-injection and browser cases of run 3. |
| The package structure reflects the layers declared in E2 | ✅ | Step 20. |
| Offline operation tested in airplane mode, with synchronization verified | 🔄 | Step 24 adaptation: FI-02, FI-04, FI-08, `test_transport.py`. |
| The physical artefact or validation base, if any, is ready and registered | ✅ | Step 25: `tests/e2e/lab_target.py`, fixtures, `evaluation/`. |

### Before E4 — Tests and documentation

| Condition | Status | Evidence |
|---|---|---|
| At least one test case per high-priority acceptance criterion | ✅ | TEST_PLAN §7; TR-02. |
| The battery includes invalid-input cases, not only success | ✅ | TR-03: 8 ST cases and all 10 FI cases. |
| Every blocker and high defect fixed and re-verified by re-execution | ✅ | Blocker D-02 and highs D-01, D-03, D-04, D-06, D-09, D-10 (and D-05, D-07, D-08) verified by re-execution. |
| The five technical documents consistent with the delivered product | ✅ | §3.1. |

### Before the defence (Fase 6 — for planning)

| Condition | Status | What remains |
|---|---|---|
| Someone outside the team installed the system using only the manual | ⏳ | MT-04 / CA-07. The manual was rewritten for this purpose; record every question the person asks and fix the manual. |
| The presentation was rehearsed with a timer and fits in 12 minutes | ⏳ | Fase 6, step 34. |
| The demonstration was tested on site and on the defence equipment | ⏳ | Fase 6. `tests/e2e/lab_target.py` gives a reproducible, offline-safe demonstration target. |
| Every member can answer about any part of the work | ⏳ | Team. |

## 6. Open items

1. **MT-04 / CA-07** — a person outside the team installs the system using only
   [INSTALLATION_AND_USER_MANUAL.md](INSTALLATION_AND_USER_MANUAL.md) and runs one analysis; record
   it in [TEST_REPORT.md](TEST_REPORT.md) §6 and fix the manual for every question asked. It is the
   only planned case not executed, and it cannot be automated.
2. **Fase 6** — presentation, rehearsal and demonstration on the defence equipment.

## 7. Notes on the course documents (`docs/docsAula/`)

The course documents are the reference this cycle followed; they were **not** edited. The
cross-check of 2026-10-28 found the points below, recorded here for the team:

| Document | Observation | Effect on the product |
|---|---|---|
| Termo de Referência, §3.2 items 6 and 8 | History "por período" and an export "resumo" were in the agreed scope but not fully implemented. | Implemented (D-09, D-10); FR-06 and FR-12 aligned. |
| Termo de Referência, §4 | The integration contract and the developer guide produced in Fase 5 are not listed among the deliverables; the adaptation of roadmap steps 23–25 (§1 above) is not in the change-control table. | None — documented here and in the repository. |
| Entrevista de Requisitos, §6.2 | The closing checklist is left unticked, although every item has its record in the document (A2, B1, D2, E1, F1, G1, G2, H1, §5). | None. |
| Fase 2 (§5, §6) and Estruturas de Dados (§3) | Describe the comparison map as keyed by *fingerprint*. Since D-01 the key is the finding identity (fingerprint + endpoint + parameter); the structure — one hash map per side — and its measurement are unchanged. | Recorded in [ALGORITHM_MEASUREMENTS.md](ALGORITHM_MEASUREMENTS.md), Decision 4. |
| Fase 3, §5.2 and §6.1 | Test counts (106 / 115) and the remark that the PDO adapters were never run against MariaDB are as of 23/09; both are superseded by the Fase 5 results. | None — the documents are dated. |
