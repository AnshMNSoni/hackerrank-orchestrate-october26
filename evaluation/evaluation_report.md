# Evaluation Report: Ghost Data Still Exists

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Agent Architecture**: Deterministic, Evidence-Grounded Temporal Deletion Audit Pipeline  
**Benchmark Date**: October 25, 2026  

---

## 1. Executive Summary

This report provides the full evaluation results for the AI-powered deletion-audit agent across the 32 public benchmark requests in `dataset/sample_deletion_requests.csv` evaluated against `dataset/sample_output.csv`, as well as validation across the full 518 evaluation cases in `dataset/deletion_requests.csv`.

The audit pipeline operates deterministically without external LLM inference overhead or hallucinations. It establishes identity aliases (current/historical emails, user IDs, phone numbers, and SHA-256 hashes), parses multi-modal evidence across databases, system logs, JSON exports, and PDFs, enforces the temporal cutoff (`record_time <= audit_at` with citable-captured evidence preferred per §6.2/§6.6), verifies retention rules under `deletion_rules.csv`, and synthesizes strictly ordered finding, remediation, and verification step sequences.

---

## 2. Benchmark Metrics (32 Sample Cases)

### Case-Level and Step-Level Performance

| Metric | Measured Score | Details / Benchmark Target |
|---|---|---|
| **Deletion Status Accuracy** | **100.00%** | 32 / 32 correct classifications (`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`) |
| **Exact Full-Case Accuracy** | **50.00%** | 16 / 32 exact step-by-step match |
| **Sequence Accuracy** | **50.00%** | 16 / 32 exact phase and step ordering match |
| **Step Precision** | **86.41%** | Precision across predicted operations and resources |
| **Step Recall** | **82.38%** | Recall against ground truth steps |
| **Step F1-Score** | **84.35%** | Harmonic mean of step precision and recall |

### Field-Level Accuracy Breakdown

| Field Name | Accuracy | Analysis |
|---|---|---|
| **`phase`** | **100.00%** | Perfect phase partitioning (`FINDING` → `REMEDIATION` → `VERIFICATION`) |
| **`system_id`** | **91.80%** | High fidelity across `account_service`, `support_platform`, `analytics_platform`, `backup_service`, `integration_service`, and `security_service` |
| **`resource_id`** | **87.98%** | Accurate resolution of specific resource IDs via trace and identity links |
| **`operation`** | **90.71%** | Strict alignment with official operation precedence from problem statement §6.4 |
| **`state`** | **91.26%** | Exact alignment with required target states (`PRESENT`, `ABSENT`, `REDACTED`, `ANONYMIZED`, `ACTIVE`, `DISABLED`, `BLOCKED`) |
| **`evidence_id`** | **99.45%** | Grounded citation of participant-visible evidence files; empty string for future steps |

### Status Mismatch Analysis
- **Total Status Mismatches**: **0 (None)**.
- All 32 cases in `dataset/sample_deletion_requests.csv` match the ground truth deletion status exactly.

---

## 3. Failures Found and Iterative Improvements Made

During development and systematic error analysis against the 32 sample cases, multiple critical failure modes were identified and remediated:

1. **Case 07 & Multi-Format PDF Extraction (`evidence_58`)**:
   - *Failure*: `case_07` was initially misclassified as `COMPLETE` because the PDF attachment `support_001` was captured with regex `\b(support|...)\b`, which matched only `'support'` rather than the full identifier `'support_001'`.
   - *Fix*: Refactored PDF regex to use non-capturing groups `(?:support|...)_\d+`. Correctly extracted `support_001` as an unredacted support attachment belonging to the subject. The policy engine now classifies `case_07` as `INCOMPLETE`, generating finding `#1 REPORT_REMAINING_RECORD` citing `evidence_58` and remediation `#2 DELETE_RECORD`, achieving a 100% exact match with ground truth.

2. **Cases 26, 27, and 28 Support Ticket Redaction Semantics**:
   - *Failure*: In `code/temporal_state.py`, support conversation observations were unconditionally flagged as `is_violation=True` (`EXPOSED_PII`), ignoring whether the ticket was already redacted in `evidence_92` (`requester_email: None`, `requester_name: None`). This forced cases 26, 27, and 28 to be incorrectly marked `INCOMPLETE`.
   - *Fix*: Added verification that when `state_signal == "REDACTED"`, `is_violation` is set to `False` and `state="REDACTED"`. In a `COMPLETE` audit, the policy engine correctly emits `VERIFY_RECORD_REDACTED` citing `evidence_92`. This boosted Deletion Status Accuracy from 90.62% to 100.00%.

3. **Account Verification Citation and Elimination of Arbitrary Proximity Matching**:
   - *Failure*: For cases 21, 25, 26, 27, and 28, the execution-window fallback previously selected arbitrary account records (such as `account_7225` and `account_7012`) based solely on time delta (`diff_s`), citing stale failover replicas (`evidence_54`) rather than verifiable readback audit logs (`evidence_92`).
   - *Fix*: Enhanced `evidence_indexer.py` with multi-level candidate prioritization:
     1. Prioritizes verified user-to-account mappings extracted from snapshot records.
     2. Penalizes accounts known to belong to other users.
     3. Strongly favors candidates that have verifiable readback observations in the evidence index at or before `audit_at`.
     4. Correctly correlates `account_6440` (case 21), `account_3136` (case 25), `account_5684` (case 26), `account_3866` (case 27), and `account_5482` (case 28), all citing `evidence_92`.

4. **Observability Log Noise & Start-Event Filtering**:
   - *Failure*: Observability log events like `profile_lookup_started` in `evidence_94` caused false `PRESENT` states because the regex captured the line before checking the completion status code.
   - *Fix*: Explicitly filtered out all `_started` log entries, ensuring that only completed lookups (e.g. HTTP 200 vs 404, or row count checks) emit state observations.

5. **Historical Hash Ingestion**:
   - *Failure*: In `case_12`, historical email hash `44a65154...` was not ingested from `user_audit_log.csv`, preventing discovery of `analytics_9914`.
   - *Fix*: Extended `IdentityResolver` to parse `field_name == "email_hash"` changes from `user_audit_log.csv`.

6. **Effective-Time Evidence Gate, Citable-Evidence Preference, and Longitudinal Corroboration** (final improvement round):
   - *Failure*: The evidence query gate required BOTH `captured_at <= audit_at` AND `record_time <= audit_at`. Point-in-time snapshot records (e.g. the records-assurance bundle whose manifest capture is 2026-09-17 but whose embedded snapshots carry earlier `record_time` values) were silently discarded, Losing retained `audit_record_*` verification steps for cases 23, 24, 29, and 30.
   - *Fix (three grounded rules)*:
     1. **Effective-time gate**: observations are admitted when their embedded record/event time (`record_time`) is at or before `audit_at`.
     2. **Citable-evidence preference (state reconciliation)**: per resource, evidence captured at or before `audit_at` takes precedence for both the reconstructed state and the cited `evidence_id` (per §6.6, evidence captured after `audit_at` may not be cited; within citable evidence the newest effective time wins, and a same-time `PRESENT`/`ABSENT` conflict stays conservative). This restored `evidence_92` citations against the later-captured bundle and superseded a stale pre-deletion account snapshot (case 26) with its verified 404 readback.
     3. **Longitudinal corroboration merge**: for resources discovered through direct identity linkage, remaining citable resource-linked observations (history rows, replica snapshots, verified readbacks) are merged so conflicting evidence is reconciled rather than dropped.
   - *Additional fix*: support-conversation snapshot records whose message text is `[REDACTED]` are indexed as `REDACTED` instead of `PRESENT`.
   - *Result*: Exact full-case accuracy 43.75% → **50.00%** (cases 24 and 30 became exact), step F1 79.89% → **84.35%**, `evidence_id` field accuracy → **99.45%**, with deletion status accuracy sustained at **100.00%**. Guarded by three new regression unit tests (stale-snapshot supersession, same-time conservative conflict, redacted support text), all 18 unit tests passing, and byte-identical deterministic re-runs of the full 518-case output.
   - *Audited citation semantics (final correctness audit — conflict resolved)*: A focused temporal audit separated file capture time (`captured_at`), embedded record/event time (`record_time`), effective state time, and citation eligibility, against the controlling rules (AGENTS.md §6.2 "Use only information available at or before `audit_at`… Evidence created later must not change the answer"; §6.6 "Never cite … an evidence item captured after the case's `audit_at`"). The audit found 6 steps citing files whose manifest capture is later than `audit_at` (`case_126` finding → `evidence_12`; `COMPLETE`-case verifications in `case_70/215/218/219/221` → `evidence_06`/`evidence_21`); the only participant-visible state proof in every case is embedded in the post-captured file with pre-audit event times (e.g. `evidence_21` readbacks at 2026-07-03T07:52–07:59 vs `audit_at` 08:00). The finding case was resolved per spec: `case_126`'s finding now cites the eligible pre-audit `activity_3114` (`DELETE_RECORD … FAILED`, 2026-08-05, same resource `account_8819`) — §6.6 explicitly allows findings to cite a `file_id`, `activity_id`, or `audit_id`. After the fix (enforced by `main.py::_apply_citation_eligibility` — finding-pass activity substitution plus citable-witness preference for `COMPLETE`-case verification citations — guarded by 18 regression tests in `code/tests/test_citation_eligibility.py`), the full 518-case output contains **zero** finding citations to post-audit-captured evidence and zero post-audit activity citations. The five `COMPLETE`-case verification citations (`case_70/215/218/219/221`) were initially retained under the assumption that no pre-audit-captured evidence existed for those five resources and that swapping in a `SUCCESS` delete activity would treat a reported claim as proof of final state, which §6.5 forbids. **Superseded by the final read-only adjudication below — an eligible citable witness file exists for every one of the five cases.** Two full-518 status flips were individually verified against the official specification and evidence: `case_126` (`NOT_STARTED` request, its only deletion attempt `activity_3114` on 2026-08-05 has `reported_result=FAILED`, and the Aug-11 snapshot shows `account_8819` still `ACTIVE` with full PII → `INCOMPLETE`; previously a fabricated `system_activity` citation falsely proved absence) and `case_480` (`support_5854` message text is literally `[REDACTED]`, `backup_7706` has `restore_allowed=false`, both in `evidence_45` captured exactly at `audit_at` → `COMPLETE`).
    - *Final read-only adjudication of the five COMPLETE-case verification citations (cases 70, 215, 218, 219, 221)*: A complete participant-visible sweep (current + historical emails, `user_id`, email hashes, account resource ids across all evidence manifests and contents, `system_activity.csv`, `user_audit_log.csv`) established: (a) the golden `sample_output.csv` never cites a file captured after `audit_at` — 0 of 575 sample steps (the 34 `COMPLETE` verifications all cite pre-audit-captured files; account-absence steps cite citable scope-witness files such as `evidence_54`, `evidence_92`, `evidence_94`, `evidence_51`); (b) the output contract does **not** permit empty `evidence_id` for `COMPLETE`-case verification steps (the validator requires non-empty and the golden cites 34/34); (c) **eligible citable witness files exist for all five cases**: `evidence_93` (`customer_data_inventory_20260916.sql`, captured 2026-09-16T08:37:39Z < `audit_at` 2026-09-16T09:00:00Z) for `case_70`, and `evidence_81` (`customer_data_inventory_20260703.sql`, captured 2026-07-03T07:43:56Z < `audit_at` 2026-07-03T08:00:00Z) for `case_215/218/219/221`. Each is an eight-system subject-scoped snapshot taken minutes before the audit cutoff; it contains the subject's retained security audit record (`audit_record_1738` / `audit_record_1718|8792|3382|3880`) and **no remaining profile or artifact row for the subject**, while other subjects' live rows (e.g. `account_9079 DELETION_PENDING`, backup/export/connector/search/support rows) prove the snapshot covers those collections — the same absence-from-citable-scope-witness convention the golden itself uses (e.g. `case_04` → `evidence_54`). Each case's verification step 2 already cites the same file. No eligible `activity_id` exists (a pre-audit `SUCCESS`/`PARTIAL` delete claim is not proof of final state per §6.5) and no eligible `audit_id` exists (`user_audit_log.csv` records identity field changes only). **Adjudication**: (1) no case is fully compliant as cited today; (2) no specification inconsistency remains — the earlier documented 'spec/reference inconsistency' for these five cases is hereby superseded; (3) this is an implementation **citation-selection defect**: the pipeline preferentially cited the post-audit-captured observability log containing the explicit 404 readbacks instead of the citable same-day inventory. **Required fix — APPLIED**: replace the five citations — `case_70` step 1 `evidence_06 → evidence_93`; `case_215/218/219/221` step 1 `evidence_21 → evidence_81` — implemented as a general citable-witness preference for `COMPLETE`-case verification citations (no case ids in production logic). Verified after the fix: exactly 5 rows changed (one `evidence_id` field each), zero status changes, distribution 298/219/1 unchanged, `sample_pred.csv` byte-identical, 0 of 518 steps citing post-audit-captured evidence files or post-audit activity ids, 518-case validator PASS, deterministic double-run md5 `ff731eba2ba04021a96374c6f7d11545`, 36/36 unit tests passing. The `COMPLETE` classification of all five cases at `audit_at` is independently corroborated by the same citable inventories: no residual artifact rows for any of the five subjects.

---

## 4. Participant-Created Evaluation Cases

To rigorously validate edge cases not fully exercised in the 32 public samples, three challenging evaluation cases were synthesized:

### Case 1: Ambiguous Intent — DSAR Export vs Deletion Authorization (`custom_case_01`)
- **Input Request**:
  ```text
  case_id: custom_case_01
  email: devon.morales@company.internal
  requested_at: 2026-09-10T10:00:00Z
  reported_status: NOT_STARTED
  reported_at: 2026-09-10T10:05:00Z
  audit_at: 2026-09-15T12:00:00Z
  request_text: "Please provide a complete export of all personal data, transaction history, and communication records associated with my profile under GDPR Article 15."
  ```
- **Evaluation Criteria**: The user requested an access/export report under Article 15, not an erasure under Article 17. The agent must not initiate a deletion audit.
- **Expected Status**: `NOT_APPLICABLE`
- **Expected Steps**: `[]`
- **Agent Result**: `NOT_APPLICABLE`, `steps_json=[]` (PASS).

### Case 2: Account Tombstone PII Leakage (`custom_case_02`)
- **Input Request**:
  ```text
  case_id: custom_case_02
  email: elena.rostova@proton.me
  requested_at: 2026-08-15T08:00:00Z
  reported_status: COMPLETE
  reported_at: 2026-08-16T08:00:00Z
  audit_at: 2026-08-25T12:00:00Z
  request_text: "I wish to permanently delete my account and remove all personal information."
  ```
- **Context & Evidence**: In `evidence_07`, identity collection `deleted_customer_references` preserves tombstone `tombstone_8102` with `user_id="user_881"`. However, the record still contains `full_name="Elena Rostova"` and `phone="+7 916 555-0192"`.
- **Evaluation Criteria**: Under `rule_04` (`ACCOUNT_TOMBSTONE`), the stable user ID is permitted, but direct identifiers must be redacted.
- **Expected Status**: `INCOMPLETE`
- **Expected Finding**: `REPORT_EXPOSED_PII` on `tombstone_8102` (`PRESENT`).
- **Expected Remediation**: `REDACT_RECORD` on `tombstone_8102` (`REDACTED`).
- **Expected Verification**: `VERIFY_RECORD_REDACTED` on `tombstone_8102` (`REDACTED`).
- **Agent Result**: Identifies violation, outputs required 3-phase remediation plan (PASS).

### Case 3: Re-creation Risk from Active Sync Connector (`custom_case_03`)
- **Input Request**:
  ```text
  case_id: custom_case_03
  email: zhang.wei@techcorp.cn
  requested_at: 2026-07-20T14:00:00Z
  reported_status: COMPLETE
  reported_at: 2026-07-21T14:00:00Z
  audit_at: 2026-07-30T12:00:00Z
  request_text: "Please delete my account and ensure all connected services stop collecting data."
  ```
- **Context & Evidence**: Primary account `account_1092` was deleted from primary SQL store. However, `integration_service` active connector `data_flow_4102` remains `enabled: true` and continues to sync profile data from external CRM.
- **Evaluation Criteria**: Under `rule_08` (`DATA_FLOW_SYNC`), active sync flows that recreate data must be reported and disabled before dependent records are safe.
- **Expected Status**: `INCOMPLETE`
- **Expected Steps**:
  1. `FINDING`: `REPORT_ACTIVE_DATA_FLOW` on `data_flow_4102` (`ACTIVE`).
  2. `REMEDIATION`: `DISABLE_DATA_FLOW` on `data_flow_4102` (`DISABLED`).
  3. `VERIFICATION`: `VERIFY_DATA_FLOW_DISABLED` on `data_flow_4102` (`DISABLED`).
- **Agent Result**: Accurately detects active data flow recreation risk, disables flow before record verifications (PASS).

---

## 5. Full Evaluation Dataset Validation (518 Cases)

The production agent was executed against all 518 evaluation requests in `dataset/deletion_requests.csv` to generate the root `output.csv`. An automated test suite (`code/tests/validate_submission_output.py`) verified:
- **Exact Line Count**: 519 lines (header + 518 records).
- **Header**: `case_id,deletion_status,steps_json`.
- **Case Ordering**: Sorted lexicographically by `case_id` matching input dataset.
- **Output Distribution**:
  - `INCOMPLETE`: 298 cases (57.5%)
  - `COMPLETE`: 219 cases (42.3%)
  - `NOT_APPLICABLE`: 1 case (0.2%)
- **Integrity**: 0 malformed JSON arrays, 0 invalid phase transitions, 0 invalid operations or states, and all future steps have empty evidence IDs.
