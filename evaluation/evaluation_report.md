# Evaluation Report: Ghost Data Still Exists

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Agent Architecture**: Deterministic, Evidence-Grounded Temporal Deletion Audit Pipeline  
**Benchmark Date**: October 25, 2026  

---

## 1. Executive Summary

This report provides the full evaluation results for the AI-powered deletion-audit agent across the 32 public benchmark requests in `dataset/sample_deletion_requests.csv` evaluated against `dataset/sample_output.csv`, as well as validation across the full 518 evaluation cases in `dataset/deletion_requests.csv`.

The audit pipeline operates deterministically without external LLM inference overhead or hallucinations. It establishes identity aliases (current/historical emails, user IDs, phone numbers, and SHA-256 hashes), parses multi-modal evidence across databases, system logs, JSON exports, and PDFs, enforces temporal cutoffs (`captured_at <= audit_at` and `record_time <= audit_at`), verifies retention rules under `deletion_rules.csv`, and synthesizes strictly ordered finding, remediation, and verification step sequences.

---

## 2. Benchmark Metrics (32 Sample Cases)

### Case-Level and Step-Level Performance

| Metric | Measured Score | Details / Benchmark Target |
|---|---|---|
| **Deletion Status Accuracy** | **100.00%** | 32 / 32 correct classifications (`COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`) |
| **Exact Full-Case Accuracy** | **43.75%** | 14 / 32 exact step-by-step match |
| **Sequence Accuracy** | **43.75%** | 14 / 32 exact phase and step ordering match |
| **Step Precision** | **82.78%** | Precision across predicted operations and resources |
| **Step Recall** | **77.20%** | Recall against ground truth steps |
| **Step F1-Score** | **79.89%** | Harmonic mean of step precision and recall |

### Field-Level Accuracy Breakdown

| Field Name | Accuracy | Analysis |
|---|---|---|
| **`phase`** | **100.00%** | Perfect phase partitioning (`FINDING` → `REMEDIATION` → `VERIFICATION`) |
| **`system_id`** | **88.27%** | High fidelity across `account_service`, `support_platform`, `analytics_platform`, `backup_service`, `integration_service`, and `security_service` |
| **`resource_id`** | **84.36%** | Accurate resolution of specific resource IDs via trace and identity links |
| **`operation`** | **87.15%** | Strict alignment with official operation precedence from problem statement §6.4 |
| **`state`** | **87.71%** | Exact alignment with required target states (`PRESENT`, `ABSENT`, `REDACTED`, `ANONYMIZED`, `ACTIVE`, `DISABLED`, `BLOCKED`) |
| **`evidence_id`** | **99.44%** | Grounded citation of participant-visible evidence files; empty string for future steps |

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
