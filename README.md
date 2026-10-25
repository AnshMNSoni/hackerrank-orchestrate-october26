# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.

### Setup

Requirements: Python 3.10+ (standard library only; no mandatory dependencies).

Optional but recommended for full PDF evidence parsing:

```bash
pip install pypdf
```

Without `pypdf` the pipeline still runs, but PDF evidence attachments degrade to no extraction.

### Run the full audit (518 cases → `output.csv`)

From the repository root:

```bash
python code/main.py --dataset dataset --input dataset/deletion_requests.csv --output output.csv
```

This produces the root-level `output.csv` with 518 sorted data rows (header: `case_id,deletion_status,steps_json`). The pipeline is fully deterministic and makes no network calls.

Other useful commands:

```bash
# Audit only the 32 public sample cases
python code/main.py --dataset dataset --input dataset/sample_deletion_requests.csv --output sample_pred_audit.csv

# Run the unit tests (36 tests)
python -m pytest code/tests -q --ignore=code/tests/validate_submission_output.py

# Validate the submission output.csv (row count, schema, JSON, ordering)
python code/tests/validate_submission_output.py

# Evaluate predictions against the sample ground truth
python code/evaluation/evaluator.py --pred sample_pred_audit.csv --truth dataset/sample_output.csv
```

## Solution Architecture

The pipeline in `code/` is deterministic and evidence-grounded:

1. **Identity resolution** (`identity_resolver.py`) — resolves current and historical identifiers (emails, SHA-256 hashes, phones) from `user_identities.csv` and `user_audit_log.csv`.
2. **Evidence indexing** (`evidence_indexer.py`) — parses SQL snapshot exports, JSON bundles, logs, PDFs, and `system_activity.csv` into observations with strict temporal cutoffs (`captured_at <= audit_at`).
3. **Temporal reconstruction** (`temporal_state.py`) — builds the resource state at `audit_at`, filtering out operation-start events and later evidence.
4. **Policy evaluation** (`policy_engine.py`) — classifies intent from `request_text` and applies `deletion_rules.csv`, including tombstone redact/anonymize/retain semantics.
5. **Step planning** (`remediation_planner.py`) — emits findings, ordered remediation, and verification steps in the required `FINDING → REMEDIATION → VERIFICATION` order.
6. **Citation-eligibility enforcement** (`main.py::_apply_citation_eligibility`) — enforces the written temporal citation rules on the final planned steps (see *Approach Overview* below).

## Approach Overview

The agent answers each case by reconstructing *what was true at `audit_at`* from participant-visible evidence only — never from reported statuses, and never from evidence that became available after the audit cutoff.

**Pipeline flow per case**

1. **Intent gate (NOT_APPLICABLE)** — `request_text` is classified for deletion authorization. Access, correction, export, or marketing opt-out requests are `NOT_APPLICABLE` with empty steps, even when other fields resemble a deletion case.
2. **Identity resolution** — the request email may be a historical address. The resolver merges the current identity snapshot (`user_identities.csv`) with the change history (`user_audit_log.csv`) into the live `user_id` plus the set of all historical emails, phones, and SHA-256 email hashes, so evidence recorded under any prior identifier is linked.
3. **Effective-time evidence gate** — every evidence observation is admitted only if its file was captured at or before `audit_at` **and** its embedded record/event time is at or before `audit_at`. Manifest capture time (`captured_at`) and effective state time (`record_time`) are treated as distinct axes.
4. **Temporal reconciliation** — for each resource linked to the subject (accounts, audit records, support records, search indexes, analytics profiles, exports, connectors, backups), the newest admitted observation wins within the same resource scope; same-time PRESENT/ABSENT conflicts resolve conservatively (presence-heavy); identical subject–collection observations captured at different times merge longitudinally so a resource linked by means of multiple files remains reachable.
5. **Policy application** — `deletion_rules.csv` maps each data category to its required treatment: `DELETE`, `REDACT` (direct identifiers removed, stable reference preserved — account tombstones), `ANONYMIZE`, or `RETAIN`. A violation is a resource whose reconstructed state differs from its required treatment.
6. **Status decision** — `INCOMPLETE` when any policy violation or recreation risk (active data flow / restorable backup) remains at `audit_at`; `COMPLETE` only when every relevant copy has its required treatment, every retained record remains available, and no flow can recreate prohibited data.
7. **Step planning and citation enforcement** — findings, ordered remediation (`DISABLE_DATA_FLOW`/`BLOCK_RESTORE` before record-level action; downstream copies before sources), and verification steps are emitted with consecutive numbering; then `_apply_citation_eligibility` enforces the citation rules below.

**Evidence semantics — claims versus proof**

- `system_activity.csv` rows (workflow claims such as `DELETE_RECORD … SUCCESS/FAILED/PARTIAL`) and reported statuses are **claims, not proof** of final state; they corroborate but never alone establish it.
- Records themselves (SQL snapshots, bundles, readback logs, support/redaction records, inventories) are the state-defining evidence. A scope-witness snapshot that lists the subject's retention records while showing no remaining subject rows is valid absence evidence.

**Citation rules (spec §6.2/§6.6 semantics)**

- No step may cite an evidence file whose manifest capture is after `audit_at`, and no post-audit activity may support a decision.
- `INCOMPLETE` cases: findings cite the participant-visible `file_id`/`activity_id`/`audit_id` that proves them; when the only supporting file was post-audit-captured, the finding cites the eligible pre-audit `activity_id` of a `FAILED`/`PARTIAL` delete on the same resource (`SUCCESS` claims are never substituted). Proposed remediation and future verification steps carry empty `evidence_id`.
- `COMPLETE` cases (all steps are `VERIFICATION`): the citation must be non-empty and must prove the compliant state at `audit_at`. When a step cites a post-audit-captured file, a **citable-witness preference** re-points it — deterministically — first to a citable file the same case already cites, else to the lowest-`file_id` citable file carrying an effective-time observation for the same subject. Activity claims are never used as verification citations and resource states are never altered by this pass.

**Determinism and cost**

Standard library only (`pypdf` optional), no LLM/network calls, fixed ordering everywhere (`FINDING → REMEDIATION → VERIFICATION`, then operation precedence, `system_id`, `resource_id`), stable JSON serialization. Re-running the full 518-case audit reproduces `output.csv` byte-identically (final run md5 `ff731eba2ba04021a96374c6f7d11545`).

**Verified results snapshot** (36/36 unit tests; deterministic re-runs; submission validator passes all 518 rows):

| Metric (32 public cases) | Value |
| --- | --- |
| Deletion-status accuracy | **100.00%** (32/32) |
| Exact full-case accuracy | **50.00%** (16/32) |
| Sequence accuracy | **50.00%** (16/32) |
| Step precision / recall / F1 | 86.41% / 82.38% / **84.35%** |
| Status distribution (518 cases) | INCOMPLETE 298 · COMPLETE 219 · NOT_APPLICABLE 1 |

Temporal integrity is audited end-to-end: zero steps across all 518 outputs cite evidence captured after `audit_at` or post-audit activity ids. Full details, custom evaluation cases, and the token/cost breakdown are in `code/evaluation/evaluation_report.md` and `code/evaluation/usage_report.md`.

## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.
