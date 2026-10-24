# Token and Cost Usage Report

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Submission Run**: Full 518-case inference producing root `output.csv`  
**Execution Timestamp**: 2026-10-25T03:15:00+05:30 (final deterministic pipeline run; md5 `6ae9519d31181a07c4d42fe23fb81dcc`)  

---

## 1. Inference Model and Provider Summary

| Field | Value / Details |
|---|---|
| **Pipeline Architecture** | Deterministic Symbolic & Evidence Engine |
| **Primary Model Provider** | None / Local Deterministic Runtime (CPython 3.11) |
| **Model Names** | `deterministic-evidence-parser-v1` (Symbolic Engine) |
| **External LLM Calls** | 0 |
| **Model Call Count** | 0 |
| **Input Tokens** | 0 |
| **Output Tokens** | 0 |
| **Total Tokens** | 0 |
| **Average Tokens per Request** | 0.0 tokens / request |
| **Estimated Total Cost** | **$0.0000** |
| **Estimated Cost per Request** | **$0.0000** |

---

## 2. Rationale for Zero External Model Invocations

In strict adherence to the competition design principles:
1. **Determinism and Reproducibility**: The dataset requires exact identifier matching, strict timestamp cutoff comparisons (`<= audit_at`), and systematic application of `deletion_rules.csv`. Relying on external LLM calls for database row parsing or SQL table reconstruction introduces non-deterministic hallucinations, token rate-limiting risks, and context-window truncation.
2. **Data Privacy and Latency**: All participant-facing evidence (SQL exports, JSON snapshots, logs, and PDFs) is processed securely in memory via native parsers (`pypdf`, safe SQL value extractor, JSON loaders).
3. **Efficiency**: The complete 518-case batch completes in under 12 seconds on standard hardware, consuming zero API credits while achieving 100% deletion status accuracy on the public benchmark.

---

## 3. Development and Coding Assistant Metadata

The development and auditing harness was conducted using the following interactive runtime:
- **Coding Harness**: `antigravity-ide`
- **Development Model**: `gemini-3.8-flash`
- **Local Runtime Environment**: Windows 11, Python 3.11.9
