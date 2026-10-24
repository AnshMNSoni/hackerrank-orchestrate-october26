"""
Remediation Planner for Ghost Data Still Exists.
Consumes CaseEvaluationResult from PolicyEngine and synthesizes the exact
ordered list of steps according to the official problem statement contract:
1. Strict phase ordering: FINDING -> REMEDIATION -> VERIFICATION.
2. Official operation precedence within each phase.
3. Secondary sorting: ascending system_id, then ascending resource_id.
4. Consecutive 1-indexed step_no numbering.
5. Strict evidence citation rules (empty string for proposed/future steps in INCOMPLETE cases).
"""

from typing import Any, Dict, List

from code.policy_engine import CaseEvaluationResult, PlannedStep

# Official operation precedence rankings from problem_statement.md §101
FINDING_PRECEDENCE = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
}

REMEDIATION_PRECEDENCE = {
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
}

VERIFICATION_PRECEDENCE = {
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}


class RemediationPlanner:
    def __init__(self):
        pass

    def plan_steps(self, eval_result: CaseEvaluationResult) -> List[Dict[str, Any]]:
        if eval_result.status == "NOT_APPLICABLE":
            return []

        all_steps: List[PlannedStep] = []

        if eval_result.status == "COMPLETE":
            # For COMPLETE cases, include ONLY verification steps
            sorted_verifs = self._sort_steps(eval_result.verifications, VERIFICATION_PRECEDENCE)
            all_steps.extend(sorted_verifs)
        else:
            # For INCOMPLETE cases: FINDING -> REMEDIATION -> VERIFICATION
            sorted_findings = self._sort_steps(eval_result.findings, FINDING_PRECEDENCE)
            sorted_remediations = self._sort_steps(eval_result.remediations, REMEDIATION_PRECEDENCE)
            sorted_verifications = self._sort_steps(eval_result.verifications, VERIFICATION_PRECEDENCE)

            all_steps.extend(sorted_findings)
            all_steps.extend(sorted_remediations)
            all_steps.extend(sorted_verifications)

        # De-duplicate steps having identical (phase, system_id, resource_id, operation)
        seen_keys = set()
        deduped: List[PlannedStep] = []
        for s in all_steps:
            k = (s.phase, s.system_id, s.resource_id, s.operation)
            if k not in seen_keys:
                seen_keys.add(k)
                deduped.append(s)

        # Serialize into exact schema with consecutive step numbering
        output_steps: List[Dict[str, Any]] = []
        for idx, s in enumerate(deduped, start=1):
            # In INCOMPLETE cases, remediation and verification use empty evidence_id
            ev_id = s.evidence_id
            if eval_result.status == "INCOMPLETE" and s.phase in ("REMEDIATION", "VERIFICATION"):
                ev_id = ""

            step_dict = {
                "step_no": idx,
                "phase": s.phase,
                "system_id": s.system_id,
                "resource_id": s.resource_id,
                "operation": s.operation,
                "state": s.state,
                "evidence_id": ev_id,
            }
            output_steps.append(step_dict)

        return output_steps

    def _sort_steps(
        self,
        steps: List[PlannedStep],
        precedence_map: Dict[str, int],
    ) -> List[PlannedStep]:
        return sorted(
            steps,
            key=lambda s: (
                precedence_map.get(s.operation, 99),
                s.system_id,
                s.resource_id,
            ),
        )
