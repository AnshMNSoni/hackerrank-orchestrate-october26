"""
Policy Engine for Ghost Data Still Exists.
Evaluates user request text for deletion authorization (or NOT_APPLICABLE).
Applies deletion_rules.csv to each ResourceTemporalState to determine:
- Findings (violations & recreation risks)
- Required remediation actions
- Post-remediation and compliant verification checks
- Overall deletion status: COMPLETE, INCOMPLETE, or NOT_APPLICABLE
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from code.temporal_state import ResourceTemporalState


@dataclass
class PlannedStep:
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


@dataclass
class CaseEvaluationResult:
    case_id: str
    status: str  # COMPLETE, INCOMPLETE, NOT_APPLICABLE
    is_deletion_authorized: bool
    findings: List[PlannedStep] = field(default_factory=list)
    remediations: List[PlannedStep] = field(default_factory=list)
    verifications: List[PlannedStep] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = rules_path

    def is_deletion_authorized(self, request_text: str) -> bool:
        """
        Determines whether request_text authorizes deletion.
        Requests strictly for data export, access, rectification, or marketing opt-out
        without requesting account deletion/erasure/closure are NOT_APPLICABLE.
        """
        if not request_text:
            return False

        txt = request_text.strip().lower()

        # Explicit non-deletion requests
        if "keep the account" in txt or "do not delete" in txt:
            return False

        # Multilingual deletion verbs
        deletion_signals = [
            "delet", "eras", "clos", "remov", "supprim", "eliminar",
            "lösch", "effac", "cancelar", "cancella", "削除", "消去", "smazat", "usuni"
        ]
        has_deletion_intent = any(sig in txt for sig in deletion_signals)

        # Non-deletion keywords (export/access/opt-out)
        non_deletion_keywords = [
            "download my account information", "access my data", "copy of my data",
            "export my data only", "marketing opt-out", "update my phone only"
        ]
        has_non_deletion = any(k in txt for k in non_deletion_keywords)

        if has_non_deletion and not has_deletion_intent:
            return False

        return True

    def evaluate_case(
        self,
        case_id: str,
        request_text: str,
        resource_states: Dict[str, ResourceTemporalState],
    ) -> CaseEvaluationResult:
        # 1. Intent check
        if not self.is_deletion_authorized(request_text):
            return CaseEvaluationResult(
                case_id=case_id,
                status="NOT_APPLICABLE",
                is_deletion_authorized=False,
                findings=[],
                remediations=[],
                verifications=[],
            )

        findings: List[PlannedStep] = []
        remediations: List[PlannedStep] = []
        verifications: List[PlannedStep] = []

        has_violations = any(st.is_violation for st in resource_states.values())
        overall_status = "INCOMPLETE" if has_violations else "COMPLETE"

        for res_id, st in resource_states.items():
            sys_id = st.system_id
            ev_id = st.supporting_file_id

            # Active Data Flow
            if st.resource_type == "data_flow" or sys_id == "integration_service":
                if st.is_violation:
                    findings.append(
                        PlannedStep(
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_ACTIVE_DATA_FLOW",
                            state="ACTIVE",
                            evidence_id=ev_id,
                        )
                    )
                    remediations.append(
                        PlannedStep(
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="DISABLE_DATA_FLOW",
                            state="DISABLED",
                            evidence_id="",
                        )
                    )
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_DATA_FLOW_DISABLED",
                            state="DISABLED",
                            evidence_id="",
                        )
                    )
                else:
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_DATA_FLOW_DISABLED",
                            state="DISABLED",
                            evidence_id=ev_id if overall_status == "COMPLETE" else "",
                        )
                    )

            # Backup Restore Risk
            elif st.resource_type == "backup_archive" or sys_id == "backup_service":
                if st.is_violation:
                    findings.append(
                        PlannedStep(
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_RESTORE_RISK",
                            state="ACTIVE",
                            evidence_id=ev_id,
                        )
                    )
                    remediations.append(
                        PlannedStep(
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="BLOCK_RESTORE",
                            state="BLOCKED",
                            evidence_id="",
                        )
                    )
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RESTORE_BLOCKED",
                            state="BLOCKED",
                            evidence_id="",
                        )
                    )
                else:
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RESTORE_BLOCKED",
                            state="BLOCKED",
                            evidence_id=ev_id if overall_status == "COMPLETE" else "",
                        )
                    )

            # Account Tombstone
            elif st.resource_type == "account_tombstone" or sys_id == "identity_service":
                if st.is_violation:
                    findings.append(
                        PlannedStep(
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=ev_id,
                        )
                    )
                    remediations.append(
                        PlannedStep(
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REDACT_RECORD",
                            state="REDACTED",
                            evidence_id="",
                        )
                    )
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_REDACTED",
                            state="REDACTED",
                            evidence_id="",
                        )
                    )
                else:
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_REDACTED",
                            state="REDACTED",
                            evidence_id=ev_id if overall_status == "COMPLETE" else "",
                        )
                    )

            # Retained Security Audit Log
            elif st.resource_type == "security_audit_record" or sys_id == "security_service":
                verifications.append(
                    PlannedStep(
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=res_id,
                        operation="VERIFY_RECORD_PRESENT",
                        state="PRESENT",
                        evidence_id=ev_id if overall_status == "COMPLETE" else "",
                    )
                )

            # Analytics Profiles (Anonymize rule)
            elif st.resource_type == "analytics_profile" or sys_id == "analytics_platform":
                if st.is_violation:
                    findings.append(
                        PlannedStep(
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=ev_id,
                        )
                    )
                    remediations.append(
                        PlannedStep(
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="ANONYMIZE_RECORD",
                            state="ANONYMIZED",
                            evidence_id="",
                        )
                    )
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ANONYMIZED",
                            state="ANONYMIZED",
                            evidence_id="",
                        )
                    )
                else:
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ANONYMIZED",
                            state="ANONYMIZED",
                            evidence_id=ev_id if overall_status == "COMPLETE" else "",
                        )
                    )

            # Support Records (Redact conversation vs Delete attachment)
            elif st.resource_type in ("support_record", "support_conversation", "support_attachment") or sys_id == "support_platform":
                if st.resource_type == "support_attachment":
                    # Attachments belong only to subject -> DELETE
                    if st.is_violation:
                        findings.append(
                            PlannedStep(
                                phase="FINDING",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="REPORT_REMAINING_RECORD",
                                state="PRESENT",
                                evidence_id=ev_id,
                            )
                        )
                        remediations.append(
                            PlannedStep(
                                phase="REMEDIATION",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="DELETE_RECORD",
                                state="ABSENT",
                                evidence_id="",
                            )
                        )
                        verifications.append(
                            PlannedStep(
                                phase="VERIFICATION",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="VERIFY_RECORD_ABSENT",
                                state="ABSENT",
                                evidence_id="",
                            )
                        )
                    else:
                        verifications.append(
                            PlannedStep(
                                phase="VERIFICATION",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="VERIFY_RECORD_ABSENT",
                                state="ABSENT",
                                evidence_id=ev_id if overall_status == "COMPLETE" else "",
                            )
                        )
                else:
                    # Conversation messages with shared context -> REDACT
                    if st.is_violation:
                        findings.append(
                            PlannedStep(
                                phase="FINDING",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="REPORT_EXPOSED_PII",
                                state="PRESENT",
                                evidence_id=ev_id,
                            )
                        )
                        remediations.append(
                            PlannedStep(
                                phase="REMEDIATION",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="REDACT_RECORD",
                                state="REDACTED",
                                evidence_id="",
                            )
                        )
                        verifications.append(
                            PlannedStep(
                                phase="VERIFICATION",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="VERIFY_RECORD_REDACTED",
                                state="REDACTED",
                                evidence_id="",
                            )
                        )
                    else:
                        verifications.append(
                            PlannedStep(
                                phase="VERIFICATION",
                                system_id=sys_id,
                                resource_id=res_id,
                                operation="VERIFY_RECORD_REDACTED",
                                state="REDACTED",
                                evidence_id=ev_id if overall_status == "COMPLETE" else "",
                            )
                        )

            # Standard Records (Account profiles, Search documents, Exports -> DELETE)
            else:
                if st.is_violation:
                    findings.append(
                        PlannedStep(
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=ev_id,
                        )
                    )
                    remediations.append(
                        PlannedStep(
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="DELETE_RECORD",
                            state="ABSENT",
                            evidence_id="",
                        )
                    )
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ABSENT",
                            state="ABSENT",
                            evidence_id="",
                        )
                    )
                else:
                    verifications.append(
                        PlannedStep(
                            phase="VERIFICATION",
                            system_id=sys_id,
                            resource_id=res_id,
                            operation="VERIFY_RECORD_ABSENT",
                            state="ABSENT",
                            evidence_id=ev_id if overall_status == "COMPLETE" else "",
                        )
                    )

        return CaseEvaluationResult(
            case_id=case_id,
            status=overall_status,
            is_deletion_authorized=True,
            findings=findings,
            remediations=remediations,
            verifications=verifications,
        )
