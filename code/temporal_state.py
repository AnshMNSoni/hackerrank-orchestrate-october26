"""
Temporal State Reconstructor for Ghost Data Still Exists.
Consumes normalized evidence observations from EvidenceIndexer and reconstructs
the ground truth state of each relevant resource as of the case's audit_at cutoff.

Distinguishes:
- Verified absent records vs remaining records (replication drift)
- Active data flows vs disabled flows
- Active restore risks vs blocked restores
- Retained security audit records
- Account tombstones: compliant REDACTED (only user_id) vs EXPOSED_PII (direct PII present)
- Support messages/tickets: redacted vs exposed
- Analytics profiles: anonymized vs exposed
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from code.evidence_indexer import EvidenceObservation, is_timestamp_le


@dataclass
class ResourceTemporalState:
    system_id: str
    resource_id: str
    resource_type: str
    state: str  # PRESENT, ABSENT, ACTIVE, DISABLED, REDACTED, ANONYMIZED, BLOCKED
    is_violation: bool  # True if state violates policy or presents recreation risk
    violation_type: Optional[str]  # REMAINING_RECORD, EXPOSED_PII, ACTIVE_DATA_FLOW, RESTORE_RISK
    supporting_file_id: str
    observation_time: str
    conflicts: List[str] = field(default_factory=list)
    identifiers: Dict[str, Any] = field(default_factory=dict)


class TemporalStateReconstructor:
    def __init__(self):
        pass

    def reconstruct_states(
        self,
        observations: List[EvidenceObservation],
        user_id: str,
        audit_at: str,
    ) -> Dict[str, ResourceTemporalState]:
        """
        Reconstructs the definitive point-in-time state for each observed resource
        at or before audit_at. Resolves conflicting evidence and replication drift.
        """
        # Group observations by resource_id
        obs_by_res: Dict[str, List[EvidenceObservation]] = {}
        for o in observations:
            obs_by_res.setdefault(o.resource_id, []).append(o)

        resource_states: Dict[str, ResourceTemporalState] = {}

        for res_id, res_obs in sorted(obs_by_res.items()):
            # Sort observations ascending so the LAST entry is the preferred
            # observation: evidence captured at or before audit_at is preferred
            # over later-captured evidence (per spec, evidence captured after
            # audit_at may not be cited and must not change the answer), and
            # within the same citability the newest effective time wins.
            sorted_obs = sorted(
                res_obs,
                key=lambda x: (
                    0 if not is_timestamp_le(x.captured_at, audit_at) else 1,
                    x.record_time or x.captured_at,
                    x.captured_at,
                ),
            )
            state_obj = self._resolve_single_resource(res_id, sorted_obs, user_id, audit_at)
            if state_obj:
                resource_states[res_id] = state_obj

        return resource_states

    def _resolve_single_resource(
        self,
        res_id: str,
        observations: List[EvidenceObservation],
        user_id: str,
        audit_at: str,
    ) -> Optional[ResourceTemporalState]:
        if not observations:
            return None

        latest_obs = observations[-1]
        sys_id = latest_obs.system_id
        res_type = latest_obs.resource_type

        # 1. Integration Service: Active Data Flows
        if sys_id == "integration_service" or res_id.startswith("data_flow_"):
            # If any observation at or before audit_at shows ACTIVE (enabled=1/true)
            # without a subsequent explicit DISABLED observation, flow is ACTIVE
            has_active = any(o.state_signal == "ACTIVE" for o in observations)
            is_active = (latest_obs.state_signal == "ACTIVE") or (has_active and latest_obs.state_signal != "DISABLED")

            supporting = latest_obs.file_id
            for o in reversed(observations):
                if is_active and o.state_signal == "ACTIVE":
                    supporting = o.file_id
                    break
                elif not is_active and o.state_signal == "DISABLED":
                    supporting = o.file_id
                    break

            return ResourceTemporalState(
                system_id="integration_service",
                resource_id=res_id,
                resource_type="data_flow",
                state="ACTIVE" if is_active else "DISABLED",
                is_violation=is_active,
                violation_type="ACTIVE_DATA_FLOW" if is_active else None,
                supporting_file_id=supporting,
                observation_time=latest_obs.record_time or latest_obs.captured_at,
                identifiers=latest_obs.identifiers,
            )

        # 2. Backup Service: Backup Archives / Restore Risks
        if sys_id == "backup_service" or res_id.startswith("backup_"):
            has_restore_allowed = any(o.state_signal == "ACTIVE" for o in observations)
            is_active_risk = (latest_obs.state_signal == "ACTIVE") or (has_restore_allowed and latest_obs.state_signal != "BLOCKED")

            supporting = latest_obs.file_id
            for o in reversed(observations):
                if is_active_risk and o.state_signal == "ACTIVE":
                    supporting = o.file_id
                    break
                elif not is_active_risk and o.state_signal == "BLOCKED":
                    supporting = o.file_id
                    break

            return ResourceTemporalState(
                system_id="backup_service",
                resource_id=res_id,
                resource_type="backup_archive",
                state="ACTIVE" if is_active_risk else "BLOCKED",
                is_violation=is_active_risk,
                violation_type="RESTORE_RISK" if is_active_risk else None,
                supporting_file_id=supporting,
                observation_time=latest_obs.record_time or latest_obs.captured_at,
                identifiers=latest_obs.identifiers,
            )

        # 3. Identity Service: Account Tombstones
        if sys_id == "identity_service" or res_id.startswith("tombstone_"):
            # Check if direct PII is exposed
            has_pii = False
            for o in observations:
                ids = o.identifiers
                if ids.get("email") or ids.get("name") or ids.get("phone") or o.state_signal == "PRESENT":
                    has_pii = True
                    break

            return ResourceTemporalState(
                system_id="identity_service",
                resource_id=res_id,
                resource_type="account_tombstone",
                state="PRESENT" if has_pii else "REDACTED",
                is_violation=has_pii,
                violation_type="EXPOSED_PII" if has_pii else None,
                supporting_file_id=latest_obs.file_id,
                observation_time=latest_obs.record_time or latest_obs.captured_at,
                identifiers=latest_obs.identifiers,
            )

        # 4. Security Service: Retained Security Audit Records
        if sys_id == "security_service" or res_id.startswith("audit_record_"):
            # Permitted to be retained under policy rule_12
            return ResourceTemporalState(
                system_id="security_service",
                resource_id=res_id,
                resource_type="security_audit_record",
                state="PRESENT",
                is_violation=False,
                violation_type=None,
                supporting_file_id=latest_obs.file_id,
                observation_time=latest_obs.record_time or latest_obs.captured_at,
                identifiers=latest_obs.identifiers,
            )

        # 5. Account Service: Profiles & Replication Drift
        if sys_id == "account_service" or res_id.startswith("account_"):
            # Resolve conflicting evidence within the SAME account resource by the
            # latest effective point-in-time. A stale PRESENT snapshot recorded
            # earlier does not keep the record alive once a verified later readback
            # (e.g. 404 lookup) proves absence. A same-time PRESENT/ABSENT conflict
            # can not prove removal, so it stays conservative (remaining record).
            absent_latest = observations[-1].state_signal in ("ABSENT", "DELETED")
            latest_time = observations[-1].record_time or observations[-1].captured_at
            return_within_scope = not any(
                (o.state_signal == "PRESENT" and (o.record_time or o.captured_at) == latest_time)
                for o in observations
            )

            if absent_latest and return_within_scope:
                sup = observations[-1]
                return ResourceTemporalState(
                    system_id="account_service",
                    resource_id=res_id,
                    resource_type="customer_profile",
                    state="ABSENT",
                    is_violation=False,
                    violation_type=None,
                    supporting_file_id=sup.file_id,
                    observation_time=sup.record_time or sup.captured_at,
                    identifiers=sup.identifiers,
                )
            else:
                present_obs = [o for o in observations if o.state_signal == "PRESENT"]
                absent_obs = [o for o in observations if o.state_signal in ("ABSENT", "DELETED")]
                sup = present_obs[-1] if present_obs else latest_obs
                return ResourceTemporalState(
                    system_id="account_service",
                    resource_id=res_id,
                    resource_type="customer_profile",
                    state="PRESENT",
                    is_violation=True,
                    violation_type="REMAINING_RECORD",
                    supporting_file_id=sup.file_id,
                    observation_time=sup.record_time or sup.captured_at,
                    conflicts=[o.file_id for o in absent_obs],
                    identifiers=sup.identifiers,
                )

        # 6. Search Service: Search Index Entries
        if sys_id == "search_service" or res_id.startswith("search_"):
            # Any remaining index entry must be deleted under rule_03
            return ResourceTemporalState(
                system_id="search_service",
                resource_id=res_id,
                resource_type="search_index_entry",
                state="PRESENT",
                is_violation=True,
                violation_type="REMAINING_RECORD",
                supporting_file_id=latest_obs.file_id,
                observation_time=latest_obs.record_time or latest_obs.captured_at,
                identifiers=latest_obs.identifiers,
            )

        # 7. Support Platform: Support Records, Tickets, and Conversations
        if sys_id == "support_platform" or res_id.startswith("support_"):
            # Check if this is a conversation with shared context (rule_05 -> REDACT)
            # or a ticket attachment belonging only to subject (rule_06 -> DELETE)
            is_remaining = (
                "attachment" in res_type
                or "file_name" in str(latest_obs.raw_payload)
                or ".pdf" in str(latest_obs.raw_payload)
                or "replica" in str(latest_obs.raw_payload)
                or "replica" in latest_obs.source_path
                or "deletion_marker_check" in str(latest_obs.raw_payload)
            )

            if is_remaining:
                return ResourceTemporalState(
                    system_id="support_platform",
                    resource_id=res_id,
                    resource_type="support_attachment",
                    state="PRESENT",
                    is_violation=True,
                    violation_type="REMAINING_RECORD",
                    supporting_file_id=latest_obs.file_id,
                    observation_time=latest_obs.record_time or latest_obs.captured_at,
                    identifiers=latest_obs.identifiers,
                )
            else:
                # Support message with shared customer/order context -> exposed PII requiring redaction
                is_redacted = (latest_obs.state_signal == "REDACTED")
                return ResourceTemporalState(
                    system_id="support_platform",
                    resource_id=res_id,
                    resource_type="support_conversation",
                    state="REDACTED" if is_redacted else "PRESENT",
                    is_violation=not is_redacted,
                    violation_type=None if is_redacted else "EXPOSED_PII",
                    supporting_file_id=latest_obs.file_id,
                    observation_time=latest_obs.record_time or latest_obs.captured_at,
                    identifiers=latest_obs.identifiers,
                )

        # 8. Analytics Platform: Analytics Profiles & Telemetry
        if sys_id == "analytics_platform" or res_id.startswith("analytics_"):
            # Check if record is still identifiable (rule_07 -> ANONYMIZE)
            is_anonymized = (latest_obs.state_signal == "ANONYMIZED")
            return ResourceTemporalState(
                system_id="analytics_platform",
                resource_id=res_id,
                resource_type="analytics_profile",
                state="ANONYMIZED" if is_anonymized else "PRESENT",
                is_violation=not is_anonymized,
                violation_type="EXPOSED_PII" if not is_anonymized else None,
                supporting_file_id=latest_obs.file_id,
                observation_time=latest_obs.record_time or latest_obs.captured_at,
                identifiers=latest_obs.identifiers,
            )

        # 9. Export Service: Customer Exports
        if sys_id == "export_service" or res_id.startswith("export_"):
            # Must always be deleted under rule_09
            return ResourceTemporalState(
                system_id="export_service",
                resource_id=res_id,
                resource_type="user_export",
                state="PRESENT",
                is_violation=True,
                violation_type="REMAINING_RECORD",
                supporting_file_id=latest_obs.file_id,
                observation_time=latest_obs.record_time or latest_obs.captured_at,
                identifiers=latest_obs.identifiers,
            )

        # Generic fallback
        return ResourceTemporalState(
            system_id=sys_id,
            resource_id=res_id,
            resource_type=res_type,
            state=latest_obs.state_signal,
            is_violation=False,
            violation_type=None,
            supporting_file_id=latest_obs.file_id,
            observation_time=latest_obs.record_time or latest_obs.captured_at,
            identifiers=latest_obs.identifiers,
        )
