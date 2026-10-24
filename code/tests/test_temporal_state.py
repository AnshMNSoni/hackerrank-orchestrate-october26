"""
Unit tests for code/temporal_state.py.
Verifies state reconstruction across:
- Replication drift (account_service)
- Active vs disabled data flows (integration_service)
- Active restore risks vs blocked restores (backup_service)
- Account tombstones (identity_service)
- Retained security audit records (security_service)
- Support messages vs attachments (support_platform)
"""

import os
import sys
import unittest

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from code.evidence_indexer import EvidenceObservation
from code.temporal_state import TemporalStateReconstructor


class TestTemporalStateReconstructor(unittest.TestCase):
    def setUp(self):
        self.reconstructor = TemporalStateReconstructor()

    def test_replication_drift(self):
        # account_005: absent in primary, but present in failover replica
        obs = [
            EvidenceObservation(
                file_id="evidence_54",
                source_path="evidence/databases/customer_accounts_failover_replica_20260902.sql",
                captured_at="2026-09-02T23:00:00Z",
                record_time="2026-09-02T22:45:00Z",
                system_id="account_service",
                resource_id="account_005",
                resource_type="customer_profile",
                state_signal="PRESENT",
            ),
            EvidenceObservation(
                file_id="evidence_54",
                source_path="evidence/databases/customer_accounts_failover_replica_20260902.sql",
                captured_at="2026-09-02T23:00:00Z",
                record_time="2026-09-02T22:45:00Z",
                system_id="account_service",
                resource_id="account_005",
                resource_type="customer_profile",
                state_signal="ABSENT",
            ),
        ]
        states = self.reconstructor.reconstruct_states(obs, "user_05", "2026-09-08T13:40:00Z")
        self.assertIn("account_005", states)
        st = states["account_005"]
        self.assertEqual(st.state, "PRESENT")
        self.assertTrue(st.is_violation)
        self.assertEqual(st.violation_type, "REMAINING_RECORD")

    def test_active_data_flow(self):
        obs = [
            EvidenceObservation(
                file_id="evidence_01",
                source_path="evidence/logs/service_events_ap_south_20260915.log",
                captured_at="2026-09-15T11:59:39Z",
                record_time="2026-09-15T11:58:11Z",
                system_id="integration_service",
                resource_id="data_flow_9846",
                resource_type="data_flow",
                state_signal="ACTIVE",
            )
        ]
        states = self.reconstructor.reconstruct_states(obs, "user_15", "2026-09-15T12:00:00Z")
        st = states["data_flow_9846"]
        self.assertEqual(st.state, "ACTIVE")
        self.assertTrue(st.is_violation)
        self.assertEqual(st.violation_type, "ACTIVE_DATA_FLOW")

    def test_restore_risk(self):
        obs = [
            EvidenceObservation(
                file_id="evidence_93",
                source_path="evidence/databases/customer_data_inventory_20260916.sql",
                captured_at="2026-09-16T08:37:39Z",
                record_time="2026-09-16T07:59:54Z",
                system_id="backup_service",
                resource_id="backup_4978",
                resource_type="backup_archive",
                state_signal="ACTIVE",
            )
        ]
        states = self.reconstructor.reconstruct_states(obs, "user_61", "2026-09-16T09:00:00Z")
        st = states["backup_4978"]
        self.assertEqual(st.state, "ACTIVE")
        self.assertTrue(st.is_violation)
        self.assertEqual(st.violation_type, "RESTORE_RISK")

    def test_tombstone_redacted_vs_exposed(self):
        # Compliant tombstone (all direct PII null)
        clean_obs = [
            EvidenceObservation(
                file_id="evidence_51",
                source_path="evidence/records/customer_data_snapshot_bundle_20260915.json",
                captured_at="2026-09-15T12:00:00Z",
                record_time="2026-09-15T12:00:00Z",
                system_id="identity_service",
                resource_id="tombstone_440",
                resource_type="account_tombstone",
                state_signal="REDACTED",
                identifiers={"user_id": "user_541", "name": None, "email": None, "phone": None},
            )
        ]
        states_clean = self.reconstructor.reconstruct_states(clean_obs, "user_541", "2026-09-15T12:00:00Z")
        st_clean = states_clean["tombstone_440"]
        self.assertEqual(st_clean.state, "REDACTED")
        self.assertFalse(st_clean.is_violation)

        # Non-compliant tombstone (email still populated)
        dirty_obs = [
            EvidenceObservation(
                file_id="evidence_51",
                source_path="evidence/records/customer_data_snapshot_bundle_20260915.json",
                captured_at="2026-09-15T12:00:00Z",
                record_time="2026-09-15T12:00:00Z",
                system_id="identity_service",
                resource_id="tombstone_9178",
                resource_type="account_tombstone",
                state_signal="PRESENT",
                identifiers={"user_id": "user_542", "name": "Kofi Addo", "email": "addo.kofi@gmail.com"},
            )
        ]
        states_dirty = self.reconstructor.reconstruct_states(dirty_obs, "user_542", "2026-09-15T12:00:00Z")
        st_dirty = states_dirty["tombstone_9178"]
        self.assertEqual(st_dirty.state, "PRESENT")
        self.assertTrue(st_dirty.is_violation)
        self.assertEqual(st_dirty.violation_type, "EXPOSED_PII")

    def test_stale_snapshot_superseded_by_later_verified_absence(self):
        # Regression for cases 26/27/28: an older pre-deletion account snapshot
        # (recorded earlier than audit_at) must not keep the record alive once a
        # verified later readback (404 lookup) proves absence within its scope.
        obs = [
            EvidenceObservation(
                file_id="evidence_02",
                source_path="evidence/records/customer_data_snapshot_bundle_20260917.json",
                captured_at="2026-09-17T12:00:00Z",
                record_time="2026-09-09T12:00:00Z",
                system_id="account_service",
                resource_id="account_5684",
                resource_type="customer_profile",
                state_signal="PRESENT",
            ),
            EvidenceObservation(
                file_id="evidence_92",
                source_path="evidence/records/service_resource_export_20260915_114455.json",
                captured_at="2026-09-15T11:44:55Z",
                record_time="2026-09-15T09:01:48Z",
                system_id="account_service",
                resource_id="account_5684",
                resource_type="customer_profile",
                state_signal="ABSENT",
            ),
        ]
        states = self.reconstructor.reconstruct_states(obs, "user_26", "2026-09-15T12:00:00Z")
        st = states["account_5684"]
        self.assertEqual(st.state, "ABSENT")
        self.assertFalse(st.is_violation)
        # The supporting evidence must be the later verified readback
        self.assertEqual(st.supporting_file_id, "evidence_92")

    def test_same_time_conflict_stays_conservative(self):
        # A PRESENT/ABSENT conflict recorded at the same effective time cannot
        # prove removal; it stays a remaining record (conservative).
        obs = [
            EvidenceObservation(
                file_id="evidence_a",
                source_path="evidence/databases/customer_accounts_failover_replica_20260902.sql",
                captured_at="2026-09-02T23:00:00Z",
                record_time="2026-09-02T22:45:00Z",
                system_id="account_service",
                resource_id="account_123",
                resource_type="customer_profile",
                state_signal="PRESENT",
            ),
            EvidenceObservation(
                file_id="evidence_b",
                source_path="evidence/logs/resource_lookup_trace.log",
                captured_at="2026-09-02T23:00:00Z",
                record_time="2026-09-02T22:45:00Z",
                system_id="account_service",
                resource_id="account_123",
                resource_type="customer_profile",
                state_signal="ABSENT",
            ),
        ]
        states = self.reconstructor.reconstruct_states(obs, "user_05", "2026-09-08T13:40:00Z")
        st = states["account_123"]
        self.assertEqual(st.state, "PRESENT")
        self.assertTrue(st.is_violation)

    def test_support_redacted_text_is_not_exposed_pii(self):
        # '[REDACTED]' message text in a snapshot support conversation must not
        # be treated as exposed PII.
        from code.evidence_indexer import EvidenceIndexer
        import tempfile, json as jsonlib

        bundle = {
            "exported_at": "2026-09-17T12:00:00Z",
            "source": "records_assurance_service",
            "snapshots": [
                {
                    "captured_at": "2026-09-15T12:00:00Z",
                    "data_store": "support_platform",
                    "collection": "support_conversations",
                    "records": [
                        {
                            "resource_id": "support_9901",
                            "ticket_id": "CS-9990",
                            "subject_reference": "user_26",
                            "channel": "email",
                            "message_text": "[REDACTED]",
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            rel = os.path.join("evidence", "records")
            os.makedirs(os.path.join(tmp, rel), exist_ok=True)
            with open(os.path.join(tmp, rel, "customer_data_snapshot_bundle_20260917.json"), "w", encoding="utf-8") as f:
                jsonlib.dump(bundle, f)
            with open(os.path.join(tmp, "evidence_files.csv"), "w", encoding="utf-8") as f:
                f.write("file_id,file_path,origin,captured_at\n")
                f.write("evidence_T," + rel + "/customer_data_snapshot_bundle_20260917.json,records_assurance_snapshot_bundle,2026-09-17T12:00:00Z\n")
            indexer = EvidenceIndexer(tmp)
            matched = [o for o in indexer.obs_by_user_id.get("user_26", []) if o.resource_id == "support_9901"]
            self.assertTrue(matched, "subject-linked support record must be identity-indexed")
            self.assertEqual(matched[0].state_signal, "REDACTED")

            states = self.reconstructor.reconstruct_states(matched, "user_26", "2026-09-15T12:00:00Z")
            st = states["support_9901"]
            self.assertEqual(st.state, "REDACTED")
            self.assertFalse(st.is_violation)


if __name__ == "__main__":
    unittest.main()
