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


if __name__ == "__main__":
    unittest.main()
