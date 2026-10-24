"""
Unit and edge-case tests for system_activity correlation, trace isolation,
start-versus-completion semantics, cutoff enforcement, and duplicate handling.
"""

import os
import sys
import unittest

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from code.evidence_indexer import EvidenceIndexer, is_timestamp_le
from code.identity_resolver import IdentityResolver


class TestActivityCorrelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.indexer = EvidenceIndexer("dataset")
        cls.resolver = IdentityResolver("dataset/user_identities.csv", "dataset/user_audit_log.csv")

    def test_activity_ingestion_and_counts(self):
        # Verify system_activity.csv is loaded
        self.assertGreater(len(self.indexer.system_activities), 3000)

    def test_timestamp_cutoff_enforcement(self):
        # Event after cutoff must not be returned
        cutoff = "2026-08-01T00:00:00Z"
        # user_01 requested in mid August, so mid August activity must NOT be returned before Aug 1
        user = self.resolver.resolve_by_email("amina.elmasri@gmail.com")
        obs = self.indexer.query_observations_for_user(
            user_id=user.user_id,
            emails=user.all_emails,
            audit_at=cutoff,
            hashes=user.email_hashes,
        )
        self.assertEqual(len(obs), 0)

    def test_start_versus_completion_semantics(self):
        # Ensure _started events are not emitting PRESENT state signals
        # In evidence_94, line 18 is profile_lookup_started for account_7566
        # Only the completed lookup (status 404) should be indexed
        acc_obs = self.indexer.obs_by_resource_id.get("account_7566", [])
        for o in acc_obs:
            self.assertNotEqual(o.state_signal, "PRESENT", "profile_lookup_started must not emit PRESENT")

    def test_historical_identifier_correlation(self):
        # user_12 has historical email_hash 44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e
        user = self.resolver.resolve_by_email("minjun.kim@gmail.com")
        self.assertIn("44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e", user.email_hashes)
        obs = self.indexer.query_observations_for_user(
            user_id=user.user_id,
            emails=user.all_emails,
            audit_at="2026-09-15T12:00:00Z",
            hashes=user.email_hashes,
        )
        # Should link analytics_9914 via the historical hash
        found = any(o.resource_id == "analytics_9914" for o in obs)
        self.assertTrue(found, "Historical email hash must link analytics_9914")

    def test_trace_isolation_no_leakage(self):
        # Traces must keep user identifiers strictly isolated per trace
        # Test trace rb-085737-009 in evidence_94 contains l.fontaine46@yahoo.com
        # Verify it doesn't leak into other traces
        obs_7566 = [o for o in self.indexer.observations if o.resource_id == "account_7566"]
        self.assertGreater(len(obs_7566), 0)
        for o in obs_7566:
            if o.identifiers.get("email"):
                self.assertEqual(o.identifiers["email"], "l.fontaine46@yahoo.com")

    def test_resource_absent_from_snapshots(self):
        # account_001 is deleted and absent from snapshot evidence
        user = self.resolver.resolve_by_email("amina.elmasri@gmail.com")
        obs = self.indexer.query_observations_for_user(
            user_id=user.user_id,
            emails=user.all_emails,
            audit_at="2026-09-03T11:30:00Z",
            hashes=user.email_hashes,
            requested_at="2026-08-18T09:14:00Z",
            reported_at="2026-08-20T16:42:00Z",
            reported_status="COMPLETE",
        )
        found_acc = [o for o in obs if o.resource_id == "account_001"]
        self.assertEqual(len(found_acc), 1)
        self.assertEqual(found_acc[0].state_signal, "ABSENT")


if __name__ == "__main__":
    unittest.main()
