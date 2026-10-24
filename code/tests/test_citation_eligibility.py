"""
Regression tests for the citation-eligibility enforcement pass (AGENTS.md
sections 6.2 / 6.6): no step may cite an evidence file captured after the
case's audit_at, and findings supported only by such a file must instead cite
an eligible pre-audit system activity for the same resource.
"""

import csv
import os
import sys
import unittest
from types import SimpleNamespace

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from code.main import DeletionAuditAgent
from code.evidence_indexer import is_timestamp_le


AUDIT_AT = "2026-07-03T08:00:00Z"


def make_agent(evidence_files, system_activities):
    """Build an agent with a stubbed indexer (no dataset load)."""
    agent = DeletionAuditAgent.__new__(DeletionAuditAgent)
    agent.evidence_indexer = SimpleNamespace(
        evidence_files=evidence_files,
        system_activities=system_activities,
    )
    return agent


def make_agent_from_real_dataset():
    """Agent backed by the real dataset (integration-level assertions)."""
    return DeletionAuditAgent("dataset")


class TestCitationEligibility(unittest.TestCase):
    def _finding(self, ev="evidence_post", op="REPORT_REMAINING_RECORD", res="account_1"):
        return {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": res,
            "operation": op,
            "state": "PRESENT",
            "evidence_id": ev,
        }

    def test_failed_delete_activity_substitutes_for_post_capture_file(self):
        # A finding whose only supporting file was captured after audit_at
        # must cite the eligible pre-audit FAILED delete activity instead.
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_10", "event_time": "2026-07-01T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "FAILED",
                 "resource_id": "account_1", "details": "delete attempt failed"},
            ],
        )
        steps = [self._finding()]
        out = agent._apply_citation_eligibility(steps, AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "activity_10")

    def test_partial_delete_activity_also_eligible(self):
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_11", "event_time": "2026-07-02T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "PARTIAL",
                 "resource_id": "account_1", "details": ""},
            ],
        )
        out = agent._apply_citation_eligibility([self._finding()], AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "activity_11")

    def test_success_delete_activity_never_substitutes_a_finding(self):
        # A SUCCESS delete is a claim that nothing remains and can never
        # support a remaining-record finding.
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_12", "event_time": "2026-07-01T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "SUCCESS",
                 "resource_id": "account_1", "details": ""},
            ],
        )
        out = agent._apply_citation_eligibility([self._finding()], AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "evidence_post")

    def test_activity_after_audit_at_is_not_eligible(self):
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_13", "event_time": "2026-07-03T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "FAILED",
                 "resource_id": "account_1", "details": ""},
            ],
        )
        out = agent._apply_citation_eligibility([self._finding()], AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "evidence_post")

    def test_activity_for_different_resource_is_not_substituted(self):
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_14", "event_time": "2026-07-01T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "FAILED",
                 "resource_id": "account_999", "details": ""},
            ],
        )
        out = agent._apply_citation_eligibility([self._finding()], AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "evidence_post")

    def test_pre_audit_cited_file_is_untouched(self):
        agent = make_agent(
            evidence_files={
                "evidence_ok": SimpleNamespace(file_id="evidence_ok", file_path="p", origin="o",
                                               captured_at="2026-07-01T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_15", "event_time": "2026-07-01T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "FAILED",
                 "resource_id": "account_1", "details": ""},
            ],
        )
        out = agent._apply_citation_eligibility([self._finding(ev="evidence_ok")], AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "evidence_ok")

    def test_verification_steps_are_never_swapped(self):
        # Verifications are not rewritten: a SUCCESS activity is a claim, not
        # proof of final state; verifications keep their containing citation.
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_16", "event_time": "2026-07-01T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "SUCCESS",
                 "resource_id": "account_1", "details": ""},
            ],
        )
        step = self._finding(ev="evidence_post")
        step["phase"] = "VERIFICATION"
        step["operation"] = "VERIFY_RECORD_ABSENT"
        step["state"] = "ABSENT"
        out = agent._apply_citation_eligibility([step], AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "evidence_post")

    def test_no_steps_or_empty_audit_at_is_noop(self):
        agent = make_agent(evidence_files={}, system_activities=[])
        self.assertEqual(agent._apply_citation_eligibility([], AUDIT_AT), [])
        steps = [self._finding()]
        self.assertEqual(agent._apply_citation_eligibility(steps, ""), steps)

    def test_case_126_finding_cites_activity_3114_from_real_dataset(self):
        # Integration regression: the real case_126 finding must cite the
        # eligible pre-audit activity (DELETE FAILED, 2026-08-05) rather than
        # evidence_12, whose manifest capture (2026-08-19) is after audit_at.
        agent = make_agent_from_real_dataset()
        steps = [
            self._finding(ev="evidence_12", res="account_8819"),
        ]
        out = agent._apply_citation_eligibility(steps, "2026-08-17T10:00:00Z")
        self.assertEqual(out[0]["evidence_id"], "activity_3114")

    def test_real_step_3114_is_pre_audit_failed_delete(self):
        agent = make_agent_from_real_dataset()
        act = [a for a in agent.evidence_indexer.system_activities
               if a["activity_id"] == "activity_3114"][0]
        self.assertEqual(act["event_type"], "DELETE_RECORD")
        self.assertEqual(act["reported_result"], "FAILED")
        self.assertEqual(act["resource_id"], "account_8819")
        self.assertTrue(is_timestamp_le(act["event_time"], "2026-08-17T10:00:00Z"))

    def _verif(self, ev, res, op="VERIFY_RECORD_ABSENT", state="ABSENT"):
        return {
            "step_no": 1,
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": res,
            "operation": op,
            "state": state,
            "evidence_id": ev,
        }

    # --- citable-witness preference for COMPLETE-case verifications ---

    def test_absent_verification_prefers_same_case_citable_citation(self):
        # A verification citing a post-audit-captured file must be re-pointed
        # to the citable file the same case already cites (the same subject's
        # citable audit-dossier witness). No case id logic.
        obs_post = SimpleNamespace(record_time=None, captured_at="2026-07-02T00:00:00Z", file_id="evidence_post")
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
                "evidence_witness": SimpleNamespace(file_id="evidence_witness", file_path="p2", origin="o2",
                                                    captured_at="2026-07-03T07:00:00Z"),
            },
            system_activities=[],
        )
        steps = [
            self._verif("evidence_post", "account_1"),
            self._verif("evidence_witness", "audit_record_1", op="VERIFY_RECORD_PRESENT", state="PRESENT"),
        ]
        out = agent._apply_citation_eligibility(steps, AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "evidence_witness")
        self.assertEqual(out[1]["evidence_id"], "evidence_witness")

    def test_absent_verification_falls_back_to_subject_scoped_citable_file(self):
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
                "evidence_a": SimpleNamespace(file_id="evidence_a", file_path="p2", origin="o2",
                                              captured_at="2026-07-03T07:00:00Z"),
                "evidence_b_late": SimpleNamespace(file_id="evidence_b_late", file_path="p3", origin="o3",
                                                   captured_at="2026-07-06T07:00:00Z"),
            },
            system_activities=[],
        )
        agent.evidence_indexer.obs_by_user_id = {
            "user_9": [SimpleNamespace(record_time="2026-07-03T05:00:00Z",
                                       captured_at="2026-07-03T07:00:00Z", file_id="evidence_a"),
                       SimpleNamespace(record_time="2026-07-03T05:00:00Z",
                                       captured_at="2026-07-06T07:00:00Z", file_id="evidence_b_late")],
        }
        agent.evidence_indexer.obs_by_email = {}
        agent.evidence_indexer.obs_by_hash = {}
        steps = [self._verif("evidence_post", "account_2")]
        out = agent._apply_citation_eligibility(
            steps, AUDIT_AT, user_id="user_9", emails=["u9@example.com"], hashes=["h9"],
            observations=[],
        )
        self.assertEqual(out[0]["evidence_id"], "evidence_a")

    def test_absent_verification_without_citable_candidate_is_unchanged(self):
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[],
        )
        agent.evidence_indexer.obs_by_user_id = {}
        agent.evidence_indexer.obs_by_email = {}
        agent.evidence_indexer.obs_by_hash = {}
        steps = [self._verif("evidence_post", "account_3")]
        out = agent._apply_citation_eligibility(
            steps, AUDIT_AT, user_id="user_8", emails=["u8@example.com"], hashes=[],
            observations=[],
        )
        self.assertEqual(out[0]["evidence_id"], "evidence_post")

    def test_citable_verification_is_never_touched(self):
        agent = make_agent(
            evidence_files={
                "evidence_ok": SimpleNamespace(file_id="evidence_ok", file_path="p", origin="o",
                                               captured_at="2026-07-01T07:00:00Z"),
                "evidence_other": SimpleNamespace(file_id="evidence_other", file_path="p2", origin="o2",
                                                  captured_at="2026-07-02T07:00:00Z"),
            },
            system_activities=[],
        )
        steps = [
            self._verif("evidence_ok", "account_4"),
            self._verif("evidence_other", "audit_record_4", op="VERIFY_RECORD_PRESENT", state="PRESENT"),
        ]
        out = agent._apply_citation_eligibility(steps, AUDIT_AT)
        self.assertEqual(out[0]["evidence_id"], "evidence_ok")
        self.assertEqual(out[1]["evidence_id"], "evidence_other")

    def test_success_and_partial_delete_claims_never_become_verification_citations(self):
        agent = make_agent(
            evidence_files={
                "evidence_post": SimpleNamespace(file_id="evidence_post", file_path="p", origin="o",
                                                 captured_at="2026-07-05T07:00:00Z"),
            },
            system_activities=[
                {"activity_id": "activity_20", "event_time": "2026-07-01T09:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "SUCCESS",
                 "resource_id": "account_5", "details": ""},
                {"activity_id": "activity_21", "event_time": "2026-07-01T10:00:00Z",
                 "event_type": "DELETE_RECORD", "reported_result": "PARTIAL",
                 "resource_id": "account_5", "details": ""},
            ],
        )
        agent.evidence_indexer.obs_by_user_id = {}
        agent.evidence_indexer.obs_by_email = {}
        agent.evidence_indexer.obs_by_hash = {}
        steps = [self._verif("evidence_post", "account_5")]
        out = agent._apply_citation_eligibility(
            steps, AUDIT_AT, user_id="user_7", emails=["u7@example.com"], hashes=[],
            observations=[],
        )
        self.assertEqual(out[0]["evidence_id"], "evidence_post")

    def test_real_case_70_absent_citation_becomes_evidence_93(self):
        agent = make_agent_from_real_dataset()
        steps = [
            self._verif("evidence_06", "account_6633"),
            self._verif("evidence_93", "audit_record_1738", op="VERIFY_RECORD_PRESENT", state="PRESENT"),
        ]
        out = agent._apply_citation_eligibility(
            steps, "2026-09-16T09:00:00Z", user_id="user_68",
            emails=["collins.grace@icloud.com"], hashes=["90d09f3df13df7c987633adf915ab5624896522461d8ec7c3aae5e8164670686"],
            observations=[],
        )
        self.assertEqual(out[0]["evidence_id"], "evidence_93")
        self.assertEqual(out[1]["evidence_id"], "evidence_93")

    def test_real_case_215_absent_citation_becomes_evidence_81(self):
        agent = make_agent_from_real_dataset()
        steps = [
            self._verif("evidence_21", "account_1956"),
            self._verif("evidence_81", "audit_record_1718", op="VERIFY_RECORD_PRESENT", state="PRESENT"),
        ]
        out = agent._apply_citation_eligibility(
            steps, "2026-07-03T08:00:00Z", user_id="user_213",
            emails=["nils-lindberg@proton.me"], hashes=["ab0e7ffacd95eac905fff1e4dc3ee2db8c0eed4636d1381ca6e7af29202ff761"],
            observations=[],
        )
        self.assertEqual(out[0]["evidence_id"], "evidence_81")
        self.assertEqual(out[1]["evidence_id"], "evidence_81")

    def test_real_end_to_end_audit_case_70_and_215(self):
        agent = make_agent_from_real_dataset()
        rows = {r["case_id"]: r for r in csv.DictReader(
            open("dataset/deletion_requests.csv", encoding="utf-8-sig"))}
        for cid, want_ev in (("case_70", "evidence_93"), ("case_215", "evidence_81")):
            cid_out, status, steps = agent.audit_case(rows[cid])
            self.assertEqual(cid_out, cid)
            self.assertEqual(status, "COMPLETE", cid)
            absent_steps = [s for s in steps if s["operation"] == "VERIFY_RECORD_ABSENT"]
            self.assertEqual(len(absent_steps), 1, cid)
            self.assertEqual(absent_steps[0]["evidence_id"], want_ev, cid)
            for s in steps:
                self.assertNotEqual(s["evidence_id"], "evidence_06")
                self.assertNotEqual(s["evidence_id"], "evidence_21")


if __name__ == "__main__":
    unittest.main()
