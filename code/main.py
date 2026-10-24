"""
Main entry point for Ghost Data Still Exists Deletion-Audit Agent.
Executes the full pipeline:
1. Identity Resolution (IdentityResolver)
2. Evidence Indexing & Temporal Cutoff Filtering (EvidenceIndexer)
3. Point-in-Time State Reconstruction (TemporalStateReconstructor)
4. Policy Application & Intent Checking (PolicyEngine)
5. Deterministic Remediation & Verification Planning (RemediationPlanner)
6. Serializes predictions to CSV matching official schema.
"""

import csv
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is in sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from code.evidence_indexer import EvidenceIndexer
from code.identity_resolver import IdentityResolver
from code.policy_engine import PolicyEngine
from code.remediation_planner import RemediationPlanner
from code.temporal_state import TemporalStateReconstructor


class DeletionAuditAgent:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        print("Initializing DeletionAuditAgent...")
        print("  Loading Identity Resolver...")
        self.identity_resolver = IdentityResolver(
            os.path.join(dataset_dir, "user_identities.csv"),
            os.path.join(dataset_dir, "user_audit_log.csv"),
        )
        print("  Indexing Evidence Files...")
        self.evidence_indexer = EvidenceIndexer(dataset_dir)
        print(f"  Indexed {len(self.evidence_indexer.observations)} evidence observations.")
        self.temporal_reconstructor = TemporalStateReconstructor()
        self.policy_engine = PolicyEngine()
        self.remediation_planner = RemediationPlanner()
        print("Initialization complete.")

    def audit_case(self, case_row: Dict[str, str]) -> Tuple[str, str, List[Dict[str, Any]]]:
        case_id = case_row["case_id"].strip()
        email = case_row.get("email", "").strip()
        requested_at = case_row.get("requested_at", "").strip()
        reported_at = case_row.get("reported_at", "").strip()
        reported_status = case_row.get("reported_status", "").strip()
        audit_at = case_row.get("audit_at", "").strip()
        request_text = case_row.get("request_text", "").strip()

        # 1. Intent check
        if not self.policy_engine.is_deletion_authorized(request_text):
            return case_id, "NOT_APPLICABLE", []

        # 2. Identity resolution
        user = self.identity_resolver.resolve_by_email(email)
        if not user:
            # Fallback if email not found
            return case_id, "NOT_APPLICABLE", []

        # 3. Query observations at or before audit_at
        observations = self.evidence_indexer.query_observations_for_user(
            user_id=user.user_id,
            emails=user.all_emails,
            audit_at=audit_at,
            hashes=user.email_hashes,
            requested_at=requested_at,
            reported_at=reported_at,
            reported_status=reported_status,
        )

        # 4. Temporal state reconstruction
        resource_states = self.temporal_reconstructor.reconstruct_states(
            observations=observations,
            user_id=user.user_id,
            audit_at=audit_at,
        )

        # 5. Policy evaluation
        eval_result = self.policy_engine.evaluate_case(
            case_id=case_id,
            request_text=request_text,
            resource_states=resource_states,
        )

        # 6. Remediation & verification planning
        steps = self.remediation_planner.plan_steps(eval_result)

        return case_id, eval_result.status, steps

    def run_csv(self, input_csv_path: str, output_csv_path: str):
        print(f"Processing requests from: {input_csv_path}")
        results = []

        with open(input_csv_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            cases = list(reader)

        total = len(cases)
        for i, row in enumerate(cases, start=1):
            cid, status, steps = self.audit_case(row)
            steps_json_str = json.dumps(steps, separators=(",", ":"))
            results.append({
                "case_id": cid,
                "deletion_status": status,
                "steps_json": steps_json_str,
            })
            if i % 50 == 0 or i == total:
                print(f"  Processed {i}/{total} cases...")

        # Sort strictly by case_id
        results.sort(key=lambda r: r["case_id"])

        # Write output CSV
        with open(output_csv_path, mode="w", encoding="utf-8", newline="") as f:
            fieldnames = ["case_id", "deletion_status", "steps_json"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)

        print(f"Successfully generated {len(results)} rows to: {output_csv_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run Ghost Data Still Exists audit agent")
    parser.add_argument("--dataset", default="dataset", help="Dataset directory")
    parser.add_argument(
        "--input",
        default="dataset/sample_deletion_requests.csv",
        help="Input CSV file (e.g. sample_deletion_requests.csv or deletion_requests.csv)",
    )
    parser.add_argument(
        "--output",
        default="sample_output_pred.csv",
        help="Output CSV file path",
    )
    args = parser.parse_args()

    agent = DeletionAuditAgent(args.dataset)
    agent.run_csv(args.input, args.output)


if __name__ == "__main__":
    main()
