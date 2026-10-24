"""
Evaluation harness for Ghost Data Still Exists.
Compares predicted output CSV against ground truth CSV (e.g. sample_output.csv).
Computes:
- Case-level deletion-status accuracy
- Step-level precision, recall, F1, and field-level accuracy
- Sequence accuracy (order of steps)
- Detailed per-case failure analysis
"""

import csv
import json
import os
import sys
from typing import Any, Dict, List, Tuple


def parse_steps(steps_raw: Any) -> List[Dict[str, Any]]:
    if isinstance(steps_raw, list):
        return steps_raw
    if not steps_raw:
        return []
    try:
        return json.loads(steps_raw)
    except Exception:
        return []


def load_csv(csv_path: str) -> Dict[str, Dict[str, Any]]:
    cases = {}
    with open(csv_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            case_id = row["case_id"].strip()
            status = row["deletion_status"].strip()
            steps = parse_steps(row.get("steps_json", "[]"))
            cases[case_id] = {
                "case_id": case_id,
                "deletion_status": status,
                "steps": steps,
            }
    return cases


def evaluate_predictions(
    pred_path: str,
    truth_path: str,
    verbose: bool = True,
) -> Dict[str, Any]:
    preds = load_csv(pred_path)
    truths = load_csv(truth_path)

    total_cases = len(truths)
    if total_cases == 0:
        return {"error": "Empty ground truth file"}

    status_matches = 0
    exact_step_matches = 0
    sequence_matches = 0

    total_truth_steps = 0
    total_pred_steps = 0
    matched_steps = 0

    field_correct_counts = {
        "phase": 0,
        "system_id": 0,
        "resource_id": 0,
        "operation": 0,
        "state": 0,
        "evidence_id": 0,
    }
    field_total_counts = {k: 0 for k in field_correct_counts}

    mismatches = []

    for case_id, truth in sorted(truths.items()):
        pred = preds.get(case_id)
        if not pred:
            mismatches.append({
                "case_id": case_id,
                "error": "Missing from predictions",
                "truth_status": truth["deletion_status"],
            })
            continue

        truth_status = truth["deletion_status"]
        pred_status = pred["deletion_status"]
        status_ok = (truth_status == pred_status)
        if status_ok:
            status_matches += 1

        t_steps = truth["steps"]
        p_steps = pred["steps"]
        total_truth_steps += len(t_steps)
        total_pred_steps += len(p_steps)

        # Sequence match check (ordered list of operations & resource IDs)
        t_seq = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation")) for s in t_steps]
        p_seq = [(s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation")) for s in p_steps]
        seq_ok = (t_seq == p_seq)
        if seq_ok and status_ok:
            sequence_matches += 1

        # Step-level field alignment
        case_step_match = (len(t_steps) == len(p_steps))
        for idx in range(min(len(t_steps), len(p_steps))):
            ts = t_steps[idx]
            ps = p_steps[idx]
            all_fields_match = True
            for field in field_correct_counts:
                field_total_counts[field] += 1
                if ts.get(field) == ps.get(field):
                    field_correct_counts[field] += 1
                else:
                    all_fields_match = False
            if all_fields_match:
                matched_steps += 1
            else:
                case_step_match = False

        if len(t_steps) != len(p_steps):
            case_step_match = False

        if case_step_match and status_ok:
            exact_step_matches += 1
        elif not status_ok or not case_step_match or not seq_ok:
            mismatches.append({
                "case_id": case_id,
                "status_ok": status_ok,
                "truth_status": truth_status,
                "pred_status": pred_status,
                "truth_steps_count": len(t_steps),
                "pred_steps_count": len(p_steps),
                "truth_steps": t_steps,
                "pred_steps": p_steps,
            })

    status_acc = status_matches / total_cases if total_cases > 0 else 0.0
    exact_case_acc = exact_step_matches / total_cases if total_cases > 0 else 0.0
    seq_acc = sequence_matches / total_cases if total_cases > 0 else 0.0

    step_precision = matched_steps / total_pred_steps if total_pred_steps > 0 else 0.0
    step_recall = matched_steps / total_truth_steps if total_truth_steps > 0 else 0.0
    step_f1 = (
        2 * (step_precision * step_recall) / (step_precision + step_recall)
        if (step_precision + step_recall) > 0
        else 0.0
    )

    field_accs = {
        f: field_correct_counts[f] / field_total_counts[f]
        if field_total_counts[f] > 0
        else 0.0
        for f in field_correct_counts
    }

    report = {
        "total_cases": total_cases,
        "status_accuracy": status_acc,
        "exact_case_accuracy": exact_case_acc,
        "sequence_accuracy": seq_acc,
        "step_precision": step_precision,
        "step_recall": step_recall,
        "step_f1": step_f1,
        "field_accuracies": field_accs,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }

    if verbose:
        print("=" * 60)
        print("EVALUATION REPORT")
        print("=" * 60)
        print(f"Total Cases Evaluated: {total_cases}")
        print(f"Deletion Status Accuracy: {status_acc * 100:.2f}% ({status_matches}/{total_cases})")
        print(f"Exact Full-Case Accuracy: {exact_case_acc * 100:.2f}% ({exact_step_matches}/{total_cases})")
        print(f"Sequence Accuracy:        {seq_acc * 100:.2f}% ({sequence_matches}/{total_cases})")
        print(f"Step Precision / Recall:  {step_precision * 100:.2f}% / {step_recall * 100:.2f}% (F1: {step_f1 * 100:.2f}%)")
        print("-" * 60)
        print("Field-Level Accuracies:")
        for f, acc in field_accs.items():
            print(f"  - {f:12s}: {acc * 100:.2f}%")
        print("-" * 60)
        if mismatches:
            print(f"Mismatches ({len(mismatches)}):")
            for m in mismatches[:10]:
                cid = m["case_id"]
                if "error" in m:
                    print(f"  [{cid}] {m['error']}")
                else:
                    print(f"  [{cid}] Status: Pred={m['pred_status']} Truth={m['truth_status']} | Steps: Pred={m['pred_steps_count']} Truth={m['truth_steps_count']}")
            if len(mismatches) > 10:
                print(f"  ... and {len(mismatches) - 10} more.")
        else:
            print("ALL CASES MATCHED PERFECTLY!")
        print("=" * 60)

    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate Ghost Data Still Exists predictions")
    parser.add_argument("--pred", default="dataset/sample_output.csv", help="Path to prediction CSV")
    parser.add_argument("--truth", default="dataset/sample_output.csv", help="Path to ground truth CSV")
    args = parser.parse_args()

    evaluate_predictions(args.pred, args.truth)
