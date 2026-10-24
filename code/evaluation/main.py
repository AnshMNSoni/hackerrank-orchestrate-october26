"""
Entry point for evaluating Ghost Data Still Exists predictions and generating report.
"""

import os
import sys

# Ensure repository root is in sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from code.evaluation.evaluator import evaluate_predictions


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run evaluation and generate evaluation_report.md")
    parser.add_argument(
        "--pred",
        default="dataset/sample_output.csv",
        help="Path to predictions CSV file",
    )
    parser.add_argument(
        "--truth",
        default="dataset/sample_output.csv",
        help="Path to ground truth CSV file",
    )
    parser.add_argument(
        "--output-report",
        default="code/evaluation/evaluation_report.md",
        help="Path to write evaluation report markdown",
    )
    args = parser.parse_args()

    results = evaluate_predictions(args.pred, args.truth, verbose=True)


if __name__ == "__main__":
    main()
