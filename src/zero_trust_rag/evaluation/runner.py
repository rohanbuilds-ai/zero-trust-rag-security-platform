"""Command-line entry point and runner for Zero-Trust RAG security evaluations."""

import sys
import argparse
from pathlib import Path
from typing import Optional

from zero_trust_rag.evaluation.models import ScenarioCategory
from zero_trust_rag.evaluation.datasets import load_all_scenarios
from zero_trust_rag.evaluation.evaluator import SecurityEvaluator
from zero_trust_rag.evaluation.reporter import (
    generate_json_report,
    generate_markdown_report,
    print_terminal_summary,
)


def run_benchmark(
    category_filter: Optional[str] = None,
    output_dir: Optional[Path] = None,
    db_path: Optional[Path] = None,
) -> int:
    """
    Execute security benchmark suite, output reports, and return exit code.
    Returns 0 on complete success, 1 if any hard security criteria fail.
    """
    cat_enum = None
    if category_filter:
        try:
            cat_enum = ScenarioCategory(category_filter.lower())
        except ValueError:
            print(f"Error: Unknown category '{category_filter}'. Valid choices: {[c.value for c in ScenarioCategory]}")
            return 2

    scenarios = load_all_scenarios(category_filter=cat_enum)
    print(f"\n[+] Loaded {len(scenarios)} evaluation scenarios (Category filter: {category_filter or 'ALL'}).")
    print("[+] Initializing isolated evaluation service environment...")

    evaluator = SecurityEvaluator(db_path=db_path)
    try:
        report = evaluator.run_all(scenarios)
    finally:
        evaluator.cleanup()

    # Generate reports
    if output_dir is None:
        output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "evaluation_report.json"
    md_path = output_dir / "evaluation_report.md"

    generate_json_report(report, json_path)
    generate_markdown_report(report, md_path)

    print_terminal_summary(report)
    print(f"[+] Saved JSON report to:     {json_path}")
    print(f"[+] Saved Markdown report to: {md_path}\n")

    # Hard acceptance check
    if report.acceptance_criteria.overall_acceptance_passed and report.operational_metrics.total_failed == 0:
        return 0
    return 1


def main():
    parser = argparse.ArgumentParser(description="Zero-Trust RAG Security Platform Evaluation Suite")
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Run only scenarios from a specific category (prompt_injection, access_control, dlp_sensitive_data, content_integrity, benign_usability)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory where evaluation JSON and Markdown reports will be written (default: reports/)"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Optional path to isolated evaluation SQLite database. If omitted, uses temporary directory."
    )

    args = parser.parse_args()
    exit_code = run_benchmark(
        category_filter=args.category,
        output_dir=Path(args.output_dir),
        db_path=Path(args.db_path) if args.db_path else None,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
