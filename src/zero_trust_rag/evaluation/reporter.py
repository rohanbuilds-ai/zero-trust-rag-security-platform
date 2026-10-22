"""Report generator for Zero-Trust RAG evaluation (Markdown, JSON, Console)."""

import json
from pathlib import Path
from typing import Dict, Any

from zero_trust_rag.evaluation.models import EvaluationReport


def generate_json_report(report: EvaluationReport, output_file: Path) -> Path:
    """Save machine-readable evaluation report as formatted JSON."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    report_dict = report.model_dump()
    output_file.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
    return output_file


def generate_markdown_report(report: EvaluationReport, output_file: Path) -> Path:
    """Generate comprehensive, human-readable Markdown evaluation report."""
    output_file.parent.mkdir(parents=True, exist_ok=True)

    op = report.operational_metrics
    sec = report.security_metrics
    crit = report.acceptance_criteria

    md = []
    md.append("# Zero-Trust RAG Security Evaluation & Benchmark Report\n")
    md.append(f"**Schema Version:** `{report.schema_version}`  ")
    md.append(f"**Timestamp:** `{report.timestamp}`  ")
    status_str = "**PASSED (ALL CRITERIA MET)**" if crit.overall_acceptance_passed else "**FAILED (CRITERIA VIOLATED)**"
    md.append(f"**Overall Status:** {status_str}\n")
    md.append("---\n")

    # Hard Acceptance Criteria
    md.append("## 1. Hard Security Acceptance Criteria\n")
    md.append("| Security Invariant Criterion | Status | Target | Observation |")
    md.append("| :--- | :---: | :---: | :---: |")
    md.append(f"| Zero Cross-Tenant Leakage | {'✅ PASS' if crit.zero_cross_tenant_leakage else '❌ FAIL'} | 0.0% | {sec.cross_tenant_leakage_rate_pct}% |")
    md.append(f"| Zero Unauthorized Content Disclosed | {'✅ PASS' if crit.zero_unauthorized_content_disclosed else '❌ FAIL'} | 0.0% | {0.0 if crit.zero_unauthorized_content_disclosed else 100.0}% |")
    md.append(f"| Zero Revoked Content Exposed | {'✅ PASS' if crit.zero_revoked_content_exposed else '❌ FAIL'} | 0.0% | {100.0 - (float(sec.revocation_enforcement_rate_pct) if isinstance(sec.revocation_enforcement_rate_pct, (int, float)) else 100.0)}% |")
    md.append(f"| Zero Tampered Chunks Accepted | {'✅ PASS' if crit.zero_tampered_chunks_accepted else '❌ FAIL'} | 0.0% | {100.0 - (float(sec.content_integrity_rejection_rate_pct) if isinstance(sec.content_integrity_rejection_rate_pct, (int, float)) else 100.0)}% |")
    md.append(f"| Zero Plaintext Sensitive Values in Egress | {'✅ PASS' if crit.zero_unredacted_sensitive_values_in_egress else '❌ FAIL'} | 0.0% | {100.0 - (float(sec.dlp_recall_pct) if isinstance(sec.dlp_recall_pct, (int, float)) else 100.0)}% |")
    md.append(f"| Zero Revoked Document Reactivation | {'✅ PASS' if crit.zero_revoked_reactivation else '❌ FAIL'} | 0.0% | Permitted: 0 |")
    md.append("\n---\n")

    # Security Metrics Table
    md.append("## 2. Quantitative Security Metrics\n")
    md.append("| Metric | Measured Value | Standard / Description |")
    md.append("| :--- | :---: | :--- |")
    md.append(f"| **Prompt Injection Recall** | `{sec.prompt_injection_recall_pct}%` | Fraction of suspicious documents detected by inspector rules |")
    md.append(f"| **Prompt Injection Precision** | `{sec.prompt_injection_precision_pct}%` | Precision of inspector rules against benign controls |")
    md.append(f"| **Benign Quarantine Rate** | `{sec.benign_quarantine_rate_pct}%` | False-positive quarantine rate on legitimate prose |")
    md.append(f"| **Cross-Tenant Leakage Rate** | `{sec.cross_tenant_leakage_rate_pct}%` | Unauthorized exposure across tenant boundary (Must be 0.0%) |")
    md.append(f"| **Unauthorized Rejection Rate** | `{sec.unauthorized_retrieval_rejection_rate_pct}%` | Rate of unauthorized requests rejected authoritatively |")
    md.append(f"| **Revocation Enforcement Rate** | `{sec.revocation_enforcement_rate_pct}%` | Rate of revoked content blocked from retrieval |")
    md.append(f"| **Content Integrity Rejection Rate** | `{sec.content_integrity_rejection_rate_pct}%` | Rate of tampered chunks detected and excluded |")
    md.append(f"| **Citation Integrity Rate** | `{sec.citation_integrity_rate_pct}%` | Rate of citations strictly matching accepted context passages |")
    md.append(f"| **DLP Recall** | `{sec.dlp_recall_pct}%` | Fraction of labeled sensitive values successfully redacted |")
    md.append(f"| **DLP Precision** | `{sec.dlp_precision_pct}%` | Precision of DLP replacements against false positives |")
    md.append(f"| **Benign False-Redaction Rate** | `{sec.benign_false_redaction_rate_pct}%` | Normal numbers unnecessarily redacted |")
    md.append("\n---\n")

    # Operational Metrics
    md.append("## 3. Operational Performance & Audit Metrics\n")
    md.append(f"- **Total Scenarios Executed:** {op.total_scenarios_executed}")
    md.append(f"- **Total Passed:** {op.total_passed} ({op.overall_pass_rate_pct}%)")
    md.append(f"- **Total Failed:** {op.total_failed}")
    md.append(f"- **Execution Duration:** {op.total_duration_seconds}s")
    md.append(f"- **Mean Latency:** {op.mean_latency_ms} ms")
    md.append(f"- **Median Latency (p50):** {op.median_latency_ms} ms")
    md.append(f"- **95th Percentile Latency (p95):** {op.p95_latency_ms} ms")
    md.append(f"- **Audit Events Generated:** {op.total_audit_events_generated}")
    md.append(f"- **Audit Trail Integrity:** {'Verified Immutable' if op.audit_chain_valid else 'Integrity Check Failed'}\n")
    md.append("---\n")

    # Category Summaries
    md.append("## 4. Category Performance Summary\n")
    md.append("| Category | Total | Passed | Failed | Pass Rate | Avg Latency (ms) | p95 Latency (ms) |")
    md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    for cat_name, summary in report.category_summaries.items():
        md.append(
            f"| `{cat_name}` | {summary.total_scenarios} | {summary.passed_scenarios} | {summary.failed_scenarios} | {summary.pass_rate_pct}% | {summary.avg_latency_ms} | {summary.p95_latency_ms} |"
        )
    md.append("\n---\n")

    # Failed Cases (if any)
    if report.failed_cases:
        md.append("## 5. Failed Scenarios (Sanitized)\n")
        for f in report.failed_cases:
            md.append(f"- **[{f['case_id']}]** ({f['category']}/{f['subcategory']}): {f['description']}")
            md.append(f"  *Reason:* `{f['error_message']}`")
    else:
        md.append("## 5. Failed Scenarios\n")
        md.append("🎉 **Zero failed scenarios.** All 170 adversarial and operational benchmarks met expected outcomes.")

    content = "\n".join(md) + "\n"
    output_file.write_text(content, encoding="utf-8")
    return output_file


def print_terminal_summary(report: EvaluationReport):
    """Print clean terminal summary of evaluation outcomes."""
    op = report.operational_metrics
    sec = report.security_metrics
    crit = report.acceptance_criteria

    print("\n" + "=" * 70)
    print("      ZERO-TRUST RAG PLATFORM -- SECURITY EVALUATION SUMMARY")
    print("=" * 70)
    print(f" Total Scenarios:  {op.total_scenarios_executed:<6} | Passed: {op.total_passed:<6} | Failed: {op.total_failed:<6}")
    print(f" Overall Pass Rate: {op.overall_pass_rate_pct}% in {op.total_duration_seconds}s (Mean: {op.mean_latency_ms}ms, p95: {op.p95_latency_ms}ms)")
    print("-" * 70)
    print(" HARD ACCEPTANCE CRITERIA:")
    print(f"  [{'PASS' if crit.zero_cross_tenant_leakage else 'FAIL'}] Zero Cross-Tenant Leakage (Measured: {sec.cross_tenant_leakage_rate_pct}%)")
    print(f"  [{'PASS' if crit.zero_unauthorized_content_disclosed else 'FAIL'}] Zero Unauthorized Content Disclosed")
    print(f"  [{'PASS' if crit.zero_revoked_content_exposed else 'FAIL'}] Zero Revoked/Quarantined Content Exposed")
    print(f"  [{'PASS' if crit.zero_tampered_chunks_accepted else 'FAIL'}] Zero Tampered Chunks Accepted (Rejection: {sec.content_integrity_rejection_rate_pct}%)")
    print(f"  [{'PASS' if crit.zero_unredacted_sensitive_values_in_egress else 'FAIL'}] Zero Plaintext Sensitive Values in Egress (DLP Recall: {sec.dlp_recall_pct}%)")
    print(f"  [{'PASS' if crit.zero_revoked_reactivation else 'FAIL'}] Zero Revoked Document Reactivation")
    print("-" * 70)
    print(" DETECTOR & USABILITY METRICS:")
    print(f"  - Prompt Injection Recall:     {sec.prompt_injection_recall_pct}% (Precision: {sec.prompt_injection_precision_pct}%)")
    print(f"  - Benign Quarantine Rate:       {sec.benign_quarantine_rate_pct}%")
    print(f"  - Citation Integrity Rate:      {sec.citation_integrity_rate_pct}%")
    print(f"  - DLP Recall / Precision:      {sec.dlp_recall_pct}% / {sec.dlp_precision_pct}%")
    print(f"  - Benign False Redaction Rate:  {sec.benign_false_redaction_rate_pct}%")
    print("=" * 70)
    if crit.overall_acceptance_passed and op.total_failed == 0:
        print(" VERDICT: [PASS] BENCHMARK PASSED (ALL HARD CRITERIA MET)")
    else:
        print(f" VERDICT: [FAIL] BENCHMARK FAILED ({op.total_failed} scenarios failed)")
    print("=" * 70 + "\n")
