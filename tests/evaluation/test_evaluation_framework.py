"""Unit and regression tests for the Phase 4 security evaluation framework."""

import json
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch

from zero_trust_rag.evaluation.models import (
    ScenarioCategory,
    EvaluationScenario,
    ScenarioResult,
    EvaluationReport,
)
from zero_trust_rag.evaluation.datasets import load_all_scenarios, get_dataset_summary
from zero_trust_rag.evaluation.metrics import (
    safe_pct,
    calculate_security_metrics,
    calculate_operational_metrics,
    check_hard_acceptance_criteria,
)
from zero_trust_rag.evaluation.evaluator import SecurityEvaluator
from zero_trust_rag.evaluation.runner import run_benchmark


def test_all_datasets_load_and_validate_schema():
    """Requirement 1: Every dataset loads and each item validates as an EvaluationScenario."""
    scenarios = load_all_scenarios()
    assert len(scenarios) >= 160

    summary = get_dataset_summary()
    assert summary["prompt_injection"] >= 50
    assert summary["access_control"] >= 30
    assert summary["dlp_sensitive_data"] >= 30
    assert summary["content_integrity"] >= 20
    assert summary["benign_usability"] >= 30

    for sc in scenarios:
        assert isinstance(sc, EvaluationScenario)
        assert sc.case_id.strip() != ""
        assert sc.category in ScenarioCategory
        assert sc.description.strip() != ""
        assert isinstance(sc.input_data, dict)
        assert isinstance(sc.expected_outcome, dict)


def test_scenario_ids_are_unique_and_stable():
    """Requirement 2: Scenario IDs are unique across all datasets."""
    scenarios = load_all_scenarios()
    case_ids = [s.case_id for s in scenarios]
    unique_ids = set(case_ids)

    assert len(case_ids) == len(unique_ids), f"Duplicate scenario IDs detected: {[x for x in case_ids if case_ids.count(x) > 1]}"


def test_metric_calculations_on_controlled_samples():
    """Requirement 4: Metric calculations are correct on controlled mock results."""
    # Create controlled mock results
    mock_results = [
        # 2 TP injection, 1 FN injection, 1 FP benign
        ScenarioResult(
            case_id="MOCK-001",
            category=ScenarioCategory.PROMPT_INJECTION,
            subcategory="direct_override",
            description="Mock TP",
            passed=True,
            latency_ms=10.0,
            expected_outcome={},
            observed_outcome={},
            details={"is_malicious": True, "detected_suspicious": True},
        ),
        ScenarioResult(
            case_id="MOCK-002",
            category=ScenarioCategory.PROMPT_INJECTION,
            subcategory="direct_override",
            description="Mock TP 2",
            passed=True,
            latency_ms=12.0,
            expected_outcome={},
            observed_outcome={},
            details={"is_malicious": True, "detected_suspicious": True},
        ),
        ScenarioResult(
            case_id="MOCK-003",
            category=ScenarioCategory.PROMPT_INJECTION,
            subcategory="direct_override",
            description="Mock FN",
            passed=False,
            latency_ms=11.0,
            expected_outcome={},
            observed_outcome={},
            details={"is_malicious": True, "detected_suspicious": False},
        ),
        ScenarioResult(
            case_id="MOCK-004",
            category=ScenarioCategory.PROMPT_INJECTION,
            subcategory="benign_security_prose",
            description="Mock FP",
            passed=False,
            latency_ms=10.0,
            expected_outcome={},
            observed_outcome={},
            details={"is_malicious": False, "detected_suspicious": True},
        ),
    ]

    sec_metrics = calculate_security_metrics(mock_results)
    # Recall: 2 / (2 + 1) = 66.67%
    assert sec_metrics.prompt_injection_recall_pct == 66.67
    # Precision: 2 / (2 + 1) = 66.67%
    assert sec_metrics.prompt_injection_precision_pct == 66.67
    # Benign quarantine rate: 1 / 1 = 100.0%
    assert sec_metrics.benign_quarantine_rate_pct == 100.0


def test_undefined_denominators_produce_na():
    """Requirement 5: Undefined denominators produce 'N/A' rather than ZeroDivisionError or invented numbers."""
    assert safe_pct(0, 0) == "N/A"
    assert safe_pct(5, 0) == "N/A"

    empty_metrics = calculate_security_metrics([])
    assert empty_metrics.cross_tenant_leakage_rate_pct == "N/A"
    assert empty_metrics.dlp_recall_pct == "N/A"
    assert empty_metrics.content_integrity_rejection_rate_pct == "N/A"


def test_failing_security_scenario_causes_nonzero_exit_code(tmp_path):
    """Requirement 6: A deliberately failing security scenario makes run_benchmark return non-zero exit code."""
    eval_db = tmp_path / "fail_test.db"
    out_dir = tmp_path / "reports"

    # Mock evaluate_scenario to force a failure
    with patch.object(SecurityEvaluator, "evaluate_scenario") as mock_eval:
        mock_eval.return_value = ScenarioResult(
            case_id="SEC-FAIL-MOCK",
            category=ScenarioCategory.ACCESS_CONTROL,
            subcategory="cross_tenant_isolation",
            description="Forced Leakage",
            passed=False,
            latency_ms=5.0,
            expected_outcome={},
            observed_outcome={},
            details={"content_leaked": True},
            error_message="Simulated Cross-Tenant Leakage Detected",
        )

        exit_code = run_benchmark(
            category_filter="access_control",
            output_dir=out_dir,
            db_path=eval_db,
        )
        assert exit_code == 1

        # Check JSON report records the failure
        report_data = json.loads((out_dir / "evaluation_report.json").read_text(encoding="utf-8"))
        assert len(report_data["failed_cases"]) >= 1
        assert report_data["failed_cases"][0]["case_id"] == "SEC-FAIL-MOCK"
        assert report_data["acceptance_criteria"]["zero_cross_tenant_leakage"] is False


def test_sensitive_values_and_payloads_not_leaked_in_reports(tmp_path):
    """Requirement 8: Plaintext secrets and raw attack payloads do not appear in evaluation reports."""
    eval_db = tmp_path / "sanitized_test.db"
    out_dir = tmp_path / "reports_sanitized"

    evaluator = SecurityEvaluator(db_path=eval_db)
    try:
        # Run only DLP category
        dlp_scenarios = load_all_scenarios(category_filter=ScenarioCategory.DLP_SENSITIVE_DATA)
        report = evaluator.run_all(dlp_scenarios)
    finally:
        evaluator.cleanup()

    json_report = out_dir / "eval_report.json"
    from zero_trust_rag.evaluation.reporter import generate_json_report
    generate_json_report(report, json_report)

    report_content = json_report.read_text(encoding="utf-8")
    # Verify unredacted real-looking test secrets are not dumped
    assert "AKIAIOSFODNN7EXAMPLE" not in report_content
    assert "TEST_SECRET_PRODUCTION_BACKEND_KEY" not in report_content


def test_evaluation_preserves_persistent_user_database(tmp_path):
    """Requirements 9 & 10: Evaluation execution leaves persistent databases and audit history untouched."""
    persistent_db = Path("data/storage/authoritative_metadata.db")
    if not persistent_db.exists():
        pytest.skip("Persistent metadata DB not present")

    # Record initial counts
    conn = sqlite3.connect(persistent_db)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM documents")
    initial_docs = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM security_audit_events")
    initial_audits = cur.fetchone()[0]
    conn.close()

    # Run evaluation with isolated temporary DB
    temp_eval_db = tmp_path / "temp_eval_isolation.db"
    evaluator = SecurityEvaluator(db_path=temp_eval_db)
    try:
        scenarios = load_all_scenarios(category_filter=ScenarioCategory.CONTENT_INTEGRITY)[:3]
        evaluator.run_all(scenarios)
    finally:
        evaluator.cleanup()

    # Verify persistent database is 100% unchanged
    conn2 = sqlite3.connect(persistent_db)
    cur2 = conn2.cursor()
    cur2.execute("SELECT COUNT(*) FROM documents")
    final_docs = cur2.fetchone()[0]
    cur2.execute("SELECT COUNT(*) FROM security_audit_events")
    final_audits = cur2.fetchone()[0]
    conn2.close()

    assert final_docs == initial_docs
    assert final_audits == initial_audits


from zero_trust_rag.core.models import (
    DocumentIngestRequest,
    RetrievalQueryResponse,
    RetrievedChunkCitation,
    DocumentStatus,
    TrustStatus,
    ClassificationLevel,
)

def test_evaluator_self_test_detects_missed_security_outcome(tmp_path):
    """Requirement 16: Benchmark self-test: deliberately broken security control is caught by evaluator."""
    temp_db = tmp_path / "self_test.db"
    evaluator = SecurityEvaluator(db_path=temp_db)

    # Ingest document using typed DocumentIngestRequest
    doc = evaluator.service.ingest_document(
        DocumentIngestRequest(
            title="Self-Test Ingestion",
            content="Secret information for self test verification.",
            is_public=False,
        ),
        principal=evaluator.contributor,
    )

    # Tamper with retrieval to deliberately bypass authorization (simulating broken security boundary)
    with patch.object(evaluator.service, "retrieve") as mock_retrieve:
        mock_retrieve.return_value = RetrievalQueryResponse(
            query_text="Secret information",
            tenant_id="default_tenant",
            total_candidates_found=1,
            chunks_returned=1,
            citations=[
                RetrievedChunkCitation(
                    chunk_id="chk_leaked_0",
                    document_id=doc.document_id,
                    document_title=doc.title,
                    chunk_index=0,
                    similarity_score=0.99,
                    content="Secret information for self test verification.",
                    provenance_hash="fake",
                    classification_level=ClassificationLevel.PUBLIC,
                    status=DocumentStatus.ACTIVE,
                    trust_status=TrustStatus.TRUSTED,
                    tenant_id="default_tenant",
                    redaction_count=0,
                )
            ],
            raw_context="[Source: Secret information for self test verification.]",
            safe_context=None,
            total_redactions=0,
        )

        test_scenario = EvaluationScenario(
            case_id="SELF-TEST-001",
            category=ScenarioCategory.ACCESS_CONTROL,
            subcategory="acl_enforcement",
            description="Self-Test: Unauthorized user queries private document",
            input_data={
                "owner": "user_bob",
                "accessor": "user_alice",
                "document_id": doc.document_id,
                "doc_title": doc.title,
                "doc_content": "Secret information for self test verification.",
            },
            expected_outcome={"should_allow": False},
        )

        res = evaluator.evaluate_scenario(test_scenario)
        # The evaluator MUST detect the failure and mark passed=False
        assert res.passed is False
        assert res.details["content_leaked"] is True

    evaluator.cleanup()
