"""Data models and schemas for the Zero-Trust RAG security evaluation framework."""

from enum import Enum
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field


class ScenarioCategory(str, Enum):
    """Evaluation corpus categories."""
    PROMPT_INJECTION = "prompt_injection"
    ACCESS_CONTROL = "access_control"
    DLP_SENSITIVE_DATA = "dlp_sensitive_data"
    CONTENT_INTEGRITY = "content_integrity"
    BENIGN_USABILITY = "benign_usability"


class EvaluationScenario(BaseModel):
    """
    Specification of a single adversarial or usability benchmark scenario.
    Every scenario has a stable identifier, category, description,
    input data/fixtures, expected outcome, and validation attributes.
    """
    case_id: str
    category: ScenarioCategory
    subcategory: str
    description: str
    input_data: Dict[str, Any]
    expected_outcome: Dict[str, Any]
    tags: List[str] = Field(default_factory=list)


class ScenarioResult(BaseModel):
    """Execution result and empirical observations for a single scenario."""
    case_id: str
    category: ScenarioCategory
    subcategory: str
    description: str
    passed: bool
    latency_ms: float
    expected_outcome: Dict[str, Any]
    observed_outcome: Dict[str, Any]
    details: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


class CategoryMetricSummary(BaseModel):
    """Summary metrics for a specific evaluation category."""
    category: ScenarioCategory
    total_scenarios: int
    passed_scenarios: int
    failed_scenarios: int
    pass_rate_pct: float
    avg_latency_ms: float
    p95_latency_ms: float
    metrics: Dict[str, Union[float, str]]


class SecurityMetrics(BaseModel):
    """Formal security metrics with explicit numerators and denominators."""
    # Prompt Injection & Inspection
    prompt_injection_recall_pct: Union[float, str]
    prompt_injection_precision_pct: Union[float, str]
    benign_quarantine_rate_pct: Union[float, str]

    # Access Control & Isolation
    cross_tenant_leakage_rate_pct: Union[float, str]
    unauthorized_retrieval_rejection_rate_pct: Union[float, str]
    revocation_enforcement_rate_pct: Union[float, str]

    # Content Integrity & Isolation
    content_integrity_rejection_rate_pct: Union[float, str]
    citation_integrity_rate_pct: Union[float, str]

    # DLP & Secret Scrubbing
    dlp_recall_pct: Union[float, str]
    dlp_precision_pct: Union[float, str]
    benign_false_redaction_rate_pct: Union[float, str]


class OperationalMetrics(BaseModel):
    """Operational and performance metrics for the benchmark run."""
    total_scenarios_executed: int
    total_passed: int
    total_failed: int
    overall_pass_rate_pct: float
    total_duration_seconds: float
    mean_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    total_audit_events_generated: int
    audit_chain_valid: bool


class HardAcceptanceCriteria(BaseModel):
    """Hard security criteria required for passing the benchmark."""
    zero_cross_tenant_leakage: bool
    zero_unauthorized_content_disclosed: bool
    zero_revoked_content_exposed: bool
    zero_tampered_chunks_accepted: bool
    zero_unredacted_sensitive_values_in_egress: bool
    zero_revoked_reactivation: bool
    overall_acceptance_passed: bool


class EvaluationReport(BaseModel):
    """Complete machine-readable evaluation report."""
    schema_version: str = "1.0.0"
    timestamp: str
    environment: Dict[str, str]
    operational_metrics: OperationalMetrics
    security_metrics: SecurityMetrics
    acceptance_criteria: HardAcceptanceCriteria
    category_summaries: Dict[str, CategoryMetricSummary]
    scenario_results: List[ScenarioResult]
    failed_cases: List[Dict[str, Any]]
