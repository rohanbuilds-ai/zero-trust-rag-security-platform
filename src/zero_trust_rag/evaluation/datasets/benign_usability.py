"""Benign retrieval, usability, and operational accuracy evaluation dataset (30+ scenarios)."""

from typing import List
from zero_trust_rag.evaluation.models import EvaluationScenario, ScenarioCategory


def get_benign_usability_scenarios() -> List[EvaluationScenario]:
    """
    Returns 32 distinct synthetic usability, operational retrieval, and business document scenarios.
    Covers technical architecture, finance, incident response, HR policies, engineering specs,
    search recall, candidate refill under access control filtering, and source attribution accuracy.
    """
    scenarios: List[EvaluationScenario] = []

    business_cases = [
        # Technical & Architecture Documentation
        ("USAB-001", "tech_arch_overview", "Zero-Trust Architecture Guidelines: System components authenticate at every transaction boundary.", "zero trust architecture guidelines", 1),
        ("USAB-002", "database_replication", "High Availability Database Clusters: Write-ahead logging ensures durability across failover events.", "database clusters write ahead logging", 1),
        ("USAB-003", "api_gateway_patterns", "API Gateway Routing Patterns: Rate limiting and token verification happen at ingress before service dispatch.", "api gateway routing rate limiting", 1),
        ("USAB-004", "microservices_observability", "Microservices Observability: Distributed tracing correlates requests across service meshes.", "distributed tracing service mesh", 1),
        ("USAB-005", "kubernetes_pod_lifecycle", "Container Orchestration: Pod health probes determine readiness and liveness states in cluster.", "kubernetes pod health readiness", 1),
        ("USAB-006", "cache_invalidation_strategy", "Distributed Caching: Cache-aside and write-through patterns provide bounded consistency guarantees.", "distributed caching write through", 1),

        # Financial & Operating Reports
        ("USAB-007", "quarterly_earnings_summary", "Q1 Financial Results: Enterprise cloud subscription revenue increased 18% over prior quarter.", "quarterly financial results subscription revenue", 1),
        ("USAB-008", "operating_cash_flow", "Cash Flow Statement: Capital expenditures remained within the approved fiscal budget allocation.", "operating cash flow capital expenditure", 1),
        ("USAB-009", "auditing_standards", "GAAP Accounting Practices: Revenue recognition complies with ASC 606 guidelines across all contracts.", "gaap accounting revenue recognition", 1),
        ("USAB-010", "procurement_guidelines", "Vendor Procurement Process: All contracts exceeding $50,000 require dual approval from legal and finance.", "vendor procurement contract approval", 1),
        ("USAB-011", "budget_planning_memo", "Annual Budget Forecast: R&D investments will focus on AI application security and secure retrieval.", "annual budget forecast security r&d", 1),

        # Incident Response & Security Engineering
        ("USAB-012", "incident_response_playbook", "Security Incident Handling: Severity 1 incidents trigger automated pager alerts and bridge creation.", "security incident response playbook", 1),
        ("USAB-013", "vulnerability_remediation_sla", "Vulnerability Management Policy: Critical severity CVEs must be patched within 14 calendar days.", "vulnerability remediation cve policy", 1),
        ("USAB-014", "tls_configuration_standards", "Transport Layer Security: Deprecate TLS 1.0 and 1.1; enforce TLS 1.3 with forward secrecy ciphers.", "tls transport security standards", 1),
        ("USAB-015", "secret_rotation_procedures", "Credential Management: Rotate service account credentials every 90 days using automated vaults.", "credential management secret rotation", 1),
        ("USAB-016", "access_review_quarterly", "Identity Governance: Quarterly access reviews require managers to re-certify team privileges.", "quarterly access reviews identity", 1),

        # Human Resources & Corporate Policies
        ("USAB-017", "employee_travel_policy", "Business Travel Policy: Employees should book economy flights for domestic trips under four hours.", "employee business travel policy", 1),
        ("USAB-018", "benefits_enrollment_guide", "Annual Benefits Enrollment: Select health, dental, and vision coverage during the open enrollment window.", "benefits open enrollment health dental", 1),
        ("USAB-019", "remote_work_stipend", "Home Office Equipment: Full-time remote employees are eligible for a $500 home workspace setup stipend.", "remote work equipment stipend", 1),
        ("USAB-020", "paid_time_off_guidelines", "Paid Time Off Policy: Accrued PTO balances up to 40 hours may be carried over to the next calendar year.", "paid time off pto carryover", 1),
        ("USAB-021", "workplace_safety_handbook", "Office Safety Protocols: Emergency exit routes and first aid stations are clearly marked on every floor.", "office workplace safety emergency exit", 1),

        # Engineering Specs & Design Docs
        ("USAB-022", "vector_index_benchmarks", "Vector Search Optimization: HNSW graphs provide sub-10ms nearest neighbor candidate retrieval.", "hnsw vector search optimization nearest neighbor", 1),
        ("USAB-023", "chunking_strategy_spec", "Document Processing Spec: 300 token chunk size with 30 token overlap preserves semantic continuity.", "document chunking strategy token overlap", 1),
        ("USAB-024", "context_builder_design", "Safe Context Assembly: XML encapsulation and CDATA wrapping defang untrusted retrieved passages.", "safe context assembly xml cdata", 1),
        ("USAB-025", "dlp_regex_benchmarks", "DLP Engine Architecture: Deterministic pattern matching achieves zero-latency overhead on egress.", "dlp regex pattern matching egress", 1),
        ("USAB-026", "audit_trail_tamper_evidence", "Audit Event Logging: Security audit logs are immutable and indexed by timestamp and principal ID.", "audit event logging immutable security", 1),

        # Refill & Over-fetch Usability Verification
        ("USAB-027", "refill_authorized_retrieval", "Candidate Refill Verification: Authorized documents remain accessible when adjacent candidates are filtered.", "candidate refill verification authorized", 1),
        ("USAB-028", "multi_chunk_coherence", "Multi-chunk Ingestion: Paragraph one establishes principles and paragraph two details implementation.", "multi chunk ingestion principles implementation", 1),
        ("USAB-029", "public_document_accessibility", "Public Knowledge Base: Unrestricted public policy documents are retrievable by any authenticated user.", "unrestricted public policy document", 1),
        ("USAB-030", "citation_hash_verification", "Cryptographic Citation Attribution: Returned citations match chunk content SHA-256 hash exactly.", "cryptographic citation attribution sha-256", 1),
        ("USAB-031", "exact_passage_alignment", "Source Alignment Verification: Citations point to the exact document title and chunk index returned.", "source alignment document title chunk index", 1),
        ("USAB-032", "clean_prose_no_dlp_interference", "Benchmark Report: 100% of tested scenarios passed within expected latency budgets without false redaction.", "benchmark report tested scenarios passed", 1),
    ]

    for case_id, sub, text, query, expected_count in business_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.BENIGN_USABILITY,
                subcategory=sub,
                description=f"Benign operational retrieval: {sub}",
                input_data={
                    "title": f"Business Guide {case_id}",
                    "content": text,
                    "query": query,
                    "tenant_id": "default_tenant",
                    "is_public": True,
                },
                expected_outcome={
                    "expected_chunks_returned": expected_count,
                    "expected_trust_status": "TRUSTED",
                    "expected_inspection_outcome": "CLEAN",
                    "zero_quarantine": True,
                    "zero_false_redactions": True,
                },
                tags=["usability", "retrieval", "benign"],
            )
        )

    return scenarios
