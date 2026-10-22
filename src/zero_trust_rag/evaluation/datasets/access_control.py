"""Access-control, tenant-isolation, and authorization evaluation dataset (30+ scenarios)."""

from typing import List
from zero_trust_rag.evaluation.models import EvaluationScenario, ScenarioCategory


def get_access_control_scenarios() -> List[EvaluationScenario]:
    """
    Returns 32 distinct synthetic access control, tenant isolation, and clearance scenarios.
    Covers cross-tenant leakage, document ID enumeration, ACL restrictions, clearance levels,
    spoofed claims, stale vector revocation, forged vector candidate metadata, and refill isolation.
    """
    scenarios: List[EvaluationScenario] = []

    # ------------------------------------------------------------------------
    # 1. Cross-Tenant Retrieval & Foreign Tenant ID Probing (SEC-ACC-001 to SEC-ACC-008)
    # ------------------------------------------------------------------------
    cross_tenant_cases = [
        ("SEC-ACC-001", "cross_tenant_query_alpha_to_beta", "default_tenant", "tenant_isolated_beta", "Alpha user queries for Beta tenant documents", "user_alice", False),
        ("SEC-ACC-002", "cross_tenant_query_beta_to_alpha", "tenant_isolated_beta", "default_tenant", "Beta user queries for Alpha tenant confidential roadmaps", "user_beta_zara", False),
        ("SEC-ACC-003", "known_foreign_doc_id_probe", "default_tenant", "tenant_isolated_beta", "Direct probe using known foreign tenant document ID", "user_alice", False),
        ("SEC-ACC-004", "cross_tenant_metadata_read", "tenant_isolated_beta", "default_tenant", "Attempt to read foreign tenant document metadata via API", "user_beta_zara", False),
        ("SEC-ACC-005", "cross_tenant_list_documents", "default_tenant", "tenant_isolated_beta", "Listing documents with foreign tenant parameter", "user_alice", False),
        ("SEC-ACC-006", "cross_tenant_audit_event_read", "default_tenant", "tenant_isolated_beta", "Attempt to query foreign tenant security audit log entries", "user_alice", False),
        ("SEC-ACC-007", "cross_tenant_vector_overfetch_leak", "default_tenant", "tenant_isolated_beta", "Vector over-fetch candidate returns foreign tenant chunk", "user_alice", False),
        ("SEC-ACC-008", "cross_tenant_admin_boundary", "tenant_isolated_beta", "default_tenant", "Beta admin attempts to approve default tenant document", "user_beta_zara", False),
    ]
    for case_id, sub, caller_tenant, target_tenant, desc, caller_principal, is_allowed in cross_tenant_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.ACCESS_CONTROL,
                subcategory="cross_tenant_isolation",
                description=desc,
                input_data={
                    "caller_tenant": caller_tenant,
                    "target_tenant": target_tenant,
                    "caller_principal": caller_principal,
                    "target_doc_title": f"Target Confidential Asset {case_id}",
                    "target_doc_content": f"Confidential internal strategic asset owned exclusively by {target_tenant}.",
                },
                expected_outcome={
                    "should_allow": is_allowed,
                    "expected_chunks_returned": 0,
                    "zero_leakage_required": True,
                },
                tags=["access_control", "cross_tenant"],
            )
        )

    # ------------------------------------------------------------------------
    # 2. Same-Tenant ACL Restrictions (SEC-ACC-009 to SEC-ACC-014)
    # ------------------------------------------------------------------------
    acl_cases = [
        ("SEC-ACC-009", "private_doc_without_acl", "user_bob", "user_alice", "Alice attempts to retrieve Bob's private document without ACL grant", False),
        ("SEC-ACC-010", "private_doc_with_grant", "user_bob", "user_alice", "Alice retrieves Bob's private document after explicit ACL grant", True),
        ("SEC-ACC-011", "acl_revoked_after_grant", "user_bob", "user_alice", "Alice attempts retrieval after ACL grant has been revoked", False),
        ("SEC-ACC-012", "non_owner_attempts_acl_grant", "user_bob", "user_alice", "Alice attempts to grant ACL for Bob's document to third party", False),
        ("SEC-ACC-013", "reader_attempts_document_ingest", "default_tenant", "user_alice", "Standard reader attempts to ingest document without contributor role", False),
        ("SEC-ACC-014", "unauthorized_acl_deletion", "user_bob", "user_alice", "Alice attempts to delete ACL on Bob's document", False),
    ]
    for case_id, sub, owner, accessor, desc, is_allowed in acl_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.ACCESS_CONTROL,
                subcategory="acl_enforcement",
                description=desc,
                input_data={
                    "owner": owner,
                    "accessor": accessor,
                    "tenant_id": "default_tenant",
                    "doc_title": f"Restricted Access Asset {case_id}",
                    "doc_content": f"Internal private sensitive text protected by ACL for {case_id}.",
                },
                expected_outcome={
                    "should_allow": is_allowed,
                    "zero_leakage_required": True,
                },
                tags=["access_control", "acl"],
            )
        )

    # ------------------------------------------------------------------------
    # 3. Clearance-Level Violations (SEC-ACC-015 to SEC-ACC-020)
    # ------------------------------------------------------------------------
    clearance_cases = [
        ("SEC-ACC-015", "public_clearance_reading_internal", 1, 2, "Public clearance user queries Internal classification document", False),
        ("SEC-ACC-016", "public_clearance_reading_confidential", 1, 3, "Public clearance user queries Confidential classification document", False),
        ("SEC-ACC-017", "public_clearance_reading_restricted", 1, 4, "Public clearance user queries Restricted executive document", False),
        ("SEC-ACC-018", "internal_clearance_reading_confidential", 2, 3, "Internal clearance user queries Confidential financial document", False),
        ("SEC-ACC-019", "confidential_clearance_reading_confidential", 3, 3, "Confidential clearance user queries Confidential financial document", True),
        ("SEC-ACC-020", "confidential_clearance_reading_restricted", 3, 4, "Confidential clearance user queries Restricted executive document", False),
    ]
    for case_id, sub, user_clearance, doc_classification, desc, is_allowed in clearance_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.ACCESS_CONTROL,
                subcategory="clearance_levels",
                description=desc,
                input_data={
                    "user_clearance": user_clearance,
                    "doc_classification": doc_classification,
                    "doc_title": f"Classified Data Asset {case_id}",
                    "doc_content": f"High clearance sensitive operational material for {case_id}.",
                },
                expected_outcome={
                    "should_allow": is_allowed,
                    "zero_leakage_required": True,
                },
                tags=["access_control", "clearance"],
            )
        )

    # ------------------------------------------------------------------------
    # 4. Client-Supplied Claim Spoofing (SEC-ACC-021 to SEC-ACC-024)
    # ------------------------------------------------------------------------
    spoofed_cases = [
        ("SEC-ACC-021", "header_tenant_spoofing", "X-Tenant-ID header injected to access foreign tenant", "tenant_isolated_beta"),
        ("SEC-ACC-022", "body_tenant_spoofing", "Request body tenant_id injected to bypass token tenant", "tenant_isolated_beta"),
        ("SEC-ACC-023", "body_role_spoofing", "Request body role claim injected claiming tenant_admin", "tenant_admin"),
        ("SEC-ACC-024", "body_clearance_spoofing", "Request body clearance claim injected claiming level 4", 4),
    ]
    for case_id, sub, desc, spoofed_value in spoofed_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.ACCESS_CONTROL,
                subcategory="spoofed_claims",
                description=desc,
                input_data={
                    "token": "demo-token-alice-reader",
                    "spoofed_claim_type": sub,
                    "spoofed_value": spoofed_value,
                },
                expected_outcome={
                    "should_allow": False,
                    "must_ignore_client_claims": True,
                    "zero_leakage_required": True,
                },
                tags=["access_control", "spoofing"],
            )
        )

    # ------------------------------------------------------------------------
    # 5. Revocation & Stale Vector Defense (SEC-ACC-025 to SEC-ACC-028)
    # ------------------------------------------------------------------------
    revocation_cases = [
        ("SEC-ACC-025", "revoked_doc_blocked_immediately", "Revoked document cannot be retrieved immediately after revocation"),
        ("SEC-ACC-026", "stale_vector_survives_deletion_failure", "Stale vector entry survives vector store deletion failure but SQLite blocks retrieval"),
        ("SEC-ACC-027", "revoked_document_reactivation_attempt", "Tenant admin attempts to re-approve revoked document, which remains permanently REVOKED"),
        ("SEC-ACC-028", "unauthorized_user_revocation_attempt", "Reader attempts to revoke document owned by contributor"),
    ]
    for case_id, sub, desc in revocation_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.ACCESS_CONTROL,
                subcategory="revocation_safety",
                description=desc,
                input_data={"sub": sub},
                expected_outcome={
                    "zero_leakage_required": True,
                    "revocation_enforced": True,
                },
                tags=["access_control", "revocation"],
            )
        )

    # ------------------------------------------------------------------------
    # 6. Forged Vectors, Corrupted Records & Refill Isolation (SEC-ACC-029 to SEC-ACC-032)
    # ------------------------------------------------------------------------
    integrity_cases = [
        ("SEC-ACC-029", "forged_tenant_in_vector_store", "Vector candidate tagged with forged tenant is rejected by SQLite post-retrieval verification"),
        ("SEC-ACC-030", "dangling_vector_missing_in_sqlite", "Vector store returns candidate with non-existent chunk_id, failing closed"),
        ("SEC-ACC-031", "unauthorized_candidate_refill_prevented", "Unauthorized candidates do not displace authorized candidates; slots refill safely"),
        ("SEC-ACC-032", "sqlite_failure_fails_closed", "Database transient error triggers fail-closed with 0 chunks and audit log entry"),
    ]
    for case_id, sub, desc in integrity_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.ACCESS_CONTROL,
                subcategory="authoritative_sqlite_verification",
                description=desc,
                input_data={"sub": sub},
                expected_outcome={
                    "zero_leakage_required": True,
                    "fail_closed_enforced": True,
                },
                tags=["access_control", "post_retrieval_verification"],
            )
        )

    return scenarios
