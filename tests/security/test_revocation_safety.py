"""Security tests for document revocation lifecycle, vector desynchronization resilience, and audit integrity."""

import pytest
from unittest.mock import patch
from zero_trust_rag.core.models import (
    DocumentIngestRequest,
    RetrievalQueryRequest,
    DocumentStatus,
    PrincipalRole,
    PrincipalContext,
    ClassificationLevel,
)

def test_authorized_revocation_blocks_subsequent_retrieval(test_client):
    """Scenario 23: Authorized revocation immediately prevents subsequent retrieval across all endpoints."""
    headers_charlie = {"Authorization": "Bearer demo-token-charlie-admin"}

    # 1. Ingest document
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={
            "title": "Revocable Guidelines",
            "content": "Operational guidelines to be revoked upon policy update.",
            "is_public": True,
        },
        headers=headers_charlie
    )
    assert ingest_res.status_code == 201
    doc_id = ingest_res.json()["document_id"]

    # 2. Verify retrievable
    query_payload = {"query_text": "operational guidelines policy update", "top_k": 3}
    res_before = test_client.post("/api/v1/retrieval/query", json=query_payload, headers=headers_charlie)
    assert res_before.status_code == 200
    assert res_before.json()["chunks_returned"] >= 1

    # 3. Revoke document
    revoke_res = test_client.post(f"/api/v1/documents/{doc_id}/revoke", headers=headers_charlie)
    assert revoke_res.status_code == 200
    assert "successfully revoked" in revoke_res.json()["message"]

    # 4. Confirm immediately unretrievable
    res_after = test_client.post("/api/v1/retrieval/query", json=query_payload, headers=headers_charlie)
    assert res_after.status_code == 200
    assert res_after.json()["chunks_returned"] == 0
    assert doc_id not in str(res_after.content)

def test_unauthorized_revocation_rejected_status_unchanged(test_client):
    """Scenario 24: Unauthorized revocation attempts are rejected with 403 and status remains ACTIVE."""
    # 1. Bob (contributor) ingests document
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={"title": "Important Document", "content": "Critical document content.", "is_public": True},
        headers=headers_bob
    )
    doc_id = ingest_res.json()["document_id"]

    # 2. Alice (reader) attempts to revoke Bob's document
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}
    revoke_res = test_client.post(f"/api/v1/documents/{doc_id}/revoke", headers=headers_alice)
    assert revoke_res.status_code == 403

    # 3. Verify status remains ACTIVE
    get_res = test_client.get(f"/api/v1/documents/{doc_id}", headers=headers_bob)
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "ACTIVE"

def test_vector_deletion_failure_does_not_restore_access(rag_service):
    """Scenario 25: If vector store deletion fails, SQLite authoritative state prevents access."""
    # 1. Ingest document
    doc = rag_service.ingest_document(
        DocumentIngestRequest(
            title="Fault Tolerant Policy",
            content="Testing cleanup failure resilience and authoritative gating.",
            tenant_id="default_tenant",
            is_public=True
        )
    )

    # 2. Revoke document, but simulate vector store deletion failure
    with patch.object(rag_service.vector_store, "delete_by_document", side_effect=RuntimeError("Simulated Chroma lock")):
        success = rag_service.revoke_document(doc.document_id)
        # Service handles error safely and marks SQLite status as REVOKED
        assert success is True

    # Check SQLite status is REVOKED
    db_doc = rag_service.db.get_document(doc.document_id)
    assert db_doc.status == DocumentStatus.REVOKED

    # 3. Query: The vector is still in the vector store, but Stage 2 check blocks it!
    resp = rag_service.retrieve(
        RetrievalQueryRequest(query_text="cleanup failure resilience authoritative gating", top_k=3)
    )
    assert resp.chunks_returned == 0
    assert len(resp.citations) == 0

def test_security_audit_trail_integrity(test_client, test_db):
    """Scenario 26: Security decisions are recorded with hashes and zero plain content disclosure."""
    headers_admin = {"Authorization": "Bearer demo-token-charlie-admin"}

    # Execute an authorized query
    test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "audit trail query test text", "top_k": 2},
        headers=headers_admin
    )

    # Fetch audit events via API
    events_res = test_client.get("/api/v1/audit/events", headers=headers_admin)
    assert events_res.status_code == 200
    events = events_res.json()
    assert len(events) >= 1

    # Inspect events
    for event in events:
        assert "event_id" in event
        assert "timestamp" in event
        assert "principal_id" in event
        assert "tenant_id" in event
        assert "decision" in event
        # Plaintext query MUST NOT be in the log; only query_hash
        assert "audit trail query test text" not in str(event.get("query_text", ""))
        if event.get("query_hash"):
            assert len(event["query_hash"]) == 64  # SHA-256 hash length
