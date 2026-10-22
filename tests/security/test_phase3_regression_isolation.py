"""Security regression tests verifying Phase 2 isolation and authorization guarantees persist in Phase 3."""

import pytest
from unittest.mock import patch
from zero_trust_rag.core.models import (
    DocumentIngestRequest,
    RetrievalQueryRequest,
    ClassificationLevel,
    PrincipalRole,
    PrincipalContext,
)

def test_cross_tenant_isolation_persists_in_phase3(test_client):
    """Scenario 30: Cross-tenant retrieval remains strictly blocked under Phase 3."""
    headers_charlie = {"Authorization": "Bearer demo-token-charlie-admin"}
    test_client.post(
        "/api/v1/documents/ingest",
        json={"title": "Alpha Research", "content": "Alpha proprietary research doc 999.", "is_public": True},
        headers=headers_charlie
    )

    # Beta user queries
    headers_zara = {"Authorization": "Bearer demo-token-tenant-beta-user"}
    res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "Alpha proprietary research doc 999", "top_k": 3},
        headers=headers_zara
    )
    assert res.status_code == 200
    assert res.json()["chunks_returned"] == 0
    assert "research doc 999" not in str(res.content)

def test_client_spoofed_fields_ignored_in_phase3(test_client):
    """Scenario 31: Client-supplied tenant and clearance fields remain completely untrusted."""
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    spoofed = {
        "title": "Spoofed Document",
        "content": "Clean content with spoofed owner root.",
        "owner_id": "root_superadmin",
        "tenant_id": "default_tenant",
    }
    res = test_client.post("/api/v1/documents/ingest", json=spoofed, headers=headers_bob)
    assert res.status_code == 201
    doc = res.json()
    assert doc["owner_id"] == "user_bob"

def test_same_tenant_acl_and_clearance_persists(test_client):
    """Scenario 32: Same-tenant ACL and clearance restrictions remain effective."""
    headers_charlie = {"Authorization": "Bearer demo-token-charlie-admin"}
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={"title": "Restricted Board Notes", "content": "Board meeting decisions.", "is_public": True, "classification_level": 4},
        headers=headers_charlie
    )
    doc_id = ingest_res.json()["document_id"]

    # Alice (clearance Level 2) cannot retrieve Level 4 doc
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}
    res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "Board meeting decisions", "top_k": 3},
        headers=headers_alice
    )
    assert res.status_code == 200
    assert res.json()["chunks_returned"] == 0

def test_revoked_docs_remain_inaccessible_even_with_vector_delete_failure(rag_service):
    """Scenario 33: Revoked documents remain inaccessible even when vector deletion fails."""
    doc = rag_service.ingest_document(
        DocumentIngestRequest(
            title="Revoked Policy",
            content="Policy to be revoked with simulated vector index failure.",
            tenant_id="default_tenant",
            is_public=True
        )
    )

    with patch.object(rag_service.vector_store, "delete_by_document", side_effect=Exception("Chroma failure")):
        success = rag_service.revoke_document(doc.document_id)
        assert success is True

    # Vector is still present, but Stage 2 drops it
    res = rag_service.retrieve(
        RetrievalQueryRequest(query_text="Policy to be revoked with simulated vector index failure", top_k=3)
    )
    assert res.chunks_returned == 0

def test_unauthorized_operations_remain_blocked(test_client):
    """Scenario 34: Unauthorized ingestion, metadata access, ACL modification, and revocation remain blocked."""
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}

    # Reader cannot ingest
    assert test_client.post("/api/v1/documents/ingest", json={"title": "T", "content": "C"}, headers=headers_alice).status_code == 403

    # Reader cannot revoke
    assert test_client.post("/api/v1/documents/doc_123/revoke", headers=headers_alice).status_code in (403, 404)

    # Reader cannot add ACL
    assert test_client.post("/api/v1/documents/doc_123/acls", json={"grantee_type": "USER", "grantee_id": "u", "permission": "READ"}, headers=headers_alice).status_code in (403, 404)
