"""Security tests for two-stage retrieval authorization, tenant isolation, and refill strategy."""

import pytest
from unittest.mock import patch
from zero_trust_rag.core.models import (
    DocumentIngestRequest,
    RetrievalQueryRequest,
    ClassificationLevel,
    DocumentStatus,
    PrincipalRole,
    PrincipalContext,
    ChunkRecord,
)

def test_authorized_user_retrieves_active_document(test_client):
    """Scenario 12: An authorized user can retrieve an active document in their tenant."""
    # Bob (contributor) ingests an internal document with public=True (within tenant)
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={
            "title": "Default Tenant Knowledgebase",
            "content": "Zero-trust principles mandate continuous verification and least privilege.",
            "is_public": True,
            "classification_level": 2  # INTERNAL
        },
        headers=headers_bob
    )
    assert ingest_res.status_code == 201
    doc_id = ingest_res.json()["document_id"]

    # Alice (reader, clearance INTERNAL = 2) queries for this content
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}
    query_res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "zero-trust continuous verification least privilege", "top_k": 3},
        headers=headers_alice
    )
    assert query_res.status_code == 200
    data = query_res.json()
    assert data["chunks_returned"] >= 1
    assert data["citations"][0]["document_id"] == doc_id
    assert "least privilege" in data["raw_context"].lower()

def test_cross_tenant_chunks_never_returned(test_client):
    """Scenario 13: Cross-tenant document chunks are never returned to a foreign tenant."""
    # 1. Tenant A (Charlie in default_tenant) ingests confidential document
    headers_charlie = {"Authorization": "Bearer demo-token-charlie-admin"}
    test_client.post(
        "/api/v1/documents/ingest",
        json={
            "title": "Tenant Alpha Secret Formula",
            "content": "Secret formula for compound X99 is strictly confidential to Alpha Corp.",
            "is_public": True,
        },
        headers=headers_charlie
    )

    # 2. Tenant B (Zara in tenant_isolated_beta) searches for the exact phrase
    headers_zara = {"Authorization": "Bearer demo-token-tenant-beta-user"}
    query_res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "Secret formula for compound X99 Alpha Corp", "top_k": 5},
        headers=headers_zara
    )
    assert query_res.status_code == 200
    data = query_res.json()
    # ZERO chunks returned
    assert data["chunks_returned"] == 0
    assert len(data["citations"]) == 0
    assert data["raw_context"] == ""
    # Verify no leaks of sensitive string in response payload
    assert "compound X99" not in str(query_res.content)

def test_same_tenant_document_without_acl_is_not_returned(test_client):
    """Scenario 14: A same-tenant private document without applicable ACL is never returned."""
    # 1. Bob ingests a private document (is_public=False)
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={
            "title": "Bob's Private Diary",
            "content": "Personal design musings and unapproved architectural theories.",
            "is_public": False,
            "classification_level": 2,
        },
        headers=headers_bob
    )
    doc_id = ingest_res.json()["document_id"]

    # 2. Alice (reader) queries for Bob's diary content
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}
    query_res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "personal design musings unapproved theories", "top_k": 3},
        headers=headers_alice
    )
    assert query_res.status_code == 200
    data = query_res.json()
    # Alice is not the owner, doc is not public, no ACL exists -> 0 chunks
    assert data["chunks_returned"] == 0
    assert doc_id not in str(query_res.content)

    # 3. Now Bob grants Alice an explicit ACL rule
    acl_res = test_client.post(
        f"/api/v1/documents/{doc_id}/acls",
        json={"grantee_type": "USER", "grantee_id": "user_alice", "permission": "READ"},
        headers=headers_bob
    )
    assert acl_res.status_code == 201

    # 4. Alice re-queries and is now authorized!
    re_query_res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "personal design musings unapproved theories", "top_k": 3},
        headers=headers_alice
    )
    assert re_query_res.status_code == 200
    assert re_query_res.json()["chunks_returned"] >= 1
    assert re_query_res.json()["citations"][0]["document_id"] == doc_id

def test_low_clearance_principal_cannot_retrieve_higher_clearance_doc(test_client):
    """Scenario 15: A low-clearance principal cannot retrieve a document above their clearance."""
    # 1. Charlie (admin) ingests a RESTRICTED (Level 4) document (public within tenant)
    headers_charlie = {"Authorization": "Bearer demo-token-charlie-admin"}
    test_client.post(
        "/api/v1/documents/ingest",
        json={
            "title": "Nuclear Reactor Schematics",
            "content": "Critical infrastructure cooling reactor core specifications.",
            "is_public": True,
            "classification_level": 4,  # RESTRICTED
        },
        headers=headers_charlie
    )

    # 2. Eve has clearance level PUBLIC = 1
    headers_eve = {"Authorization": "Bearer demo-token-eve-low"}
    query_res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "infrastructure cooling reactor core specifications", "top_k": 3},
        headers=headers_eve
    )
    assert query_res.status_code == 200
    # Eve cannot access Level 4 document
    assert query_res.json()["chunks_returned"] == 0
    assert "reactor core" not in str(query_res.content)

def test_inconsistent_chunk_parent_relationship_denied(rag_service):
    """Scenario 16: Unknown or inconsistent chunk-to-document relationships are dropped."""
    # 1. Add an orphan vector directly into the vector store that has no SQLite record
    orphan_chunk = ChunkRecord(
        chunk_id="chk_orphan_999",
        document_id="doc_missing_123",
        tenant_id="default_tenant",
        chunk_index=0,
        token_count=10,
        content="Orphan chunk without valid parent document in SQLite.",
        content_hash="hash999",
        classification_level=ClassificationLevel.INTERNAL,
        status=DocumentStatus.ACTIVE
    )
    rag_service.vector_store.add_chunks([orphan_chunk], [[1.0] * 384])

    # 2. Query for orphan content
    q_req = RetrievalQueryRequest(query_text="orphan chunk without valid parent", top_k=5)
    resp = rag_service.retrieve(q_req)
    # Orphan chunk must be dropped by Stage 2 verification
    returned_ids = [c.chunk_id for c in resp.citations]
    assert "chk_orphan_999" not in returned_ids

def test_vector_candidate_with_forged_tenant_rejected_authoritatively(rag_service):
    """Scenario 17: A vector candidate with spoofed tenant metadata is rejected authoritatively by SQLite."""
    # Tenant Beta doc
    beta_principal = PrincipalContext(
        principal_id="user_beta",
        tenant_id="tenant_isolated_beta",
        role=PrincipalRole.CONTRIBUTOR,
        clearance_level=ClassificationLevel.INTERNAL
    )
    doc_beta = rag_service.ingest_document(
        DocumentIngestRequest(title="Beta Secret", content="Beta confidential blueprints."),
        principal=beta_principal
    )

    # Malicious injection: Vector store chunk is tagged with tenant_id="default_tenant",
    # but SQLite authoritative record still has tenant_id="tenant_isolated_beta"
    fake_chunk = ChunkRecord(
        chunk_id=f"chk_{doc_beta.document_id}_0",
        document_id=doc_beta.document_id,
        tenant_id="default_tenant",  # Forged tenant in vector store metadata
        chunk_index=0,
        token_count=10,
        content="Beta confidential blueprints.",
        content_hash="hbeta",
        classification_level=ClassificationLevel.INTERNAL,
        status=DocumentStatus.ACTIVE
    )
    rag_service.vector_store.add_chunks([fake_chunk], [[1.0] * 384])

    # Default tenant user queries for blueprints
    alpha_principal = PrincipalContext(
        principal_id="user_alice",
        tenant_id="default_tenant",
        role=PrincipalRole.READER,
        clearance_level=ClassificationLevel.INTERNAL
    )
    resp = rag_service.retrieve(
        RetrievalQueryRequest(query_text="confidential blueprints", top_k=3),
        principal=alpha_principal
    )
    # Stage 2 authoritative SQLite check detects doc.tenant_id == 'tenant_isolated_beta' != 'default_tenant' -> Drops chunk!
    assert resp.chunks_returned == 0
    assert "blueprints" not in str(resp.citations)

def test_stale_vector_belonging_to_revoked_doc_rejected(rag_service):
    """Scenario 18 & 19: Stale vectors from revoked documents are rejected without leaking title/snippets."""
    doc = rag_service.ingest_document(
        DocumentIngestRequest(
            title="Revoked Security Briefing",
            content="Sensitive vulnerability CVE-2026-0001 details before patching.",
            tenant_id="default_tenant",
            is_public=True
        )
    )

    # Artificially keep vector in store, but mark document REVOKED in SQLite
    rag_service.db.update_document_status(doc.document_id, DocumentStatus.REVOKED)

    # Query for the vulnerability
    resp = rag_service.retrieve(
        RetrievalQueryRequest(query_text="vulnerability CVE-2026-0001 patching details", top_k=3)
    )
    # Chunks from revoked document must be dropped
    assert resp.chunks_returned == 0
    assert len(resp.citations) == 0
    assert "CVE-2026-0001" not in resp.raw_context
    assert "Revoked Security Briefing" not in str(resp.citations)

def test_authoritative_sqlite_failure_fails_closed(rag_service):
    """Scenario 20: SQLite failure prevents any unverified retrieval results from returning."""
    rag_service.ingest_document(
        DocumentIngestRequest(
            title="Resilience Policy",
            content="Testing resilience and fail-closed security properties.",
            tenant_id="default_tenant",
            is_public=True
        )
    )

    # Simulate database crash/failure during post-retrieval verification
    with patch.object(rag_service.db, "get_chunk", side_effect=Exception("Database lock/connection lost")):
        resp = rag_service.retrieve(
            RetrievalQueryRequest(query_text="resilience fail-closed security", top_k=3)
        )
        # MUST fail closed with 0 chunks returned
        assert resp.chunks_returned == 0
        assert resp.citations == []
        assert resp.raw_context == ""

def test_refill_strategy_prevents_unauthorized_displacement(rag_service):
    """Scenario 21 & 22: Unauthorized top-ranked candidates do not displace authorized candidates; candidate budget enforced."""
    admin_principal = PrincipalContext(
        principal_id="admin_dave",
        tenant_id="default_tenant",
        role=PrincipalRole.TENANT_ADMIN,
        clearance_level=ClassificationLevel.RESTRICTED
    )
    reader_principal = PrincipalContext(
        principal_id="reader_eve",
        tenant_id="default_tenant",
        role=PrincipalRole.READER,
        clearance_level=ClassificationLevel.PUBLIC
    )

    # 1. Ingest restricted document (High similarity, Level 4)
    rag_service.ingest_document(
        DocumentIngestRequest(
            title="Restricted Blueprint",
            content="Alpha Project secret architecture with highest cosine match for keyword.",
            classification_level=ClassificationLevel.RESTRICTED,
            is_public=True
        ),
        principal=admin_principal
    )

    # 2. Ingest public document (Slightly lower similarity, Level 1)
    doc_pub = rag_service.ingest_document(
        DocumentIngestRequest(
            title="Public Overview",
            content="Alpha Project public overview with architecture summary for keyword.",
            classification_level=ClassificationLevel.PUBLIC,
            is_public=True
        ),
        principal=admin_principal
    )

    # Reader requests top_k=1
    resp = rag_service.retrieve(
        RetrievalQueryRequest(query_text="Alpha Project architecture keyword", top_k=1),
        principal=reader_principal
    )
    # The bounded refill over-fetch inspected both candidates, dropped the Level 4 match,
    # and successfully refilled the budget with the authorized Public Overview!
    assert resp.chunks_returned == 1
    assert resp.citations[0].document_id == doc_pub.document_id
    assert resp.citations[0].document_title == "Public Overview"
