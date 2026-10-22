"""Integration tests for the end-to-end RAG pipeline and FastAPI endpoints."""

from zero_trust_rag.core.models import (
    DocumentIngestRequest,
    RetrievalQueryRequest,
    ClassificationLevel,
)

AUTH_HEADER = {"Authorization": "Bearer demo-token-charlie-admin"}

def test_service_ingest_and_retrieve(rag_service):
    # Ingest document directly through service
    doc_req = DocumentIngestRequest(
        title="Zero-Trust Access Control Policy",
        content=(
            "The Zero-Trust Architecture requires that all access requests are strictly authenticated "
            "and authorized. No implicit trust is granted based on network location. "
            "Every chunk retrieved from a vector database must undergo deterministic verification."
        ),
        tenant_id="default_tenant",
        classification_level=ClassificationLevel.INTERNAL,
    )
    doc_record = rag_service.ingest_document(doc_req)
    assert doc_record.document_id.startswith("doc_")
    assert doc_record.chunk_count >= 1

    # Query matching concept
    query_req = RetrievalQueryRequest(
        query_text="zero-trust network architecture authorization",
        tenant_id="default_tenant",
        top_k=3,
    )
    resp = rag_service.retrieve(query_req)
    assert resp.chunks_returned >= 1
    assert resp.citations[0].document_id == doc_record.document_id
    assert "Zero-Trust" in resp.raw_context

def test_service_revocation_removes_from_retrieval(rag_service):
    doc_req = DocumentIngestRequest(
        title="Ephemeral Secrets Document",
        content="Temporary tokens and internal configuration parameters for Q3 release.",
        tenant_id="default_tenant",
    )
    doc_record = rag_service.ingest_document(doc_req)

    # Confirm retrievable before revocation
    query_req = RetrievalQueryRequest(
        query_text="ephemeral secrets temporary tokens",
        tenant_id="default_tenant",
        top_k=2,
    )
    before_resp = rag_service.retrieve(query_req)
    assert before_resp.chunks_returned >= 1

    # Revoke document
    success = rag_service.revoke_document(doc_record.document_id)
    assert success is True

    # Confirm vector purge: 0 chunks returned
    after_resp = rag_service.retrieve(query_req)
    assert after_resp.chunks_returned == 0

def test_api_health_endpoint(test_client):
    response = test_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert "components" in data
    assert data["components"]["authoritative_sqlite"] == "connected"

def test_api_e2e_ingestion_and_retrieval(test_client):
    # 1. Ingest via API with Bearer token
    payload = {
        "title": "API Ingestion Test Document",
        "content": "Cryptographic attestation and SHA-256 integrity verification across document chunks.",
        "tenant_id": "default_tenant",
        "classification_level": 2,
        "is_public": False,
        "custom_metadata": {"author": "Security Team"}
    }
    ingest_res = test_client.post("/api/v1/documents/ingest", json=payload, headers=AUTH_HEADER)
    assert ingest_res.status_code == 201
    doc_data = ingest_res.json()
    doc_id = doc_data["document_id"]
    assert doc_id.startswith("doc_")

    # 2. Get document metadata with Bearer token
    get_res = test_client.get(f"/api/v1/documents/{doc_id}", headers=AUTH_HEADER)
    assert get_res.status_code == 200
    assert get_res.json()["title"] == "API Ingestion Test Document"

    # 3. Query via API with Bearer token
    query_payload = {
        "query_text": "cryptographic attestation integrity verification",
        "tenant_id": "default_tenant",
        "top_k": 3,
        "min_similarity": 0.0
    }
    query_res = test_client.post("/api/v1/retrieval/query", json=query_payload, headers=AUTH_HEADER)
    assert query_res.status_code == 200
    query_data = query_res.json()
    assert query_data["chunks_returned"] >= 1
    assert query_data["citations"][0]["document_id"] == doc_id

    # 4. Revoke via API with Bearer token
    revoke_res = test_client.post(f"/api/v1/documents/{doc_id}/revoke", headers=AUTH_HEADER)
    assert revoke_res.status_code == 200

    # 5. Verify query returns zero results after revocation
    re_query_res = test_client.post("/api/v1/retrieval/query", json=query_payload, headers=AUTH_HEADER)
    assert re_query_res.status_code == 200
    assert re_query_res.json()["chunks_returned"] == 0
