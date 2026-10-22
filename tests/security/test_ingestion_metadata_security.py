"""Security tests for ingestion controls, metadata authorization, and BOLA/IDOR protection."""

import pytest

def test_authorized_contributor_can_ingest(test_client):
    """Scenario 6: An authorized contributor can ingest documents into their own tenant."""
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    payload = {
        "title": "Contributor Guide",
        "content": "Valid contributor documentation for tenant operations.",
        "is_public": False,
    }
    res = test_client.post("/api/v1/documents/ingest", json=payload, headers=headers_bob)
    assert res.status_code == 201
    doc = res.json()
    assert doc["title"] == "Contributor Guide"
    assert doc["owner_id"] == "user_bob"
    assert doc["tenant_id"] == "default_tenant"

def test_reader_cannot_ingest_document(test_client):
    """Scenario 7: A reader without ingestion permission cannot create documents (HTTP 403)."""
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}
    payload = {
        "title": "Reader Upload Attempt",
        "content": "Readers are strictly read-only callers.",
    }
    res = test_client.post("/api/v1/documents/ingest", json=payload, headers=headers_alice)
    assert res.status_code == 403
    assert "reader" in res.json()["detail"].lower()

def test_cannot_ingest_into_foreign_tenant(test_client):
    """Scenario 8: A client cannot ingest a document into another tenant."""
    headers_zara = {"Authorization": "Bearer demo-token-tenant-beta-user"}
    payload = {
        "title": "Cross Tenant Ingestion Attempt",
        "content": "Zara attempting to inject a document into default_tenant.",
        "tenant_id": "default_tenant",
    }
    res = test_client.post("/api/v1/documents/ingest", json=payload, headers=headers_zara)
    assert res.status_code == 403
    assert "Cannot ingest documents on behalf of another tenant" in res.json()["detail"]

def test_user_cannot_read_foreign_tenant_metadata(test_client):
    """Scenario 9: A user cannot read another tenant's document metadata."""
    # 1. Ingest document as default_tenant admin
    headers_charlie = {"Authorization": "Bearer demo-token-charlie-admin"}
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={"title": "Default Tenant Secrets", "content": "Proprietary internal algorithms."},
        headers=headers_charlie
    )
    assert ingest_res.status_code == 201
    doc_id = ingest_res.json()["document_id"]

    # 2. Zara (tenant_isolated_beta) attempts to read metadata of doc_id
    headers_zara = {"Authorization": "Bearer demo-token-tenant-beta-user"}
    read_res = test_client.get(f"/api/v1/documents/{doc_id}", headers=headers_zara)
    # Must return 404 uniformly (no existence disclosure or metadata leak)
    assert read_res.status_code == 404
    assert read_res.json()["detail"] == "Document not found."

def test_document_id_knowledge_cannot_bypass_authorization(test_client):
    """Scenario 10: Knowing a document identifier cannot bypass document-level ACLs (BOLA/IDOR)."""
    # 1. Charlie (admin) ingests a private confidential document
    headers_charlie = {"Authorization": "Bearer demo-token-charlie-admin"}
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={
            "title": "Executive Compensation 2026",
            "content": "Confidential compensation plans.",
            "is_public": False,
            "classification_level": 3  # CONFIDENTIAL
        },
        headers=headers_charlie
    )
    assert ingest_res.status_code == 201
    doc_id = ingest_res.json()["document_id"]

    # 2. Eve (reader, clearance PUBLIC = 1) attempts to read metadata of doc_id
    headers_eve = {"Authorization": "Bearer demo-token-eve-low"}
    res_eve = test_client.get(f"/api/v1/documents/{doc_id}", headers=headers_eve)
    # Insufficient clearance / private doc -> 404 Not Found
    assert res_eve.status_code == 404

def test_unauthorized_users_cannot_modify_acls_or_revoke(test_client):
    """Scenario 11: Unauthorized users cannot modify ACLs or revoke documents."""
    # 1. Bob ingests a document
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={"title": "Bob's Project Spec", "content": "Specifications for project alpha."},
        headers=headers_bob
    )
    doc_id = ingest_res.json()["document_id"]

    # 2. Alice (reader) attempts to revoke Bob's document
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}
    revoke_res = test_client.post(f"/api/v1/documents/{doc_id}/revoke", headers=headers_alice)
    assert revoke_res.status_code == 403
    assert "Insufficient permissions" in revoke_res.json()["detail"]

    # 3. Alice attempts to add an ACL entry to Bob's document
    acl_payload = {"grantee_type": "USER", "grantee_id": "user_eve", "permission": "READ"}
    acl_res = test_client.post(f"/api/v1/documents/{doc_id}/acls", json=acl_payload, headers=headers_alice)
    assert acl_res.status_code == 403
    assert "Insufficient permissions" in acl_res.json()["detail"]
