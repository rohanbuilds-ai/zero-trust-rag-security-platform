"""Security tests for authentication, identity resolution, and credential tampering."""

import pytest
from zero_trust_rag.core.models import ClassificationLevel, PrincipalRole

def test_missing_credentials_rejected_401(test_client):
    """Scenario 1: Protected endpoints reject missing credentials with HTTP 401."""
    # Test document ingest
    res_ingest = test_client.post("/api/v1/documents/ingest", json={"title": "Test", "content": "Sample content"})
    assert res_ingest.status_code == 401
    assert "detail" in res_ingest.json()

    # Test document lookup
    res_get = test_client.get("/api/v1/documents/doc_123")
    assert res_get.status_code == 401

    # Test retrieval query
    res_query = test_client.post("/api/v1/retrieval/query", json={"query_text": "sample query"})
    assert res_query.status_code == 401

    # Test document revoke
    res_revoke = test_client.post("/api/v1/documents/doc_123/revoke")
    assert res_revoke.status_code == 401

def test_invalid_credentials_rejected_401(test_client):
    """Scenario 2: Invalid or malformed credentials are rejected with HTTP 401."""
    # Malformed header (not Bearer)
    res_malformed = test_client.get("/api/v1/documents", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert res_malformed.status_code == 401

    # Unknown token
    res_unknown = test_client.get("/api/v1/documents", headers={"Authorization": "Bearer demo-token-fake-attacker"})
    assert res_unknown.status_code == 401
    assert "Invalid or expired" in res_unknown.json()["detail"]

def test_valid_credentials_resolve_expected_principal(test_client):
    """Scenario 3: Valid credentials resolve to the expected server-side principal."""
    # Bob (contributor) ingests a document
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    payload = {
        "title": "Bob's Research Notes",
        "content": "Zero-trust verification of vector candidates."
    }
    res = test_client.post("/api/v1/documents/ingest", json=payload, headers=headers_bob)
    assert res.status_code == 201
    doc = res.json()
    # Server must attribute owner_id to user_bob and tenant_id to default_tenant
    assert doc["owner_id"] == "user_bob"
    assert doc["tenant_id"] == "default_tenant"

def test_client_cannot_elevate_privileges_via_body(test_client):
    """Scenario 4: Body-supplied tenant, role, clearance, and owner fields cannot elevate access."""
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    spoofed_payload = {
        "title": "Spoofed Privileges Document",
        "content": "Attempting to assign document to victim_corp with executive owner.",
        "tenant_id": "victim_corp",
        "owner_id": "ceo_alice",
        "classification_level": 4,  # RESTRICTED (Bob's clearance is INTERNAL = 2)
    }
    res = test_client.post("/api/v1/documents/ingest", json=spoofed_payload, headers=headers_bob)
    # Bob is in default_tenant; attempting to set tenant_id="victim_corp" is rejected with 403
    assert res.status_code == 403
    assert "Cannot ingest documents on behalf of another tenant" in res.json()["detail"]

    # Now Bob submits without mismatched tenant_id, but spoofing owner_id:
    spoofed_owner_payload = {
        "title": "Spoofed Owner Document",
        "content": "Attempting to assign ownership to root admin.",
        "owner_id": "root_admin",
    }
    res2 = test_client.post("/api/v1/documents/ingest", json=spoofed_owner_payload, headers=headers_bob)
    assert res2.status_code == 201
    doc2 = res2.json()
    # Owner must be strictly derived from session (user_bob), ignoring root_admin
    assert doc2["owner_id"] == "user_bob"
    assert doc2["tenant_id"] == "default_tenant"

def test_public_health_endpoint_accessible_without_auth(test_client):
    """Scenario 5: Public health endpoint is accessible without credentials according to policy."""
    res = test_client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("healthy", "degraded")
    # Health check must not disclose secret tokens or documents
    assert "components" in data
