"""Security tests for Data Loss Prevention (DLP), sensitive-data redaction, and audit privacy."""

import pytest
from zero_trust_rag.security.dlp import DataLossPreventionEngine, luhn_checksum_valid

@pytest.fixture
def dlp():
    return DataLossPreventionEngine()

def test_ssn_redaction(dlp):
    """Scenario 22: Synthetic SSN is redacted before response is returned."""
    sample = "Employee tax identifier is 123-45-6789 for payroll records."
    redacted, count, categories = dlp.redact_text(sample)
    assert count == 1
    assert "123-45-6789" not in redacted
    assert "[REDACTED_SSN]" in redacted
    assert categories["SSN"] == 1

def test_luhn_valid_credit_card_redaction(dlp):
    """Scenario 23: Synthetic Luhn-valid credit card numbers are redacted."""
    # Canonical Visa test card 4111-1111-1111-1111 is strictly Luhn-valid
    card_number = "4111-1111-1111-1111"
    assert luhn_checksum_valid(card_number)

    sample = f"Payment processed on customer card {card_number} successfully."
    redacted, count, categories = dlp.redact_text(sample)
    assert count == 1
    assert card_number not in redacted
    assert "[REDACTED_CREDIT_CARD]" in redacted
    assert categories["CREDIT_CARD"] == 1

def test_api_keys_and_bearer_tokens_redacted(dlp):
    """Scenario 24: Recognizable API keys and bearer tokens are redacted."""
    sample = (
        "AWS credentials: AKIAIOSFODNN7EXAMPLE.\n"
        "Session bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c.\n"
        "Test secret token: TEST_SECRET_ALPHA99_KEY."
    )
    redacted, count, categories = dlp.redact_text(sample)
    assert count == 3
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_API_KEY]" in redacted
    assert "[REDACTED_BEARER_TOKEN]" in redacted
    assert "[REDACTED_SECRET]" in redacted

def test_nested_structure_recursive_redaction(dlp):
    """Scenario 25: Nested response content (dicts/lists) is recursively inspected and redacted."""
    nested_data = {
        "status": "success",
        "records": [
            {"id": 1, "note": "SSN is 219-65-4321 for client."},
            {"id": 2, "credentials": {"key": "AKIA1111222233334444"}},
        ],
        "meta": {"tags": ["finance", "payment: 4111-1111-1111-1111"]}
    }
    sanitized, count, categories = dlp.inspect_and_redact_object(nested_data)
    assert count == 3
    assert "219-65-4321" not in str(sanitized)
    assert "AKIA1111222233334444" not in str(sanitized)
    assert "4111-1111-1111-1111" not in str(sanitized)
    assert "[REDACTED_SSN]" in sanitized["records"][0]["note"]
    assert "[REDACTED_API_KEY]" in sanitized["records"][1]["credentials"]["key"]
    assert "[REDACTED_CREDIT_CARD]" in sanitized["meta"]["tags"][1]

def test_normal_content_preserved_without_unnecessary_redaction(dlp):
    """Scenario 26: Normal content (numeric IDs, dates, phone numbers) remains readable."""
    normal_text = (
        "Order #987654321 was confirmed on 2026-10-22. "
        "User tracking ID is 1234567890. "
        "Total invoice amount is $450.00 with standard 15% discount."
    )
    sanitized, count, categories = dlp.redact_text(normal_text)
    assert count == 0
    assert sanitized == normal_text

def test_multiple_sensitive_values_counted_correctly(dlp):
    """Scenario 27: Multiple sensitive values in a single string are all redacted and counted."""
    text = (
        "Customer records:\n"
        "Alice: SSN 111-22-3333, Card 4111 1111 1111 1111\n"
        "Bob: SSN 444-55-6666, Key AKIA9999888877776666"
    )
    sanitized, count, categories = dlp.redact_text(text)
    assert count == 4
    assert categories["SSN"] == 2
    assert categories["CREDIT_CARD"] == 1
    assert categories["API_KEY"] == 1

def test_dlp_failure_fails_closed(dlp):
    """Scenario 28: DLP failure never returns uninspected sensitive payload."""
    class DummyFailingPattern:
        def sub(self, *args, **kwargs):
            raise RuntimeError("DLP Engine Internal Crash")

    dlp._ssn_pattern = DummyFailingPattern()

    sanitized, count, categories = dlp.redact_text("Secret SSN 123-45-6789")
    # Fail closed: must return safe error token, NEVER raw text
    assert "123-45-6789" not in sanitized
    assert sanitized == "[DLP_INSPECTION_FAILED]"
    assert count == 1

def test_logs_and_audits_do_not_contain_plaintext_secrets(test_client):
    """Scenario 29: Logs and audit records do not contain original sensitive values."""
    headers_bob = {"Authorization": "Bearer demo-token-bob-contrib"}
    # Ingest document containing SSN
    test_client.post(
        "/api/v1/documents/ingest",
        json={"title": "Client Tax Notes", "content": "Tax filing with SSN 333-22-1111.", "is_public": True},
        headers=headers_bob
    )

    # Query for tax notes
    headers_alice = {"Authorization": "Bearer demo-token-alice-reader"}
    query_res = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "tax filing client records", "top_k": 2},
        headers=headers_alice
    )
    assert query_res.status_code == 200
    res_data = query_res.json()
    # Egress text is redacted
    assert "333-22-1111" not in str(query_res.content)
    assert "[REDACTED_SSN]" in res_data["raw_context"]

    # Check audit events
    headers_admin = {"Authorization": "Bearer demo-token-charlie-admin"}
    events_res = test_client.get("/api/v1/audit/events", headers=headers_admin)
    assert events_res.status_code == 200
    events = events_res.json()
    # Audit log must contain zero plain SSNs
    for event in events:
        assert "333-22-1111" not in str(event)

def test_dlp_cannot_bypass_authorization_precedence(test_client):
    """
    Scenario 30 (Audit Finding): DLP is applied strictly AFTER authoritative authorization.
    An unauthorized user querying for confidential documents containing PII is completely
    denied at Stage 2 (0 chunks returned, 0 citations). DLP is never used to justify
    returning unauthorized content in redacted form.
    """
    headers_admin = {"Authorization": "Bearer demo-token-charlie-admin"}
    headers_reader = {"Authorization": "Bearer demo-token-alice-reader"}

    # 1. Admin ingests a classified CONFIDENTIAL document containing PII/Secrets
    ingest_res = test_client.post(
        "/api/v1/documents/ingest",
        json={
            "title": "Executive Payroll & Compensation Record",
            "content": "Confidential executive Jane Doe salary: SSN 219-45-6789, Card 4111-1111-1111-1111.",
            "is_public": False,
            "classification_level": 3,  # CONFIDENTIAL
        },
        headers=headers_admin,
    )
    assert ingest_res.status_code == 201

    # 2. Reader Alice (clearance INTERNAL = 2) queries for the confidential document
    query_unauth = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "Confidential executive Jane Doe salary SSN", "top_k": 3},
        headers=headers_reader,
    )
    assert query_unauth.status_code == 200
    unauth_data = query_unauth.json()
    # CRITICAL: Must be rejected authoritatively at Stage 2. Must NOT return redacted content!
    assert unauth_data["chunks_returned"] == 0
    assert len(unauth_data["citations"]) == 0
    assert not unauth_data["raw_context"]
    assert "219-45-6789" not in str(query_unauth.content)

    # 3. Admin (clearance CONFIDENTIAL = 3) queries the same document
    query_auth = test_client.post(
        "/api/v1/retrieval/query",
        json={"query_text": "Confidential executive Jane Doe salary SSN", "top_k": 3},
        headers=headers_admin,
    )
    assert query_auth.status_code == 200
    auth_data = query_auth.json()
    # Authorized user receives content, but with DLP redaction applied before egress
    assert auth_data["chunks_returned"] > 0
    assert "219-45-6789" not in str(query_auth.content)
    assert "4111-1111-1111-1111" not in str(query_auth.content)
    assert "[REDACTED_SSN]" in auth_data["raw_context"]
    assert "[REDACTED_CREDIT_CARD]" in auth_data["raw_context"]
