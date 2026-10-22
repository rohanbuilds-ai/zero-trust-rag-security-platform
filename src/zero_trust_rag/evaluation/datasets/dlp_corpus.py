"""Data Loss Prevention (DLP) and sensitive-data evaluation dataset (30+ scenarios)."""

from typing import List
from zero_trust_rag.evaluation.models import EvaluationScenario, ScenarioCategory


def get_dlp_scenarios() -> List[EvaluationScenario]:
    """
    Returns 32 distinct synthetic DLP scenarios covering positive detections
    (SSNs, Luhn CCs, API keys, JWTs, synthetic tokens, zero-width obfuscated secrets, nested objects)
    and negative controls (benign numbers, order IDs, dates, SKUs, normal documentation).
    """
    scenarios: List[EvaluationScenario] = []

    # ------------------------------------------------------------------------
    # 1. Social Security Numbers (DLP-001 to DLP-006)
    # ------------------------------------------------------------------------
    ssn_cases = [
        ("DLP-001", "standard_hyphen_ssn", "Employee record for John Doe SSN 123-45-6789 active.", "SSN", "[REDACTED_SSN]", 1),
        ("DLP-002", "space_delimited_ssn", "Contractor tax ID record SSN 219 65 4320 logged.", "SSN", "[REDACTED_SSN]", 1),
        ("DLP-003", "multiple_ssns_in_table", "Row 1: 111-22-3333\nRow 2: 444-55-6666\nRow 3: 777-88-9999", "SSN", "[REDACTED_SSN]", 3),
        ("DLP-004", "zero_width_space_in_ssn_separator", "Taxpayer reference: 123\u200b-45-6789 on file.", "SSN", "[REDACTED_SSN]", 1),
        ("DLP-005", "zero_width_in_ssn_digits", "Payroll record: 1\u200b23-4\u200c5-678\u200d9 confirmed.", "SSN", "[REDACTED_SSN]", 1),
        ("DLP-006", "soft_hyphen_ssn", "HR record: 321\u00ad-65-4321 archived.", "SSN", "[REDACTED_SSN]", 1),
    ]
    for case_id, sub, text, cat, marker, count in ssn_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.DLP_SENSITIVE_DATA,
                subcategory="ssn_detection",
                description=f"SSN redaction test: {sub}",
                input_data={"content": text, "expected_category": cat},
                expected_outcome={
                    "expected_redaction_count": count,
                    "expected_marker": marker,
                    "zero_unredacted_leaked": True,
                },
                tags=["dlp", "ssn"],
            )
        )

    # ------------------------------------------------------------------------
    # 2. Luhn-Valid Credit Cards (DLP-007 to DLP-012)
    # ------------------------------------------------------------------------
    cc_cases = [
        ("DLP-007", "valid_visa_16_digit", "Customer payment card Visa: 4111-1111-1111-1111 charged.", "CREDIT_CARD", "[REDACTED_CREDIT_CARD]", 1),
        ("DLP-008", "valid_mastercard_16_digit", "Cardholder account: 5555 5555 5555 4444 verified.", "CREDIT_CARD", "[REDACTED_CREDIT_CARD]", 1),
        ("DLP-009", "valid_amex_15_digit", "Amex corporate expense card: 3782-822463-10005 billed.", "CREDIT_CARD", "[REDACTED_CREDIT_CARD]", 1),
        ("DLP-010", "valid_cc_continuous_digits", "Payment gateway log: card=4111111111111111 authorized.", "CREDIT_CARD", "[REDACTED_CREDIT_CARD]", 1),
        ("DLP-011", "zero_width_obfuscated_credit_card", "Billing record: 4111\u200b1111\u200b1111\u200b1111 processed.", "CREDIT_CARD", "[REDACTED_CREDIT_CARD]", 1),
        ("DLP-012", "multiple_credit_cards", "Accounts: 4111-1111-1111-1111 and 5555-5555-5555-4444.", "CREDIT_CARD", "[REDACTED_CREDIT_CARD]", 2),
    ]
    for case_id, sub, text, cat, marker, count in cc_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.DLP_SENSITIVE_DATA,
                subcategory="credit_card_detection",
                description=f"Luhn-valid credit card test: {sub}",
                input_data={"content": text, "expected_category": cat},
                expected_outcome={
                    "expected_redaction_count": count,
                    "expected_marker": marker,
                    "zero_unredacted_leaked": True,
                },
                tags=["dlp", "credit_card"],
            )
        )

    # ------------------------------------------------------------------------
    # 3. API Keys, Tokens & Cloud Credentials (DLP-013 to DLP-020)
    # ------------------------------------------------------------------------
    credential_cases = [
        ("DLP-013", "aws_access_key_standard", "Cloud sync credentials: AWS_KEY=AKIAIOSFODNN7EXAMPLE active.", "API_KEY", "[REDACTED_API_KEY]", 1),
        ("DLP-014", "aws_key_zero_width", "Cloud sync credentials: AWS_KEY=AKIA\u200bIOSFODNN7EXAMPLE active.", "API_KEY", "[REDACTED_API_KEY]", 1),
        ("DLP-015", "jwt_bearer_token", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzTqOmvV_m_example token.", "BEARER_TOKEN", "[REDACTED_BEARER_TOKEN]", 1),
        ("DLP-016", "synthetic_test_secret", "Config setting: secret_token = TEST_SECRET_PRODUCTION_BACKEND_KEY.", "TEST_SECRET", "[REDACTED_SECRET]", 1),
        ("DLP-017", "stripe_live_key", "Payment gateway config: sk_live_123456789012345678901234 active.", "TEST_SECRET", "[REDACTED_SECRET]", 1),
        ("DLP-018", "github_personal_token", "CI deployment token: ghp_123456789012345678901234567890123456 configured.", "TEST_SECRET", "[REDACTED_SECRET]", 1),
        ("DLP-019", "generic_key_assignment", 'Configuration: api_key: "abcdef1234567890abcdef1234567890"', "API_KEY", "[REDACTED_API_KEY]", 1),
        ("DLP-020", "generic_secret_key_assignment", 'Settings: secret_key: "xyz9876543210zyx9876543210"', "API_KEY", "[REDACTED_API_KEY]", 1),
    ]
    for case_id, sub, text, cat, marker, count in credential_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.DLP_SENSITIVE_DATA,
                subcategory="credential_detection",
                description=f"Credential & API key redaction: {sub}",
                input_data={"content": text, "expected_category": cat},
                expected_outcome={
                    "expected_redaction_count": count,
                    "expected_marker": marker,
                    "zero_unredacted_leaked": True,
                },
                tags=["dlp", "credentials"],
            )
        )

    # ------------------------------------------------------------------------
    # 4. Structured & Nested Context Objects (DLP-021 to DLP-024)
    # ------------------------------------------------------------------------
    nested_cases = [
        ("DLP-021", "nested_dict_redaction", {"user": {"ssn": "123-45-6789", "name": "Alice"}}, 1),
        ("DLP-022", "nested_list_of_records", {"records": [{"card": "4111-1111-1111-1111"}, {"card": "5555-5555-5555-4444"}]}, 2),
        ("DLP-023", "mixed_nested_credentials", {"cloud": {"key": "AKIAIOSFODNN7EXAMPLE", "secret": "TEST_SECRET_ABC"}}, 2),
        ("DLP-024", "deep_json_tree", {"a": {"b": {"c": [{"d": "123-45-6789"}]}}}, 1),
    ]
    for case_id, sub, nested_obj, count in nested_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.DLP_SENSITIVE_DATA,
                subcategory="nested_structure",
                description=f"Recursive DLP redaction on structured object: {sub}",
                input_data={"nested_object": nested_obj},
                expected_outcome={
                    "expected_redaction_count": count,
                    "zero_unredacted_leaked": True,
                },
                tags=["dlp", "nested"],
            )
        )

    # ------------------------------------------------------------------------
    # 5. Benign Negative Controls (DLP-025 to DLP-032)
    # ------------------------------------------------------------------------
    benign_cases = [
        ("DLP-025", "order_number", "Shipping Notice: Order reference #ORD-98421102 has been dispatched.", 0),
        ("DLP-026", "iso_timestamp", "System event timestamp: 2026-10-22T14:30:00Z recorded in audit ledger.", 0),
        ("DLP-027", "git_commit_sha", "Deployment build commit: git sha a1b2c3d4e5f6789012345678 successfully tested.", 0),
        ("DLP-028", "product_sku_and_price", "Item SKU: PROD-789-012, Quantity: 5, Unit Price: $49.99.", 0),
        ("DLP-029", "phone_number_format", "Customer support helpline: (800) 555-0199 available 24/7.", 0),
        ("DLP-030", "invoice_reference", "Vendor billing ref INV-2026-88741 balance due $1,450.00.", 0),
        ("DLP-031", "invalid_luhn_credit_card", "Fake card number failing Luhn check: 4532-0150-1234-5679 not redacted.", 0),
        ("DLP-032", "clean_business_report", "Annual report indicates operating margins improved 3.2% year-over-year.", 0),
    ]
    for case_id, sub, text, count in benign_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.DLP_SENSITIVE_DATA,
                subcategory="benign_negative_controls",
                description=f"Benign content preserving formatting: {sub}",
                input_data={"content": text, "is_benign": True},
                expected_outcome={
                    "expected_redaction_count": 0,
                    "zero_false_redactions": True,
                },
                tags=["dlp", "benign_control"],
            )
        )

    return scenarios
