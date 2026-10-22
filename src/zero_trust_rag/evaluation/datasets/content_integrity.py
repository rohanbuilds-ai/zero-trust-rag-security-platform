"""Content integrity, provenance verification, and safe context assembly dataset (20+ scenarios)."""

from typing import List
from zero_trust_rag.evaluation.models import EvaluationScenario, ScenarioCategory


def get_content_integrity_scenarios() -> List[EvaluationScenario]:
    """
    Returns 22 distinct synthetic content integrity, provenance, and safe context assembly scenarios.
    Covers tampered chunk hashes, parent hash mismatch, missing documents, context budgets,
    XML attribute escaping, embedded CDATA closers, and citation alignment.
    """
    scenarios: List[EvaluationScenario] = []

    integrity_cases = [
        ("INT-001", "tampered_chunk_content_hash", "Chunk content modified in SQLite causes SHA-256 hash mismatch and is dropped"),
        ("INT-002", "parent_hash_version_mismatch", "Chunk parent_hash does not match parent document sha256_hash and is dropped"),
        ("INT-003", "missing_parent_document", "Chunk refers to a non-existent parent document ID and fails closed"),
        ("INT-004", "chunk_budget_max_chunks_limit", "Exceeding max_chunks budget safely drops lower-ranked candidates"),
        ("INT-005", "context_budget_max_chars_limit", "Exceeding max_characters budget truncates or breaks context expansion safely"),
        ("INT-006", "quarantined_chunk_dropped_in_builder", "Candidate chunk belonging to quarantined document is excluded from safe context"),
        ("INT-007", "pending_review_chunk_dropped_in_builder", "Candidate chunk awaiting review is excluded from safe context passages"),
        ("INT-008", "revoked_chunk_with_stale_vector_dropped", "Revoked document chunk returned by stale vector search is excluded"),
        ("INT-009", "citation_source_alignment_tampered_candidate", "When candidate 0 fails hash verification, citations strictly match accepted candidate 1"),
        ("INT-010", "citation_source_alignment_budget_cutoff", "When candidate 2 is dropped due to budget, citations match accepted candidates 0 and 1 only"),
        ("INT-011", "xml_attribute_double_quote_escaping", "Passage ID containing double quotes is safely escaped in XML attributes"),
        ("INT-012", "xml_attribute_ampersand_escaping", "Document title and ID containing ampersands are safely quoted and escaped"),
        ("INT-013", "xml_attribute_angle_bracket_escaping", "Document title containing <script> is safely escaped in XML attributes"),
        ("INT-014", "cdata_closer_defanging", "Untrusted text containing CDATA closer ']]>' is defanged to ']] >'"),
        ("INT-015", "multiple_cdata_closers_defanged", "Untrusted text containing ']]>]]>' multiple closers is completely defanged"),
        ("INT-016", "provenance_hash_integrity_in_citations", "Returned citations expose cryptographic provenance SHA-256 chunk hash"),
        ("INT-017", "dlp_sanitized_consistency_in_citations", "Citations content matches safe_context passages after DLP redaction"),
        ("INT-018", "raw_context_content_consistency", "Raw context string contains identical sanitized passages as safe_context envelope"),
        ("INT-019", "empty_candidate_list_safe_envelope", "ContextBuilder handles empty candidate list returning zero passages and valid envelope"),
        ("INT-020", "duplicate_candidate_chunk_ids_handled", "Duplicate chunk IDs in candidates list handled safely without corruption"),
        ("INT-021", "dlp_failure_fails_closed_in_retrieval", "DLP internal exception fails closed with fallback placeholder"),
        ("INT-022", "unmapped_passage_fails_closed", "Passage that cannot be mapped to verified candidate source is omitted"),
    ]

    for case_id, sub, desc in integrity_cases:
        scenarios.append(
            EvaluationScenario(
                case_id=case_id,
                category=ScenarioCategory.CONTENT_INTEGRITY,
                subcategory=sub,
                description=desc,
                input_data={"scenario_type": sub},
                expected_outcome={
                    "tamper_rejected": True,
                    "zero_unauthorized_disclosed": True,
                    "citation_integrity_verified": True,
                },
                tags=["content_integrity", "safe_context"],
            )
        )

    return scenarios
