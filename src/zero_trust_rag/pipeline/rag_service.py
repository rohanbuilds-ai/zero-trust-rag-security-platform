"""Core RAG service coordinating ingestion, trust inspection, safe context assembly, and DLP."""

import uuid
import hashlib
import datetime
from typing import Optional, List, Tuple, Dict, Any

from zero_trust_rag.core.models import (
    DocumentIngestRequest,
    DocumentRecord,
    ChunkRecord,
    DocumentStatus,
    ClassificationLevel,
    TrustStatus,
    SourceType,
    InspectionOutcome,
    PrincipalContext,
    PrincipalRole,
    RetrievalQueryRequest,
    RetrievalQueryResponse,
    RetrievedChunkCitation,
    SafeContextEnvelope,
)
from zero_trust_rag.pipeline.chunker import DeterministicChunker
from zero_trust_rag.pipeline.embeddings import BaseEmbeddingEngine, get_embedding_engine
from zero_trust_rag.pipeline.context_builder import ContextBuilder, format_xml_envelope
from zero_trust_rag.security.document_inspector import DocumentInspector
from zero_trust_rag.security.dlp import DataLossPreventionEngine
from zero_trust_rag.storage.database import AuthoritativeDatabase
from zero_trust_rag.storage.vector_store import BaseVectorStore, get_vector_store
from zero_trust_rag.core.config import settings

class RAGService:
    """Coordinates document ingestion, trust inspection, vector indexing, two-stage authorization, and DLP."""

    def __init__(
        self,
        database: Optional[AuthoritativeDatabase] = None,
        vector_store: Optional[BaseVectorStore] = None,
        embedding_engine: Optional[BaseEmbeddingEngine] = None,
        chunker: Optional[DeterministicChunker] = None,
        inspector: Optional[DocumentInspector] = None,
        context_builder: Optional[ContextBuilder] = None,
        dlp_engine: Optional[DataLossPreventionEngine] = None,
    ):
        self.db = database or AuthoritativeDatabase()
        self.vector_store = vector_store or get_vector_store()
        self.embedding_engine = embedding_engine or get_embedding_engine(use_mock=settings.use_mock_embeddings)
        self.chunker = chunker or DeterministicChunker(
            chunk_size=settings.default_chunk_size,
            chunk_overlap=settings.default_chunk_overlap
        )
        self.inspector = inspector or DocumentInspector(max_length=settings.max_document_characters)
        self.context_builder = context_builder or ContextBuilder(max_chunks=8, max_characters=8000)
        self.dlp_engine = dlp_engine or DataLossPreventionEngine()

    def ingest_document(
        self,
        request: DocumentIngestRequest,
        principal: Optional[PrincipalContext] = None
    ) -> DocumentRecord:
        """
        Ingest, inspect for suspicious content, chunk, store authoritatively with provenance,
        and index vector embeddings.
        Client cannot assert trusted status or spoof server-controlled provenance.
        """
        doc_id = f"doc_{uuid.uuid4().hex[:12]}"
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
        content_hash = hashlib.sha256(request.content.encode("utf-8")).hexdigest()

        # Authoritative identity resolution
        if principal:
            tenant_id = principal.tenant_id
            owner_id = principal.principal_id
        else:
            tenant_id = request.tenant_id or "default_tenant"
            owner_id = request.owner_id or "system_admin"

        # Step 1: Suspicious content and prompt injection inspection
        inspection = self.inspector.inspect(request.content)

        # Step 2: Server-side trust assignment
        if inspection.outcome == InspectionOutcome.SUSPICIOUS:
            doc_status = DocumentStatus.QUARANTINED
            trust_status = TrustStatus.QUARANTINED
            self.db.log_audit_event(
                event_type="SUSPICIOUS_DOCUMENT_DETECTED",
                principal_id=owner_id,
                tenant_id=tenant_id,
                decision="DENY",
                reason_code="POISONING_OR_INJECTION_DETECTED",
                document_id=doc_id,
                details={
                    "rule_ids": [f.rule_id for f in inspection.findings],
                    "severities": [f.severity for f in inspection.findings],
                }
            )
            self.db.log_audit_event(
                event_type="DOCUMENT_QUARANTINED",
                principal_id=owner_id,
                tenant_id=tenant_id,
                decision="DENY",
                reason_code="AUTOMATIC_INSPECTION_QUARANTINE",
                document_id=doc_id
            )
        elif inspection.outcome == InspectionOutcome.INSPECTION_ERROR:
            doc_status = DocumentStatus.QUARANTINED
            trust_status = TrustStatus.QUARANTINED
            self.db.log_audit_event(
                event_type="DOCUMENT_QUARANTINED",
                principal_id=owner_id,
                tenant_id=tenant_id,
                decision="DENY",
                reason_code="INSPECTION_ERROR_FAIL_CLOSED",
                document_id=doc_id
            )
        else:
            # Inspection is CLEAN
            doc_status = DocumentStatus.ACTIVE
            if request.request_review:
                trust_status = TrustStatus.PENDING_REVIEW
            else:
                trust_status = TrustStatus.TRUSTED

            self.db.log_audit_event(
                event_type="DOCUMENT_INSPECTION_COMPLETED",
                principal_id=owner_id,
                tenant_id=tenant_id,
                decision="PERMIT",
                reason_code="INSPECTION_CLEAN",
                document_id=doc_id,
                details={"detector_version": inspection.detector_version}
            )

        # Build provenance record
        provenance = {
            "ingested_by": owner_id,
            "ingested_at": now_str,
            "content_hash": content_hash,
            "source_type": SourceType.LOCAL_UPLOAD.value,
            "detector_version": inspection.detector_version,
            "findings_count": len(inspection.findings)
        }

        # Step 3: Chunk content deterministically
        raw_chunks = self.chunker.chunk_text(request.content)
        chunk_count = len(raw_chunks)

        # Step 4: Create authoritative document record
        doc_record = DocumentRecord(
            document_id=doc_id,
            tenant_id=tenant_id,
            owner_id=owner_id,
            title=request.title,
            sha256_hash=content_hash,
            classification_level=request.classification_level,
            status=doc_status,
            trust_score=0.1 if trust_status == TrustStatus.QUARANTINED else 1.0,
            trust_status=trust_status,
            source_type=SourceType.LOCAL_UPLOAD,
            inspection_status=inspection.outcome,
            provenance_json=provenance,
            is_public=request.is_public,
            chunk_count=chunk_count,
            created_at=now_str,
            updated_at=now_str,
        )
        self.db.insert_document(doc_record)

        if not raw_chunks:
            return doc_record

        # Step 5: Create authoritative chunk records with parent_hash link
        chunk_records: List[ChunkRecord] = []
        chunk_texts: List[str] = []
        for rc in raw_chunks:
            c_id = f"chk_{doc_id}_{rc['chunk_index']}"
            chunk_rec = ChunkRecord(
                chunk_id=c_id,
                document_id=doc_id,
                tenant_id=tenant_id,
                chunk_index=rc["chunk_index"],
                token_count=rc["token_count"],
                content=rc["content"],
                content_hash=rc["content_hash"],
                parent_hash=content_hash,
                classification_level=request.classification_level,
                status=doc_status,
            )
            chunk_records.append(chunk_rec)
            chunk_texts.append(rc["content"])

        self.db.insert_chunks(chunk_records)

        # Step 6: Generate vector embeddings and index in vector store
        embeddings = self.embedding_engine.embed_batch(chunk_texts)
        self.vector_store.add_chunks(chunk_records, embeddings)

        self.db.log_audit_event(
            event_type="DOCUMENT_INGESTED",
            principal_id=owner_id,
            tenant_id=tenant_id,
            decision="PERMIT" if doc_status == DocumentStatus.ACTIVE else "DENY",
            reason_code="INGESTION_COMPLETED",
            document_id=doc_id,
            details={
                "title": request.title,
                "chunk_count": chunk_count,
                "trust_status": trust_status.value,
                "status": doc_status.value
            }
        )

        return doc_record

    def retrieve(
        self,
        request: RetrievalQueryRequest,
        principal: Optional[PrincipalContext] = None
    ) -> RetrievalQueryResponse:
        """
        Execute two-stage authorized retrieval, safe context assembly, and DLP redaction:
          - Stage 1: Pre-retrieval tenant-scoping and bounded candidate over-fetch.
          - Stage 2: Authoritative post-retrieval verification against SQLite (lifecycle, clearance, ACL, trust).
          - Stage 3: Structured XML safe context construction.
          - Stage 4: DLP sensitive-data redaction.
        """
        if principal:
            tenant_id = principal.tenant_id
            user_id = principal.principal_id
            role = principal.role
            clearance = principal.clearance_level
        else:
            tenant_id = request.tenant_id or "default_tenant"
            user_id = "system_admin"
            role = PrincipalRole.TENANT_ADMIN
            clearance = ClassificationLevel.RESTRICTED

        query_emb = self.embedding_engine.embed_text(request.query_text)

        # Stage 1: Pre-retrieval scoping with bounded candidate over-fetch
        target_top_k = request.top_k
        candidate_limit = min(max(target_top_k * 3, 10), 50)

        candidates = self.vector_store.query_similar(
            query_embedding=query_emb,
            top_k=candidate_limit,
            tenant_filter=tenant_id
        )

        total_candidates = len(candidates)
        verified_candidates: List[Tuple[ChunkRecord, DocumentRecord, float]] = []

        # Stage 2: Authoritative post-retrieval verification against SQLite
        try:
            for chunk_id, sim in candidates:
                if len(verified_candidates) >= target_top_k:
                    break

                if sim < request.min_similarity:
                    continue

                chunk = self.db.get_chunk(chunk_id)
                if not chunk:
                    self.db.log_audit_event(
                        event_type="RETRIEVAL_CANDIDATE_DROPPED",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code="ORPHAN_CHUNK_NOT_IN_SQLITE",
                        chunk_id=chunk_id,
                        query_text=request.query_text
                    )
                    continue

                doc = self.db.get_document(chunk.document_id)
                if not doc:
                    self.db.log_audit_event(
                        event_type="RETRIEVAL_CANDIDATE_DROPPED",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code="PARENT_DOCUMENT_NOT_FOUND",
                        document_id=chunk.document_id,
                        chunk_id=chunk_id,
                        query_text=request.query_text
                    )
                    continue

                # Verify tenant boundary
                if chunk.tenant_id != tenant_id or doc.tenant_id != tenant_id:
                    self.db.log_audit_event(
                        event_type="CROSS_TENANT_LEAKAGE_PREVENTED",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code="TENANT_MISMATCH",
                        document_id=doc.document_id,
                        chunk_id=chunk.chunk_id,
                        query_text=request.query_text
                    )
                    continue

                # Verify chunk-to-parent consistency
                if chunk.document_id != doc.document_id:
                    self.db.log_audit_event(
                        event_type="CONTENT_INTEGRITY_MISMATCH",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code="INCONSISTENT_CHUNK_PARENT",
                        document_id=doc.document_id,
                        chunk_id=chunk.chunk_id,
                        query_text=request.query_text
                    )
                    continue

                # Verify lifecycle state (ACTIVE only)
                if doc.status != DocumentStatus.ACTIVE or chunk.status != DocumentStatus.ACTIVE:
                    self.db.log_audit_event(
                        event_type="STALE_REVOKED_VECTOR_BLOCKED",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code="DOCUMENT_REVOKED_OR_INACTIVE",
                        document_id=doc.document_id,
                        chunk_id=chunk.chunk_id,
                        query_text=request.query_text
                    )
                    continue

                # Phase 3: Verify Trust Status (TRUSTED only)
                if doc.trust_status != TrustStatus.TRUSTED:
                    self.db.log_audit_event(
                        event_type="CONTEXT_CHUNK_REJECTED",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code=f"DOCUMENT_TRUST_STATUS_{doc.trust_status.value}",
                        document_id=doc.document_id,
                        chunk_id=chunk.chunk_id,
                        query_text=request.query_text
                    )
                    continue

                # Verify clearance level
                if doc.classification_level > clearance:
                    self.db.log_audit_event(
                        event_type="INSUFFICIENT_CLEARANCE_BLOCKED",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code="CLEARANCE_EXCEEDED",
                        document_id=doc.document_id,
                        chunk_id=chunk.chunk_id,
                        query_text=request.query_text
                    )
                    continue

                # Verify document ACL / ownership
                is_authorized = False
                if role in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN):
                    is_authorized = True
                elif doc.owner_id == user_id:
                    is_authorized = True
                elif doc.is_public:
                    is_authorized = True
                else:
                    is_authorized = self.db.check_document_acl(
                        document_id=doc.document_id,
                        principal_id=user_id,
                        role=role.value if hasattr(role, "value") else str(role)
                    )

                if not is_authorized:
                    self.db.log_audit_event(
                        event_type="DOCUMENT_ACL_DENIED",
                        principal_id=user_id,
                        tenant_id=tenant_id,
                        decision="DENY",
                        reason_code="NO_MATCHING_ACL_RULE",
                        document_id=doc.document_id,
                        chunk_id=chunk.chunk_id,
                        query_text=request.query_text
                    )
                    continue

                verified_candidates.append((chunk, doc, sim))

        except Exception as exc:
            self.db.log_audit_event(
                event_type="RETRIEVAL_VERIFICATION_FAILURE",
                principal_id=user_id,
                tenant_id=tenant_id,
                decision="DENY",
                reason_code="DATABASE_ERROR_FAIL_CLOSED",
                query_text=request.query_text,
                details={"error": str(exc)}
            )
            return RetrievalQueryResponse(
                total_candidates_found=total_candidates,
                chunks_returned=0,
                citations=[],
                raw_context="",
                safe_context=None,
                total_redactions=0
            )

        # Stage 3: Safe Context Construction
        safe_envelope = self.context_builder.build_safe_context(verified_candidates)

        # Stage 4: Response Data Loss Prevention (DLP Redaction)
        total_dlp_redactions = 0
        raw_context_parts: List[str] = []
        citations: List[RetrievedChunkCitation] = []

        # Sanitize safe envelope passages
        for passage in safe_envelope.passages:
            sanitized_text, r_count, _ = self.dlp_engine.redact_text(passage.untrusted_content)
            passage.untrusted_content = sanitized_text
            passage.is_sanitized = True
            passage.redaction_count = r_count
            total_dlp_redactions += r_count

        # Re-build sanitized envelope string safely using attribute-escaped helper
        safe_envelope.formatted_envelope = format_xml_envelope(
            safe_envelope.context_id, safe_envelope.passages
        )

        # Build candidate lookup map by chunk_id for deterministic passage matching
        candidate_map: Dict[str, Tuple[ChunkRecord, DocumentRecord, float]] = {
            chunk.chunk_id: (chunk, doc, sim) for (chunk, doc, sim) in verified_candidates
        }

        # Build citations and raw context strictly from the accepted safe passages
        for passage in safe_envelope.passages:
            if passage.passage_id not in candidate_map:
                # If an accepted passage cannot be mapped unambiguously to its verified source, omit it (fail closed)
                continue

            chunk, doc, sim = candidate_map[passage.passage_id]

            # Ensure DLP-redacted content is used consistently in every user-visible response field
            citation = RetrievedChunkCitation(
                chunk_id=chunk.chunk_id,
                document_id=chunk.document_id,
                document_title=doc.title,
                chunk_index=chunk.chunk_index,
                similarity_score=round(sim, 4),
                content=passage.untrusted_content,
                provenance_hash=chunk.content_hash,
                classification_level=chunk.classification_level,
                status=chunk.status,
                trust_status=doc.trust_status,
                tenant_id=chunk.tenant_id,
                redaction_count=passage.redaction_count,
            )
            citations.append(citation)
            raw_context_parts.append(f"[Source: {doc.title} (ID: {chunk.chunk_id})]\n{passage.untrusted_content}")

        raw_context = "\n\n---\n\n".join(raw_context_parts) if raw_context_parts else ""

        if total_dlp_redactions > 0:
            self.db.log_audit_event(
                event_type="DLP_REDACTION_APPLIED",
                principal_id=user_id,
                tenant_id=tenant_id,
                decision="PERMIT",
                reason_code="SENSITIVE_DATA_REDACTED",
                query_text=request.query_text,
                details={"total_redactions": total_dlp_redactions}
            )

        self.db.log_audit_event(
            event_type="RETRIEVAL_QUERY",
            principal_id=user_id,
            tenant_id=tenant_id,
            decision="PERMIT",
            reason_code="SUCCESS",
            query_text=request.query_text,
            details={
                "top_k_requested": target_top_k,
                "candidates_inspected": total_candidates,
                "chunks_returned": len(citations),
                "total_redactions": total_dlp_redactions
            }
        )

        return RetrievalQueryResponse(
            total_candidates_found=total_candidates,
            chunks_returned=len(citations),
            citations=citations,
            raw_context=raw_context,
            safe_context=safe_envelope,
            total_redactions=total_dlp_redactions
        )

    def revoke_document(
        self,
        document_id: str,
        principal: Optional[PrincipalContext] = None
    ) -> bool:
        doc = self.db.get_document(document_id)
        if not doc:
            return False

        if principal:
            if doc.tenant_id != principal.tenant_id:
                self.db.log_audit_event(
                    event_type="UNAUTHORIZED_REVOCATION_ATTEMPT",
                    principal_id=principal.principal_id,
                    tenant_id=principal.tenant_id,
                    decision="DENY",
                    reason_code="CROSS_TENANT_REVOCATION_BLOCKED",
                    document_id=document_id
                )
                return False

            is_permitted = (
                principal.role in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN)
                or doc.owner_id == principal.principal_id
            )
            if not is_permitted:
                self.db.log_audit_event(
                    event_type="UNAUTHORIZED_REVOCATION_ATTEMPT",
                    principal_id=principal.principal_id,
                    tenant_id=principal.tenant_id,
                    decision="DENY",
                    reason_code="INSUFFICIENT_PERMISSIONS_TO_REVOKE",
                    document_id=document_id
                )
                return False

        success = self.db.update_document_status(document_id, DocumentStatus.REVOKED)
        if not success:
            return False

        try:
            self.vector_store.delete_by_document(document_id)
        except Exception as exc:
            self.db.log_audit_event(
                event_type="VECTOR_CLEANUP_FAILED",
                principal_id=principal.principal_id if principal else "system",
                tenant_id=doc.tenant_id,
                decision="DENY",
                reason_code="VECTOR_DELETE_ERROR",
                document_id=document_id,
                details={"error": str(exc)}
            )

        self.db.log_audit_event(
            event_type="DOCUMENT_REVOKED",
            principal_id=principal.principal_id if principal else "system",
            tenant_id=doc.tenant_id,
            decision="PERMIT",
            reason_code="REVOCATION_SUCCESS",
            document_id=document_id
        )

        return True

    def approve_document(
        self,
        document_id: str,
        principal: PrincipalContext
    ) -> bool:
        """Tenant Administrator approval workflow transitioning PENDING_REVIEW or QUARANTINED to TRUSTED."""
        doc = self.db.get_document(document_id)
        if not doc or doc.tenant_id != principal.tenant_id:
            return False

        if principal.role not in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN):
            return False

        # Invariant: Never approve or reactivate a REVOKED document
        if doc.status == DocumentStatus.REVOKED:
            return False

        # Only documents in PENDING_REVIEW or QUARANTINED can be approved
        if doc.trust_status not in (TrustStatus.PENDING_REVIEW, TrustStatus.QUARANTINED):
            return False

        success = self.db.update_document_trust_status(document_id, TrustStatus.TRUSTED)
        if success:
            self.db.log_audit_event(
                event_type="DOCUMENT_TRUST_STATUS_CHANGED",
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                decision="PERMIT",
                reason_code="ADMIN_APPROVED_TRUSTED",
                document_id=document_id
            )
        return success

    def quarantine_document(
        self,
        document_id: str,
        principal: PrincipalContext,
        reason: str = "MANUAL_QUARANTINE"
    ) -> bool:
        """Administrative quarantine of suspicious or compromised document."""
        doc = self.db.get_document(document_id)
        if not doc or doc.tenant_id != principal.tenant_id:
            return False

        if principal.role not in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN):
            return False

        # Invariant: Cannot quarantine an already REVOKED document
        if doc.status == DocumentStatus.REVOKED:
            return False

        success = self.db.update_document_trust_status(document_id, TrustStatus.QUARANTINED, reason=reason)
        if success:
            self.db.log_audit_event(
                event_type="DOCUMENT_QUARANTINED",
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                decision="DENY",
                reason_code=reason,
                document_id=document_id
            )
        return success
        return success
