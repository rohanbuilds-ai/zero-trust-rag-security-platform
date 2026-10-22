"""Safe context assembly module encapsulating untrusted retrieval text."""

import hashlib
import uuid
from xml.sax.saxutils import quoteattr
from typing import List, Tuple, Optional
from zero_trust_rag.core.models import (
    ChunkRecord,
    DocumentRecord,
    ContextPassage,
    SafeContextEnvelope,
    TrustStatus,
    DocumentStatus,
)

def format_xml_passage(p: ContextPassage) -> str:
    """
    Safely format a single context passage as XML.
    Attributes are safely quoted and escaped using quoteattr to prevent attribute injection.
    Untrusted text is encapsulated in CDATA with any embedded CDATA closers defanged.
    """
    defanged = p.untrusted_content.replace("]]>", "]] >")
    q_id = quoteattr(str(p.passage_id))
    q_doc_id = quoteattr(str(p.document_id))
    q_class = quoteattr(str(p.classification_level.name))
    return (
        f'  <passage id={q_id} doc_id={q_doc_id} classification={q_class}>\n'
        f'    <untrusted_content>\n<![CDATA[\n{defanged}\n]]>\n    </untrusted_content>\n'
        f'  </passage>'
    )


def format_xml_envelope(context_id: str, passages: List[ContextPassage]) -> str:
    """
    Safely format the complete retrieved evidence XML envelope.
    All attributes are safely quoted and escaped.
    """
    xml_passages = [format_xml_passage(p) for p in passages]
    q_ctx_id = quoteattr(str(context_id))
    q_total = quoteattr(str(len(passages)))
    return (
        f'<retrieved_evidence_envelope context_id={q_ctx_id} total_passages={q_total}>\n'
        + "\n".join(xml_passages)
        + "\n</retrieved_evidence_envelope>"
    )


class ContextBuilder:
    """
    Constructs a hardened, isolated context representation.
    Ensures untrusted retrieved text is strictly demarcated as passive data,
    never privileged system instructions, and enforces size and chunk limits.
    """

    def __init__(self, max_chunks: int = 8, max_characters: int = 8000):
        self.max_chunks = max_chunks
        self.max_characters = max_characters

    def build_safe_context(
        self,
        verified_candidates: List[Tuple[ChunkRecord, DocumentRecord, float]],
    ) -> SafeContextEnvelope:
        """
        Assemble safe structured context from verified candidates.
        Drops any chunk failing provenance, hash verification, or trust state.
        """
        context_id = f"ctx_{uuid.uuid4().hex[:12]}"
        passages: List[ContextPassage] = []
        total_chars = 0

        for chunk, doc, sim in verified_candidates:
            if len(passages) >= self.max_chunks:
                break

            # 1. Verify Document Status (ACTIVE only)
            if doc.status != DocumentStatus.ACTIVE or chunk.status != DocumentStatus.ACTIVE:
                continue

            # 2. Verify Document Trust Status (TRUSTED only)
            if doc.trust_status != TrustStatus.TRUSTED:
                continue

            # 3. Content Integrity & Provenance Verification
            computed_chunk_hash = hashlib.sha256(chunk.content.encode("utf-8")).hexdigest()
            if chunk.content_hash != computed_chunk_hash:
                # Content tampered or hash mismatch
                continue

            if chunk.parent_hash and chunk.parent_hash != doc.sha256_hash:
                # Content version mismatch between chunk and parent doc
                continue

            chunk_len = len(chunk.content)
            if total_chars + chunk_len > self.max_characters:
                # Truncate or break to prevent context size explosion
                remaining = self.max_characters - total_chars
                if remaining <= 50:
                    break
                usable_content = chunk.content[:remaining]
            else:
                usable_content = chunk.content

            passage = ContextPassage(
                passage_id=chunk.chunk_id,
                document_id=doc.document_id,
                document_title=doc.title,
                chunk_index=chunk.chunk_index,
                trust_status=doc.trust_status,
                content_hash=chunk.content_hash,
                parent_hash=doc.sha256_hash,
                classification_level=chunk.classification_level,
                untrusted_content=usable_content,
                is_sanitized=False,
                redaction_count=0
            )

            passages.append(passage)
            total_chars += len(usable_content)

        # Build structural XML envelope using safely escaped attribute helper
        envelope_str = format_xml_envelope(context_id, passages)

        return SafeContextEnvelope(
            context_id=context_id,
            total_passages=len(passages),
            total_characters=total_chars,
            passages=passages,
            formatted_envelope=envelope_str
        )
