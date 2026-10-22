"""Pydantic data models and schemas for Zero-Trust RAG (Phase 3)."""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, ConfigDict
import uuid
import datetime

class ClassificationLevel(int, Enum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4

class DocumentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    QUARANTINED = "QUARANTINED"
    DELETED = "DELETED"

class TrustStatus(str, Enum):
    TRUSTED = "TRUSTED"
    PENDING_REVIEW = "PENDING_REVIEW"
    SUSPICIOUS = "SUSPICIOUS"
    QUARANTINED = "QUARANTINED"

class SourceType(str, Enum):
    LOCAL_UPLOAD = "LOCAL_UPLOAD"
    APPROVED_SEED = "APPROVED_SEED"

class InspectionOutcome(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    INSPECTION_ERROR = "INSPECTION_ERROR"
    UNINSPECTED = "UNINSPECTED"

class PrincipalRole(str, Enum):
    READER = "reader"
    CONTRIBUTOR = "contributor"
    TENANT_ADMIN = "tenant_admin"
    PLATFORM_ADMIN = "platform_admin"

class PrincipalContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    principal_id: str
    tenant_id: str
    role: PrincipalRole
    clearance_level: ClassificationLevel = ClassificationLevel.PUBLIC

class DocumentIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(..., min_length=1, max_length=250, description="Title of the document")
    content: str = Field(..., min_length=1, max_length=1_000_000, description="Raw text content of the document")
    tenant_id: Optional[str] = Field(default=None, description="Client-requested tenant (ignored/overwritten by server)")
    owner_id: Optional[str] = Field(default=None, description="Client-requested owner (ignored/overwritten by server)")
    classification_level: ClassificationLevel = Field(default=ClassificationLevel.INTERNAL)
    is_public: bool = Field(default=False)
    request_review: bool = Field(default=False, description="Flag document as requiring manual review before being trusted")
    # Client cannot assert trusted status or source type directly
    trust_status: Optional[str] = Field(default=None, description="Client-requested trust status (forbidden/ignored by server)")
    source_type: Optional[str] = Field(default=None, description="Client-requested source type (forbidden/ignored by server)")
    custom_metadata: Dict[str, Any] = Field(default_factory=dict)

class DocumentRecord(BaseModel):
    document_id: str
    tenant_id: str
    owner_id: str
    title: str
    sha256_hash: str
    classification_level: ClassificationLevel
    status: DocumentStatus
    trust_score: float
    trust_status: TrustStatus = TrustStatus.PENDING_REVIEW
    source_type: SourceType = SourceType.LOCAL_UPLOAD
    inspection_status: InspectionOutcome = InspectionOutcome.UNINSPECTED
    provenance_json: Dict[str, Any] = Field(default_factory=dict)
    is_public: bool
    chunk_count: int
    created_at: str
    updated_at: str

class ChunkRecord(BaseModel):
    chunk_id: str
    document_id: str
    tenant_id: str
    chunk_index: int
    content: str
    token_count: int
    content_hash: str
    parent_hash: str = ""
    classification_level: ClassificationLevel
    status: DocumentStatus

class DocumentACLCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grantee_type: str = Field(..., pattern="^(USER|ROLE)$", description="Target type: 'USER' or 'ROLE'")
    grantee_id: str = Field(..., min_length=1, max_length=100, description="User ID or Role name")
    permission: str = Field(default="READ", pattern="^(READ|ADMIN)$", description="Permission type")

class DocumentACLRecord(BaseModel):
    acl_id: str
    document_id: str
    grantee_type: str
    grantee_id: str
    permission: str

class ContextPassage(BaseModel):
    passage_id: str
    document_id: str
    document_title: str
    chunk_index: int
    trust_status: TrustStatus
    content_hash: str
    parent_hash: str
    classification_level: ClassificationLevel
    untrusted_content: str
    is_sanitized: bool = False
    redaction_count: int = 0

class SafeContextEnvelope(BaseModel):
    context_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_passages: int
    total_characters: int
    passages: List[ContextPassage]
    formatted_envelope: str

class RetrievalQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query_text: str = Field(..., min_length=1, max_length=2000, description="Search query string")
    tenant_id: Optional[str] = Field(default=None, description="Client tenant claim (ignored/overwritten by principal context)")
    top_k: int = Field(default=4, ge=1, le=50, description="Number of results to retrieve")
    min_similarity: float = Field(default=0.0, ge=-1.0, le=1.0, description="Cosine similarity cutoff threshold")

class RetrievedChunkCitation(BaseModel):
    chunk_id: str
    document_id: str
    document_title: str
    chunk_index: int
    similarity_score: float
    content: str
    provenance_hash: str
    classification_level: ClassificationLevel
    status: DocumentStatus
    trust_status: TrustStatus = TrustStatus.TRUSTED
    tenant_id: str
    redaction_count: int = 0

class RetrievalQueryResponse(BaseModel):
    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_candidates_found: int
    chunks_returned: int
    citations: List[RetrievedChunkCitation]
    raw_context: Optional[str] = None
    safe_context: Optional[SafeContextEnvelope] = None
    total_redactions: int = 0
