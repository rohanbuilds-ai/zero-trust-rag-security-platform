"""FastAPI dependencies for services, storage, and trusted identity resolution."""

from functools import lru_cache
from typing import Optional, List
from fastapi import Header, HTTPException, status, Depends, Request

from zero_trust_rag.storage.database import AuthoritativeDatabase
from zero_trust_rag.storage.vector_store import BaseVectorStore, get_vector_store
from zero_trust_rag.pipeline.embeddings import BaseEmbeddingEngine, get_embedding_engine
from zero_trust_rag.pipeline.rag_service import RAGService
from zero_trust_rag.core.config import settings
from zero_trust_rag.core.models import PrincipalContext, PrincipalRole
from zero_trust_rag.core.auth import resolve_token

@lru_cache()
def get_authoritative_database() -> AuthoritativeDatabase:
    """Singleton authoritative database."""
    return AuthoritativeDatabase()

@lru_cache()
def get_vector_store_instance() -> BaseVectorStore:
    """Singleton vector store."""
    return get_vector_store()

@lru_cache()
def get_embedding_engine_instance() -> BaseEmbeddingEngine:
    """Singleton embedding engine."""
    return get_embedding_engine(use_mock=settings.use_mock_embeddings)

def get_rag_service() -> RAGService:
    """Returns RAGService with shared database, vector store, and embedding engine."""
    return RAGService(
        database=get_authoritative_database(),
        vector_store=get_vector_store_instance(),
        embedding_engine=get_embedding_engine_instance()
    )

def get_current_principal(
    authorization: Optional[str] = Header(None, description="Bearer token authentication"),
    db: AuthoritativeDatabase = Depends(get_authoritative_database)
) -> PrincipalContext:
    """
    Resolve and verify caller identity from the Bearer token.
    Fails closed with HTTP 401 on missing, malformed, or unrecognized credentials.
    """
    if not authorization:
        db.log_audit_event(
            event_type="AUTH_FAILURE",
            principal_id="anonymous",
            tenant_id="unknown",
            decision="DENY",
            reason_code="MISSING_CREDENTIALS",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        db.log_audit_event(
            event_type="AUTH_FAILURE",
            principal_id="anonymous",
            tenant_id="unknown",
            decision="DENY",
            reason_code="MALFORMED_AUTHORIZATION_HEADER",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed Authorization header. Format must be 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    principal = resolve_token(token)
    if not principal:
        db.log_audit_event(
            event_type="AUTH_FAILURE",
            principal_id="anonymous",
            tenant_id="unknown",
            decision="DENY",
            reason_code="INVALID_CREDENTIALS",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return principal

def require_contributor(
    principal: PrincipalContext = Depends(get_current_principal),
    db: AuthoritativeDatabase = Depends(get_authoritative_database)
) -> PrincipalContext:
    """Ensure principal has ingestion/contributor privileges."""
    allowed_roles = (PrincipalRole.CONTRIBUTOR, PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN)
    if principal.role not in allowed_roles:
        db.log_audit_event(
            event_type="UNAUTHORIZED_INGESTION_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="INSUFFICIENT_ROLE_FOR_INGESTION",
            details={"required_roles": [r.value for r in allowed_roles], "user_role": principal.role.value}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Role 'reader' cannot ingest documents."
        )
    return principal

def require_tenant_admin(
    principal: PrincipalContext = Depends(get_current_principal),
    db: AuthoritativeDatabase = Depends(get_authoritative_database)
) -> PrincipalContext:
    """Ensure principal has administrative privileges for ACLs or revocation."""
    allowed_roles = (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN)
    if principal.role not in allowed_roles:
        db.log_audit_event(
            event_type="UNAUTHORIZED_ADMIN_ACTION",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="INSUFFICIENT_ROLE_FOR_ADMIN",
            details={"required_roles": [r.value for r in allowed_roles], "user_role": principal.role.value}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required for this action."
        )
    return principal
