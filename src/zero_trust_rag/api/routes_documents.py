"""Document management endpoints secured with deterministic authorization and trust controls."""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional

from zero_trust_rag.core.models import (
    DocumentIngestRequest,
    DocumentRecord,
    DocumentACLCreateRequest,
    DocumentACLRecord,
    DocumentStatus,
    TrustStatus,
    PrincipalContext,
    PrincipalRole,
)
from zero_trust_rag.pipeline.rag_service import RAGService
from zero_trust_rag.api.dependencies import (
    get_rag_service,
    get_current_principal,
    require_contributor,
    require_tenant_admin,
)

router = APIRouter(prefix="/api/v1/documents", tags=["documents"])

@router.post("/ingest", response_model=DocumentRecord, status_code=status.HTTP_201_CREATED)
def ingest_document(
    request: DocumentIngestRequest,
    principal: PrincipalContext = Depends(require_contributor),
    service: RAGService = Depends(get_rag_service)
):
    """
    Ingest a document into the knowledge base.
    Derives tenant and owner strictly from caller's authenticated session.
    Rejects any attempt to ingest into another tenant.
    Inspects content for prompt injection and suspicious directives.
    """
    if request.tenant_id and request.tenant_id != principal.tenant_id:
        service.db.log_audit_event(
            event_type="UNAUTHORIZED_INGESTION_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="CROSS_TENANT_INGESTION_REJECTED",
            details={"requested_tenant": request.tenant_id, "principal_tenant": principal.tenant_id}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot ingest documents on behalf of another tenant."
        )

    return service.ingest_document(request, principal=principal)

@router.get("/{document_id}", response_model=DocumentRecord)
def get_document(
    document_id: str,
    principal: PrincipalContext = Depends(get_current_principal),
    service: RAGService = Depends(get_rag_service)
):
    """
    Fetch authoritative document metadata.
    Enforces tenant isolation, clearance level, and document ACLs.
    Returns HTTP 404 uniformly for non-existent and unpermitted documents to prevent ID enumeration.
    """
    doc = service.db.get_document(document_id)
    if not doc or doc.tenant_id != principal.tenant_id:
        service.db.log_audit_event(
            event_type="UNAUTHORIZED_METADATA_ACCESS_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="DOCUMENT_NOT_FOUND_OR_CROSS_TENANT",
            document_id=document_id
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    # Check caller clearance
    if doc.classification_level > principal.clearance_level:
        service.db.log_audit_event(
            event_type="UNAUTHORIZED_METADATA_ACCESS_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="INSUFFICIENT_CLEARANCE",
            document_id=document_id
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    # Check caller authorization
    is_authorized = False
    if principal.role in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN):
        is_authorized = True
    elif doc.owner_id == principal.principal_id:
        is_authorized = True
    elif doc.is_public:
        is_authorized = True
    else:
        is_authorized = service.db.check_document_acl(
            document_id=doc.document_id,
            principal_id=principal.principal_id,
            role=principal.role.value
        )

    if not is_authorized:
        service.db.log_audit_event(
            event_type="UNAUTHORIZED_METADATA_ACCESS_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="DOCUMENT_ACL_UNAUTHORIZED",
            document_id=document_id
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    return doc

@router.post("/{document_id}/revoke")
def revoke_document(
    document_id: str,
    principal: PrincipalContext = Depends(get_current_principal),
    service: RAGService = Depends(get_rag_service)
):
    """
    Revoke a document and purge its vectors.
    Requires tenant administrator capability or document ownership.
    """
    doc = service.db.get_document(document_id)
    if not doc or doc.tenant_id != principal.tenant_id:
        service.db.log_audit_event(
            event_type="UNAUTHORIZED_REVOCATION_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="DOCUMENT_NOT_FOUND_OR_CROSS_TENANT",
            document_id=document_id
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    is_admin = principal.role in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN)
    is_owner = (doc.owner_id == principal.principal_id)
    if not (is_admin or is_owner):
        service.db.log_audit_event(
            event_type="UNAUTHORIZED_REVOCATION_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="INSUFFICIENT_PERMISSIONS_TO_REVOKE",
            document_id=document_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to revoke document. Tenant administrator or document owner role required."
        )

    if doc.status == DocumentStatus.REVOKED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Document '{document_id}' is already revoked."
        )

    success = service.revoke_document(document_id, principal=principal)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update document status to revoked."
        )

    return {
        "status": "success",
        "message": f"Document '{document_id}' successfully revoked and purged from vector index."
    }

@router.post("/{document_id}/approve")
def approve_document(
    document_id: str,
    principal: PrincipalContext = Depends(require_tenant_admin),
    service: RAGService = Depends(get_rag_service)
):
    """Approve a document awaiting review or in quarantine, transitioning it to TRUSTED."""
    doc = service.db.get_document(document_id)
    if not doc or doc.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

    if doc.status == DocumentStatus.REVOKED:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot approve a revoked document.")

    success = service.approve_document(document_id, principal=principal)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to approve document or invalid document state.")

    return {"status": "success", "message": f"Document '{document_id}' approved and marked TRUSTED."}

@router.post("/{document_id}/quarantine")
def quarantine_document(
    document_id: str,
    principal: PrincipalContext = Depends(require_tenant_admin),
    service: RAGService = Depends(get_rag_service)
):
    """Manually quarantine a document."""
    doc = service.db.get_document(document_id)
    if not doc or doc.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

    success = service.quarantine_document(document_id, principal=principal, reason="MANUAL_ADMIN_QUARANTINE")
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to quarantine document.")

    return {"status": "success", "message": f"Document '{document_id}' quarantined."}

@router.post("/{document_id}/acls", response_model=DocumentACLRecord, status_code=status.HTTP_201_CREATED)
def add_document_acl(
    document_id: str,
    request: DocumentACLCreateRequest,
    principal: PrincipalContext = Depends(get_current_principal),
    service: RAGService = Depends(get_rag_service)
):
    doc = service.db.get_document(document_id)
    if not doc or doc.tenant_id != principal.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    is_admin = principal.role in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN)
    is_owner = (doc.owner_id == principal.principal_id)
    if not (is_admin or is_owner):
        service.db.log_audit_event(
            event_type="UNAUTHORIZED_ACL_MODIFICATION_ATTEMPT",
            principal_id=principal.principal_id,
            tenant_id=principal.tenant_id,
            decision="DENY",
            reason_code="INSUFFICIENT_ROLE_FOR_ACL_EDIT",
            document_id=document_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify document ACLs."
        )

    acl_record = service.db.add_document_acl(
        document_id=document_id,
        grantee_type=request.grantee_type,
        grantee_id=request.grantee_id,
        permission=request.permission
    )

    service.db.log_audit_event(
        event_type="DOCUMENT_ACL_CREATED",
        principal_id=principal.principal_id,
        tenant_id=principal.tenant_id,
        decision="PERMIT",
        reason_code="ACL_RULE_ADDED",
        document_id=document_id,
        details={"grantee_type": request.grantee_type, "grantee_id": request.grantee_id, "permission": request.permission}
    )

    return acl_record

@router.get("/{document_id}/acls", response_model=List[DocumentACLRecord])
def list_document_acls(
    document_id: str,
    principal: PrincipalContext = Depends(get_current_principal),
    service: RAGService = Depends(get_rag_service)
):
    doc = service.db.get_document(document_id)
    if not doc or doc.tenant_id != principal.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found."
        )

    is_admin = principal.role in (PrincipalRole.TENANT_ADMIN, PrincipalRole.PLATFORM_ADMIN)
    is_owner = (doc.owner_id == principal.principal_id)
    if not (is_admin or is_owner):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view document ACLs."
        )

    return service.db.get_document_acls(document_id)

@router.get("", response_model=List[DocumentRecord])
def list_documents(
    principal: PrincipalContext = Depends(get_current_principal),
    service: RAGService = Depends(get_rag_service)
):
    return service.db.list_documents(tenant_id=principal.tenant_id)
