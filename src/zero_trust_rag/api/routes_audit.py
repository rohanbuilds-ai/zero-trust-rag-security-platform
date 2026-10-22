"""Security audit review endpoints."""

from fastapi import APIRouter, Depends
from typing import List, Dict, Any, Optional

from zero_trust_rag.core.models import PrincipalContext
from zero_trust_rag.pipeline.rag_service import RAGService
from zero_trust_rag.api.dependencies import get_rag_service, require_tenant_admin

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

@router.get("/events", response_model=List[Dict[str, Any]])
def list_audit_events(
    event_type: Optional[str] = None,
    limit: int = 50,
    principal: PrincipalContext = Depends(require_tenant_admin),
    service: RAGService = Depends(get_rag_service)
):
    """
    Retrieve structured security audit decision events for the caller's tenant.
    Requires tenant administrator privilege. Never discloses sensitive raw content.
    """
    return service.db.get_audit_events(
        tenant_id=principal.tenant_id,
        event_type=event_type,
        limit=min(limit, 100)
    )
