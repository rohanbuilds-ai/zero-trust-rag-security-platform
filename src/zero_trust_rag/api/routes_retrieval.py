"""Retrieval and semantic search endpoints secured with two-stage authorization."""

from fastapi import APIRouter, Depends
from zero_trust_rag.core.models import (
    RetrievalQueryRequest,
    RetrievalQueryResponse,
    PrincipalContext,
)
from zero_trust_rag.pipeline.rag_service import RAGService
from zero_trust_rag.api.dependencies import get_rag_service, get_current_principal

router = APIRouter(prefix="/api/v1/retrieval", tags=["retrieval"])

@router.post("/query", response_model=RetrievalQueryResponse)
def query_retrieval(
    request: RetrievalQueryRequest,
    principal: PrincipalContext = Depends(get_current_principal),
    service: RAGService = Depends(get_rag_service)
):
    """
    Retrieve semantically similar chunks with citations.
    Enforces two-stage authorization:
      1. Pre-retrieval vector scoping (caller's tenant).
      2. Authoritative post-retrieval verification against SQLite (lifecycle, clearance, ACL).
    """
    return service.retrieve(request, principal=principal)
