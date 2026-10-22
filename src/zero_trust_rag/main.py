"""FastAPI application entry point for Zero-Trust RAG Security Platform."""

from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
import datetime

from zero_trust_rag.core.config import settings
from zero_trust_rag.api.routes_documents import router as documents_router
from zero_trust_rag.api.routes_retrieval import router as retrieval_router
from zero_trust_rag.api.routes_audit import router as audit_router
from zero_trust_rag.storage.database import AuthoritativeDatabase
from zero_trust_rag.storage.vector_store import get_vector_store

app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description="Deterministic defense-in-depth security platform for RAG architectures."
)

app.include_router(documents_router)
app.include_router(retrieval_router)
app.include_router(audit_router)

@app.get("/api/v1/health", tags=["health"])
def health_check():
    """
    Public health check reporting database and vector store connectivity.
    Explicitly exempted from Bearer authentication for liveness and readiness monitoring.
    Never exposes document content or user identities.
    """
    db_ok = False
    vstore_count = 0
    try:
        db = AuthoritativeDatabase()
        with db.get_connection() as conn:
            cursor = conn.execute("SELECT 1")
            db_ok = cursor.fetchone()[0] == 1
    except Exception:
        db_ok = False

    try:
        vstore = get_vector_store()
        vstore_count = vstore.count()
        vstore_ok = True
    except Exception:
        vstore_ok = False

    overall_status = "healthy" if db_ok and vstore_ok else "degraded"

    return {
        "status": overall_status,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "components": {
            "authoritative_sqlite": "connected" if db_ok else "disconnected",
            "vector_store": "ready" if vstore_ok else "error",
            "indexed_vectors_count": vstore_count,
        },
        "config": {
            "use_mock_embeddings": settings.use_mock_embeddings,
            "embedding_dimension": settings.embedding_dimension,
        }
    }

@app.get("/", tags=["root"])
def root():
    return {
        "platform": settings.api_title,
        "version": settings.api_version,
        "docs_url": "/docs",
        "health_url": "/api/v1/health"
    }
