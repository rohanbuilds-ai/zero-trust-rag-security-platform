"""Database seeding script for Zero-Trust RAG platform."""

import os
import sys
from pathlib import Path

# Add src to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from zero_trust_rag.core.models import DocumentIngestRequest, RetrievalQueryRequest, ClassificationLevel
from zero_trust_rag.pipeline.rag_service import RAGService
from zero_trust_rag.storage.database import AuthoritativeDatabase
from zero_trust_rag.storage.vector_store import get_vector_store
from zero_trust_rag.pipeline.embeddings import get_embedding_engine

def seed():
    print("=" * 60)
    print("Seeding Zero-Trust RAG Knowledge Base...")
    print("=" * 60)

    corpus_dir = BASE_DIR / "data" / "sample_corpus"
    if not corpus_dir.exists():
        print(f"Error: Corpus directory '{corpus_dir}' not found.")
        return

    service = RAGService()

    files = list(corpus_dir.glob("*.txt"))
    print(f"Found {len(files)} sample corpus documents.")

    for file_path in files:
        title = file_path.stem.replace("_", " ").title()
        content = file_path.read_text(encoding="utf-8")

        # Determine classification
        classification = ClassificationLevel.INTERNAL
        if "confidential" in file_path.name.lower() or "financial" in file_path.name.lower():
            classification = ClassificationLevel.CONFIDENTIAL
        elif "policy" in file_path.name.lower():
            classification = ClassificationLevel.PUBLIC

        req = DocumentIngestRequest(
            title=title,
            content=content,
            tenant_id="default_tenant",
            classification_level=classification,
            is_public=(classification == ClassificationLevel.PUBLIC),
        )
        doc = service.ingest_document(req)
        print(f"  [+] Ingested: '{doc.title}' ({doc.document_id}) - {doc.chunk_count} chunks - Hash: {doc.sha256_hash[:12]}...")

    print("\nExecuting sample retrieval query: 'zero-trust security least privilege'...")
    query_req = RetrievalQueryRequest(
        query_text="zero-trust security least privilege",
        tenant_id="default_tenant",
        top_k=2
    )
    res = service.retrieve(query_req)
    print(f"Found {res.chunks_returned} matching chunks:")
    for idx, c in enumerate(res.citations, 1):
        print(f"  {idx}. [{c.document_title}] (Similarity: {c.similarity_score})")
        print(f"     Excerpt: {c.content[:100]}...\n")

    print("Seeding complete!")

if __name__ == "__main__":
    seed()
