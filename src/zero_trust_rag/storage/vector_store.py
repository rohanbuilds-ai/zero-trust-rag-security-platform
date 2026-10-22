"""Vector store abstraction and implementations (ChromaDB & In-Memory)."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import numpy as np

from zero_trust_rag.core.models import ChunkRecord
from zero_trust_rag.core.config import settings

class BaseVectorStore(ABC):
    """Abstract interface for vector stores."""

    @abstractmethod
    def add_chunks(self, chunks: List[ChunkRecord], embeddings: List[List[float]]) -> None:
        """Add chunks with their precomputed embeddings."""
        pass

    @abstractmethod
    def query_similar(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        tenant_filter: Optional[str] = None
    ) -> List[Tuple[str, float]]:
        """Return list of (chunk_id, similarity_score) sorted by highest similarity."""
        pass

    @abstractmethod
    def delete_chunks(self, chunk_ids: List[str]) -> None:
        """Delete chunks by IDs."""
        pass

    @abstractmethod
    def delete_by_document(self, document_id: str) -> None:
        """Delete all chunks for a document."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Total vectors stored."""
        pass


class InMemoryVectorStore(BaseVectorStore):
    """
    High-performance in-memory numpy vector store.
    Zero external dependencies, ideal for fast deterministic testing.
    """

    def __init__(self):
        self._chunk_ids: List[str] = []
        self._doc_ids: Dict[str, str] = {}  # chunk_id -> document_id
        self._tenant_ids: Dict[str, str] = {}  # chunk_id -> tenant_id
        self._embeddings: Dict[str, np.ndarray] = {}

    def add_chunks(self, chunks: List[ChunkRecord], embeddings: List[List[float]]) -> None:
        for chunk, emb in zip(chunks, embeddings):
            c_id = chunk.chunk_id
            if c_id not in self._embeddings:
                self._chunk_ids.append(c_id)
            self._doc_ids[c_id] = chunk.document_id
            self._tenant_ids[c_id] = chunk.tenant_id

            # Normalize vector
            vec = np.array(emb, dtype=np.float32)
            norm = np.linalg.norm(vec)
            if norm > 1e-8:
                vec = vec / norm
            self._embeddings[c_id] = vec

    def query_similar(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        tenant_filter: Optional[str] = None
    ) -> List[Tuple[str, float]]:
        if not self._chunk_ids:
            return []

        q_vec = np.array(query_embedding, dtype=np.float32)
        q_norm = np.linalg.norm(q_vec)
        if q_norm > 1e-8:
            q_vec = q_vec / q_norm

        candidates: List[Tuple[str, float]] = []
        for c_id in self._chunk_ids:
            if tenant_filter and self._tenant_ids.get(c_id) != tenant_filter:
                continue
            emb = self._embeddings[c_id]
            # Cosine similarity between normalized vectors is dot product
            sim = float(np.dot(q_vec, emb))
            candidates.append((c_id, sim))

        # Sort descending by similarity
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]

    def delete_chunks(self, chunk_ids: List[str]) -> None:
        target_set = set(chunk_ids)
        self._chunk_ids = [c for c in self._chunk_ids if c not in target_set]
        for c_id in target_set:
            self._embeddings.pop(c_id, None)
            self._doc_ids.pop(c_id, None)
            self._tenant_ids.pop(c_id, None)

    def delete_by_document(self, document_id: str) -> None:
        to_delete = [c_id for c_id, d_id in self._doc_ids.items() if d_id == document_id]
        self.delete_chunks(to_delete)

    def count(self) -> int:
        return len(self._chunk_ids)


class ChromaVectorStore(BaseVectorStore):
    """ChromaDB implementation with metadata pre-filtering."""

    def __init__(self, persist_dir: Optional[Path] = None, collection_name: str = "documents"):
        import chromadb
        self.persist_dir = persist_dir or settings.vector_store_path
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(self.persist_dir))
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"}
        )

    def add_chunks(self, chunks: List[ChunkRecord], embeddings: List[List[float]]) -> None:
        if not chunks:
            return
        ids = [c.chunk_id for c in chunks]
        metadatas = [
            {
                "document_id": c.document_id,
                "tenant_id": c.tenant_id,
                "chunk_index": c.chunk_index,
                "classification_level": int(c.classification_level),
            }
            for c in chunks
        ]
        documents = [c.content for c in chunks]
        self._collection.upsert(
            ids=ids,
            embeddings=embeddings,
            metadatas=metadatas,
            documents=documents
        )

    def query_similar(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        tenant_filter: Optional[str] = None
    ) -> List[Tuple[str, float]]:
        where_filter = {"tenant_id": tenant_filter} if tenant_filter else None
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where_filter,
            include=["distances"]
        )

        candidates: List[Tuple[str, float]] = []
        if results and results.get("ids") and results["ids"][0]:
            ids = results["ids"][0]
            # Chroma returns cosine distance (1 - similarity); convert to similarity:
            distances = results["distances"][0] if results.get("distances") else [0.0] * len(ids)
            for c_id, dist in zip(ids, distances):
                sim = 1.0 - dist
                candidates.append((c_id, float(sim)))

        return candidates

    def delete_chunks(self, chunk_ids: List[str]) -> None:
        if chunk_ids:
            self._collection.delete(ids=chunk_ids)

    def delete_by_document(self, document_id: str) -> None:
        self._collection.delete(where={"document_id": document_id})

    def count(self) -> int:
        return self._collection.count()


def get_vector_store(
    in_memory: bool = False,
    persist_dir: Optional[Path] = None
) -> BaseVectorStore:
    """Factory creating vector store instance."""
    if in_memory or getattr(settings, "vector_store_type", "chroma") == "memory":
        return InMemoryVectorStore()

    try:
        import chromadb
        return ChromaVectorStore(persist_dir=persist_dir)
    except Exception:
        # Fallback to InMemoryVectorStore if chromadb has runtime import issues
        return InMemoryVectorStore()
