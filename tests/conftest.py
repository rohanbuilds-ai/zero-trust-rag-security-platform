"""Pytest fixtures for Zero-Trust RAG platform."""

import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure src directory is in Python path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from zero_trust_rag.storage.database import AuthoritativeDatabase
from zero_trust_rag.storage.vector_store import InMemoryVectorStore, ChromaVectorStore
from zero_trust_rag.pipeline.embeddings import MockDeterministicEmbeddingEngine
from zero_trust_rag.pipeline.chunker import DeterministicChunker
from zero_trust_rag.pipeline.rag_service import RAGService
from zero_trust_rag.main import app
from zero_trust_rag.api.dependencies import (
    get_authoritative_database,
    get_vector_store_instance,
    get_embedding_engine_instance,
    get_rag_service,
)

@pytest.fixture
def mock_embedding_engine():
    """Deterministic mock embedding engine for offline tests."""
    return MockDeterministicEmbeddingEngine(dimension=384)

@pytest.fixture
def test_db(tmp_path):
    """Isolated SQLite database in temporary directory."""
    db_file = tmp_path / "test_authoritative.db"
    return AuthoritativeDatabase(db_path=db_file)

@pytest.fixture
def test_vector_store():
    """Fast in-memory vector store for unit tests."""
    return InMemoryVectorStore()

@pytest.fixture
def test_chroma_store(tmp_path):
    """Temporary file-backed Chroma vector store."""
    chroma_dir = tmp_path / "test_chroma"
    return ChromaVectorStore(persist_dir=chroma_dir, collection_name="test_collection")

@pytest.fixture
def deterministic_chunker():
    """Standard chunker."""
    return DeterministicChunker(chunk_size=300, chunk_overlap=30)

@pytest.fixture
def rag_service(test_db, test_vector_store, mock_embedding_engine, deterministic_chunker):
    """Fully isolated RAGService instance."""
    return RAGService(
        database=test_db,
        vector_store=test_vector_store,
        embedding_engine=mock_embedding_engine,
        chunker=deterministic_chunker,
    )

@pytest.fixture
def test_client(test_db, test_vector_store, mock_embedding_engine, deterministic_chunker):
    """FastAPI TestClient with isolated dependency overrides."""
    isolated_service = RAGService(
        database=test_db,
        vector_store=test_vector_store,
        embedding_engine=mock_embedding_engine,
        chunker=deterministic_chunker,
    )

    app.dependency_overrides[get_authoritative_database] = lambda: test_db
    app.dependency_overrides[get_vector_store_instance] = lambda: test_vector_store
    app.dependency_overrides[get_embedding_engine_instance] = lambda: mock_embedding_engine
    app.dependency_overrides[get_rag_service] = lambda: isolated_service

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()
