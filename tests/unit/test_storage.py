"""Unit tests for storage layer (SQLite authoritative database & vector store)."""

import datetime
from zero_trust_rag.core.models import (
    DocumentRecord,
    ChunkRecord,
    DocumentStatus,
    ClassificationLevel,
)
from zero_trust_rag.storage.vector_store import InMemoryVectorStore, ChromaVectorStore

def test_sqlite_insert_and_get_document(test_db):
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    doc = DocumentRecord(
        document_id="doc_test_001",
        tenant_id="default_tenant",
        owner_id="admin_user",
        title="Test Architecture Document",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        classification_level=ClassificationLevel.INTERNAL,
        status=DocumentStatus.ACTIVE,
        trust_score=1.0,
        is_public=False,
        chunk_count=2,
        created_at=now_str,
        updated_at=now_str,
    )
    test_db.insert_document(doc)

    fetched = test_db.get_document("doc_test_001")
    assert fetched is not None
    assert fetched.document_id == "doc_test_001"
    assert fetched.title == "Test Architecture Document"
    assert fetched.classification_level == ClassificationLevel.INTERNAL
    assert fetched.status == DocumentStatus.ACTIVE

def test_sqlite_chunk_and_cascade_status(test_db):
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    doc = DocumentRecord(
        document_id="doc_test_002",
        tenant_id="default_tenant",
        owner_id="admin_user",
        title="Test Document 2",
        sha256_hash="abc123hash",
        classification_level=ClassificationLevel.CONFIDENTIAL,
        status=DocumentStatus.ACTIVE,
        trust_score=1.0,
        is_public=False,
        chunk_count=2,
        created_at=now_str,
        updated_at=now_str,
    )
    test_db.insert_document(doc)

    chunks = [
        ChunkRecord(
            chunk_id="chk_test_002_0",
            document_id="doc_test_002",
            tenant_id="default_tenant",
            chunk_index=0,
            token_count=25,
            content="First chunk content.",
            content_hash="h1",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            status=DocumentStatus.ACTIVE,
        ),
        ChunkRecord(
            chunk_id="chk_test_002_1",
            document_id="doc_test_002",
            tenant_id="default_tenant",
            chunk_index=1,
            token_count=30,
            content="Second chunk content.",
            content_hash="h2",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            status=DocumentStatus.ACTIVE,
        ),
    ]
    test_db.insert_chunks(chunks)

    # Verify chunks are inserted
    c0 = test_db.get_chunk("chk_test_002_0")
    assert c0 is not None
    assert c0.status == DocumentStatus.ACTIVE

    # Update document status to REVOKED
    success = test_db.update_document_status("doc_test_002", DocumentStatus.REVOKED)
    assert success is True

    # Verify both document and chunks are now REVOKED
    doc_revoked = test_db.get_document("doc_test_002")
    assert doc_revoked.status == DocumentStatus.REVOKED
    c0_revoked = test_db.get_chunk("chk_test_002_0")
    assert c0_revoked.status == DocumentStatus.REVOKED

def test_in_memory_vector_store_operations(test_vector_store):
    chunks = [
        ChunkRecord(
            chunk_id="chk_vec_1",
            document_id="doc_1",
            tenant_id="tenant_a",
            chunk_index=0,
            token_count=10,
            content="Alpha content",
            content_hash="ha",
            classification_level=ClassificationLevel.INTERNAL,
            status=DocumentStatus.ACTIVE,
        ),
        ChunkRecord(
            chunk_id="chk_vec_2",
            document_id="doc_2",
            tenant_id="tenant_b",
            chunk_index=0,
            token_count=10,
            content="Beta content",
            content_hash="hb",
            classification_level=ClassificationLevel.INTERNAL,
            status=DocumentStatus.ACTIVE,
        ),
    ]
    # Unit vectors
    emb1 = [1.0, 0.0, 0.0]
    emb2 = [0.0, 1.0, 0.0]
    test_vector_store.add_chunks(chunks, [emb1, emb2])
    assert test_vector_store.count() == 2

    # Query matching emb1
    results = test_vector_store.query_similar([1.0, 0.0, 0.0], top_k=2)
    assert len(results) == 2
    assert results[0][0] == "chk_vec_1"
    assert abs(results[0][1] - 1.0) < 1e-4

    # Query with tenant filter
    filtered = test_vector_store.query_similar([1.0, 0.0, 0.0], top_k=2, tenant_filter="tenant_b")
    assert len(filtered) == 1
    assert filtered[0][0] == "chk_vec_2"

    # Delete doc_1
    test_vector_store.delete_by_document("doc_1")
    assert test_vector_store.count() == 1
    remaining = test_vector_store.query_similar([1.0, 0.0, 0.0], top_k=2)
    assert len(remaining) == 1
    assert remaining[0][0] == "chk_vec_2"

def test_chroma_vector_store_operations(test_chroma_store):
    chunks = [
        ChunkRecord(
            chunk_id="chk_chroma_1",
            document_id="doc_c1",
            tenant_id="tenant_x",
            chunk_index=0,
            token_count=15,
            content="Chroma document content alpha",
            content_hash="hc1",
            classification_level=ClassificationLevel.INTERNAL,
            status=DocumentStatus.ACTIVE,
        )
    ]
    emb = [0.5, 0.5, 0.5] + [0.0] * 381
    test_chroma_store.add_chunks(chunks, [emb])
    assert test_chroma_store.count() == 1

    results = test_chroma_store.query_similar(emb, top_k=1, tenant_filter="tenant_x")
    assert len(results) == 1
    assert results[0][0] == "chk_chroma_1"

    test_chroma_store.delete_by_document("doc_c1")
    assert test_chroma_store.count() == 0
