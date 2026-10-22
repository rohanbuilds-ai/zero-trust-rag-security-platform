"""Unit tests for deterministic chunker."""

import pytest
from zero_trust_rag.pipeline.chunker import DeterministicChunker

def test_chunker_empty_and_whitespace():
    chunker = DeterministicChunker(chunk_size=200, chunk_overlap=20)
    assert chunker.chunk_text("") == []
    assert chunker.chunk_text("   \n\n  \t  ") == []

def test_chunker_short_text():
    chunker = DeterministicChunker(chunk_size=200, chunk_overlap=20)
    text = "Short single paragraph document."
    chunks = chunker.chunk_text(text)
    assert len(chunks) == 1
    assert chunks[0]["chunk_index"] == 0
    assert chunks[0]["content"] == text
    assert len(chunks[0]["content_hash"]) == 64
    assert chunks[0]["token_count"] > 0

def test_chunker_deterministic_output():
    chunker = DeterministicChunker(chunk_size=100, chunk_overlap=15)
    text = (
        "Paragraph one discusses zero-trust architectures and least privilege.\n\n"
        "Paragraph two discusses vector index security and indirect prompt injection.\n\n"
        "Paragraph three covers cryptographic attestation and tamper-evident audit trails."
    )
    run1 = chunker.chunk_text(text)
    run2 = chunker.chunk_text(text)
    assert len(run1) == len(run2)
    for c1, c2 in zip(run1, run2):
        assert c1["chunk_index"] == c2["chunk_index"]
        assert c1["content"] == c2["content"]
        assert c1["content_hash"] == c2["content_hash"]

def test_chunker_invalid_overlap():
    with pytest.raises(ValueError, match="chunk_size must be strictly greater than chunk_overlap"):
        DeterministicChunker(chunk_size=100, chunk_overlap=100)

    with pytest.raises(ValueError):
        DeterministicChunker(chunk_size=50, chunk_overlap=80)
