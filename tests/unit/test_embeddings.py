"""Unit tests for embedding engines."""

import numpy as np
from zero_trust_rag.pipeline.embeddings import (
    MockDeterministicEmbeddingEngine,
    get_embedding_engine,
)

def test_mock_embedding_dimension():
    engine = MockDeterministicEmbeddingEngine(dimension=384)
    assert engine.dimension == 384
    vec = engine.embed_text("Authentication and authorization.")
    assert len(vec) == 384

def test_mock_embedding_normalization():
    engine = MockDeterministicEmbeddingEngine(dimension=256)
    vec = np.array(engine.embed_text("Testing vector normalization properties."))
    norm = np.linalg.norm(vec)
    assert abs(norm - 1.0) < 1e-4

def test_mock_embedding_identity_and_determinism():
    engine = MockDeterministicEmbeddingEngine(dimension=384)
    text = "Zero-trust RAG pipeline security controls."
    vec1 = np.array(engine.embed_text(text))
    vec2 = np.array(engine.embed_text(text))
    np.testing.assert_array_almost_equal(vec1, vec2)
    # Cosine similarity with self is 1.0
    sim = np.dot(vec1, vec2)
    assert abs(sim - 1.0) < 1e-4

def test_mock_embedding_semantic_correlation():
    engine = MockDeterministicEmbeddingEngine(dimension=384)
    # Texts sharing vocabulary should have higher cosine similarity than unrelated texts
    base = np.array(engine.embed_text("zero-trust network access and authentication proxy"))
    related = np.array(engine.embed_text("authentication proxy and access verification"))
    unrelated = np.array(engine.embed_text("culinary recipe for baking chocolate cookies with vanilla"))

    sim_related = float(np.dot(base, related))
    sim_unrelated = float(np.dot(base, unrelated))
    assert sim_related > sim_unrelated

def test_factory_returns_mock():
    engine = get_embedding_engine(use_mock=True)
    assert isinstance(engine, MockDeterministicEmbeddingEngine)
