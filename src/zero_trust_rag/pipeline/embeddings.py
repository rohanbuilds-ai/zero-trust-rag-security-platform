"""Embedding engines for Zero-Trust RAG."""

from abc import ABC, abstractmethod
import hashlib
import math
from typing import List
import numpy as np

class BaseEmbeddingEngine(ABC):
    """Abstract base class for all embedding generators."""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Vector dimension."""
        pass

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Generate embedding vector for a single string."""
        pass

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embedding vectors for a batch of strings."""
        pass


class MockDeterministicEmbeddingEngine(BaseEmbeddingEngine):
    """
    Deterministic pseudo-semantic embedding engine for offline testing.
    Constructs vectors using hashed character n-grams and bag-of-words
    so that texts sharing vocabulary exhibit higher cosine similarity.
    Requires no external model download or network connection.
    """

    def __init__(self, dimension: int = 384):
        self._dimension = dimension

    @property
    def dimension(self) -> int:
        return self._dimension

    def _text_to_vector(self, text: str) -> List[float]:
        vec = np.zeros(self._dimension, dtype=np.float32)
        words = text.lower().split()
        if not words:
            # Deterministic zero/unit vector
            vec[0] = 1.0
            return vec.tolist()

        # Word-level contribution
        for word in words:
            # Hash each word to 4 deterministic coordinates
            word_hash = hashlib.sha256(word.encode("utf-8")).digest()
            for i in range(4):
                idx = int.from_bytes(word_hash[i*4:(i+1)*4], byteorder="big") % self._dimension
                val = (word_hash[(i+1)*4 % 32] / 255.0) * 2.0 - 1.0
                vec[idx] += val

        # Character bi-gram contribution for typo-tolerance & partial match
        cleaned = text.lower().replace(" ", "")
        for i in range(len(cleaned) - 1):
            bigram = cleaned[i:i+2]
            b_hash = hashlib.md5(bigram.encode("utf-8")).digest()
            idx = int.from_bytes(b_hash[:4], byteorder="big") % self._dimension
            vec[idx] += 0.2

        # L2 Normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec = vec / norm
        else:
            vec[0] = 1.0

        return vec.tolist()

    def embed_text(self, text: str) -> List[float]:
        return self._text_to_vector(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self._text_to_vector(t) for t in texts]


class SentenceTransformerEmbeddingEngine(BaseEmbeddingEngine):
    """Real local embedding engine using sentence-transformers (lazy loaded)."""

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        self._dimension = 384

    def _load_model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self.model_name)
                self._dimension = self._model.get_sentence_embedding_dimension()
            except ImportError:
                raise ImportError(
                    "sentence-transformers is not installed. "
                    "Install it or use MockDeterministicEmbeddingEngine."
                )

    @property
    def dimension(self) -> int:
        if self._model is None:
            return self._dimension
        return self._model.get_sentence_embedding_dimension()

    def embed_text(self, text: str) -> List[float]:
        self._load_model()
        vector = self._model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
        return vector.tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        self._load_model()
        vectors = self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
        return vectors.tolist()


def get_embedding_engine(use_mock: bool = True) -> BaseEmbeddingEngine:
    """Factory helper to obtain an embedding engine."""
    if use_mock:
        return MockDeterministicEmbeddingEngine(dimension=384)
    return SentenceTransformerEmbeddingEngine()
