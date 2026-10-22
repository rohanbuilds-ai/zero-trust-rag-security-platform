"""Configuration management for Zero-Trust RAG."""

from pathlib import Path
from typing import Optional
import os

try:
    from pydantic_settings import BaseSettings
except ImportError:
    class BaseSettings:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

class Settings:
    """Application settings with environment variable support and safe local defaults."""

    def __init__(self):
        self.base_dir: Path = BASE_DIR

        # Configurable storage directories
        data_dir_env = os.getenv("DATA_DIR")
        self.data_dir: Path = Path(data_dir_env) if data_dir_env else (BASE_DIR / "data")

        storage_dir_env = os.getenv("STORAGE_DIR")
        self.storage_dir: Path = Path(storage_dir_env) if storage_dir_env else (self.data_dir / "storage")

        sqlite_env = os.getenv("SQLITE_PATH")
        self.sqlite_path: Path = Path(sqlite_env) if sqlite_env else (self.storage_dir / "authoritative_metadata.db")

        vector_env = os.getenv("VECTOR_STORE_PATH")
        self.vector_store_path: Path = Path(vector_env) if vector_env else (self.storage_dir / "vector_store")

        # Vector store type: "chroma" or "memory"
        self.vector_store_type: str = os.getenv("VECTOR_STORE_TYPE", "chroma").lower()

        # Embedding settings
        self.embedding_dimension: int = int(os.getenv("EMBEDDING_DIMENSION", "384"))
        self.embedding_model_name: str = os.getenv(
            "EMBEDDING_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"
        )
        self.use_mock_embeddings: bool = os.getenv("USE_MOCK_EMBEDDINGS", "true").lower() in ("true", "1", "yes")

        # Ingestion constraints
        self.max_document_bytes: int = int(os.getenv("MAX_DOCUMENT_BYTES", str(5 * 1024 * 1024)))
        self.max_document_characters: int = int(os.getenv("MAX_DOCUMENT_CHARACTERS", "500000"))
        self.default_chunk_size: int = int(os.getenv("DEFAULT_CHUNK_SIZE", "500"))
        self.default_chunk_overlap: int = int(os.getenv("DEFAULT_CHUNK_OVERLAP", "50"))

        # API settings
        self.api_title: str = os.getenv("API_TITLE", "Zero-Trust RAG Security Platform")
        self.api_version: str = os.getenv("API_VERSION", "0.1.0")
        self.debug: bool = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

        # Host and Port
        self.host: str = os.getenv("HOST", "127.0.0.1")
        self.port: int = int(os.getenv("PORT", "8000"))

        # Ensure directories exist
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            self.data_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

settings = Settings()
