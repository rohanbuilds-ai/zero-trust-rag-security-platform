# ==============================================================================
# Zero-Trust RAG Security Platform - Production & Demo Containerfile
# Multi-stage minimal footprint, non-root execution, offline-deterministic by default.
# ==============================================================================

FROM python:3.11-slim

# Prevent Python from buffering stdout/stderr and writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/app/data \
    STORAGE_DIR=/app/data/storage \
    SQLITE_PATH=/app/data/storage/authoritative_metadata.db \
    VECTOR_STORE_PATH=/app/data/storage/vector_store \
    USE_MOCK_EMBEDDINGS=true \
    HOST=0.0.0.0 \
    PORT=8000

# Install curl for container health check and clean up package cache immediately
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group (least privilege)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

WORKDIR /app

# Create storage directories and set ownership before dropping privileges
RUN mkdir -p /app/data/storage/vector_store && \
    chown -R appuser:appgroup /app

# Copy project specification and application source
COPY --chown=appuser:appgroup pyproject.toml README.md /app/
COPY --chown=appuser:appgroup src/ /app/src/

# Install application and runtime dependencies
RUN pip install --no-cache-dir .

# Switch to non-root user
USER appuser

# Expose internal service port
EXPOSE 8000

# Health check targeting public unauthenticated endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/v1/health || exit 1

# Start FastAPI application with Uvicorn
CMD ["uvicorn", "zero_trust_rag.main:app", "--host", "0.0.0.0", "--port", "8000"]
