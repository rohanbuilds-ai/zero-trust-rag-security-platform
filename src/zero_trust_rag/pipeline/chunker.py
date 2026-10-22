"""Deterministic document chunker for Zero-Trust RAG."""

import hashlib
import re
from typing import List, Dict, Any

class DeterministicChunker:
    """Chunks text documents deterministically respecting paragraph and sentence boundaries."""

    def __init__(self, chunk_size: int = 500, chunk_overlap: int = 50):
        if chunk_size <= chunk_overlap:
            raise ValueError("chunk_size must be strictly greater than chunk_overlap")
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def chunk_text(self, text: str) -> List[Dict[str, Any]]:
        """Split text into overlapping chunks deterministically."""
        cleaned = text.strip()
        if not cleaned:
            return []

        chunks: List[str] = []
        start = 0
        text_len = len(cleaned)

        while start < text_len:
            end = min(start + self.chunk_size, text_len)

            # If not at the end of the text, look for natural break boundaries
            if end < text_len:
                # Look backwards for a paragraph break
                para_break = cleaned.rfind("\n\n", start + self.chunk_overlap, end)
                if para_break != -1:
                    end = para_break + 2
                else:
                    # Look backwards for sentence end
                    sentence_break = max(
                        cleaned.rfind(". ", start + self.chunk_overlap, end),
                        cleaned.rfind("! ", start + self.chunk_overlap, end),
                        cleaned.rfind("? ", start + self.chunk_overlap, end),
                        cleaned.rfind(";\n", start + self.chunk_overlap, end),
                    )
                    if sentence_break != -1:
                        end = sentence_break + 2
                    else:
                        # Look backwards for space
                        space_break = cleaned.rfind(" ", start + self.chunk_overlap, end)
                        if space_break != -1:
                            end = space_break + 1

            chunk_content = cleaned[start:end].strip()
            if chunk_content:
                chunks.append(chunk_content)

            # Move start pointer forward
            if end >= text_len:
                break
            start = max(start + 1, end - self.chunk_overlap)

        # Assemble chunk records
        records = []
        for idx, content in enumerate(chunks):
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            # Approximate token count (~4 characters per token in English text)
            token_count = max(1, len(content) // 4)
            records.append({
                "chunk_index": idx,
                "content": content,
                "token_count": token_count,
                "content_hash": content_hash
            })

        return records
