"""Command-line entry point to run Zero-Trust RAG security evaluation benchmark."""

import os
import sys
from pathlib import Path

# Add src to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from zero_trust_rag.evaluation.runner import main

if __name__ == "__main__":
    main()
