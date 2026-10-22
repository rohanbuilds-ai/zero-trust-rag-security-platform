"""Dataset loaders for Zero-Trust RAG evaluation."""

from typing import List, Dict, Optional
from zero_trust_rag.evaluation.models import EvaluationScenario, ScenarioCategory
from zero_trust_rag.evaluation.datasets.prompt_injection import get_prompt_injection_scenarios
from zero_trust_rag.evaluation.datasets.access_control import get_access_control_scenarios
from zero_trust_rag.evaluation.datasets.dlp_corpus import get_dlp_scenarios
from zero_trust_rag.evaluation.datasets.content_integrity import get_content_integrity_scenarios
from zero_trust_rag.evaluation.datasets.benign_usability import get_benign_usability_scenarios


def load_all_scenarios(category_filter: Optional[ScenarioCategory] = None) -> List[EvaluationScenario]:
    """Load all benchmark scenarios, optionally filtered by category."""
    all_scenarios: List[EvaluationScenario] = []
    all_scenarios.extend(get_prompt_injection_scenarios())
    all_scenarios.extend(get_access_control_scenarios())
    all_scenarios.extend(get_dlp_scenarios())
    all_scenarios.extend(get_content_integrity_scenarios())
    all_scenarios.extend(get_benign_usability_scenarios())

    if category_filter:
        return [s for s in all_scenarios if s.category == category_filter]
    return all_scenarios


def get_dataset_summary() -> Dict[str, int]:
    """Return counts of scenarios per category."""
    return {
        "prompt_injection": len(get_prompt_injection_scenarios()),
        "access_control": len(get_access_control_scenarios()),
        "dlp_sensitive_data": len(get_dlp_scenarios()),
        "content_integrity": len(get_content_integrity_scenarios()),
        "benign_usability": len(get_benign_usability_scenarios()),
        "total": len(load_all_scenarios()),
    }
