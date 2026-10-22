"""Deterministic inspection of suspicious document content for prompt injection and poisoning."""

import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from zero_trust_rag.core.models import InspectionOutcome
from zero_trust_rag.security.canonicalization import normalize_for_inspection

class InspectionFinding(BaseModel):
    rule_id: str
    severity: str  # HIGH, MEDIUM, LOW
    description: str

class InspectionResult(BaseModel):
    outcome: InspectionOutcome
    findings: List[InspectionFinding] = Field(default_factory=list)
    inspected_length: int
    detector_version: str = "1.0.0"

class DocumentInspector:
    """
    Deterministic rule-based document inspector.
    Identifies high-confidence indirect prompt injection payloads, system overrides,
    and adversarial context manipulation patterns without broad false positives.
    """

    def __init__(self, max_length: int = 500_000):
        self.max_length = max_length
        self._rules = [
            # 1. Direct Instruction Overrides
            (
                "INST_OVERRIDE",
                "HIGH",
                re.compile(
                    r"(?i)\b(ignore|disregard|forget|override|cancel)\s+(all\s+)?(previous|prior|above|preceding|system)\s+(instructions?|prompts?|rules?|commands?|directives?)\b"
                ),
                "Direct instruction override attempt detected (e.g. ignore prior instructions)."
            ),
            (
                "INST_OVERRIDE_ALT",
                "HIGH",
                re.compile(
                    r"(?i)\b(system\s+override|admin\s+override|mode\s+switch:\s*developer|instruction\s+priority\s*=\s*override)\b"
                ),
                "System override or developer mode switch directive detected."
            ),
            # 2. Requests to Expose Credentials, Secrets, or Cross-Tenant Data
            (
                "CRED_EXPOSURE",
                "HIGH",
                re.compile(
                    r"(?i)\b(output|print|reveal|expose|dump|leak|show|display)\s+(the\s+)?(internal\s+)?(system\s+prompt|master\s+key|api\s+keys?|other\s+tenants?|all\s+passwords?|private\s+keys?)\b"
                ),
                "Instruction to expose system prompts, credentials, or cross-tenant secrets detected."
            ),
            (
                "PROMPT_LEAK",
                "HIGH",
                re.compile(
                    r"(?i)\b(show|display|return|repeat)\s+(me\s+)?(the\s+)?(underlying|hidden|initial|original)\s+system\s+(prompt|instructions?)\b"
                ),
                "Request to leak underlying system instructions detected."
            ),
            # 3. Authorization Bypass Instructions
            (
                "AUTH_BYPASS",
                "HIGH",
                re.compile(
                    r"(?i)\b(bypass|disable|skip|override)\s+(all\s+)?(authorization|security\s+checks?|rbac|access\s+controls?|acls?|guardrails?|filters?)\b"
                ),
                "Directive to bypass authorization or security checks detected."
            ),
            (
                "PRIV_ELEVATION",
                "HIGH",
                re.compile(
                    r"(?i)\bgrant\s+(me\s+)?(all\s+)?(permissions?|admin\s+access|root\s+privileges?|unrestricted\s+access)\b"
                ),
                "Privilege elevation command detected in document content."
            ),
            # 4. Embedded Assistant Directives Aimed at Downstream Models
            (
                "EMBEDDED_DIRECTIVE",
                "HIGH",
                re.compile(
                    r"(?i)(\[\s*system\s*:\s*execute|<\s*system_command\s*>|\bassistant\s*:\s*you\s+must\s+now\b|\bfrom\s+now\s+on,\s+you\s+are\s+no\s+longer\b)"
                ),
                "Embedded system directive designed to hijack downstream assistant behavior detected."
            ),
            # 5. Retrieval Context Manipulation and Citation Suppression
            (
                "CONTEXT_MANIPULATION",
                "HIGH",
                re.compile(
                    r"(?i)\b(suppress|omit|delete|hide|do\s+not\s+(show|include|output))\s+(the\s+)?(citations?|sources?|provenance|attributions?)\b"
                ),
                "Attempt to suppress source attribution or tamper with retrieval citations detected."
            ),
        ]

    def inspect(self, text: Optional[str]) -> InspectionResult:
        """
        Inspect text for suspicious content.
        Fails closed with INSPECTION_ERROR on oversized content.
        Returns CLEAN if no high-confidence malicious patterns match.
        """
        if not text:
            return InspectionResult(outcome=InspectionOutcome.CLEAN, inspected_length=0)

        length = len(text)
        if length > self.max_length:
            return InspectionResult(
                outcome=InspectionOutcome.INSPECTION_ERROR,
                findings=[
                    InspectionFinding(
                        rule_id="SIZE_EXCEEDED",
                        severity="HIGH",
                        description=f"Document length {length} exceeds maximum inspectable size {self.max_length} characters."
                    )
                ],
                inspected_length=length
            )

        findings: List[InspectionFinding] = []
        seen_rule_ids = set()
        variants = normalize_for_inspection(text)

        for rule_id, severity, pattern, desc in self._rules:
            for variant in variants:
                if pattern.search(variant):
                    if rule_id not in seen_rule_ids:
                        findings.append(
                            InspectionFinding(
                                rule_id=rule_id,
                                severity=severity,
                                description=desc
                            )
                        )
                        seen_rule_ids.add(rule_id)
                    break

        if findings:
            return InspectionResult(
                outcome=InspectionOutcome.SUSPICIOUS,
                findings=findings,
                inspected_length=length
            )

        return InspectionResult(
            outcome=InspectionOutcome.CLEAN,
            findings=[],
            inspected_length=length
        )
