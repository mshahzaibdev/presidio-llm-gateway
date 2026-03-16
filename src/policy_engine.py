"""
Policy Decision Engine
Combines injection detection and PII analysis results to produce
a final decision: ALLOW, MASK, or BLOCK.
"""

from enum import Enum
from typing import Dict, Optional


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    BLOCK = "BLOCK"


class PolicyEngine:
    """
    Evaluates injection and PII signals and returns a policy decision.

    Decision logic (evaluated in order):
    1. BLOCK  – injection score >= injection_threshold
    2. MASK   – PII detected and anonymization is enabled
    3. ALLOW  – everything else
    """

    def __init__(
        self,
        injection_threshold: int = 50,
        pii_confidence_threshold: float = 0.7,
        block_on_injection: bool = True,
        mask_on_pii: bool = True,
    ):
        self.injection_threshold = injection_threshold
        self.pii_confidence_threshold = pii_confidence_threshold
        self.block_on_injection = block_on_injection
        self.mask_on_pii = mask_on_pii

    def decide(
        self,
        injection_result: Dict,
        pii_result: Optional[Dict] = None,
    ) -> Dict:
        """
        Produce a policy decision.

        Parameters
        ----------
        injection_result : dict
            Output from InjectionDetector.detect().
        pii_result : dict, optional
            Output from PresidioHandler.analyze().

        Returns
        -------
        dict with keys: decision, reason, safe_text, metadata
        """
        decision = Decision.ALLOW
        reason = "Input appears safe."
        safe_text = None

        # --- Rule 1: BLOCK on injection ---
        if self.block_on_injection and injection_result.get("is_injection", False):
            decision = Decision.BLOCK
            risk = injection_result.get("risk_level", "HIGH")
            score = injection_result.get("score", 0)
            cats = injection_result.get("matched_categories", [])
            reason = (
                f"Injection detected (score={score}, risk={risk}). "
                f"Categories: {', '.join(cats) if cats else 'N/A'}."
            )
            safe_text = None

        # --- Rule 2: MASK on PII ---
        elif self.mask_on_pii and pii_result and pii_result.get("pii_found", False):
            decision = Decision.MASK
            entity_types = list({e["entity_type"] for e in pii_result.get("entities", [])})
            composite = pii_result.get("composite_risk", 0.0)
            reason = (
                f"PII detected: {', '.join(entity_types)}. "
                f"Composite risk={composite:.2f}. Text anonymised."
            )
            safe_text = pii_result.get("anonymized_text", None)

        else:
            safe_text = (
                pii_result.get("anonymized_text") if pii_result else None
            ) or injection_result.get("_original_text")

        return {
            "decision": decision.value,
            "reason": reason,
            "safe_text": safe_text,
            "metadata": {
                "injection_score": injection_result.get("score", 0),
                "injection_risk_level": injection_result.get("risk_level", "SAFE"),
                "pii_entities_found": len(pii_result.get("entities", [])) if pii_result else 0,
                "composite_pii_risk": pii_result.get("composite_risk", 0.0) if pii_result else 0.0,
            },
        }
