"""
Presidio Handler Module
Wraps Microsoft Presidio Analyzer + Anonymizer with:
  - Custom recognizers (PK_CNIC, PK_PHONE, API_KEY)
  - Context-aware confidence boosting  (Customization #4)
  - Composite entity detection          (Customization #5)
  - Confidence calibration per entity   (Customization #6 — bonus)
"""

import time
from typing import Dict, List, Optional

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .custom_recognizers import get_custom_recognizers


# ---------------------------------------------------------------------------
# Sensitivity context keywords that boost confidence scores
# ---------------------------------------------------------------------------
SENSITIVE_CONTEXT_KEYWORDS = [
    "my", "personal", "private", "confidential", "secret",
    "password is", "ssn is", "number is", "email is", "address is",
    "id is", "cnic is", "phone is", "key is", "token is",
]

# Per-entity confidence calibration deltas (Customization #6)
CONFIDENCE_CALIBRATION: Dict[str, float] = {
    "PERSON":        0.0,
    "EMAIL_ADDRESS":  0.05,
    "PHONE_NUMBER":   0.0,
    "CREDIT_CARD":    0.05,
    "US_SSN":         0.05,
    "PK_CNIC":        0.0,
    "PK_PHONE":       0.0,
    "API_KEY":        0.05,
    "LOCATION":      -0.35,   # High FP rate (country/city names in normal text) — push below threshold
    "DATE_TIME":     -0.35,   # Dates rarely constitute sensitive PII alone
}


class PresidioHandler:
    """
    Detects and anonymises PII in text.

    Parameters
    ----------
    confidence_threshold : float
        Minimum Presidio confidence score to treat a result as a true PII hit.
    anonymization_enabled : bool
        When True, PII is replaced with ``<ENTITY_TYPE>`` placeholders.
    """

    def __init__(self, confidence_threshold: float = 0.7, anonymization_enabled: bool = True):
        self.confidence_threshold = confidence_threshold
        self.anonymization_enabled = anonymization_enabled

        # Build NLP engine (spaCy en_core_web_lg or fallback to sm)
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
            })
            nlp_engine = provider.create_engine()
        except Exception:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            })
            nlp_engine = provider.create_engine()

        # Register custom recognizers
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp_engine)
        for recognizer in get_custom_recognizers():
            registry.add_recognizer(recognizer)

        self.analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine)
        self.anonymizer = AnonymizerEngine()

        # Warm-up: force spaCy model load now so first real request isn't slow
        self.analyzer.analyze(text="warmup", language="en")

    # ------------------------------------------------------------------
    # Customization #4 – Context-aware confidence boosting
    # ------------------------------------------------------------------

    def _boost_by_context(self, text: str, results: list) -> list:
        """
        Increase entity confidence when sensitive keywords appear near the match.
        Checks a ±80 character window around each detected entity.
        """
        text_lower = text.lower()
        boosted = []
        for r in results:
            window_start = max(0, r.start - 80)
            window_end = min(len(text), r.end + 80)
            window = text_lower[window_start:window_end]
            boost = 0.0
            for kw in SENSITIVE_CONTEXT_KEYWORDS:
                if kw in window:
                    boost = 0.15
                    break
            new_score = min(1.0, r.score + boost)
            # Rebuild with updated score (Presidio RecognizerResult is a simple dataclass)
            r.score = new_score
            boosted.append(r)
        return boosted

    # ------------------------------------------------------------------
    # Customization #6 – Confidence calibration
    # ------------------------------------------------------------------

    def _calibrate_confidence(self, results: list) -> list:
        """Apply per-entity-type calibration deltas."""
        for r in results:
            delta = CONFIDENCE_CALIBRATION.get(r.entity_type, 0.0)
            r.score = min(1.0, max(0.0, r.score + delta))
        return results

    # ------------------------------------------------------------------
    # Customization #5 – Composite entity detection
    # ------------------------------------------------------------------

    def _composite_risk_score(self, entities: List[Dict]) -> float:
        """
        Return an elevated composite risk score (0-1) when multiple PII
        types co-occur (e.g. Name + Phone + Location = identity profile).
        """
        entity_types = {e["entity_type"] for e in entities}
        profile_indicators = {"PERSON", "PHONE_NUMBER", "PK_PHONE", "LOCATION", "EMAIL_ADDRESS"}
        credential_indicators = {"API_KEY", "US_SSN", "PK_CNIC", "CREDIT_CARD", "IBAN_CODE"}

        overlap_profile = len(entity_types & profile_indicators)
        overlap_cred = len(entity_types & credential_indicators)

        if overlap_profile >= 3 or overlap_cred >= 2:
            return 1.0
        elif overlap_profile >= 2 or overlap_cred >= 1:
            return 0.7
        elif len(entity_types) >= 1:
            return 0.4
        return 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, text: str) -> Dict:
        """
        Run PII detection pipeline on *text*.

        Returns
        -------
        dict with keys:
            entities      – list of detected entity dicts
            pii_found     – bool
            composite_risk – float 0-1
            anonymized_text – str (original if anonymization disabled)
            latency_ms    – float
        """
        start = time.perf_counter()

        raw_results = self.analyzer.analyze(text=text, language="en")

        # Apply customizations #4 and #6
        raw_results = self._boost_by_context(text, raw_results)
        raw_results = self._calibrate_confidence(raw_results)

        # Filter by calibrated threshold
        filtered = [r for r in raw_results if r.score >= self.confidence_threshold]

        entities = [
            {
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 4),
                "text": text[r.start:r.end],
            }
            for r in filtered
        ]

        pii_found = len(entities) > 0
        composite_risk = self._composite_risk_score(entities)

        anonymized_text = text
        if self.anonymization_enabled and pii_found:
            operators = {
                e["entity_type"]: OperatorConfig("replace", {"new_value": f"<{e['entity_type']}>"})
                for e in entities
            }
            anon_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=filtered,
                operators=operators,
            )
            anonymized_text = anon_result.text

        latency_ms = round((time.perf_counter() - start) * 1000, 3)

        return {
            "entities": entities,
            "pii_found": pii_found,
            "composite_risk": composite_risk,
            "anonymized_text": anonymized_text,
            "latency_ms": latency_ms,
        }
