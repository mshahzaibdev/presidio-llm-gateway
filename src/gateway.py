"""
Security Gateway – Main Orchestrator
Connects all modules in the pipeline:
  User Input → Injection Detection → Presidio Analysis → Policy Decision → LLM (optional)
"""

import time
import logging
from typing import Dict, Optional

from .injection_detector import InjectionDetector
from .presidio_handler import PresidioHandler
from .policy_engine import PolicyEngine
from .llm_client import LLMClient

logger = logging.getLogger(__name__)


class SecurityGateway:
    """
    Full pipeline orchestrator.

    Parameters
    ----------
    injection_threshold : int
        Score (0-100) above which input is BLOCKED.
    pii_confidence_threshold : float
        Presidio confidence above which PII triggers MASK.
    anonymization_enabled : bool
        Whether to anonymise PII before forwarding to LLM.
    llm_api_key : str, optional
        OpenRouter API key (can also be set via OPENROUTER_API_KEY env var).
    llm_model : str, optional
        Model identifier for OpenRouter.
    """

    def __init__(
        self,
        injection_threshold: int = 50,
        pii_confidence_threshold: float = 0.7,
        anonymization_enabled: bool = True,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
        max_tokens: int = 1000,
    ):
        self.injection_detector = InjectionDetector(threshold=injection_threshold)
        self.presidio_handler = PresidioHandler(
            confidence_threshold=pii_confidence_threshold,
            anonymization_enabled=anonymization_enabled,
        )
        self.policy_engine = PolicyEngine(
            injection_threshold=injection_threshold,
            pii_confidence_threshold=pii_confidence_threshold,
            mask_on_pii=anonymization_enabled,
        )
        self.llm_client = LLMClient(
            api_key=llm_api_key,
            model=llm_model,
            max_tokens=max_tokens,
        )

    def process(self, user_input: str, system_prompt: Optional[str] = None) -> Dict:
        """
        Process a single user input through the full security pipeline.

        Returns
        -------
        dict containing:
            decision          – ALLOW / MASK / BLOCK
            reason            – human-readable explanation
            injection_result  – raw injection detection output
            pii_result        – raw Presidio output
            llm_response      – LLM reply (None if BLOCK)
            total_latency_ms  – end-to-end latency
            component_latency – per-component breakdown
        """
        pipeline_start = time.perf_counter()

        # --- Stage 1: Injection Detection ---
        injection_result = self.injection_detector.detect(user_input)
        inj_latency = injection_result["latency_ms"]

        # --- Stage 2: PII Detection ---
        pii_result = self.presidio_handler.analyze(user_input)
        pii_latency = pii_result["latency_ms"]

        # --- Stage 3: Policy Decision ---
        policy_start = time.perf_counter()
        policy_result = self.policy_engine.decide(injection_result, pii_result)
        policy_latency = round((time.perf_counter() - policy_start) * 1000, 3)

        # --- Stage 4: LLM Call (if allowed) ---
        llm_response = None
        llm_latency = 0.0

        decision = policy_result["decision"]
        if decision in ("ALLOW", "MASK"):
            text_to_send = policy_result.get("safe_text") or user_input
            llm_result = self.llm_client.chat(text_to_send, system_prompt)
            llm_response = llm_result
            llm_latency = llm_result["latency_ms"]
        else:
            logger.warning("Request BLOCKED. Score=%s", injection_result["score"])

        total_latency = round((time.perf_counter() - pipeline_start) * 1000, 3)

        return {
            "decision": decision,
            "reason": policy_result["reason"],
            "injection_result": injection_result,
            "pii_result": pii_result,
            "policy_metadata": policy_result["metadata"],
            "llm_response": llm_response,
            "total_latency_ms": total_latency,
            "component_latency": {
                "injection_detection_ms": inj_latency,
                "presidio_analysis_ms": pii_latency,
                "policy_decision_ms": policy_latency,
                "llm_call_ms": llm_latency,
            },
        }
