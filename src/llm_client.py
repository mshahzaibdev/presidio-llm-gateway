"""
LLM Client Module
Wraps the OpenRouter API (OpenAI-compatible).
Only called when the policy engine decides ALLOW or MASK.
"""

import os
import time
from typing import Dict, Optional

import requests


class LLMClient:
    """
    Lightweight OpenRouter client using the requests library.
    Falls back gracefully when no API key is configured.
    """

    DEFAULT_MODEL = "meta-llama/llama-3.1-8b-instruct:free"
    BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1000,
        timeout: int = 30,
    ):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        self.model = model or self.DEFAULT_MODEL
        self.max_tokens = max_tokens
        self.timeout = timeout

    def chat(self, user_message: str, system_prompt: Optional[str] = None) -> Dict:
        """
        Send a message to the LLM and return the response.

        Returns
        -------
        dict with keys: content, model, usage, latency_ms, error
        """
        if not self.api_key:
            return {
                "content": "[LLM_DISABLED] No OpenRouter API key configured.",
                "model": self.model,
                "usage": {},
                "latency_ms": 0.0,
                "error": "No API key",
            }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_message})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/cen451-llm-gateway",
            "X-Title": "CEN-451 LLM Security Gateway",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
        }

        start = time.perf_counter()
        try:
            resp = requests.post(
                self.BASE_URL,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            latency_ms = round((time.perf_counter() - start) * 1000, 3)

            content = data["choices"][0]["message"]["content"]
            return {
                "content": content,
                "model": data.get("model", self.model),
                "usage": data.get("usage", {}),
                "latency_ms": latency_ms,
                "error": None,
            }

        except requests.exceptions.Timeout:
            return {"content": None, "model": self.model, "usage": {}, "latency_ms": 0.0, "error": "Timeout"}
        except requests.exceptions.RequestException as exc:
            return {"content": None, "model": self.model, "usage": {}, "latency_ms": 0.0, "error": str(exc)}
