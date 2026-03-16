"""
Utility helpers for the Security Gateway.
"""

import yaml
import os
import logging
import logging.handlers
from typing import Dict, Any


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """Load YAML configuration file."""
    if not os.path.isabs(config_path):
        # Resolve relative to project root (two levels up from this file)
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base, config_path)

    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def setup_logging(level: str = "INFO", log_file: str = "logs/gateway.log") -> None:
    """Configure root logger with console + rotating file handler."""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Console
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file
    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)


def pretty_result(result: Dict) -> str:
    """Format a gateway result for console display."""
    lines = [
        f"\n{'='*60}",
        f"  DECISION : {result['decision']}",
        f"  REASON   : {result['reason']}",
        f"  INJ SCORE: {result['injection_result']['score']} "
        f"({result['injection_result']['risk_level']})",
        f"  PII FOUND: {result['pii_result']['pii_found']} "
        f"({len(result['pii_result']['entities'])} entities)",
        f"  LATENCY  : {result['total_latency_ms']} ms",
    ]
    if result.get("llm_response") and result["llm_response"].get("content"):
        lines.append(f"  LLM REPLY: {result['llm_response']['content'][:200]}")
    lines.append("=" * 60)
    return "\n".join(lines)
