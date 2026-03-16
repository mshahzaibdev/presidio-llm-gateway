"""
Injection Detection Module
Detects prompt injection and jailbreak attempts using a weighted scoring mechanism.
Score range: 0 (safe) to 100 (definite attack).
"""

import re
import time
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Pattern definitions with per-category weights
# ---------------------------------------------------------------------------
INJECTION_PATTERNS: Dict[str, Dict] = {
    "instruction_override": {
        "patterns": [
            r"ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions?",
            r"ignore\s+all\s+(?:\w+\s+)?instructions?",
            r"disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions?",
            r"forget\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions?",
            r"override\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions?",
            r"new\s+instructions?:",
            r"from\s+now\s+on[,\s]",
            r"you\s+(must|will|should)\s+now\b",
            r"your\s+new\s+task\s+is",
        ],
        "weight": 30,
    },
    "jailbreak_roleplay": {
        "patterns": [
            r"\bDAN\b",
            r"\bdo\s+anything\s+now\b",
            r"act\s+as\s+(DAN|a\s+(hacker|criminal|terrorist|evil|malicious|unrestricted))",
            r"pretend\s+(you\s+are|to\s+be)\s+(DAN|evil|malicious|unrestricted|an?\s+AI\s+without)",
            r"you\s+are\s+now\s+(DAN|a\s+(hacker|criminal|unrestricted\s+AI))",
            r"\bjailbreak\b",
            r"developer\s+mode",
            r"no\s+(ethical\s+)?restrictions?",
            r"without\s+(any\s+)?(ethical\s+|safety\s+)?restrictions?",
            r"evil\s+mode",
            r"opposite\s+mode",
        ],
        "weight": 35,
    },
    "system_prompt_extraction": {
        "patterns": [
            r"(show|reveal|print|repeat|tell\s+me|display|output)\s+(your\s+|the\s+)?(system\s+|initial\s+|original\s+)?prompt",
            r"(show|reveal|print|repeat|tell\s+me)\s+(your\s+|the\s+)?(instructions?|directives?|rules?|guidelines?)",
            r"what\s+(are|were)\s+your\s+(initial\s+|original\s+)?(instructions?|directives?|rules?|guidelines?)",
            r"repeat\s+(everything|all)\s+(above|before|prior|verbatim)",
            r"output\s+(everything|all|your\s+)(instructions?|system\s+prompt|training\s+data)",
            r"ignore\s+.*\s+repeat\s+the",
        ],
        "weight": 25,
    },
    "hypothetical_bypass": {
        "patterns": [
            r"hypothetically\s+speaking",
            r"in\s+a\s+(fictional|hypothetical|imaginary)\s+(world|scenario|story|universe)",
            r"for\s+(a\s+story|a\s+novel|creative\s+writing|fiction|academic\s+purposes?|a\s+game)",
            r"(imagine|suppose)\s+(you\s+had\s+no|there\s+were\s+no)\s+(restrictions?|limitations?|guidelines?)",
            r"if\s+you\s+(were|had\s+no)\s+(not\s+)?(restricted|limitations?|guidelines?)",
            r"let'?s\s+play\s+a\s+(game|roleplay|simulation)",
        ],
        "weight": 15,
    },
    "encoding_obfuscation": {
        "patterns": [
            r"\bbase64\b",
            r"\brot13\b",
            r"(decode|encode)\s+(this|the\s+following)",
            r"in\s+(l33t|pig\s+latin|pig-latin|reverse|morse\s+code)",
            r"translate\s+.{1,30}\s+to\s+english",
            r"\\u[0-9a-fA-F]{4}",
        ],
        "weight": 20,
    },
    "privilege_escalation": {
        "patterns": [
            r"(admin|root|sudo|superuser|administrator)\s+(mode|access|privileges?|rights?|panel)",
            r"bypass\s+(security|safety|filter|restriction|guideline|content\s+policy)",
            r"(enable|unlock|disable|turn\s+off)\s+(safety|restriction|filter|guideline|moderation)",
            r"(grant|give)\s+(me\s+)?(admin|root|full)\s+(access|rights?|privileges?)",
        ],
        "weight": 25,
    },
    "credential_extraction": {
        "patterns": [
            r"(give|tell|show|send)\s+me\s+(your\s+)?(password|credentials?|api\s+key|secret|token)",
            r"what\s+is\s+(your\s+)?(password|api\s+key|secret\s+key|auth\s+token)",
            r"(leak|expose|reveal)\s+(the\s+)?(api\s+key|secret|credentials?|password)",
        ],
        "weight": 25,
    },
}

# Absolute red-flag phrases that force minimum score of 75
RED_FLAG_PATTERNS = [
    r"\bDAN\b",
    r"do\s+anything\s+now",
    r"ignore\s+(?:all\s+)?(?:all|previous|prior|your)?\s*instructions?",
    r"\bjailbreak\b",
    r"no\s+restrictions?",
    r"bypass\s+(safety|security|filter)",
    r"developer\s+mode",
    r"evil\s+mode",
]


class InjectionDetector:
    """
    Detects prompt injection and jailbreak attempts.
    Returns a risk score 0-100 and decision metadata.
    """

    def __init__(self, threshold: int = 50):
        self.threshold = threshold
        self._compiled_patterns = self._compile_patterns()
        self._compiled_red_flags = [re.compile(p, re.IGNORECASE) for p in RED_FLAG_PATTERNS]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compile_patterns(self) -> Dict:
        compiled = {}
        for category, data in INJECTION_PATTERNS.items():
            compiled[category] = {
                "patterns": [re.compile(p, re.IGNORECASE) for p in data["patterns"]],
                "weight": data["weight"],
            }
        return compiled

    def _get_risk_level(self, score: int) -> str:
        if score >= 75:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 25:
            return "LOW"
        return "SAFE"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calculate_score(self, text: str) -> Tuple[int, List[str], Dict]:
        """
        Compute injection risk score for *text*.

        Returns
        -------
        score : int
            Risk score 0-100.
        matched_categories : list[str]
            Names of categories that fired.
        details : dict
            Per-category match counts and score contributions.
        """
        score = 0
        matched_categories: List[str] = []
        details: Dict = {}

        for category, data in self._compiled_patterns.items():
            matches: List[str] = []
            for pattern in data["patterns"]:
                found = pattern.findall(text)
                if found:
                    matches.extend([str(m) for m in found])

            if matches:
                matched_categories.append(category)
                contribution = min(data["weight"] * len(matches), data["weight"] * 2)
                score += contribution
                details[category] = {
                    "matches": len(matches),
                    "score_contribution": contribution,
                }

        # Red flags bump score to at least 75
        for rf in self._compiled_red_flags:
            if rf.search(text):
                score = max(score, 75)
                break

        score = min(score, 100)
        return score, matched_categories, details

    def detect(self, text: str) -> Dict:
        """
        Full detection pipeline for a single input text.

        Returns a dict with keys: score, is_injection, risk_level,
        matched_categories, details, latency_ms.
        """
        start = time.perf_counter()
        score, categories, details = self.calculate_score(text)
        latency_ms = round((time.perf_counter() - start) * 1000, 3)

        return {
            "score": score,
            "is_injection": score >= self.threshold,
            "risk_level": self._get_risk_level(score),
            "matched_categories": categories,
            "details": details,
            "latency_ms": latency_ms,
        }
