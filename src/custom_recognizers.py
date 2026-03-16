"""
Custom Presidio Recognizers (Customization #1, #2, #3)

1. PakistaniCNICRecognizer  – CNIC pattern XXXXX-XXXXXXX-X
2. PakistaniPhoneRecognizer – Pakistani mobile / landline numbers
3. APIKeyRecognizer          – sk-*, Bearer tokens, JWTs
"""

from presidio_analyzer import Pattern, PatternRecognizer


class PakistaniCNICRecognizer(PatternRecognizer):
    """
    Recognises Pakistani Computerised National Identity Card numbers.
    Format: 00000-0000000-0  (13 digits with dashes)
    """

    PATTERNS = [
        Pattern(
            name="CNIC_WITH_DASHES",
            regex=r"\b\d{5}-\d{7}-\d{1}\b",
            score=0.95,
        ),
        Pattern(
            name="CNIC_COMPACT",
            regex=r"\b\d{13}\b",
            score=0.55,
        ),
    ]

    CONTEXT = [
        "cnic", "national identity", "id card", "identity card",
        "nic", "national id", "computerised national", "identity number",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PK_CNIC",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class PakistaniPhoneRecognizer(PatternRecognizer):
    """
    Recognises Pakistani phone numbers:
    - Mobile 03XX-XXXXXXX
    - International +92-3XX-XXXXXXX
    - Landline 0XX-XXXXXXX
    """

    PATTERNS = [
        Pattern(
            name="PK_MOBILE_03",
            regex=r"\b03\d{2}[-\s]?\d{7}\b",
            score=0.90,
        ),
        Pattern(
            name="PK_MOBILE_INTL",
            regex=r"\+92[-\s]?3\d{2}[-\s]?\d{7}\b",
            score=0.95,
        ),
        Pattern(
            name="PK_LANDLINE",
            regex=r"\b0[2-9]\d{1,2}[-\s]?\d{6,8}\b",
            score=0.65,
        ),
    ]

    CONTEXT = [
        "phone", "mobile", "cell", "contact", "call", "number",
        "tel", "whatsapp", "telephone", "reach me at",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PK_PHONE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


class APIKeyRecognizer(PatternRecognizer):
    """
    Recognises API keys, bearer tokens, and JWTs.
    """

    PATTERNS = [
        Pattern(
            name="OPENAI_STYLE_KEY",
            regex=r"\bsk-[A-Za-z0-9]{20,}\b",
            score=0.97,
        ),
        Pattern(
            name="BEARER_TOKEN",
            regex=r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b",
            score=0.92,
        ),
        Pattern(
            name="JWT",
            regex=r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            score=0.95,
        ),
        Pattern(
            name="HEX_API_KEY",
            regex=r"\b[0-9a-fA-F]{32,64}\b",
            score=0.45,
        ),
    ]

    CONTEXT = [
        "api key", "api_key", "apikey", "token", "secret", "key",
        "authorization", "auth", "access token", "credential",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )


def get_custom_recognizers() -> list:
    """Return all custom recognizer instances."""
    return [
        PakistaniCNICRecognizer(),
        PakistaniPhoneRecognizer(),
        APIKeyRecognizer(),
    ]
