"""PrivacyLens Core — Security & Sanitization Engine.

This package provides local-only PII detection, sanitization,
and outgoing payload guarding. No sensitive data leaves this host.
"""

from .detector import detect_pii
from .sanitizer import sanitize_text, SecretStore
from .guard import validate_outgoing_payload, SecurityViolationException

__all__ = [
    "detect_pii",
    "sanitize_text",
    "SecretStore",
    "validate_outgoing_payload",
    "SecurityViolationException",
]
