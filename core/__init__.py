"""
core/__init__.py - PrivacyLens Local Security & Privacy Engine (PS-004).

Architecture:
"Compute what is sensitive locally. Reason globally only on sanitized data."
"""

from .detector import PIIType, detect_pii, luhn_checksum
from .guard import SecurityViolationException, is_payload_safe, validate_outgoing_payload
from .sanitizer import Sanitizer

__all__ = [
    "PIIType",
    "detect_pii",
    "luhn_checksum",
    "Sanitizer",
    "SecurityViolationException",
    "validate_outgoing_payload",
    "is_payload_safe",
]
