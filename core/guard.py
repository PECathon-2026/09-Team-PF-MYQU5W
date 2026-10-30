"""
core/guard.py - Fail-Closed Outgoing Security Validator for PrivacyLens.

Architecture Requirement:
"Compute what is sensitive locally. Reason globally only on sanitized data."

This module implements the outgoing fail-closed security boundary. It scans
all outgoing payloads for unredacted PII before any data can leave the local
environment to external LLMs or third-party APIs.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .detector import detect_pii

# Configure structured security logging
logger = logging.getLogger("privacylens.guard")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [PrivacyLensGuard] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class SecurityViolationException(Exception):
    """
    Exception raised when an outgoing payload violates the fail-closed privacy policy
    by containing unredacted PII or secrets.
    """

    def __init__(
        self,
        message: str = "Payload blocked due to PII leakage risk",
        detected_pii: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.detected_pii = detected_pii or []

    def __str__(self) -> str:
        if self.detected_pii:
            types = ", ".join(d.get("type", "UNKNOWN") for d in self.detected_pii)
            return f"{self.message} (Violations detected: {types})"
        return self.message


def validate_outgoing_payload(payload_str: str, raise_exception: bool = True) -> bool:
    """
    Outgoing fail-closed security validator.
    
    Scans outgoing strings for unredacted PII using detector.py before data
    leaves the local host to external LLMs.
    
    If ANY unredacted sensitive value is detected:
        - Logs a security alert: "FAIL-CLOSED GUARD TRIGGERED: Unredacted PII detected!"
        - Raises SecurityViolationException("Payload blocked due to PII leakage risk")
        - Returns False (if exception handling is bypassed)
        
    If clean:
        - Returns True.
        
    Args:
        payload_str: Outgoing payload string intended for external LLM or API.
        raise_exception: Whether to raise SecurityViolationException on violation.
        
    Returns:
        True if the payload is completely sanitized and safe; False if blocked.
        
    Raises:
        SecurityViolationException: If unredacted PII is found and raise_exception is True.
    """
    if not isinstance(payload_str, str):
        payload_str = str(payload_str)

    # Perform multi-layered scan
    detected = detect_pii(payload_str)

    if detected:
        # 1. Log mandatory security alert
        logger.error("FAIL-CLOSED GUARD TRIGGERED: Unredacted PII detected!")

        # 2. Detailed audit logging
        for idx, item in enumerate(detected, start=1):
            logger.warning(
                "Blocked PII Leak #%d: Type=%s, Selector=%s, Span=[%d:%d]",
                idx,
                item.get("type"),
                item.get("selector"),
                item.get("start"),
                item.get("end"),
            )

        # 3. Fail-closed: raise exception and/or return False
        if raise_exception:
            raise SecurityViolationException(
                "Payload blocked due to PII leakage risk",
                detected_pii=detected,
            )
        return False

    return True


def is_payload_safe(payload_str: str) -> bool:
    """
    Non-throwing convenience check to verify if a payload is completely sanitized.
    
    Args:
        payload_str: The payload string to test.
        
    Returns:
        True if no unredacted PII is present, False otherwise.
    """
    return validate_outgoing_payload(payload_str, raise_exception=False)
