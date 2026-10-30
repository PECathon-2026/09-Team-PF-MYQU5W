"""Outgoing Payload Guard — Fail-Closed PII Blocker.

This module is the LAST LINE OF DEFENSE before any data leaves the
local machine. It scans outgoing payloads for unredacted PII and
BLOCKS transmission if any is found.

Behavior: FAIL-CLOSED
    If PII is detected → raise SecurityViolationException
    If scan fails      → raise SecurityViolationException
    If scan passes     → allow payload through
"""

from __future__ import annotations

import re
import logging
from typing import List, Optional

from .detector import detect_pii, PIIEntity, PIIType

logger = logging.getLogger(__name__)


class SecurityViolationException(Exception):
    """Raised when outgoing payload contains unredacted PII.
    
    This exception MUST be caught and the payload MUST NOT be sent.
    """

    def __init__(self, violations: List[PIIEntity], payload_preview: str = ""):
        self.violations = violations
        self.payload_preview = payload_preview[:200]  # truncated for safety
        pii_types = ", ".join(set(v.pii_type.value for v in violations))
        super().__init__(
            f"BLOCKED: Outgoing payload contains {len(violations)} "
            f"unredacted PII instance(s) of type(s): {pii_types}. "
            f"Transmission denied."
        )


def validate_outgoing_payload(
    payload: str,
    *,
    allowed_placeholders: bool = True,
    raise_on_violation: bool = True,
) -> List[PIIEntity]:
    """Scan an outgoing payload for unredacted PII. Fail-closed.
    
    This function MUST be called before any data is sent to a
    cloud LLM, external API, or any non-local endpoint.
    
    Args:
        payload: The string payload about to be transmitted.
        allowed_placeholders: If True, `[REDACTED:*]` tokens are
                              considered safe and ignored.
        raise_on_violation: If True, raise SecurityViolationException
                            on PII detection. If False, return the list.
    
    Returns:
        List of PIIEntity violations (empty if clean).
        
    Raises:
        SecurityViolationException: If unredacted PII is found and
                                     raise_on_violation is True.
    """
    try:
        violations = detect_pii(payload)
    except Exception as exc:
        # FAIL-CLOSED: If detection itself fails, block the payload
        logger.error("PII detection failed — blocking payload: %s", exc)
        if raise_on_violation:
            raise SecurityViolationException(
                violations=[],
                payload_preview=payload,
            ) from exc
        return []

    if allowed_placeholders:
        # Filter out properly redacted placeholders
        violations = [
            v for v in violations
            if not re.match(r'\[REDACTED:[A-Z_]+_\d+\]', v.value)
        ]

    if violations and raise_on_violation:
        logger.warning(
            "SecurityViolationException: %d PII leaks blocked.",
            len(violations),
        )
        raise SecurityViolationException(
            violations=violations,
            payload_preview=payload,
        )

    return violations


def guard_request(
    url: str,
    *,
    headers: Optional[dict] = None,
    body: Optional[str] = None,
) -> None:
    """Guard an outgoing HTTP request. Scans URL, headers, and body.
    
    Args:
        url: The target URL.
        headers: Optional HTTP headers dict.
        body: Optional request body string.
        
    Raises:
        SecurityViolationException: If any component contains PII.
    """
    # Scan URL
    validate_outgoing_payload(url)
    
    # Scan headers
    if headers:
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        validate_outgoing_payload(header_str)
    
    # Scan body
    if body:
        validate_outgoing_payload(body)
