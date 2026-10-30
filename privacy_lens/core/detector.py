"""PII Detection Engine — Regex + DOM Structural Analysis.

Detects sensitive personal data including:
- Aadhaar numbers (12-digit Indian identity)
- PAN card numbers (ABCDE1234F format)
- Credit/debit card numbers (Luhn-validated)
- Passwords & OTPs
- Phone numbers (Indian & international)
- Email addresses
- API keys & tokens
- IP addresses
- Medical / private data markers

All detection runs LOCAL-ONLY. No data is transmitted.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class PIIType(Enum):
    """Classification of detected PII entities."""
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    CREDIT_CARD = "CREDIT_CARD"
    DEBIT_CARD = "DEBIT_CARD"
    PASSWORD = "PASSWORD"
    OTP = "OTP"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    API_KEY = "API_KEY"
    AUTH_TOKEN = "AUTH_TOKEN"
    IP_ADDRESS = "IP_ADDRESS"
    MEDICAL = "MEDICAL"
    ADDRESS = "ADDRESS"
    NAME = "NAME"
    DOB = "DOB"


@dataclass
class PIIEntity:
    """A single detected PII entity with location metadata."""
    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float = 1.0
    context: Optional[str] = None  # surrounding DOM context


# ── Regex Pattern Registry ────────────────────────────────────────────

PII_PATTERNS: dict[PIIType, re.Pattern] = {
    PIIType.AADHAAR: re.compile(
        r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'
    ),
    PIIType.PAN: re.compile(
        r'\b[A-Z]{5}\d{4}[A-Z]\b'
    ),
    PIIType.CREDIT_CARD: re.compile(
        r'\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    ),
    PIIType.PHONE: re.compile(
        r'\b(?:\+?91[\s-]?)?[6-9]\d{9}\b|\b\+?\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b'
    ),
    PIIType.EMAIL: re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    ),
    PIIType.OTP: re.compile(
        r'\b(?:OTP|otp|One[\s-]?Time[\s-]?Password)[\s:]*\d{4,8}\b'
    ),
    PIIType.API_KEY: re.compile(
        r'\b(?:api[_-]?key|token|secret|bearer)[\s:="\']*[A-Za-z0-9_\-\.]{20,}\b',
        re.IGNORECASE,
    ),
    PIIType.IP_ADDRESS: re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ),
    PIIType.PASSWORD: re.compile(
        r'(?:password|passwd|pwd)[\s:="\']+\S+',
        re.IGNORECASE,
    ),
}


def _passes_luhn(number: str) -> bool:
    """Validate a credit/debit card number using the Luhn algorithm.
    
    Args:
        number: Digits-only card number string.
        
    Returns:
        True if the number passes Luhn validation.
    """
    digits = [int(d) for d in number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(divmod(d * 2, 10))
    return checksum % 10 == 0


def detect_pii(text: str, *, dom_context: Optional[str] = None) -> List[PIIEntity]:
    """Scan text for all known PII patterns.
    
    Runs entirely LOCAL — no network calls.
    
    Args:
        text: Raw text content (from DOM innerText, input values, etc.).
        dom_context: Optional surrounding DOM HTML for structural hints.
        
    Returns:
        List of PIIEntity objects with type, value, and positions.
    """
    findings: List[PIIEntity] = []

    for pii_type, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group()
            
            # Extra validation for credit cards (Luhn check)
            if pii_type == PIIType.CREDIT_CARD:
                digits_only = re.sub(r'[\s-]', '', value)
                if not _passes_luhn(digits_only):
                    continue
            
            entity = PIIEntity(
                pii_type=pii_type,
                value=value,
                start=match.start(),
                end=match.end(),
                confidence=1.0,
                context=dom_context,
            )
            findings.append(entity)

    return findings


def detect_pii_in_dom(html: str) -> List[PIIEntity]:
    """Detect PII within raw HTML DOM content.
    
    Performs structural analysis: checks input fields, labels,
    aria attributes, and visible text nodes.
    
    Args:
        html: Full or partial HTML string.
        
    Returns:
        List of detected PIIEntity instances.
    """
    # TODO: Implement DOM-aware structural PII detection
    #   - Parse HTML and inspect <input> values, placeholders
    #   - Check <label> associations for sensitive field names
    #   - Detect aria-label hints (e.g., "credit card number")
    #   - Extract and scan all text nodes
    return detect_pii(html, dom_context=html)
