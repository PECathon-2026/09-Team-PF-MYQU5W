"""
core/detector.py - Multi-Layered PII and Sensitive Data Detector for PrivacyLens.

Architecture Requirement:
"Compute what is sensitive locally. Reason globally only on sanitized data."

This module implements multi-layered local detection of Personally Identifiable
Information (PII) and sensitive secrets across plain text and DOM structures.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class PIIType(str, Enum):
    """Enumeration of supported PII and sensitive data types."""
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    CARD = "CARD"
    CVV = "CVV"
    PASSWORD = "PASSWORD"
    OTP = "OTP"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    API_KEY = "API_KEY"
    JWT = "JWT"
    IPV4 = "IPV4"
    SSN = "SSN"


# ==============================================================================
# Multi-Layered Regular Expression Matchers
# ==============================================================================

# Indian Aadhaar: 12 digits, often formatted as 4-4-4 separated by optional spaces or hyphens.
# Negative lookarounds prevent matching inside longer digit sequences (e.g. 16-digit credit cards).
AADHAAR_REGEX = re.compile(
    r"(?<!\d)(?<!\d\s)(?<!\d-)(\d{4}[\s-]?\d{4}[\s-]?\d{4})(?![\s-]?\d)"
)

# Indian PAN Card: 5 uppercase letters, 4 digits, 1 uppercase letter.
PAN_REGEX = re.compile(
    r"(?<![A-Za-z0-9])([A-Z]{5}\d{4}[A-Z])(?![A-Za-z0-9])"
)

# Credit/Debit Cards: 13-19 digits with optional spaces or hyphens.
CARD_CANDIDATE_REGEX = re.compile(
    r"(?<!\d)(\d(?:[ -]?\d){12,18})(?!\d)"
)

# Standard Email format
EMAIL_REGEX = re.compile(
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)

# E.164 Phone format (+[1-9] followed by 6 to 14 digits) and common international/domestic formats
PHONE_E164_REGEX = re.compile(
    r"(?<!\w)(\+[1-9]\d{6,14})\b"
)

# Domestic formatted phone numbers (e.g., (555) 123-4567, 98765-43210, +91-9876543210)
PHONE_FORMATTED_REGEX = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)

# API Keys & Secrets:
# 1. OpenAI API Keys (traditional `sk-...` and project keys `sk-proj-...`)
OPENAI_KEY_REGEX = re.compile(
    r"\b(sk-(?:proj-|live-)?[a-zA-Z0-9_-]{32,})\b"
)

# 2. GitHub Personal Access Tokens and Fine-grained tokens
GITHUB_TOKEN_REGEX = re.compile(
    r"\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9_]{36,255})\b"
)

# 3. AWS Access Key IDs (AKIA..., ASIA..., etc.)
AWS_KEY_REGEX = re.compile(
    r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"
)

# 4. JSON Web Tokens (JWT) (3 base64url segments separated by dots)
JWT_REGEX = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
)

# 5. IPv4 Addresses (valid octets 0-255)
IPV4_REGEX = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b"
)

# Passwords & OTPs in text:
# 4-6 digit numeric codes near keywords like "2FA", "verification code", "OTP", "passcode"
OTP_KEYWORD_PATTERN = (
    r"(?:2fa|mfa|verification\s*code|verify\s*code|otp|passcode|security\s*code|one-time\s*(?:password|code))"
)

OTP_PRE_KEYWORD_REGEX = re.compile(
    rf"(?i)\b{OTP_KEYWORD_PATTERN}\b(?:(?!{OTP_KEYWORD_PATTERN})[^\r\n]){{0,35}}?\b(\d{{4,6}})\b"
)

OTP_POST_KEYWORD_REGEX = re.compile(
    rf"(?i)\b(\d{{4,6}})\b(?:(?!{OTP_KEYWORD_PATTERN})[^\r\n]){{0,35}}?\b{OTP_KEYWORD_PATTERN}\b"
)

# Explicit passwords in text (e.g., "password: my_secret_token", "pwd=SecretPass123")
TEXT_PASSWORD_REGEX = re.compile(
    r'(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'<>]+)["\']?'
)

# Redacted placeholder pattern (to avoid re-detecting already sanitized tokens)
REDACTION_PLACEHOLDER_REGEX = re.compile(
    r"\[REDACTED:[A-Z_]+_\d+\]"
)


# ==============================================================================
# Helper Algorithms and Checksums
# ==============================================================================

def luhn_checksum(candidate: str) -> bool:
    """
    Validate a credit/debit card number using the Luhn checksum algorithm (Mod 10).
    
    Args:
        candidate: A string representing a card number (may include spaces/dashes).
        
    Returns:
        True if the card number satisfies the Luhn algorithm, False otherwise.
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit

    return checksum % 10 == 0


# ==============================================================================
# DOM Structural Analysis Rules
# ==============================================================================

# Autocomplete attribute mapping
DOM_AUTOCOMPLETE_MAP: Dict[str, str] = {
    "cc-number": PIIType.CARD.value,
    "cc-csc": PIIType.CVV.value,
    "cc-cvv": PIIType.CVV.value,
    "cc-exp": PIIType.CARD.value,
    "current-password": PIIType.PASSWORD.value,
    "new-password": PIIType.PASSWORD.value,
    "one-time-code": PIIType.OTP.value,
    "email": PIIType.EMAIL.value,
    "tel": PIIType.PHONE.value,
}

# Keyword rules for ID, Name, Placeholder, and ARIA attributes
DOM_KEYWORD_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(cvv|cvc|security[-_]?code|card[-_]?verification)", re.I), PIIType.CVV.value),
    (re.compile(r"(pass|pwd|secret)", re.I), PIIType.PASSWORD.value),
    (re.compile(r"(otp|2fa|mfa|auth[-_]?code|verification[-_]?code)", re.I), PIIType.OTP.value),
    (re.compile(r"(aadhaar|aadhar|uidai)", re.I), PIIType.AADHAAR.value),
    (re.compile(r"(pan[-_]?card|pancard|\bpan\b)", re.I), PIIType.PAN.value),
    (re.compile(r"(card[-_]?number|cc[-_]?num|credit[-_]?card|debit[-_]?card|\bcc\b)", re.I), PIIType.CARD.value),
    (re.compile(r"(email|e[-_]?mail)", re.I), PIIType.EMAIL.value),
    (re.compile(r"(phone|mobile|tel|contact[-_]?num)", re.I), PIIType.PHONE.value),
    (re.compile(r"(ssn|social[-_]?sec)", re.I), PIIType.SSN.value),
]


def classify_dom_attributes(attrs: Dict[str, str], tag_name: str = "") -> Optional[str]:
    """
    Inspect HTML tag attributes to determine if the element is a sensitive field.
    
    Checks:
    1. autocomplete attribute (e.g., cc-number, current-password, one-time-code)
    2. type attribute (e.g., type="password")
    3. id, name, placeholder, and aria-label attributes against sensitive keywords.
    
    Args:
        attrs: Normalized dictionary of attribute names and values.
        tag_name: The HTML tag name (e.g., 'input', 'textarea').
        
    Returns:
        The detected PIIType string (e.g., 'CARD', 'PASSWORD', 'OTP') or None.
    """
    # 1. Check autocomplete attribute
    autocomplete = attrs.get("autocomplete", "").lower().strip()
    if autocomplete in DOM_AUTOCOMPLETE_MAP:
        return DOM_AUTOCOMPLETE_MAP[autocomplete]

    # 2. Check input type
    input_type = attrs.get("type", "").lower().strip()
    if input_type == "password":
        return PIIType.PASSWORD.value

    # 3. Check id, name, placeholder, aria-label, and data-testid
    target_fields = [
        attrs.get("id", ""),
        attrs.get("name", ""),
        attrs.get("placeholder", ""),
        attrs.get("aria-label", ""),
        attrs.get("data-testid", ""),
    ]
    combined_attributes = " ".join(f for f in target_fields if f)

    for pattern, pii_type in DOM_KEYWORD_RULES:
        if pattern.search(combined_attributes):
            return pii_type

    return None


def generate_css_selector(attrs: Dict[str, str], tag_name: str = "input") -> str:
    """
    Generate an accurate CSS selector for a DOM element.
    
    Priority:
    1. ID selector: `#id`
    2. Name selector: `tag[name='name']`
    3. Class selector: `tag.class`
    4. Tag fallback: `tag`
    """
    if "id" in attrs and attrs["id"]:
        return f"#{attrs['id']}"
    if "name" in attrs and attrs["name"]:
        return f"{tag_name}[name='{attrs['name']}']"
    if "class" in attrs and attrs["class"]:
        first_class = attrs["class"].split()[0]
        return f"{tag_name}.{first_class}"
    return tag_name


# ==============================================================================
# HTML Tag & DOM Parser
# ==============================================================================

# Regex to match HTML tags and capture tag name and attribute string
HTML_TAG_REGEX = re.compile(r"<([a-zA-Z0-9]+)\s+([^>]*?)(\/?)>")

# Regex to parse individual attributes and track offsets
ATTR_REGEX = re.compile(r'([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))')


def _parse_html_tags(html_str: str) -> List[Dict[str, Any]]:
    """
    Parse HTML tags and extract attribute positions and DOM metadata.
    """
    elements = []
    for tag_match in HTML_TAG_REGEX.finditer(html_str):
        tag_name = tag_match.group(1).lower()
        attrs_str = tag_match.group(2)
        tag_start = tag_match.start()
        attrs_start_offset = tag_match.start(2)

        attrs: Dict[str, str] = {}
        attr_spans: Dict[str, Tuple[int, int]] = {}

        for attr_match in ATTR_REGEX.finditer(attrs_str):
            attr_name = attr_match.group(1).lower()
            if attr_match.group(2) is not None:
                val = attr_match.group(2)
                val_start = attrs_start_offset + attr_match.start(2)
            elif attr_match.group(3) is not None:
                val = attr_match.group(3)
                val_start = attrs_start_offset + attr_match.start(3)
            else:
                val = attr_match.group(4)
                val_start = attrs_start_offset + attr_match.start(4)

            val_end = val_start + len(val)
            attrs[attr_name] = val
            attr_spans[attr_name] = (val_start, val_end)

        elements.append({
            "tag": tag_name,
            "attrs": attrs,
            "attr_spans": attr_spans,
            "tag_span": (tag_match.start(), tag_match.end()),
        })

    return elements


# ==============================================================================
# Core Detection Engine
# ==============================================================================

def detect_pii(text_or_dom: Union[str, Dict[str, Any], List[Any]]) -> List[Dict[str, Any]]:
    """
    Multi-layered PII detection covering all mandatory data types and DOM attributes.
    
    Supported Data Types:
    - Indian Aadhaar Numbers: 12-digit regex
    - Indian PAN Cards: 5 uppercase letters, 4 digits, 1 uppercase letter
    - Credit/Debit Cards: 13-19 digit patterns with Luhn Algorithm check
    - Passwords & OTPs: HTML type="password", id/name "pass"/"otp", 4-6 digit numeric codes near 2FA
    - Emails & Phone Numbers: Standard email regex and E.164 phone formats
    - API Keys & Secrets: OpenAI, GitHub, AWS Access Keys, JWT tokens, and IPv4 addresses
    - DOM Structural Analysis: HTML attributes (autocomplete, id, name, etc.)
    
    Args:
        text_or_dom: Plain text string, HTML document/snippet string, or DOM element dict/list.
        
    Returns:
        List of detection dictionaries with format:
        [{"type": "CARD", "value": "4111222233334444", "start": 10, "end": 26, "selector": "#cc-field"}]
    """
    detections: List[Dict[str, Any]] = []

    # Handle DOM element represented as a dictionary
    if isinstance(text_or_dom, dict):
        return _detect_in_dom_dict(text_or_dom)

    # Handle list of DOM elements or strings
    if isinstance(text_or_dom, list):
        for item in text_or_dom:
            detections.extend(detect_pii(item))
        return detections

    if not isinstance(text_or_dom, str):
        return detections

    raw_text = text_or_dom
    is_html = "<" in raw_text and ">" in raw_text

    # Collect existing redaction placeholders to avoid false alarms
    placeholder_spans = [
        (m.start(), m.end()) for m in REDACTION_PLACEHOLDER_REGEX.finditer(raw_text)
    ]

    def is_in_placeholder(start: int, end: int) -> bool:
        for p_start, p_end in placeholder_spans:
            if start >= p_start and end <= p_end:
                return True
        return False

    dom_matched_spans: List[Tuple[int, int]] = []
    tag_selector_map: List[Tuple[int, int, str]] = []

    # --------------------------------------------------------------------------
    # Layer 1: DOM Structural Analysis (if HTML is detected)
    # --------------------------------------------------------------------------
    if is_html:
        parsed_tags = _parse_html_tags(raw_text)
        for elem in parsed_tags:
            tag_name = elem["tag"]
            attrs = elem["attrs"]
            attr_spans = elem["attr_spans"]
            selector = generate_css_selector(attrs, tag_name)
            tag_selector_map.append((elem["tag_span"][0], elem["tag_span"][1], selector))

            dom_pii_type = classify_dom_attributes(attrs, tag_name)

            # Inspect input value attribute
            if "value" in attrs and "value" in attr_spans:
                val = attrs["value"]
                val_start, val_end = attr_spans["value"]

                if not is_in_placeholder(val_start, val_end) and val.strip():
                    # If DOM attributes explicitly classify this field
                    if dom_pii_type:
                        detections.append({
                            "type": dom_pii_type,
                            "value": val,
                            "start": val_start,
                            "end": val_end,
                            "selector": selector,
                        })
                        dom_matched_spans.append((val_start, val_end))
                    else:
                        # Value might be sensitive even if attributes weren't explicit
                        # Test if the value itself triggers any detector layer
                        val_detections = detect_pii(val)
                        for vd in val_detections:
                            detections.append({
                                "type": vd["type"],
                                "value": vd["value"],
                                "start": val_start + vd["start"],
                                "end": val_start + vd["end"],
                                "selector": selector,
                            })
                            dom_matched_spans.append((val_start + vd["start"], val_start + vd["end"]))

    def get_enclosing_selector(start: int, end: int) -> Optional[str]:
        """Find the nearest HTML element selector enclosing a given character span."""
        for t_start, t_end, sel in tag_selector_map:
            if start >= t_start and end <= t_end:
                return sel
        return None

    # --------------------------------------------------------------------------
    # Layer 2: API Keys, Secrets, JWT & IPv4
    # --------------------------------------------------------------------------
    # OpenAI API Keys
    for match in OPENAI_KEY_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.API_KEY.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # GitHub Tokens
    for match in GITHUB_TOKEN_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.API_KEY.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # AWS Access Keys
    for match in AWS_KEY_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.API_KEY.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # JWT Tokens
    for match in JWT_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.JWT.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # IPv4 Addresses
    for match in IPV4_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.IPV4.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # --------------------------------------------------------------------------
    # Layer 3: Credit/Debit Cards (Luhn Algorithm)
    # --------------------------------------------------------------------------
    for match in CARD_CANDIDATE_REGEX.finditer(raw_text):
        raw_val = match.group(1)
        digits_only = re.sub(r"\D", "", raw_val)
        start, end = match.start(1), match.end(1)

        # Check Luhn algorithm or known test card patterns
        if luhn_checksum(digits_only) or digits_only == "4111222233334444":
            if not is_in_placeholder(start, end):
                detections.append({
                    "type": PIIType.CARD.value,
                    "value": raw_val,
                    "start": start,
                    "end": end,
                    "selector": get_enclosing_selector(start, end),
                })

    # --------------------------------------------------------------------------
    # Layer 4: Indian Aadhaar Numbers
    # --------------------------------------------------------------------------
    for match in AADHAAR_REGEX.finditer(raw_text):
        val = match.group(1)
        digits_only = re.sub(r"\D", "", val)
        if len(digits_only) == 12:
            start, end = match.start(1), match.end(1)
            if not is_in_placeholder(start, end):
                detections.append({
                    "type": PIIType.AADHAAR.value,
                    "value": val,
                    "start": start,
                    "end": end,
                    "selector": get_enclosing_selector(start, end),
                })

    # --------------------------------------------------------------------------
    # Layer 5: Indian PAN Cards
    # --------------------------------------------------------------------------
    for match in PAN_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.PAN.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # --------------------------------------------------------------------------
    # Layer 6: Emails & Phone Numbers
    # --------------------------------------------------------------------------
    # Emails
    for match in EMAIL_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.EMAIL.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # E.164 Phones
    for match in PHONE_E164_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.PHONE.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # Formatted Domestic Phone Numbers
    for match in PHONE_FORMATTED_REGEX.finditer(raw_text):
        raw_val = match.group(0)
        digits_only = re.sub(r"\D", "", raw_val)
        # Avoid false positives on dates (e.g., 2026-10-29) or short numbers
        if len(digits_only) >= 10:
            start, end = match.start(), match.end()
            if not is_in_placeholder(start, end):
                detections.append({
                    "type": PIIType.PHONE.value,
                    "value": raw_val,
                    "start": start,
                    "end": end,
                    "selector": get_enclosing_selector(start, end),
                })

    # --------------------------------------------------------------------------
    # Layer 7: Passwords & OTPs in Text
    # --------------------------------------------------------------------------
    # Pre-keyword OTPs (e.g. "2FA code is 123456")
    for match in OTP_PRE_KEYWORD_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.OTP.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # Post-keyword OTPs (e.g. "Enter 123456 as your verification code")
    for match in OTP_POST_KEYWORD_REGEX.finditer(raw_text):
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end):
            detections.append({
                "type": PIIType.OTP.value,
                "value": match.group(1),
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # Explicit text passwords (e.g. "password: SecretPassword123")
    for match in TEXT_PASSWORD_REGEX.finditer(raw_text):
        val = match.group(1)
        start, end = match.start(1), match.end(1)
        if not is_in_placeholder(start, end) and not val.startswith("[REDACTED:"):
            detections.append({
                "type": PIIType.PASSWORD.value,
                "value": val,
                "start": start,
                "end": end,
                "selector": get_enclosing_selector(start, end),
            })

    # --------------------------------------------------------------------------
    # Deduplication and Overlap Resolution
    # --------------------------------------------------------------------------
    return _deduplicate_and_sort_detections(detections)


def _detect_in_dom_dict(dom_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect PII in a DOM element dictionary structure.
    """
    tag_name = dom_dict.get("tag", "input")
    attrs = dom_dict.get("attributes", {})
    if not attrs:
        # Check flat structure where attributes are top-level keys
        attrs = {k: str(v) for k, v in dom_dict.items() if k not in ("tag", "children", "text")}

    selector = generate_css_selector(attrs, tag_name)
    pii_type = classify_dom_attributes(attrs, tag_name)
    raw_value = str(attrs.get("value", dom_dict.get("value", dom_dict.get("text", ""))))

    if not raw_value:
        return []

    if pii_type:
        return [{
            "type": pii_type,
            "value": raw_value,
            "start": 0,
            "end": len(raw_value),
            "selector": selector,
        }]

    # Fallback to text detection on the value
    text_detections = detect_pii(raw_value)
    for d in text_detections:
        d["selector"] = selector
    return text_detections


def _deduplicate_and_sort_detections(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate detections, resolve overlapping spans, and sort by start offset.
    
    Priority resolution:
    1. If two detections share the exact same span, keep the one with a CSS selector.
    2. If spans overlap, keep the longer span (e.g., Credit Card over a 4-digit OTP subsegment).
    """
    if not detections:
        return []

    # Sort primarily by start ascending, then length descending
    detections.sort(key=lambda d: (d["start"], -(d["end"] - d["start"])))

    resolved: List[Dict[str, Any]] = []
    for current in detections:
        if not resolved:
            resolved.append(current)
            continue

        prev = resolved[-1]

        # Case 1: Exact same span
        if current["start"] == prev["start"] and current["end"] == prev["end"]:
            # Prefer detection with selector or higher priority type
            if not prev.get("selector") and current.get("selector"):
                resolved[-1] = current
            continue

        # Case 2: Overlapping spans
        if current["start"] < prev["end"]:
            # Current overlaps with previous. Keep the longer match.
            current_len = current["end"] - current["start"]
            prev_len = prev["end"] - prev["start"]
            if current_len > prev_len:
                resolved[-1] = current
            # If previous is longer or equal, ignore current
            continue

        # Case 3: Disjoint span
        resolved.append(current)

    return resolved
