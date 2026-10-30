"""
core/sanitizer.py - Local State Sanitizer and Pseudonymization Engine for PrivacyLens.

Architecture Requirement:
"Compute what is sensitive locally. Reason globally only on sanitized data."

This module implements the Sanitizer class, which maintains an in-memory local
secret store, replaces sensitive PII with deterministic pseudonymized placeholders,
and preserves non-sensitive DOM structure and selectors so AI agents can navigate.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Union

from .detector import detect_pii


class Sanitizer:
    """
    Local state sanitizer maintaining an in-memory dictionary secret_store.
    
    Transforms sensitive text or DOM structures by replacing detected PII with
    deterministic placeholders (e.g. [REDACTED:CARD_1], [REDACTED:PASSWORD_1]).
    Ensures original secrets cannot be recovered without local access to secret_store.
    """

    def __init__(self) -> None:
        """Initialize an empty in-memory secret store and pseudonymization counters."""
        self.secret_store: Dict[str, str] = {}
        self._type_counters: Dict[str, int] = {}
        self._value_to_placeholder: Dict[str, str] = {}

    def _get_or_create_placeholder(self, value: str, pii_type: str) -> str:
        """
        Retrieve existing placeholder for a repeated secret or generate a new deterministic one.
        
        Args:
            value: The raw sensitive secret string.
            pii_type: The classified PII type (e.g., 'CARD', 'PASSWORD', 'AADHAAR').
            
        Returns:
            Deterministic placeholder string (e.g., '[REDACTED:CARD_1]').
        """
        # If this exact secret has already been sanitized in this session, reuse its token
        if value in self._value_to_placeholder:
            return self._value_to_placeholder[value]

        # Normalize type string for placeholder
        normalized_type = pii_type.upper().replace(" ", "_")
        current_count = self._type_counters.get(normalized_type, 0) + 1
        self._type_counters[normalized_type] = current_count

        placeholder = f"[REDACTED:{normalized_type}_{current_count}]"
        self.secret_store[placeholder] = value
        self._value_to_placeholder[value] = placeholder
        return placeholder

    def sanitize_text(
        self, text_or_dom: Union[str, Dict[str, Any], List[Any]]
    ) -> Union[str, Dict[str, Any], List[Any]]:
        """
        Sanitize input text or DOM structure by detecting PII and substituting placeholders.
        
        - Calls detector.py to identify PII.
        - Replaces sensitive values with deterministic placeholders like [REDACTED:CARD_1].
        - Maps secret_store["[REDACTED:CARD_1]"] = "4111222233334444".
        - Preserves non-sensitive DOM structure and selectors so the AI agent can navigate.
        - Ensures original secret values CANNOT be recovered without local access to secret_store.
        
        Args:
            text_or_dom: Plain text string, HTML snippet/document, or DOM element dict/list.
            
        Returns:
            Sanitized string, DOM element dictionary, or list.
        """
        if isinstance(text_or_dom, list):
            return [self.sanitize_text(item) for item in text_or_dom]

        if isinstance(text_or_dom, dict):
            return self._sanitize_dom_dict(text_or_dom)

        if not isinstance(text_or_dom, str):
            return text_or_dom

        raw_str = text_or_dom
        detections = detect_pii(raw_str)
        if not detections:
            return raw_str

        # Sort detections in reverse order of start position so replacements do not
        # alter subsequent character offsets in the string.
        sorted_detections = sorted(detections, key=lambda d: d["start"], reverse=True)

        sanitized = raw_str
        for item in sorted_detections:
            placeholder = self._get_or_create_placeholder(item["value"], item["type"])
            start, end = item["start"], item["end"]
            sanitized = sanitized[:start] + placeholder + sanitized[end:]

        return sanitized

    def _sanitize_dom_dict(self, dom_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a DOM dictionary while preserving tag, selectors, and non-sensitive attributes.
        """
        sanitized_dict = copy.deepcopy(dom_dict)
        detections = detect_pii(sanitized_dict)

        if not detections:
            return sanitized_dict

        # Determine target placeholder
        for det in detections:
            placeholder = self._get_or_create_placeholder(det["value"], det["type"])

            # Check nested 'attributes' dictionary
            if "attributes" in sanitized_dict and isinstance(sanitized_dict["attributes"], dict):
                if "value" in sanitized_dict["attributes"]:
                    sanitized_dict["attributes"]["value"] = placeholder

            # Check top-level 'value' key
            if "value" in sanitized_dict:
                sanitized_dict["value"] = placeholder

            # Check 'text' key
            if "text" in sanitized_dict and isinstance(sanitized_dict["text"], str):
                sanitized_dict["text"] = self.sanitize_text(sanitized_dict["text"])

        return sanitized_dict

    def unmask_value(self, placeholder: str) -> str:
        """
        Look up and return the raw secret from secret_store.
        
        Args:
            placeholder: Deterministic placeholder string (e.g. '[REDACTED:CARD_1]').
            
        Returns:
            The raw secret string.
            
        Raises:
            KeyError: If the placeholder does not exist in the local secret_store.
        """
        if placeholder not in self.secret_store:
            raise KeyError(f"Placeholder '{placeholder}' not found in local secret_store.")
        return self.secret_store[placeholder]

    def unmask_text(self, sanitized_text: str) -> str:
        """
        Restore all deterministic placeholders in a text string to their raw secrets.
        
        Args:
            sanitized_text: String containing [REDACTED:TYPE_N] placeholders.
            
        Returns:
            String with all known placeholders restored from secret_store.
        """
        if not isinstance(sanitized_text, str):
            return sanitized_text

        def replace_match(match: re.Match) -> str:
            token = match.group(0)
            return self.secret_store.get(token, token)

        return re.sub(r"\[REDACTED:[A-Z_]+_\d+\]", replace_match, sanitized_text)

    def get_secret_store(self) -> Dict[str, str]:
        """Return a defensive copy of the local secret store."""
        return dict(self.secret_store)

    def clear(self) -> None:
        """Reset the in-memory secret store and pseudonymization counters."""
        self.secret_store.clear()
        self._type_counters.clear()
        self._value_to_placeholder.clear()
