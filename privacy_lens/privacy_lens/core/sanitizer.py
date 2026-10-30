"""Semantic Sanitizer — Placeholder Replacement & Local Secret Store.

Replaces detected PII with semantically meaningful placeholders
(e.g., `[REDACTED:CARD_1]`) and maintains a local-only secret store
mapping placeholders back to original values.

CORE INVARIANT:
    The secret_store dict NEVER leaves the local host.
    It is used exclusively by agent/executor.py for local DOM injection.
"""

from __future__ import annotations

import threading
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field

from .detector import PIIEntity, PIIType, detect_pii


@dataclass
class SecretStore:
    """Thread-safe local secret vault.
    
    Maps redaction placeholders → original sensitive values.
    This store is NEVER serialized to disk or transmitted over the network.
    
    Example:
        {
            "[REDACTED:CARD_1]": "4111222233334444",
            "[REDACTED:PASSWORD_1]": "SecretPass123",
            "[REDACTED:AADHAAR_1]": "234567891234",
        }
    """
    _store: Dict[str, str] = field(default_factory=dict)
    _counters: Dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _next_placeholder(self, pii_type: PIIType) -> str:
        """Generate the next sequential placeholder for a PII type."""
        type_key = pii_type.value
        with self._lock:
            count = self._counters.get(type_key, 0) + 1
            self._counters[type_key] = count
        return f"[REDACTED:{type_key}_{count}]"

    def add(self, pii_type: PIIType, raw_value: str) -> str:
        """Store a secret and return its placeholder.
        
        If the raw_value already exists, return the existing placeholder.
        
        Args:
            pii_type: Classification of the PII.
            raw_value: The original sensitive value.
            
        Returns:
            The placeholder string (e.g., '[REDACTED:CARD_1]').
        """
        with self._lock:
            # Deduplicate: if value already stored, return existing placeholder
            for placeholder, stored_value in self._store.items():
                if stored_value == raw_value:
                    return placeholder
        
        placeholder = self._next_placeholder(pii_type)
        with self._lock:
            self._store[placeholder] = raw_value
        return placeholder

    def resolve(self, placeholder: str) -> Optional[str]:
        """Look up the raw secret for a given placeholder.
        
        Args:
            placeholder: The redaction placeholder string.
            
        Returns:
            The original value, or None if not found.
        """
        with self._lock:
            return self._store.get(placeholder)

    def has_secrets(self) -> bool:
        """Check whether the store contains any secrets."""
        with self._lock:
            return len(self._store) > 0

    def clear(self) -> None:
        """Securely clear all stored secrets."""
        with self._lock:
            self._store.clear()
            self._counters.clear()

    def as_dict(self) -> Dict[str, str]:
        """Return a snapshot copy (for local executor use ONLY)."""
        with self._lock:
            return dict(self._store)


# ── Module-level default store ────────────────────────────────────────
_default_store = SecretStore()


def sanitize_text(
    text: str,
    *,
    secret_store: Optional[SecretStore] = None,
) -> Tuple[str, SecretStore]:
    """Detect and replace all PII in text with redaction placeholders.
    
    Args:
        text: Raw text to sanitize.
        secret_store: Optional SecretStore instance. Uses module default
                      if not provided.
    
    Returns:
        Tuple of (sanitized_text, secret_store).
    """
    store = secret_store or _default_store
    entities = detect_pii(text)
    
    # Sort by position descending so replacements don't shift indices
    entities.sort(key=lambda e: e.start, reverse=True)
    
    sanitized = text
    for entity in entities:
        placeholder = store.add(entity.pii_type, entity.value)
        sanitized = sanitized[:entity.start] + placeholder + sanitized[entity.end:]
    
    return sanitized, store


def sanitize_dom(html: str, *, secret_store: Optional[SecretStore] = None) -> Tuple[str, SecretStore]:
    """Sanitize an HTML DOM string, replacing PII with placeholders.
    
    Args:
        html: Raw HTML content.
        secret_store: Optional SecretStore instance.
        
    Returns:
        Tuple of (sanitized_html, secret_store).
    """
    # TODO: Implement DOM-aware sanitization that preserves HTML structure
    #   - Parse HTML tree
    #   - Sanitize text nodes and attribute values separately
    #   - Preserve tag structure
    return sanitize_text(html, secret_store=secret_store)
