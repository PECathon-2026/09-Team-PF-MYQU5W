"""Executor module for PrivacyLens.

Implements ``execute_action`` which receives a Playwright ``Page`` object,
an action JSON plan produced by the ``reasoner`` and a locally‑maintained
``SecretStore`` (from ``core.sanitizer``). The executor resolves any
placeholder values, optionally prompts the user for confirmation on sensitive
actions, and then performs the appropriate Playwright interaction (type,
click, submit, etc.). All secret values are injected *locally* – the cloud LLM
never sees the raw data.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict

from playwright.sync_api import Page

# Import the secret store type – we only need the ``resolve`` method.
try:
    from privacy_lens.core.sanitizer import SecretStore
except Exception as exc:  # pragma: no cover – import guard
    raise ImportError("SecretStore could not be imported: {}".format(exc))

logger = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r"\[REDACTED:[A-Z_]+_\d+\]")

# Set PRIVACY_LENS_AUTO_APPROVE=1 to skip human-in-the-loop prompts (CI/demo mode)
_AUTO_APPROVE = os.environ.get("PRIVACY_LENS_AUTO_APPROVE", "0") == "1"


def _resolve_placeholders(value: str, store: SecretStore) -> str:
    """Replace any ``[REDACTED:*]`` tokens in *value* with the raw secret.

    Parameters
    ----------
    value: str
        The string potentially containing one or more placeholders.
    store: SecretStore
        Local in‑memory store that maps placeholders to raw secrets.
    """
    def _replace(match: re.Match) -> str:
        placeholder = match.group(0)
        secret = store.resolve(placeholder)
        if secret is None:
            logger.warning("Placeholder %s not found in secret store", placeholder)
            return placeholder
        return secret

    return _PLACEHOLDER_RE.sub(_replace, value)


def _prompt_user(action: str, selector: str) -> bool:
    """Prompt on the console for a human-in-the-loop approval.

    Set PRIVACY_LENS_AUTO_APPROVE=1 to skip (CI / demo mode).
    Returns True if approved, False to deny.
    """
    if _AUTO_APPROVE:
        logger.info("Auto-approving %s on %s (PRIVACY_LENS_AUTO_APPROVE=1)", action, selector)
        return True
    try:
        resp = input(f"APPROVAL REQUIRED: Execute {action.upper()} on {selector}? (y/n) ")
        return resp.strip().lower() == "y"
    except EOFError:
        logger.warning("No console input -- auto-denying sensitive action")
        return False


def execute_action(page: Page, action_json: Dict[str, Any], secret_store: SecretStore) -> bool:
    """Execute a single action plan on the given Playwright page.

    Parameters
    ----------
    page: playwright.sync_api.Page
        The active page handle obtained from :class:`BrowserController`.
    action_json: dict
        Must follow the contract:
        ``{"thought": str, "action": "type"|"click"|"submit", "selector": str,
        "value": str | None, "is_sensitive_action": bool}``
    secret_store: SecretStore
        In‑memory mapping of placeholders to raw secrets.

    Returns
    -------
    bool
        ``True`` on success, ``False`` on any error or user denial.
    """
    required_keys = {"action", "selector", "is_sensitive_action"}
    if not required_keys.issubset(action_json):
        logger.error("Action JSON missing required keys: %s", required_keys - action_json.keys())
        return False

    action = action_json["action"].lower()
    selector = action_json["selector"]
    is_sensitive = bool(action_json.get("is_sensitive_action", False))
    raw_value = action_json.get("value")

    # Resolve placeholders if present
    if isinstance(raw_value, str) and _PLACEHOLDER_RE.search(raw_value):
        resolved_value = _resolve_placeholders(raw_value, secret_store)
        logger.debug("Resolved placeholder %s → %s", raw_value, "<secret>")
    else:
        resolved_value = raw_value

    # Human‑in‑the‑loop check for sensitive actions or submissions
    if is_sensitive or action in {"submit", "pay", "checkout"}:
        if not _prompt_user(action, selector):
            logger.info("User denied execution of sensitive action %s on %s", action, selector)
            return False

    try:
        if action == "type":
            if resolved_value is None:
                logger.error("Type action requires a non‑null value")
                return False
            page.fill(selector, resolved_value)
            logger.info("Typed into %s (sensitive=%s)", selector, is_sensitive)
        elif action == "click" or action == "submit":
            page.click(selector)
            logger.info("Clicked %s (action=%s)", selector, action)
        else:
            logger.warning("Unsupported action type: %s", action)
            return False
        return True
    except Exception as exc:
        logger.error("Failed to execute action %s on %s: %s", action, selector, exc)
        return False
