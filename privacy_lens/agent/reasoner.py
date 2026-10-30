"""Reasoner module for PrivacyLens.

Provides a single function ``get_next_action`` that, given sanitized DOM text
and a high‑level task description, returns a JSON action plan suitable for the
executor.

The function first tries to call a remote LLM (e.g., OpenAI) when an ``api_key``
is supplied. If the key is missing, the request fails, or the response cannot be
parsed, a deterministic local heuristic parses the sanitized DOM for common input
field patterns and constructs a minimal action plan so that the demo can run
offline.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper: local heuristic fallback
# ---------------------------------------------------------------------------
def _heuristic_action(sanitized_dom: str, task_description: str) -> Dict[str, Any]:
    """Derive a simple action plan from the sanitized DOM.

    The heuristic looks for common form elements (e.g., credit‑card or password
    fields) using placeholder patterns like ``[REDACTED:CARD_1]``. It then picks
    the first matching selector based on a very naive HTML‑like search. This is
    intentionally lightweight – it is only a fallback when a cloud model is not
    available.
    """
    # Very naive selector inference: look for an ``id`` or ``name`` attribute
    # containing the PII type (card, password, email, etc.).
    selectors = {
        "CARD": "input#card_number, input[name='card_number']",
        "PASSWORD": "input[type='password'], input[name='password']",
        "OTP": "input[name='otp'], input[id='otp']",
        "EMAIL": "input[type='email'], input[name='email']",
        "PHONE": "input[type='tel'], input[name='phone']",
    }

    # Find which placeholder types exist in the sanitized text
    placeholder_pattern = r"\[REDACTED:([A-Z_]+)_\d+\]"
    types_found = set(re.findall(placeholder_pattern, sanitized_dom))

    for ptype in types_found:
        selector = selectors.get(ptype)
        if selector:
            # Return the first matching placeholder for this type
            placeholder = re.search(rf"\[REDACTED:{ptype}_\d+\]", sanitized_dom)
            if placeholder:
                return {
                    "thought": f"Heuristic: fill first detected {ptype.lower()} field",
                    "action": "type",
                    "selector": selector,
                    "value": placeholder.group(0),
                    "is_sensitive_action": True,
                }
    # Fallback – click the first button
    return {
        "thought": "Heuristic: click the first button element",
        "action": "click",
        "selector": "button, input[type='submit']",
        "value": None,
        "is_sensitive_action": False,
    }

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def get_next_action(
    sanitized_dom: str,
    task_description: str,
    *,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a JSON action plan for the given sanitized DOM.

    Parameters
    ----------
    sanitized_dom: str
        The DOM text after PII placeholders have been injected.
    task_description: str
        High‑level description of what the user wants the agent to achieve.
    api_key: str | None, optional
        If provided, the function attempts to call a cloud LLM (OpenAI style).
        When missing or if the request fails, the local heuristic is used.

    Returns
    -------
    dict
        JSON compliant with the contract required by ``agent.executor``.
    """
    system_prompt = (
        "You are PrivacyLens AI Browser Agent. You ONLY see sanitized webpage text "
        "containing semantic placeholders like [REDACTED:CARD_1] or [REDACTED:PASSWORD_1]. "
        "Analyze the interface and return a JSON action plan. DO NOT attempt to "
        "reconstruct redacted values."
    )

    if api_key:
        try:
            import openai  # type: ignore
            openai.api_key = api_key
            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Task: {task_description}\nSanitized DOM:\n{sanitized_dom}"},
                ],
                temperature=0,
                max_tokens=300,
            )
            content = response.choices[0].message["content"].strip()
            # Attempt to parse JSON – be tolerant of surrounding text
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group(0))
                logger.info("LLM returned action plan via API")
                return plan
            else:
                logger.warning("LLM response did not contain JSON; falling back to heuristic")
        except Exception as exc:
            logger.error("LLM call failed (%s); using heuristic fallback", exc)
    else:
        logger.info("No API key supplied – using heuristic fallback for action planning")

    # -------------------------------------------------------------------
    # Heuristic fallback – deterministic and offline safe
    # -------------------------------------------------------------------
    return _heuristic_action(sanitized_dom, task_description)
