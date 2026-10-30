"""PrivacyLens Agent — Browser Automation & AI Reasoning Engine.

This package handles Playwright-based DOM capture, LLM action planning
over sanitized data, and secure local secret injection during execution.
"""

from .browser import BrowserController, capture_page
from .reasoner import get_next_action
from .executor import execute_action

__all__ = [
    "BrowserController",
    "capture_page",
    "get_next_action",
    "execute_action",
]
