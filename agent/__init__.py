"""PrivacyLens Agent — Browser Automation & AI Reasoning Engine.

This package handles Playwright-based DOM capture, LLM action planning
over sanitized data, and secure local secret injection during execution.
"""

from .browser import BrowserController, capture_page
from .reasoner import ActionPlanner, get_next_action
from .executor import ActionExecutor, execute_action

__all__ = [
    "BrowserController",
    "ActionPlanner",
    "ActionExecutor",
    "capture_page",
    "get_next_action",
    "execute_action",
]
