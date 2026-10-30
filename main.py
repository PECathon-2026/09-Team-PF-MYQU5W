"""PrivacyLens — Master Pipeline Entry Point.

Orchestrates the full privacy-preserving browser agent pipeline:
1. Browser captures raw DOM & screenshots (LOCAL)
2. Detector scans for PII (LOCAL)
3. Sanitizer replaces PII with placeholders (LOCAL)
4. Guard validates outgoing payload (LOCAL, FAIL-CLOSED)
5. Reasoner plans actions over sanitized data (CLOUD — safe)
6. Executor runs actions with local secret injection (LOCAL)

Core Principle:
    "Compute what is sensitive locally.
     Reason globally only on sanitized data."

Usage:
    python -m privacy_lens.main --url <target_url> --task <task_description>
"""

import argparse
import logging
import sys
from pathlib import Path

from privacy_lens.core.detector import detect_pii
from privacy_lens.core.sanitizer import sanitize_text, SecretStore
from privacy_lens.core.guard import validate_outgoing_payload, SecurityViolationException
from privacy_lens.agent.browser import BrowserController
from privacy_lens.agent.reasoner import get_next_action
from privacy_lens.agent.executor import execute_action
from privacy_lens.ui.image_redactor import ImageRedactor, RedactionRegion

logger = logging.getLogger(__name__)

SCRATCH_DIR = Path(__file__).parent / "scratch"


def run_agent_pipeline(
    target_url_or_file: str,
    task_description: str,
    *,
    headless: bool = True,
    max_steps: int = 10,
) -> dict:
    """Execute the full PrivacyLens pipeline.
    
    Args:
        url: Target webpage URL.
        task: High-level task description for the AI agent.
        headless: Run browser in headless mode.
        max_steps: Maximum action steps before stopping.
        
    Returns:
        Dict with pipeline execution results.
    """
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    secret_store = SecretStore()
    results = {
        "url": url,
        "task": task,
        "steps_executed": 0,
        "pii_detected": 0,
        "pii_redacted": 0,
        "guard_violations": 0,
        "status": "initialized",
    }

    # ── Step 1: Launch browser and navigate ───────────────────────
    logger.info("[Step 1] Launching browser and navigating to: %s", url)
    browser = BrowserController(headless=headless)
    
    try:
        browser.launch()
        browser.navigate(url)

        for step in range(max_steps):
            logger.info("[Step %d] Starting action cycle", step + 1)

            # ── Step 2: Capture DOM (LOCAL) ───────────────────────
            raw_dom = browser.get_dom()
            raw_text = browser.get_inner_text()

            # ── Step 3: Detect PII (LOCAL) ────────────────────────
            entities = detect_pii(raw_text)
            results["pii_detected"] += len(entities)
            logger.info("  Detected %d PII entities", len(entities))

            # ── Step 4: Sanitize (LOCAL) ──────────────────────────
            sanitized_text, secret_store = sanitize_text(
                raw_text, secret_store=secret_store
            )
            results["pii_redacted"] = len(secret_store.as_dict())

            # ── Step 5: Guard validation (LOCAL, FAIL-CLOSED) ────
            try:
                validate_outgoing_payload(sanitized_text)
            except SecurityViolationException as exc:
                logger.error("  GUARD BLOCKED: %s", exc)
                results["guard_violations"] += 1
                results["status"] = "blocked_by_guard"
                break

            # ── Step 6: Plan next action (CLOUD — sanitized) ─────
            planner = ActionPlanner()
            action = planner.plan_next_action(sanitized_text, task)
            logger.info("  Planned action: %s", action.action.value)

            # ── Step 7: Execute with secret injection (LOCAL) ─────
            executor = ActionExecutor(browser, secret_store=secret_store)
            success = executor.execute(action)
            results["steps_executed"] += 1

            if action.action.value == "done":
                results["status"] = "completed"
                break

            if not success:
                results["status"] = "action_failed"
                break

        else:
            results["status"] = "max_steps_reached"

    except Exception as exc:
        logger.error("Pipeline error: %s", exc)
        results["status"] = f"error: {exc}"

    finally:
        browser.close()
        # Clear secrets from memory
        secret_store.clear()

    return results


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PrivacyLens — Privacy-Preserving AI Browser Agent",
    )
    parser.add_argument(
        "--url", required=True, help="Target webpage URL",
    )
    parser.add_argument(
        "--task", required=True, help="Task description for the AI agent",
    )
    parser.add_argument(
        "--headless", action="store_true", default=True,
        help="Run browser in headless mode (default: True)",
    )
    parser.add_argument(
        "--max-steps", type=int, default=10,
        help="Maximum action steps (default: 10)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    results = run_agent_pipeline(
        target_url_or_file=args.url,
        task_description=args.task,
        headless=args.headless,
        max_steps=args.max_steps,
    )

    print("\n" + "=" * 60)
    print("  PrivacyLens Pipeline Results")
    print("=" * 60)
    for key, value in results.items():
        print(f"  {key}: {value}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
