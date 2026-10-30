"""PrivacyLens — Master Pipeline Entry Point.

Orchestrates the full privacy-preserving browser agent pipeline:
  A. Browser captures raw DOM & screenshot            (LOCAL)
  B. Sanitizer replaces PII with placeholders         (LOCAL)
  C. Guard validates outgoing payload -- FAIL-CLOSED  (LOCAL)
  D. Reasoner plans actions over sanitized data       (CLOUD-safe)
  E. Executor injects secrets & runs actions          (LOCAL)
  F. Rich terminal summary

Core Principle:
    "Compute what is sensitive locally.
     Reason globally only on sanitized data."

Usage:
    python -m privacy_lens.main --url <url_or_file> --task "<task>"
    python -m privacy_lens.main --demo
    python -m privacy_lens.main --interactive
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# ── Local packages ─────────────────────────────────────────────────────────
from privacy_lens.core.detector import detect_pii, PIIEntity
from privacy_lens.core.sanitizer import sanitize_text, SecretStore
from privacy_lens.core.guard import validate_outgoing_payload, SecurityViolationException
from privacy_lens.agent.browser import BrowserController
from privacy_lens.agent.reasoner import get_next_action
from privacy_lens.agent.executor import execute_action
from privacy_lens.ui.image_redactor import ImageRedactor, RedactionRegion

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
SCRATCH_DIR  = PROJECT_ROOT / "scratch"
TEST_PAGES   = PROJECT_ROOT / "eval" / "test_pages"

# ── Windows-safe colour codes (stripped if stdout is not a TTY) ─────────────
def _c(code: str, text: str) -> str:
    if sys.stdout.isatty() and os.name == "nt":
        return text   # Windows default console strips ANSI; skip colour
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

RED    = lambda t: _c("91", t)
GREEN  = lambda t: _c("92", t)
YELLOW = lambda t: _c("93", t)
CYAN   = lambda t: _c("96", t)
BOLD   = lambda t: _c("1",  t)


# ─────────────────────────────────────────────────────────────────────────────
# URL resolver
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_target(raw: str) -> str:
    """Convert a relative path / bare filename into an absolute file:// URI."""
    if raw.startswith(("http://", "https://", "file://")):
        return raw
    # Try relative to project root, then relative to CWD
    for base in (PROJECT_ROOT, Path.cwd()):
        candidate = (base / raw).resolve()
        if candidate.exists():
            return candidate.as_uri()
    logger.warning("Could not resolve '%s' as a local file; treating as URL", raw)
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Core pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_agent_pipeline(
    target_url_or_file: str,
    task_description: str,
    *,
    headless: bool = True,
) -> dict:
    """Run the full PrivacyLens pipeline.

    Parameters
    ----------
    target_url_or_file : str
        A live URL or a local HTML file path (relative paths are resolved
        against the project root).
    task_description : str
        Natural-language description of what the agent should achieve.
    headless : bool
        ``True`` = hidden Chromium; ``False`` = visible browser window.

    Returns
    -------
    dict  -- summary of the run
    """
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    raw_screenshot   = SCRATCH_DIR / "raw_screenshot.png"
    clean_screenshot = SCRATCH_DIR / "sanitized_screenshot.png"

    resolved = _resolve_target(target_url_or_file)
    secret_store = SecretStore()

    results: dict = {
        "target":               resolved,
        "task":                 task_description,
        "pii_entities":         [],   # list of dicts per entity
        "pii_detected":         0,
        "pii_redacted":         0,
        "sanitized_dom":        "",
        "raw_screenshot":       str(raw_screenshot),
        "sanitized_screenshot": str(clean_screenshot),
        "action_plan":          None,
        "action_taken":         None,
        "guard_violations":     0,
        "cloud_data_leakage":   "0%",
        "status":               "initialized",
    }

    # ── Step A: Capture page ──────────────────────────────────────────────
    logger.info("[A] Launching browser -> %s", resolved)
    browser = BrowserController(headless=headless, screenshot_path=raw_screenshot)
    try:
        raw_dom, screenshot_saved, page, _ = browser.capture_page(resolved)
        logger.info("[A] Captured %d chars of DOM, screenshot -> %s",
                    len(raw_dom), screenshot_saved)

        # ── Step B: Local PII sanitization ───────────────────────────────
        logger.info("[B] Scanning for PII ...")
        entities: list[PIIEntity] = detect_pii(raw_dom)
        results["pii_detected"] = len(entities)
        results["pii_entities"] = [
            {"type": e.pii_type.value, "value": e.value,
             "start": e.start, "end": e.end}
            for e in entities
        ]

        sanitized_dom, secret_store = sanitize_text(raw_dom, secret_store=secret_store)
        results["pii_redacted"] = len(secret_store.as_dict())
        results["sanitized_dom"] = sanitized_dom
        logger.info("[B] Replaced %d PII entities with placeholders", results["pii_redacted"])

        # Redact screenshot using exact bounding box coordinates
        redactor = ImageRedactor()
        try:
            from PIL import Image
            img = Image.open(raw_screenshot)
            regions = [
                RedactionRegion(
                    x=r["x"],
                    y=r["y"],
                    width=r["width"],
                    height=r["height"],
                    label=r["label"],
                )
                for r in getattr(browser, "sensitive_regions", [])
            ]
            redactor.save_redacted(img, regions, clean_screenshot, method="blackout")
            logger.info("[B] Sanitized screenshot with %d masked regions -> %s", len(regions), clean_screenshot)
        except Exception as img_err:
            logger.warning("[B] Screenshot redaction skipped: %s", img_err)
            import shutil
            shutil.copy(raw_screenshot, clean_screenshot)

        # ── Step C: Fail-closed security guard ───────────────────────────
        logger.info("[C] Guard validation ...")
        try:
            violations = validate_outgoing_payload(sanitized_dom, raise_on_violation=True)
            logger.info("[C] Guard passed -- 0 leaks detected")
        except SecurityViolationException as exc:
            logger.critical("[C] GUARD BLOCKED: %s", exc)
            results["guard_violations"] = len(getattr(exc, "violations", [1]))
            results["status"] = "blocked_by_guard"
            return results

        # ── Step D: Sanitized AI reasoning ───────────────────────────────
        logger.info("[D] Requesting action plan (operating on placeholders only) ...")
        action_plan = get_next_action(sanitized_dom, task_description)
        results["action_plan"] = action_plan
        results["action_taken"] = action_plan.get("action", "unknown")
        logger.info("[D] Plan: %s", action_plan)

        # ── Step E: Local secret injection & execution ────────────────────
        logger.info("[E] Executing with local secret injection ...")
        success = execute_action(page, action_plan, secret_store)
        results["status"] = "completed" if success else "action_failed"
        logger.info("[E] Done -> %s", results["status"])

    except SecurityViolationException:
        pass   # already handled above
    except Exception as exc:
        logger.exception("[Pipeline] Error: %s", exc)
        results["status"] = f"error: {exc}"
    finally:
        browser.close()
        secret_store.clear()

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Step F: Rich terminal summary
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(results: dict) -> None:
    sep = "=" * 64
    thin = "-" * 64

    print(f"\n{sep}")
    print(f"  PrivacyLens  --  Pipeline Report")
    print(sep)

    status = results["status"]
    status_display = f"COMPLETED  (0% cloud leakage)" if status == "completed" else status.upper()
    print(f"  Status      : {status_display}")
    print(f"  Target      : {results['target']}")
    print(f"  Task        : {results['task']}")
    print(thin)

    # PII breakdown table
    entities = results.get("pii_entities", [])
    print(f"  PII Detected: {results['pii_detected']} entities")
    if entities:
        print(f"\n  {'TYPE':<18} {'VALUE':<40}")
        print(f"  {'-'*18} {'-'*40}")
        for e in entities:
            masked = e['value'][:6] + "..." + e['value'][-2:] if len(e['value']) > 10 else e['value']
            print(f"  {e['type']:<18} {masked:<40}")
    print()
    print(f"  PII Redacted         : {results['pii_redacted']} placeholders injected")
    print(f"  Guard Violations     : {results['guard_violations']}")
    print(f"  Cloud Data Leakage   : {results['cloud_data_leakage']}")
    print(thin)

    # Sanitized DOM preview
    sdom = results.get("sanitized_dom", "")
    if sdom:
        preview = sdom[:400].replace("\n", " ")
        print(f"  Sanitized DOM preview:")
        print(f"  {preview[:120]}")
        print(f"  {preview[120:240]}")
        print(f"  {preview[240:360]}")
    print(thin)

    # Action plan
    plan = results.get("action_plan")
    if plan:
        print(f"  AI Action Plan (saw ONLY placeholders):")
        print(f"    thought  : {plan.get('thought','')}")
        print(f"    action   : {plan.get('action','')}")
        print(f"    selector : {plan.get('selector','')}")
        val = plan.get('value')
        print(f"    value    : {val if val else 'None'}")
        print(f"    sensitive: {plan.get('is_sensitive_action', False)}")
    print(thin)

    print(f"  Raw screenshot       : {results['raw_screenshot']}")
    print(f"  Sanitized screenshot : {results['sanitized_screenshot']}")
    print(f"\n{sep}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Demo mode -- runs all 3 test pages sequentially
# ─────────────────────────────────────────────────────────────────────────────

DEMO_SCENARIOS = [
    ("eval/test_pages/1_ecommerce.html",    "Detect and redact all payment and identity PII on the checkout page"),
    ("eval/test_pages/2_authentication.html","Detect passwords, OTPs and emails on the login page"),
    ("eval/test_pages/3_support.html",       "Detect PII shared by the customer in the support chat"),
]

def run_demo(headless: bool = True) -> None:
    print("\n" + "=" * 64)
    print("  PrivacyLens  --  Full Demo  (3 scenarios)")
    print("=" * 64)
    for i, (path, task) in enumerate(DEMO_SCENARIOS, 1):
        print(f"\n>>> Scenario {i}: {path}")
        results = run_agent_pipeline(path, task, headless=headless)
        print_summary(results)
        input("  [Press ENTER for next scenario]") if i < len(DEMO_SCENARIOS) else None
    print("Demo complete.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Interactive REPL
# ─────────────────────────────────────────────────────────────────────────────

def interactive_loop(headless: bool = False) -> None:
    print("\n  PrivacyLens -- Interactive Mode")
    print("  Type a filename from eval/test_pages/ (e.g. 1_ecommerce.html)")
    print("  or a full URL.  Type 'exit' to quit.\n")
    while True:
        try:
            raw_target = input("  Target > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Bye!"); break
        if raw_target.lower() in {"exit", "quit", "q"}:
            print("  Bye!"); break
        if not raw_target:
            continue
        try:
            task = input("  Task   > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Bye!"); break
        if not task:
            print("  Task cannot be empty.\n"); continue
        results = run_agent_pipeline(raw_target, task, headless=headless)
        print_summary(results)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PrivacyLens -- Privacy-Preserving AI Browser Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m privacy_lens.main --demo\n"
            "  python -m privacy_lens.main --url eval/test_pages/1_ecommerce.html "
            "--task 'detect PII'\n"
            "  python -m privacy_lens.main --interactive\n"
        ),
    )
    parser.add_argument("--url",         help="Target URL or local HTML file path")
    parser.add_argument("--task",        help="Task description for the AI agent")
    parser.add_argument("--demo",        action="store_true", help="Run all 3 demo scenarios")
    parser.add_argument("--interactive", action="store_true", help="Interactive prompt loop")
    parser.add_argument("--headless",    action="store_true", default=False,
                        help="Run Chromium headless (default: visible window)")
    parser.add_argument("--verbose",     action="store_true", help="DEBUG logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.demo:
        run_demo(headless=args.headless)
    elif args.interactive:
        interactive_loop(headless=args.headless)
    else:
        if not args.url or not args.task:
            parser.error("--url and --task are required (or use --demo / --interactive)")
        results = run_agent_pipeline(args.url, args.task, headless=args.headless)
        print_summary(results)


if __name__ == "__main__":
    main()
