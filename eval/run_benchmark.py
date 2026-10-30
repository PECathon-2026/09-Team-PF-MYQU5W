"""Automated PII Recall & Leakage Benchmark Suite.

Runs PrivacyLens against the 5 required evaluation scenarios
and produces a structured report of:
- PII detection recall (what % of planted PII was found)
- PII leakage rate (what % of PII survived sanitization)
- Guard block rate (what % of outgoing payloads were correctly blocked)

Usage:
    python -m privacy_lens.eval.run_benchmark
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field

# Ensure project root is importable
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from privacy_lens.core.detector import detect_pii, PIIType
from privacy_lens.core.sanitizer import sanitize_text, SecretStore
from privacy_lens.core.guard import validate_outgoing_payload

logger = logging.getLogger(__name__)

TEST_PAGES_DIR = Path(__file__).parent / "test_pages"


@dataclass
class ScenarioResult:
    """Results from running a single evaluation scenario."""
    scenario_name: str
    total_pii_planted: int = 0
    pii_detected: int = 0
    pii_missed: int = 0
    leakage_count: int = 0
    guard_blocks: int = 0
    recall: float = 0.0
    leakage_rate: float = 0.0
    details: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BenchmarkReport:
    """Aggregate benchmark report across all scenarios."""
    scenarios: List[ScenarioResult] = field(default_factory=list)
    overall_recall: float = 0.0
    overall_leakage_rate: float = 0.0
    total_pii: int = 0
    total_detected: int = 0
    total_leaked: int = 0


def load_test_page(scenario_file: Path) -> str:
    """Load an HTML test page for evaluation.
    
    Args:
        scenario_file: Path to the HTML test scenario file.
        
    Returns:
        HTML content as a string.
    """
    if not scenario_file.exists():
        logger.warning("Test page not found: %s", scenario_file)
        return ""
    return scenario_file.read_text(encoding="utf-8")


def run_scenario(scenario_path: Path, expected_pii_count: int) -> ScenarioResult:
    """Run a single evaluation scenario.
    
    Args:
        scenario_path: Path to the HTML test page.
        expected_pii_count: Number of PII items planted in the page.
        
    Returns:
        ScenarioResult with detection and leakage metrics.
    """
    result = ScenarioResult(scenario_name=scenario_path.stem)
    
    html_content = load_test_page(scenario_path)
    if not html_content:
        return result
    
    result.total_pii_planted = expected_pii_count
    
    # Step 1: Detect PII
    entities = detect_pii(html_content)
    result.pii_detected = len(entities)
    result.pii_missed = max(0, expected_pii_count - len(entities))
    
    # Step 2: Sanitize
    store = SecretStore()
    sanitized, store = sanitize_text(html_content, secret_store=store)
    
    # Step 3: Check for leakage in sanitized output
    leaked = detect_pii(sanitized)
    result.leakage_count = len(leaked)
    
    # Step 4: Run guard validation
    try:
        validate_outgoing_payload(sanitized, raise_on_violation=True)
        result.guard_blocks = 0
    except Exception:
        result.guard_blocks = 1
    
    # Calculate metrics
    if expected_pii_count > 0:
        result.recall = result.pii_detected / expected_pii_count
    if result.pii_detected > 0:
        result.leakage_rate = result.leakage_count / result.pii_detected
    
    result.details = [
        {
            "type": e.pii_type.value,
            "value_preview": e.value[:8] + "...",
            "confidence": e.confidence,
        }
        for e in entities
    ]
    
    return result


def run_full_benchmark() -> BenchmarkReport:
    """Run all 5 evaluation scenarios and produce a report.
    
    Returns:
        BenchmarkReport with aggregate metrics.
    """
    scenarios = [
        (TEST_PAGES_DIR / "1_ecommerce.html", 8),
        (TEST_PAGES_DIR / "2_authentication.html", 6),
        (TEST_PAGES_DIR / "3_support.html", 5),
        (TEST_PAGES_DIR / "4_video.html", 4),
        (TEST_PAGES_DIR / "5_developer.html", 7),
    ]
    
    report = BenchmarkReport()
    
    for scenario_path, expected_count in scenarios:
        result = run_scenario(scenario_path, expected_count)
        report.scenarios.append(result)
        report.total_pii += result.total_pii_planted
        report.total_detected += result.pii_detected
        report.total_leaked += result.leakage_count
    
    if report.total_pii > 0:
        report.overall_recall = report.total_detected / report.total_pii
    if report.total_detected > 0:
        report.overall_leakage_rate = report.total_leaked / report.total_detected
    
    return report


def print_report(report: BenchmarkReport) -> None:
    """Pretty-print a benchmark report to stdout."""
    print("\n" + "=" * 70)
    print("  PrivacyLens -- PII Detection & Leakage Benchmark Report")
    print("=" * 70)
    
    for result in report.scenarios:
        print(f"\n  [*] {result.scenario_name}")
        print(f"      Planted: {result.total_pii_planted} | "
              f"Detected: {result.pii_detected} | "
              f"Missed: {result.pii_missed} | "
              f"Leaked: {result.leakage_count}")
        print(f"      Recall: {result.recall:.1%} | "
              f"Leakage Rate: {result.leakage_rate:.1%}")
    
    print(f"\n{'=' * 70}")
    print(f"  OVERALL: Recall={report.overall_recall:.1%} | "
          f"Leakage={report.overall_leakage_rate:.1%} | "
          f"PII Found={report.total_detected}/{report.total_pii}")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    report = run_full_benchmark()
    print_report(report)
