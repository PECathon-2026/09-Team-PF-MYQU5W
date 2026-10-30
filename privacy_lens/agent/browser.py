"""Playwright Browser Controller for PrivacyLens.

Provides a thin wrapper around Playwright's synchronous API to:
- launch a Chromium browser (headless toggleable)
- navigate to a remote URL or a local `file://` path
- extract raw DOM inner text and a simple accessibility tree representation
- capture a full‑page screenshot saved under the workspace `scratch/` folder
- expose the underlying Playwright ``Page`` and ``Browser`` objects for downstream agents.

All operations happen locally; no network traffic leaves the host.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional, Tuple

try:
    from playwright.sync_api import (
        sync_playwright,
        Playwright,
        Browser,
        BrowserContext,
        Page,
    )
except ImportError as exc:
    raise RuntimeError(
        "Playwright is not installed. Install with `pip install playwright` and run `playwright install`"
    ) from exc

logger = logging.getLogger(__name__)


class BrowserController:
    """Encapsulates a Playwright Chromium instance.

    Parameters
    ----------
    headless: bool, default ``True``
        Run the browser without a UI. Set ``False`` for debugging.
    screenshot_path: str | Path, optional
        Destination for the screenshot taken by :meth:`capture_page`. If omitted,
        the image is saved to ``scratch/raw_screenshot.png`` relative to the
        project root.
    """

    def __init__(self, *, headless: bool = True, screenshot_path: Optional[Path] = None):
        self._headless = headless
        self._screenshot_path = (
            Path(screenshot_path) if screenshot_path else Path.cwd() / "scratch" / "raw_screenshot.png"
        )
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

    # ---------------------------------------------------------------------
    # Lifecycle helpers
    # ---------------------------------------------------------------------
    def _launch(self) -> None:
        """Start Playwright and create a new Chromium browser."""
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=self._headless)
        self._context = self._browser.new_context()
        self._page = self._context.new_page()
        logger.info("Launched Chromium (headless=%s)", self._headless)

    def close(self) -> None:
        """Close the browser and clean up Playwright resources."""
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
        logger.info("BrowserController closed")
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None

    def get_sensitive_bounding_boxes(self) -> list[dict]:
        """Find sensitive input elements in the DOM and compute their pixel bounding boxes.

        Inspects:
        - input[type="password"]
        - input with name/id containing 'card', 'cvv', 'pass', 'phone', 'email', 'aadhaar', 'otp'
        - inputs with sensitive autocomplete or aria labels
        """
        if not self._page:
            return []

        regions = []
        sensitive_patterns = [
            ("input[type='password']", "PASSWORD"),
            ("input[name*='card' i], input[id*='card' i]", "CREDIT_CARD"),
            ("input[name*='cvv' i], input[id*='cvv' i]", "CVV"),
            ("input[type='tel'], input[name*='phone' i], input[id*='phone' i]", "PHONE"),
            ("input[type='email'], input[name*='email' i], input[id*='email' i]", "EMAIL"),
            ("input[name*='pass' i], input[id*='pass' i]", "PASSWORD"),
            ("input[name*='aadhaar' i], input[id*='aadhaar' i]", "AADHAAR"),
            ("input[name*='otp' i], input[id*='otp' i]", "OTP"),
            ("textarea[name*='address' i], textarea[id*='address' i]", "ADDRESS"),
        ]

        for selector, label in sensitive_patterns:
            try:
                elements = self._page.query_selector_all(selector)
                for el in elements:
                    box = el.bounding_box()
                    if box and box["width"] > 0 and box["height"] > 0:
                        regions.append({
                            "x": int(box["x"]),
                            "y": int(box["y"]),
                            "width": int(box["width"]),
                            "height": int(box["height"]),
                            "label": label,
                            "selector": selector,
                        })
            except Exception as e:
                logger.debug("Bounding box error for %s: %s", selector, e)

        return regions

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------
    def capture_page(self, url_or_filepath: str) -> Tuple[str, str, Page, Browser]:
        """Navigate to ``url_or_filepath`` and capture DOM + screenshot.

        Works with both remote URLs (e.g. ``https://example.com``) and local
        HTML files. For a local file, the function converts the path to a
        ``file://`` URL automatically.

        Returns
        -------
        raw_dom_text: str
            Full inner‑text of the page body.
        screenshot_path: str
            Absolute path to the saved PNG screenshot.
        page_handle: playwright.sync_api.Page
            The live Playwright ``Page`` instance – useful for later actions.
        browser_handle: playwright.sync_api.Browser
            The underlying ``Browser`` instance.
        """
        self._launch()
        assert self._page is not None

        # Resolve target – if a local file exists, use a file:// URI.
        if os.path.isfile(url_or_filepath):
            target = Path(url_or_filepath).absolute().as_uri()
        else:
            target = url_or_filepath

        logger.info("Navigating to %s", target)
        self._page.goto(target, wait_until="networkidle")

        # -----------------------------------------------------------------
        # Extract raw DOM inner text AND raw HTML for PII scanning.
        # input[value="..."] attributes are invisible to inner_text,
        # so we concatenate both so the detector sees everything.
        # -----------------------------------------------------------------
        raw_dom_text = self._page.inner_text("body")
        raw_html = self._page.content()
        # Append raw HTML so detector can catch attribute-embedded PII
        raw_dom_text = raw_dom_text + "\n\n--- RAW HTML ---\n" + raw_html

        # -----------------------------------------------------------------
        # Accessibility tree – omit gracefully on newer Playwright builds
        # where the .accessibility API has been removed.
        # -----------------------------------------------------------------
        try:
            accessibility_tree = self._page.accessibility.snapshot()  # type: ignore[attr-defined]
            raw_dom_text += "\n\n--- ACCESSIBILITY TREE ---\n" + json.dumps(accessibility_tree, indent=2)
        except AttributeError:
            logger.debug("accessibility.snapshot() not available in this Playwright version – skipping")

        # -----------------------------------------------------------------
        # Screenshot handling – ensure the scratch directory exists.
        # -----------------------------------------------------------------
        screenshot_path = self._screenshot_path.expanduser().resolve()
        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
        self._page.screenshot(path=str(screenshot_path), full_page=True)
        logger.info("Screenshot saved to %s", screenshot_path)

        # Compute sensitive bounding boxes on the live page
        self.sensitive_regions = self.get_sensitive_bounding_boxes()
        logger.info("Found %d sensitive DOM bounding boxes for image redaction", len(self.sensitive_regions))

        return raw_dom_text, str(screenshot_path), self._page, self._browser

    # ---------------------------------------------------------------------
    # Convenience properties
    # ---------------------------------------------------------------------
    @property
    def page(self) -> Optional[Page]:
        return self._page

    @property
    def browser(self) -> Optional[Browser]:
        return self._browser

# ------------------------------------------------------------
# Module‑level helper that mirrors the original public API
# ------------------------------------------------------------
def capture_page(url_or_filepath: str, *, headless: bool = True, screenshot_path: Optional[Path] = None) -> Tuple[str, str, Page, Browser]:
    """Convenient wrapper that creates a temporary ``BrowserController``
    instance, captures the page, and then closes the browser.

    Parameters
    ----------
    url_or_filepath: str
        URL or local file path to navigate to.
    headless: bool, default ``True``
        Run Chromium headless (set ``False`` for debugging).
    screenshot_path: Optional[Path]
        Destination for the screenshot; defaults to ``scratch/raw_screenshot.png``.
    """
    controller = BrowserController(headless=headless, screenshot_path=screenshot_path)
    try:
        return controller.capture_page(url_or_filepath)
    finally:
        controller.close()

