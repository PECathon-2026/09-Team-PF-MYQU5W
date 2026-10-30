"""PIL Screenshot Blackout Engine.

Provides region-based and text-based redaction of screenshots.
Used to black out sensitive areas before transmitting screenshots
to cloud AI models.

All processing runs LOCAL-ONLY.
"""

from __future__ import annotations

import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFilter
except ImportError:
    Image = None  # Graceful degradation

logger = logging.getLogger(__name__)


@dataclass
class RedactionRegion:
    """A rectangular region to redact in an image.
    
    Coordinates are in pixels (x, y) from top-left.
    """
    x: int
    y: int
    width: int
    height: int
    label: str = ""  # e.g., "CREDIT_CARD", "AADHAAR"


class ImageRedactor:
    """Redact sensitive regions from screenshot images.
    
    Supports:
    - Solid black box redaction
    - Gaussian blur redaction
    - Labeled overlay redaction
    """

    def __init__(self):
        """Initialize the image redactor."""
        if Image is None:
            raise RuntimeError("Pillow is not installed. Run: pip install pillow")

    def redact_regions(
        self,
        image: Image.Image,
        regions: List[RedactionRegion],
        *,
        method: str = "blackout",
        fill_color: Tuple[int, int, int] = (0, 0, 0),
    ) -> Image.Image:
        """Apply redaction to specified regions of an image.
        
        Args:
            image: Source PIL Image.
            regions: List of RedactionRegion to redact.
            method: Redaction method ('blackout', 'blur', 'label').
            fill_color: Fill color for blackout mode (default black).
            
        Returns:
            New PIL Image with redacted regions.
        """
        result = image.copy()
        draw = ImageDraw.Draw(result)

        for region in regions:
            box = (
                region.x,
                region.y,
                region.x + region.width,
                region.y + region.height,
            )

            if method == "blackout":
                draw.rectangle(box, fill=fill_color)
                if region.label:
                    # Draw label text over the black box
                    draw.text(
                        (region.x + 4, region.y + 2),
                        f"[{region.label}]",
                        fill=(255, 255, 255),
                    )

            elif method == "blur":
                cropped = result.crop(box)
                blurred = cropped.filter(ImageFilter.GaussianBlur(radius=20))
                result.paste(blurred, box)

            elif method == "label":
                draw.rectangle(box, fill=(50, 50, 50))
                draw.text(
                    (region.x + 4, region.y + 2),
                    f"[REDACTED: {region.label}]",
                    fill=(255, 100, 100),
                )

            logger.info(
                "Redacted region: (%d, %d, %d, %d) method=%s label=%s",
                region.x, region.y, region.width, region.height,
                method, region.label,
            )

        return result

    def redact_from_bytes(
        self,
        image_bytes: bytes,
        regions: List[RedactionRegion],
        *,
        method: str = "blackout",
    ) -> bytes:
        """Redact regions from a screenshot given as bytes.
        
        Args:
            image_bytes: PNG/JPEG image bytes.
            regions: Regions to redact.
            method: Redaction method.
            
        Returns:
            Redacted image as PNG bytes.
        """
        import io
        image = Image.open(io.BytesIO(image_bytes))
        redacted = self.redact_regions(image, regions, method=method)
        output = io.BytesIO()
        redacted.save(output, format="PNG")
        return output.getvalue()

    def save_redacted(
        self,
        image: Image.Image,
        regions: List[RedactionRegion],
        output_path: Path,
        *,
        method: str = "blackout",
    ) -> Path:
        """Redact and save an image to disk.
        
        Args:
            image: Source image.
            regions: Regions to redact.
            output_path: Where to save the redacted image.
            method: Redaction method.
            
        Returns:
            Path to the saved redacted image.
        """
        redacted = self.redact_regions(image, regions, method=method)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        redacted.save(output_path)
        logger.info("Redacted image saved to: %s", output_path)
        return output_path
