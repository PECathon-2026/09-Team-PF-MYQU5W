"""Streamlit Before/After Privacy Inspector Dashboard.

Provides a dual-column visual interface for comparing:
- LEFT:  Original page content with PII highlighted
- RIGHT: Sanitized content with [REDACTED:*] placeholders

Also displays:
- PII detection summary table
- Secret store statistics (counts only, never values)
- Screenshot comparison with visual redaction overlay

Usage:
    streamlit run privacy_lens/ui/app.py
"""

import sys
from pathlib import Path

# Ensure project root is importable
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

try:
    import streamlit as st
except ImportError:
    st = None  # Graceful degradation

from privacy_lens.core.detector import detect_pii, PIIType
from privacy_lens.core.sanitizer import sanitize_text, SecretStore
from privacy_lens.ui.image_redactor import ImageRedactor


def _highlight_pii(text: str) -> str:
    """Wrap detected PII in HTML highlight spans for display.
    
    Args:
        text: Raw text to highlight.
        
    Returns:
        HTML string with PII wrapped in colored spans.
    """
    entities = detect_pii(text)
    if not entities:
        return text
    
    # Sort by position descending to avoid index shift
    entities.sort(key=lambda e: e.start, reverse=True)
    
    highlighted = text
    for entity in entities:
        color_map = {
            PIIType.CREDIT_CARD: "#ff4444",
            PIIType.AADHAAR: "#ff6600",
            PIIType.PAN: "#ff8800",
            PIIType.PASSWORD: "#cc00cc",
            PIIType.EMAIL: "#4488ff",
            PIIType.PHONE: "#00aa44",
            PIIType.API_KEY: "#aa0000",
            PIIType.OTP: "#cc00cc",
            PIIType.IP_ADDRESS: "#888800",
        }
        color = color_map.get(entity.pii_type, "#ff4444")
        tag = (
            f'<span style="background-color: {color}; color: white; '
            f'padding: 2px 4px; border-radius: 3px; font-weight: bold;" '
            f'title="{entity.pii_type.value}">{entity.value}</span>'
        )
        highlighted = highlighted[:entity.start] + tag + highlighted[entity.end:]
    
    return highlighted


def main() -> None:
    """Run the Streamlit privacy inspector dashboard."""
    if st is None:
        print("ERROR: Streamlit is not installed. Run: pip install streamlit")
        return
    
    st.set_page_config(
        page_title="PrivacyLens Inspector",
        page_icon="🔒",
        layout="wide",
    )
    
    st.title("🔒 PrivacyLens — Before / After Privacy Inspector")
    st.markdown("---")
    
    # ── Input Area ────────────────────────────────────────────────
    input_text = st.text_area(
        "Paste text or HTML content to inspect:",
        height=200,
        placeholder="Enter text containing PII (credit cards, Aadhaar, passwords, etc.)...",
    )
    
    if st.button("🔍 Scan & Sanitize", type="primary"):
        if not input_text.strip():
            st.warning("Please enter some text to scan.")
            return
        
        store = SecretStore()
        sanitized, store = sanitize_text(input_text, secret_store=store)
        entities = detect_pii(input_text)
        
        # ── Before / After Columns ────────────────────────────────
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("⚠️ BEFORE — Original (PII Highlighted)")
            highlighted = _highlight_pii(input_text)
            st.markdown(highlighted, unsafe_allow_html=True)
        
        with col2:
            st.subheader("✅ AFTER — Sanitized")
            st.code(sanitized, language="text")
        
        # ── Detection Summary ─────────────────────────────────────
        st.markdown("---")
        st.subheader("📊 Detection Summary")
        
        if entities:
            summary_data = {}
            for entity in entities:
                pii_type = entity.pii_type.value
                if pii_type not in summary_data:
                    summary_data[pii_type] = 0
                summary_data[pii_type] += 1
            
            st.table(
                [{"PII Type": k, "Count": v} for k, v in summary_data.items()]
            )
        else:
            st.success("No PII detected in the input.")
        
        # ── Secret Store Stats ────────────────────────────────────
        st.subheader("🔐 Secret Store Statistics")
        st.info(
            f"Secrets stored: {len(store.as_dict())} entries\n\n"
            f"⚠️ Secret values are NEVER displayed or transmitted."
        )
    
    # ── Screenshot Redaction Section ──────────────────────────────
    st.markdown("---")
    st.subheader("🖼️ Screenshot Redaction")
    
    uploaded_file = st.file_uploader(
        "Upload a screenshot to redact:",
        type=["png", "jpg", "jpeg"],
    )
    
    if uploaded_file is not None:
        st.image(uploaded_file, caption="Original Screenshot", use_column_width=True)
        st.info("📌 Automated OCR-based redaction coming soon. Use image_redactor.py for manual region redaction.")


if __name__ == "__main__":
    main()
