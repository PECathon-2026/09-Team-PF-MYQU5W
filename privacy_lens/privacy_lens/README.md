# 🔒 PrivacyLens — Privacy-Preserving AI Browser Agent

> **PECathon 2026 — Problem Statement 4**

## Core Principle

> "Compute what is sensitive locally. Reason globally only on sanitized data."

PrivacyLens is a framework that securely detects and redacts sensitive personal data (Aadhaar, PAN, credit cards, passwords, OTPs, phone numbers, API keys, medical/private data) **locally** before transmitting webpage data or screenshots to cloud AI models.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    LOCAL MACHINE                        │
│                                                         │
│  ┌──────────┐    ┌───────────┐    ┌──────────────┐     │
│  │ Browser  │───▶│ Detector  │───▶│  Sanitizer   │     │
│  │ (Playwright)  │ (Regex+DOM)│    │ (Placeholders)│     │
│  └──────────┘    └───────────┘    └──────┬───────┘     │
│                                          │              │
│                                   ┌──────▼───────┐     │
│                                   │    Guard     │     │
│                                   │ (Fail-Closed)│     │
│                                   └──────┬───────┘     │
│                                          │              │
│  ┌──────────┐                     ┌──────▼───────┐     │
│  │ Executor │◀────────────────────│   Reasoner   │─ ─ ─│─ ─ ▶ Cloud LLM
│  │ (Secret  │    Action Plans     │ (Sanitized   │     │    (Safe Data
│  │ Injection)│   with Placeholders │  Data Only)  │     │     Only)
│  └──────────┘                     └──────────────┘     │
│       │                                                 │
│  Local Browser DOM (raw secrets injected locally)      │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

```
privacy_lens/
├── core/                    # Security & Sanitization (Teammate 1)
│   ├── detector.py          # Regex + DOM PII detection
│   ├── sanitizer.py         # Placeholder replacement & secret store
│   └── guard.py             # Outgoing fail-closed payload blocker
├── agent/                   # Browser & AI Engine (Teammate 2)
│   ├── browser.py           # Playwright DOM capture
│   ├── reasoner.py          # LLM action planner (sanitized data)
│   └── executor.py          # Action runner with secret injection
├── ui/                      # Dashboard & Redaction (Teammate 3)
│   ├── app.py               # Streamlit Before/After inspector
│   └── image_redactor.py    # PIL screenshot blackout
├── eval/                    # Benchmarks (Teammate 3)
│   ├── run_benchmark.py     # Automated PII recall & leakage tests
│   └── test_pages/          # 5 evaluation HTML scenarios
├── scratch/                 # Temp files (screenshots/logs)
├── main.py                  # Master pipeline entry point
├── requirements.txt         # Dependencies
└── README.md                # This file
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt
python -m playwright install chromium

# 2. Run the pipeline
python -m privacy_lens.main --url "https://example.com" --task "Fill the form"

# 3. Launch the dashboard
streamlit run privacy_lens/ui/app.py

# 4. Run benchmarks
python -m privacy_lens.eval.run_benchmark
```

## Shared Interface Contracts

### Secret Store Schema
```python
secret_store = {
    "[REDACTED:CARD_1]": "4111222233334444",
    "[REDACTED:PASSWORD_1]": "SecretPass123",
}
# ⚠️ This dict NEVER leaves the local host.
```

### Action Plan JSON
```json
{
    "thought": "Reasoning based on sanitized DOM",
    "action": "type",
    "selector": "#card_number_field",
    "value": "[REDACTED:CARD_1]",
    "is_sensitive_action": true
}
```

### Guard Validation
```python
from privacy_lens.core.guard import validate_outgoing_payload

# Raises SecurityViolationException if PII found
validate_outgoing_payload(payload_string)
```

## Security Rules

1. **NEVER** transmit raw PII over the network
2. **ALWAYS** sanitize before sending to cloud LLM
3. **FAIL-CLOSED**: Block if uncertain about PII presence
4. **SECRET STORE**: In-memory only, cleared after each session
5. **LOCAL INJECTION**: Secrets resolved locally in Playwright

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| Browser | Playwright (sync API) |
| Dashboard | Streamlit |
| Server | FastAPI + Uvicorn |
| Imaging | Pillow (PIL) |
| Validation | Pydantic |
| Testing | Pytest |

## Team

- **Teammate 1**: Core security — detector, sanitizer, guard
- **Teammate 2**: Agent engine — browser, reasoner, executor
- **Teammate 3**: UI & eval — dashboard, image redactor, benchmarks

---

*Built with 🔒 for PECathon 2026 — Problem Statement 4*
