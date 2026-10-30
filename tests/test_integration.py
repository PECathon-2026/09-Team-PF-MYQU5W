"""
Integration tests for PrivacyLens Security & Privacy Engine (PS-004).

Tests the full lifecycle:
Raw DOM / Input -> Local Detection -> Local Sanitization -> Outgoing Guard Validation -> Safe LLM Transmission -> Local Unmasking.
"""

import unittest
from core.detector import detect_pii
from core.guard import SecurityViolationException, validate_outgoing_payload
from core.sanitizer import Sanitizer


class TestPrivacyLensIntegration(unittest.TestCase):
    def setUp(self):
        self.sanitizer = Sanitizer()

    def test_end_to_end_pipeline(self):
        # 1. Raw webpage DOM containing highly sensitive financial and identity data
        raw_dom = (
            '<form id="payment-form">\n'
            '  <input id="cc-field" autocomplete="cc-number" value="4111222233334444">\n'
            '  <input id="cvv" autocomplete="cc-csc" value="789">\n'
            '  <input id="aadhaar-field" name="aadhaar" value="1234 5678 9012">\n'
            '  <input id="pan-field" name="pan" value="ABCDE1234F">\n'
            '  <input id="user-pass" type="password" value="SuperSecretToken99!">\n'
            '  <span id="user-email">customer.care@enterprise.com</span>\n'
            '</form>'
        )

        # 2. Guard MUST block unredacted raw DOM from leaving the host
        with self.assertRaises(SecurityViolationException):
            validate_outgoing_payload(raw_dom)

        # 3. Detect PII locally
        detections = detect_pii(raw_dom)
        self.assertGreaterEqual(len(detections), 6)

        # Check detected types
        detected_types = {d["type"] for d in detections}
        self.assertIn("CARD", detected_types)
        self.assertIn("CVV", detected_types)
        self.assertIn("AADHAAR", detected_types)
        self.assertIn("PAN", detected_types)
        self.assertIn("PASSWORD", detected_types)
        self.assertIn("EMAIL", detected_types)

        # 4. Local Sanitization
        sanitized_dom = self.sanitizer.sanitize_text(raw_dom)

        # Verify raw secrets are completely stripped
        self.assertNotIn("4111222233334444", sanitized_dom)
        self.assertNotIn("789", sanitized_dom)
        self.assertNotIn("1234 5678 9012", sanitized_dom)
        self.assertNotIn("ABCDE1234F", sanitized_dom)
        self.assertNotIn("SuperSecretToken99!", sanitized_dom)
        self.assertNotIn("customer.care@enterprise.com", sanitized_dom)

        # Verify selectors and structure are preserved for AI Agent navigation
        self.assertIn('id="cc-field"', sanitized_dom)
        self.assertIn('autocomplete="cc-number"', sanitized_dom)
        self.assertIn('id="cvv"', sanitized_dom)
        self.assertIn('id="aadhaar-field"', sanitized_dom)
        self.assertIn('id="pan-field"', sanitized_dom)
        self.assertIn('id="user-pass"', sanitized_dom)
        self.assertIn('id="user-email"', sanitized_dom)

        # Verify placeholders were inserted
        self.assertIn("[REDACTED:CARD_1]", sanitized_dom)
        self.assertIn("[REDACTED:PASSWORD_1]", sanitized_dom)
        self.assertIn("[REDACTED:AADHAAR_1]", sanitized_dom)

        # 5. Outgoing Guard MUST validate and approve the sanitized payload
        self.assertTrue(validate_outgoing_payload(sanitized_dom))

        # 6. Simulated Agent Response
        # The external AI agent reasons on sanitized data and issues navigation instructions:
        ai_agent_plan = (
            "Instruction: Click #cc-field and verify [REDACTED:CARD_1]. "
            "Then click #aadhaar-field with [REDACTED:AADHAAR_1]."
        )

        # 7. Local Unmasking before execution in the browser
        local_execution_plan = self.sanitizer.unmask_text(ai_agent_plan)
        self.assertIn("4111222233334444", local_execution_plan)
        self.assertIn("1234 5678 9012", local_execution_plan)
        self.assertNotIn("[REDACTED:", local_execution_plan)


if __name__ == "__main__":
    unittest.main()
