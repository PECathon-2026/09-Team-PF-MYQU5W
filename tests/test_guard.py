"""
Unit tests for core/guard.py.
"""

import unittest
from unittest.mock import patch
from core.guard import (
    SecurityViolationException,
    is_payload_safe,
    validate_outgoing_payload,
)


class TestGuard(unittest.TestCase):
    def test_clean_payload_passes(self):
        # A completely sanitized payload with placeholders must pass
        clean_payload = (
            "Agent command: click #cc-field and type [REDACTED:CARD_1] "
            "then submit for user [REDACTED:EMAIL_1]."
        )
        self.assertTrue(validate_outgoing_payload(clean_payload))
        self.assertTrue(is_payload_safe(clean_payload))

    def test_unredacted_pii_triggers_fail_closed_guard(self):
        # A payload containing an unredacted PAN card must fail and raise exception
        dirty_payload = "Please send payment verification for PAN ABCDE1234F to server."

        with self.assertLogs("privacylens.guard", level="ERROR") as log_capture:
            with self.assertRaises(SecurityViolationException) as ctx:
                validate_outgoing_payload(dirty_payload)

            self.assertIn("Payload blocked due to PII leakage risk", str(ctx.exception))
            # Verify exact alert log message as required by specification
            self.assertTrue(
                any(
                    "FAIL-CLOSED GUARD TRIGGERED: Unredacted PII detected!" in msg
                    for msg in log_capture.output
                )
            )

    def test_unredacted_pii_non_throwing_returns_false(self):
        dirty_payload = "Aadhaar: 1234 5678 9012"
        # Non-throwing validation must return False
        result = validate_outgoing_payload(dirty_payload, raise_exception=False)
        self.assertFalse(result)
        self.assertFalse(is_payload_safe(dirty_payload))

    def test_unredacted_api_key_blocks(self):
        dirty_payload = (
            '{"prompt": "Generate summary with key sk-abcdef1234567890abcdef1234567890abcdef12"}'
        )
        with self.assertRaises(SecurityViolationException):
            validate_outgoing_payload(dirty_payload)

    def test_exception_contains_detected_pii(self):
        dirty_payload = "Email leak: attacker@leak.com"
        try:
            validate_outgoing_payload(dirty_payload)
            self.fail("Expected SecurityViolationException was not raised.")
        except SecurityViolationException as exc:
            self.assertEqual(len(exc.detected_pii), 1)
            self.assertEqual(exc.detected_pii[0]["type"], "EMAIL")
            self.assertEqual(exc.detected_pii[0]["value"], "attacker@leak.com")


if __name__ == "__main__":
    unittest.main()
