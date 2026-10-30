"""
Unit tests for core/sanitizer.py.
"""

import unittest
from core.sanitizer import Sanitizer


class TestSanitizer(unittest.TestCase):
    def setUp(self):
        self.sanitizer = Sanitizer()

    def test_sanitize_plain_text(self):
        raw = "User email is test@company.com and Aadhaar is 1234 5678 9012."
        sanitized = self.sanitizer.sanitize_text(raw)

        self.assertNotIn("test@company.com", sanitized)
        self.assertNotIn("1234 5678 9012", sanitized)
        self.assertIn("[REDACTED:EMAIL_1]", sanitized)
        self.assertIn("[REDACTED:AADHAAR_1]", sanitized)

        # Check secret_store mappings
        self.assertEqual(
            self.sanitizer.secret_store["[REDACTED:EMAIL_1]"], "test@company.com"
        )
        self.assertEqual(
            self.sanitizer.secret_store["[REDACTED:AADHAAR_1]"], "1234 5678 9012"
        )

    def test_deterministic_placeholders(self):
        # The same secret value appearing twice must map to the same placeholder
        raw = "Card 4111111111111111 charged. Verify card 4111111111111111 again."
        sanitized = self.sanitizer.sanitize_text(raw)

        # Check that both occurrences are replaced with [REDACTED:CARD_1]
        self.assertEqual(sanitized.count("[REDACTED:CARD_1]"), 2)
        self.assertEqual(
            self.sanitizer.secret_store["[REDACTED:CARD_1]"], "4111111111111111"
        )

        # A different card gets [REDACTED:CARD_2]
        raw2 = "Another card: 4242424242424242"
        sanitized2 = self.sanitizer.sanitize_text(raw2)
        self.assertIn("[REDACTED:CARD_2]", sanitized2)
        self.assertEqual(
            self.sanitizer.secret_store["[REDACTED:CARD_2]"], "4242424242424242"
        )

    def test_sanitize_html_dom_structure_preservation(self):
        html_input = '<input id="cc-field" autocomplete="cc-number" value="4111222233334444">'
        sanitized = self.sanitizer.sanitize_text(html_input)

        # Structure, tag, and attributes must be perfectly preserved
        expected = '<input id="cc-field" autocomplete="cc-number" value="[REDACTED:CARD_1]">'
        self.assertEqual(sanitized, expected)
        self.assertEqual(
            self.sanitizer.secret_store["[REDACTED:CARD_1]"], "4111222233334444"
        )

    def test_sanitize_dom_dictionary(self):
        node = {
            "tag": "input",
            "attributes": {
                "id": "cc-field",
                "autocomplete": "cc-number",
                "value": "4111222233334444",
            },
        }
        sanitized_node = self.sanitizer.sanitize_text(node)

        # Selector and attributes are preserved; secret is redacted
        self.assertEqual(sanitized_node["attributes"]["id"], "cc-field")
        self.assertEqual(
            sanitized_node["attributes"]["autocomplete"], "cc-number"
        )
        self.assertEqual(
            sanitized_node["attributes"]["value"], "[REDACTED:CARD_1]"
        )
        self.assertEqual(
            self.sanitizer.secret_store["[REDACTED:CARD_1]"], "4111222233334444"
        )

    def test_unmask_value(self):
        self.sanitizer.sanitize_text("Secret key: sk-abcdef1234567890abcdef1234567890abcdef12")
        placeholder = "[REDACTED:API_KEY_1]"

        raw_secret = self.sanitizer.unmask_value(placeholder)
        self.assertEqual(
            raw_secret, "sk-abcdef1234567890abcdef1234567890abcdef12"
        )

        with self.assertRaises(KeyError):
            self.sanitizer.unmask_value("[REDACTED:UNKNOWN_99]")

    def test_unmask_text(self):
        raw_text = "Card 4242424242424242 and email dev@example.com"
        sanitized_text = self.sanitizer.sanitize_text(raw_text)

        restored_text = self.sanitizer.unmask_text(sanitized_text)
        self.assertEqual(restored_text, raw_text)

    def test_clear_secret_store(self):
        self.sanitizer.sanitize_text("Card: 4242424242424242")
        self.assertGreater(len(self.sanitizer.secret_store), 0)

        self.sanitizer.clear()
        self.assertEqual(len(self.sanitizer.secret_store), 0)
        self.assertEqual(len(self.sanitizer._type_counters), 0)


if __name__ == "__main__":
    unittest.main()
