"""
Unit tests for core/detector.py.
"""

import unittest
from core.detector import PIIType, detect_pii, luhn_checksum


class TestDetector(unittest.TestCase):
    def test_luhn_algorithm(self):
        # Valid Luhn cards
        self.assertTrue(luhn_checksum("4111111111111111"))
        self.assertTrue(luhn_checksum("4242424242424242"))
        self.assertTrue(luhn_checksum("378282246310005"))  # Amex 15-digit
        # Invalid cards
        self.assertFalse(luhn_checksum("4111111111111112"))
        self.assertFalse(luhn_checksum("1234567890123456"))
        self.assertFalse(luhn_checksum("12345"))  # Too short

    def test_indian_aadhaar_detection(self):
        # Formatted with spaces
        text1 = "Citizen Aadhaar number is 2345 6789 0123 for KYC verification."
        res1 = detect_pii(text1)
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0]["type"], PIIType.AADHAAR.value)
        self.assertEqual(res1[0]["value"], "2345 6789 0123")
        self.assertEqual(res1[0]["start"], 26)
        self.assertEqual(res1[0]["end"], 40)
        self.assertIsNone(res1[0]["selector"])

        # Unformatted 12 digits
        text2 = "Aadhaar: 987654321098"
        res2 = detect_pii(text2)
        self.assertEqual(len(res2), 1)
        self.assertEqual(res2[0]["type"], PIIType.AADHAAR.value)
        self.assertEqual(res2[0]["value"], "987654321098")

        # Hyphenated
        text3 = "UIDAI: 4567-8901-2345"
        res3 = detect_pii(text3)
        self.assertEqual(len(res3), 1)
        self.assertEqual(res3[0]["type"], PIIType.AADHAAR.value)
        self.assertEqual(res3[0]["value"], "4567-8901-2345")

    def test_indian_pan_card_detection(self):
        text = "Taxpayer PAN is ABCDE1234F registered with the department."
        res = detect_pii(text)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["type"], PIIType.PAN.value)
        self.assertEqual(res[0]["value"], "ABCDE1234F")
        self.assertEqual(res[0]["start"], 16)
        self.assertEqual(res[0]["end"], 26)

    def test_credit_card_detection(self):
        # Valid Luhn card in text
        text = "Payment processed using card 4242 4242 4242 4242 today."
        res = detect_pii(text)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["type"], PIIType.CARD.value)
        self.assertEqual(res[0]["value"], "4242 4242 4242 4242")

        # Card number without spaces
        text2 = "Card: 4111111111111111"
        res2 = detect_pii(text2)
        self.assertEqual(len(res2), 1)
        self.assertEqual(res2[0]["type"], PIIType.CARD.value)
        self.assertEqual(res2[0]["value"], "4111111111111111")

        # Known mock card pattern
        text3 = "Mock card 4111222233334444"
        res3 = detect_pii(text3)
        self.assertEqual(len(res3), 1)
        self.assertEqual(res3[0]["type"], PIIType.CARD.value)

    def test_email_and_phone_detection(self):
        text = "Reach out to user.name@domain.co.uk or call +14155552671."
        res = detect_pii(text)
        types = [r["type"] for r in res]
        values = [r["value"] for r in res]
        self.assertIn(PIIType.EMAIL.value, types)
        self.assertIn(PIIType.PHONE.value, types)
        self.assertIn("user.name@domain.co.uk", values)
        self.assertIn("+14155552671", values)

    def test_api_keys_and_secrets(self):
        # OpenAI Key
        t1 = "OpenAI key: sk-abcdef1234567890abcdef1234567890abcdef12"
        r1 = detect_pii(t1)
        self.assertEqual(r1[0]["type"], PIIType.API_KEY.value)
        self.assertEqual(r1[0]["value"], "sk-abcdef1234567890abcdef1234567890abcdef12")

        # GitHub Token
        t2 = "GitHub: ghp_1234567890abcdef1234567890abcdef1234"
        r2 = detect_pii(t2)
        self.assertEqual(r2[0]["type"], PIIType.API_KEY.value)
        self.assertEqual(r2[0]["value"], "ghp_1234567890abcdef1234567890abcdef1234")

        # AWS Key
        t3 = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        r3 = detect_pii(t3)
        self.assertEqual(r3[0]["type"], PIIType.API_KEY.value)
        self.assertEqual(r3[0]["value"], "AKIAIOSFODNN7EXAMPLE")

        # JWT
        jwt_val = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        t4 = f"Authorization: Bearer {jwt_val}"
        r4 = detect_pii(t4)
        self.assertEqual(r4[0]["type"], PIIType.JWT.value)
        self.assertEqual(r4[0]["value"], jwt_val)

        # IPv4
        t5 = "Server IP is 192.168.1.105 on port 8080"
        r5 = detect_pii(t5)
        self.assertEqual(r5[0]["type"], PIIType.IPV4.value)
        self.assertEqual(r5[0]["value"], "192.168.1.105")

    def test_passwords_and_otps(self):
        # OTP after keyword
        t1 = "Your 2FA verification code is 482910 for login."
        r1 = detect_pii(t1)
        self.assertEqual(len(r1), 1)
        self.assertEqual(r1[0]["type"], PIIType.OTP.value)
        self.assertEqual(r1[0]["value"], "482910")

        # OTP before keyword
        t2 = "Enter 948123 as your one-time password."
        r2 = detect_pii(t2)
        self.assertEqual(len(r2), 1)
        self.assertEqual(r2[0]["type"], PIIType.OTP.value)
        self.assertEqual(r2[0]["value"], "948123")

        # Explicit text password
        t3 = "user credentials: password='MySuperSecretPass!'"
        r3 = detect_pii(t3)
        self.assertEqual(len(r3), 1)
        self.assertEqual(r3[0]["type"], PIIType.PASSWORD.value)
        self.assertEqual(r3[0]["value"], "MySuperSecretPass!")

    def test_dom_structural_analysis_html(self):
        html_input = '<input id="cc-field" autocomplete="cc-number" value="4111222233334444">'
        res = detect_pii(html_input)
        self.assertEqual(len(res), 1)
        item = res[0]
        self.assertEqual(item["type"], PIIType.CARD.value)
        self.assertEqual(item["value"], "4111222233334444")
        self.assertEqual(item["selector"], "#cc-field")
        # Verify exact slice in HTML
        self.assertEqual(html_input[item["start"]:item["end"]], "4111222233334444")

    def test_dom_structural_analysis_attributes(self):
        # CVV attribute
        html_cvv = '<input type="text" id="cvv" value="123">'
        r_cvv = detect_pii(html_cvv)
        self.assertEqual(len(r_cvv), 1)
        self.assertEqual(r_cvv[0]["type"], PIIType.CVV.value)
        self.assertEqual(r_cvv[0]["value"], "123")
        self.assertEqual(r_cvv[0]["selector"], "#cvv")

        # Aadhaar name attribute
        html_aadhaar = '<input type="text" name="aadhaar" value="1234 5678 9012">'
        r_aadhaar = detect_pii(html_aadhaar)
        self.assertEqual(len(r_aadhaar), 1)
        self.assertEqual(r_aadhaar[0]["type"], PIIType.AADHAAR.value)
        self.assertEqual(r_aadhaar[0]["selector"], "input[name='aadhaar']")

        # Password input
        html_pass = '<input type="password" id="login-pwd" value="P@ssw0rd99">'
        r_pass = detect_pii(html_pass)
        self.assertEqual(len(r_pass), 1)
        self.assertEqual(r_pass[0]["type"], PIIType.PASSWORD.value)
        self.assertEqual(r_pass[0]["selector"], "#login-pwd")

    def test_dom_dict_structure(self):
        node = {
            "tag": "input",
            "attributes": {
                "id": "cc-field",
                "autocomplete": "cc-number",
                "value": "4111222233334444",
            },
        }
        res = detect_pii(node)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["type"], PIIType.CARD.value)
        self.assertEqual(res[0]["value"], "4111222233334444")
        self.assertEqual(res[0]["selector"], "#cc-field")

    def test_redacted_placeholders_ignored(self):
        # Already redacted placeholders should never trigger PII detection
        text = "Card is [REDACTED:CARD_1] and password is [REDACTED:PASSWORD_1]"
        res = detect_pii(text)
        self.assertEqual(len(res), 0)


if __name__ == "__main__":
    unittest.main()
