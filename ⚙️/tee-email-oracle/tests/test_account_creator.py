import unittest

from email_oracle.account_creator import (
    PASSWORD_CONFIRM_FIELD,
    PASSWORD_CONFIRM_HONEYPOT_FIELD,
    _registration_form_data,
)
from email_oracle.cred_store import EmailCredentials


class AccountCreatorFormTest(unittest.TestCase):
    def test_registration_form_uses_cockli_confirm_field_and_clears_honeypot(self):
        creds = EmailCredentials(
            username="testuser",
            domain="cock.email",
            password="super-secret-password",
        )

        form = _registration_form_data(
            csrf="csrf-token",
            creds=creds,
            captcha_key="captcha-key",
            captcha_solution="abc123",
        )

        self.assertEqual(form["csrf"], "csrf-token")
        self.assertEqual(form["csrf_valid"], "csrf-token")
        self.assertEqual(form["password"], creds.password)
        self.assertEqual(form[PASSWORD_CONFIRM_FIELD], creds.password)
        self.assertEqual(form[PASSWORD_CONFIRM_HONEYPOT_FIELD], "")
        self.assertNotEqual(PASSWORD_CONFIRM_FIELD, PASSWORD_CONFIRM_HONEYPOT_FIELD)
        self.assertEqual(PASSWORD_CONFIRM_FIELD, "password_confinm")
        self.assertEqual(PASSWORD_CONFIRM_HONEYPOT_FIELD, "password_confirm")
        self.assertEqual(form["noscript"], "1")
        self.assertEqual(form["tos_agree"], "on")


if __name__ == "__main__":
    unittest.main()
