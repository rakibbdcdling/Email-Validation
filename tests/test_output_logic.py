import unittest
import validator

class OutputLogicTests(unittest.TestCase):
    def test_output_columns(self):
        self.assertEqual(validator.HEADERS, [
            'Email', 'Status', 'My Sub Status', 'My MX Record',
            'My SMTP Provider', 'SMTP Response'
        ])

    def test_provider_detection(self):
        self.assertEqual(validator.identify_smtp_provider(
            ['alt1.gmail-smtp-in.l.google.com'], 'gmail.com'), 'google')
        self.assertEqual(validator.identify_smtp_provider(
            ['example-com.mail.protection.outlook.com'], 'example.com'), 'microsoft')
        self.assertEqual(validator.identify_smtp_provider(
            ['mx-att.mail.am0.yahoodns.net'], 'sbcglobal.net'), 'yahoo')

    def test_550_mailbox_evidence(self):
        self.assertTrue(validator._is_definitive_mailbox_550('550 5.1.1 User unknown'))
        self.assertTrue(validator._is_definitive_mailbox_550('550 No such mailbox'))
        self.assertFalse(validator._is_definitive_mailbox_550('550 5.7.1 Message blocked'))
        self.assertFalse(validator._is_definitive_mailbox_550('550 Requested action rejected'))

    def test_sub_status_is_conservative(self):
        self.assertEqual(validator.build_sub_status(
            'info', 'Likely catch-all; mailbox unconfirmed', '250', 'details'), 'catch_all')
        self.assertEqual(validator.build_sub_status(
            'info', 'Target accepted; mailbox unconfirmed', '250', 'details'), 'role_based')
        self.assertEqual(validator.build_sub_status(
            'alex', 'Definitive mailbox-not-found (550)', '550', '5.1.1'),
            'mailbox_not_found')
        self.assertEqual(validator.build_sub_status(
            'alex', 'Target 550; mailbox existence unconfirmed', '550', '550 5.7.1 policy'),
            'smtp_550_unconfirmed')
        self.assertEqual(validator.build_sub_status(
            'alex', 'Recipient rejected; not definitive', '553', '5.7.1'),
            'smtp_rejected_unconfirmed')

if __name__ == '__main__':
    unittest.main()
