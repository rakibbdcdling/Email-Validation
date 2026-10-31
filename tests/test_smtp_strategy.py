import socket
import unittest
from unittest.mock import patch
import validator


class FakeSMTP:
    def __init__(self, target=(250, b"2.1.5 accepted"), random=(550, b"5.1.1 user unknown"), **kwargs):
        self.target = target
        self.random = random
        self.rcpt_calls = 0
        self.esmtp_features = {}
        self.sock = None
    def set_debuglevel(self, value): pass
    def connect(self, host, port): return 220, b"ready"
    def ehlo(self): return 250, b"hello"
    def helo(self): return 250, b"hello"
    def has_extn(self, name): return False
    def mail(self, sender): return 250, b"sender ok"
    def rcpt(self, address):
        self.rcpt_calls += 1
        return self.target if self.rcpt_calls == 1 else self.random
    def rset(self): return 250, b"reset"
    def quit(self): pass
    def close(self): pass


class SMTPStrategyTests(unittest.TestCase):
    def setUp(self):
        with validator._smtp_policy_lock:
            validator._smtp_policy_cache.clear()
    def test_target_accepted_and_random_rejected_is_likely_valid(self):
        with patch.object(validator.smtplib, "SMTP", side_effect=lambda **kw: FakeSMTP()):
            result = validator._smtp_recipient_probe_limited(["mx.example.test"], "alice@example.test")
        self.assertEqual(result[0], "Target accepted; random recipient rejected")
        self.assertEqual(result[1], "250")

    def test_target_and_random_accepted_is_catch_all(self):
        with patch.object(validator.smtplib, "SMTP", side_effect=lambda **kw: FakeSMTP(random=(250, b"2.1.5 accepted"))):
            result = validator._smtp_recipient_probe_limited(["mx.example.test"], "alice@example.test")
        self.assertEqual(result[0], "Likely catch-all; mailbox unconfirmed")
        self.assertEqual(validator._get_cached_random_policy("example.test", "mx.example.test"), "random_accepted")

    def test_definitive_550_plus_random_acceptance_is_invalid_evidence(self):
        with patch.object(validator.smtplib, "SMTP", side_effect=lambda **kw: FakeSMTP(target=(550, b"5.1.1 user unknown"), random=(250, b"2.1.5 accepted"))):
            result = validator._smtp_recipient_probe_limited(["mx.example.test"], "alice@example.test")
        self.assertEqual(result[0], "Definitive mailbox-not-found (550)")

    def test_policy_550_is_not_invalid(self):
        with patch.object(validator.smtplib, "SMTP", side_effect=lambda **kw: FakeSMTP(target=(550, b"5.7.1 policy blocked"), random=(250, b"2.1.5 accepted"))):
            result = validator._smtp_recipient_probe_limited(["mx.example.test"], "alice@example.test")
        self.assertIn("unconfirmed", result[0])

    def test_generic_550_with_random_rejected_is_unknown(self):
        with patch.object(validator.smtplib, "SMTP", side_effect=lambda **kw: FakeSMTP(target=(550, b"mailbox rejected"), random=(550, b"5.1.1 user unknown"))):
            result = validator._smtp_recipient_probe_limited(["mx.example.test"], "alice@example.test")
        self.assertIn("unconfirmed", result[0])

    def test_domain_control_is_cached_for_next_address(self):
        with patch.object(validator.smtplib, "SMTP", side_effect=lambda **kw: FakeSMTP(random=(250, b"2.1.5 accepted"))):
            first = validator._smtp_recipient_probe_limited(["mx.example.test"], "alice@example.test")
        with patch.object(validator.smtplib, "SMTP", side_effect=lambda **kw: FakeSMTP(random=(550, b"5.1.1 user unknown"))):
            second = validator._smtp_recipient_probe_limited(["mx.example.test"], "bob@example.test")
        self.assertEqual(first[0], "Likely catch-all; mailbox unconfirmed")
        self.assertEqual(second[0], "Likely catch-all; mailbox unconfirmed")
        self.assertIn("policy cached", second[3])

    def test_check_email_status_from_positive_rcpt(self):
        with patch.object(validator, "check_dns", return_value=("No", "No", ["mx.example.test"], True)), \
             patch.object(validator, "check_mail_host_dns", return_value="No"), \
             patch.object(validator, "smtp_recipient_probe", return_value=("Target accepted; random recipient rejected", "250", "mx.example.test", "Target RCPT 250; random 550")):
            result = validator.check_email("alice@example.test", set())
        self.assertEqual(result["Status"], "Likely Valid")
        self.assertEqual(result["My SMTP Provider"], "Other / Unknown")
        self.assertEqual(result["SMTP Response"].split(" - ", 1)[0], "250")

    def test_temporary_connect_failure_retries(self):
        calls = {"count": 0}
        def factory(**kwargs):
            calls["count"] += 1
            if calls["count"] == 1:
                raise socket.timeout("first try timed out")
            return FakeSMTP()
        with patch.object(validator.smtplib, "SMTP", side_effect=factory), patch.object(validator.time, "sleep"):
            result = validator._smtp_recipient_probe_limited(["mx.example.test"], "alice@example.test")
        self.assertEqual(calls["count"], 2)
        self.assertEqual(result[0], "Target accepted; random recipient rejected")


if __name__ == "__main__":
    unittest.main()
