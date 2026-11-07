import os
import tempfile
import unittest

import sshcfg_audit as sca


def keys(text, kind="sshd"):
    return {(f[0], f[2]) for f in sca.audit(text, kind)}


GOOD_SSHD = """PermitRootLogin prohibit-password
PasswordAuthentication no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
"""


class SshdTests(unittest.TestCase):
    def test_good_config_clean(self):
        self.assertEqual(keys(GOOD_SSHD), set())

    def test_root_login_and_passwords(self):
        k = keys("PermitRootLogin yes\nPasswordAuthentication yes\n")
        self.assertIn(("HIGH", "PermitRootLogin"), k)
        self.assertIn(("MEDIUM", "PasswordAuthentication"), k)

    def test_unset_password_auth_is_low(self):
        self.assertIn(("LOW", "PasswordAuthentication"), keys("PermitRootLogin no\n"))

    def test_first_occurrence_wins(self):
        self.assertNotIn(("HIGH", "PermitRootLogin"), keys("PermitRootLogin no\nPermitRootLogin yes\n"))

    def test_match_block_ignored(self):
        text = GOOD_SSHD + "Match User backup\n  PermitEmptyPasswords yes\n"
        self.assertEqual(keys(text), set())

    def test_equals_syntax_and_case(self):
        self.assertIn(("HIGH", "PermitEmptyPasswords"), keys("permitemptypasswords=yes\n"))

    def test_numbers(self):
        k = keys("MaxAuthTries 10\nLoginGraceTime 2m\n")
        self.assertIn(("MEDIUM", "MaxAuthTries"), k)
        self.assertIn(("LOW", "LoginGraceTime"), k)
        self.assertIn(("MEDIUM", "LoginGraceTime"), keys("LoginGraceTime 0\n"))

    def test_weak_algorithms(self):
        k = keys("Ciphers aes128-ctr,3des-cbc\nMACs hmac-sha1,hmac-md5\nKexAlgorithms diffie-hellman-group1-sha1\n")
        self.assertIn(("HIGH", "Ciphers"), k)
        self.assertIn(("MEDIUM", "MACs"), k)
        self.assertIn(("HIGH", "MACs"), k)
        self.assertIn(("HIGH", "KexAlgorithms"), k)

    def test_removal_list_not_flagged(self):
        self.assertNotIn(("HIGH", "Ciphers"), keys("Ciphers -3des-cbc\n"))

    def test_comments_ignored(self):
        self.assertNotIn(("HIGH", "PermitRootLogin"), keys("# PermitRootLogin yes\n"))


class ClientTests(unittest.TestCase):
    def test_client_findings(self):
        text = "Host *\n  ForwardAgent yes\n  StrictHostKeyChecking no\n" \
               "Host dev\n  UserKnownHostsFile /dev/null\n  ForwardAgent yes\n"
        k = [(f[0], f[2]) for f in sca.audit(text, "ssh")]
        self.assertIn(("HIGH", "StrictHostKeyChecking"), k)
        self.assertIn(("MEDIUM", "ForwardAgent"), k)
        self.assertIn(("LOW", "ForwardAgent"), k)
        self.assertIn(("MEDIUM", "UserKnownHostsFile"), k)

    def test_good_client_clean(self):
        self.assertEqual(keys("Host *\n  StrictHostKeyChecking accept-new\n  HashKnownHosts yes\n", "ssh"), set())

    def test_accept_new_ok(self):
        self.assertEqual(keys("StrictHostKeyChecking accept-new\n", "ssh"), set())


class CliTests(unittest.TestCase):
    def test_exit_codes_and_type_guess(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "sshd_config")
            bad = os.path.join(d, "sshd_config_bad")
            with open(good, "w") as fh:
                fh.write(GOOD_SSHD)
            with open(bad, "w") as fh:
                fh.write("PermitRootLogin yes\n")
            self.assertEqual(sca.main([good]), 0)
            self.assertEqual(sca.main([bad]), 1)
            self.assertEqual(sca.main([bad, "--min-severity", "HIGH"]), 1)
            self.assertEqual(sca.main([os.path.join(d, "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
