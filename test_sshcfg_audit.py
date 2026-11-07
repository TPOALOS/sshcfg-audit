import contextlib
import io
import json
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

    def test_match_block_risky_value_is_flagged_with_its_condition(self):
        text = GOOD_SSHD + "Match User backup\n  PermitEmptyPasswords yes\n"
        found = sca.audit(text, "sshd")
        self.assertEqual([(f[0], f[2]) for f in found], [("HIGH", "PermitEmptyPasswords")])
        self.assertIn("(in Match User backup)", found[0][3])
        self.assertEqual(found[0][1], 9)

    def test_match_block_restrictive_value_is_not_flagged(self):
        text = GOOD_SSHD + "Match Address 10.0.0.0/8\n  PasswordAuthentication no\n  X11Forwarding no\n"
        self.assertEqual(keys(text), set())

    def test_match_can_reenable_password_logins(self):
        text = GOOD_SSHD + "Match Address 192.0.2.0/24\n  PasswordAuthentication yes\n"
        self.assertEqual(keys(text), {("MEDIUM", "PasswordAuthentication")})

    def test_match_does_not_affect_global_first_wins(self):
        text = "PasswordAuthentication no\nMatch User x\n  PasswordAuthentication yes\n"
        self.assertEqual({f[1] for f in sca.audit(text, "sshd") if f[2] == "PasswordAuthentication"}, {3})

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


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = sca.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class IncludeTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = self._t.name
        self.main_cfg = write(os.path.join(self.d, "sshd_config"),
                              "Include sshd_config.d/*.conf\n" + GOOD_SSHD)

    def tearDown(self):
        self._t.cleanup()

    def test_included_file_is_audited_and_attributed(self):
        write(os.path.join(self.d, "sshd_config.d", "50-cloud.conf"), "PasswordAuthentication yes\n")
        code, out, _ = run_main(self.main_cfg, "--json")
        data = json.loads(out)[0]["findings"]
        self.assertEqual(code, 1)
        self.assertEqual([(f["key"], os.path.basename(f["file"]), f["line"]) for f in data],
                         [("PasswordAuthentication", "50-cloud.conf", 1)])

    def test_first_occurrence_wins_across_includes(self):
        # the include sits first, so its PasswordAuthentication yes wins over the hardened line below it
        write(os.path.join(self.d, "sshd_config.d", "a.conf"), "PasswordAuthentication yes\n")
        self.assertEqual(run_main(self.main_cfg)[0], 1)
        # the other way round: main file says no first, the include is ignored by sshd
        write(self.main_cfg, GOOD_SSHD + "Include sshd_config.d/*.conf\n")
        self.assertEqual(run_main(self.main_cfg)[0], 0)

    def test_no_follow_ignores_includes(self):
        write(os.path.join(self.d, "sshd_config.d", "a.conf"), "PermitRootLogin yes\n")
        self.assertEqual(run_main(self.main_cfg, "--no-follow")[0], 0)
        self.assertEqual(run_main(self.main_cfg)[0], 1)

    def test_text_output_names_the_included_file(self):
        write(os.path.join(self.d, "sshd_config.d", "a.conf"), "PermitRootLogin yes\n")
        _, out, _ = run_main(self.main_cfg)
        self.assertIn("PermitRootLogin (", out)
        self.assertIn("a.conf:1)", out)

    def test_include_outside_directory_refused(self):
        with tempfile.TemporaryDirectory() as other:
            write(os.path.join(other, "evil.conf"), "PermitRootLogin yes\n")
            cfg = write(os.path.join(self.d, "sub", "sshd_config"), "Include %s\n" % os.path.join(other, "evil.conf") + GOOD_SSHD)
            warnings = []
            text, _ = sca.load_config(cfg, True, warnings.append)
            self.assertNotIn("PermitRootLogin yes", text)
            self.assertTrue(any("outside" in w for w in warnings))

    def test_symlink_escape_refused(self):
        with tempfile.TemporaryDirectory() as other:
            target = write(os.path.join(other, "evil.conf"), "PermitRootLogin yes\n")
            os.makedirs(os.path.join(self.d, "sub", "conf.d"))
            os.symlink(target, os.path.join(self.d, "sub", "conf.d", "x.conf"))
            cfg = write(os.path.join(self.d, "sub", "sshd_config"), "Include conf.d/*.conf\n" + GOOD_SSHD)
            text, _ = sca.load_config(cfg)
            self.assertNotIn("PermitRootLogin yes", text)

    def test_include_cycle_terminates(self):
        write(os.path.join(self.d, "a"), "Include b\nMaxAuthTries 3\n")
        write(os.path.join(self.d, "b"), "Include a\nX11Forwarding no\n")
        text, _ = sca.load_config(os.path.join(self.d, "a"))
        self.assertEqual(text.count("MaxAuthTries"), 1)

    def test_commented_include_not_followed(self):
        write(os.path.join(self.d, "sshd_config.d", "a.conf"), "PermitRootLogin yes\n")
        write(self.main_cfg, "# Include sshd_config.d/*.conf\n" + GOOD_SSHD)
        self.assertEqual(run_main(self.main_cfg)[0], 0)

    def test_missing_include_warns_but_does_not_fail(self):
        write(self.main_cfg, "Include nothing/*.conf\n" + GOOD_SSHD)
        code, _, err = run_main(self.main_cfg)
        self.assertEqual(code, 0)
        self.assertIn("matched no files", err)

    def test_client_config_includes_work_too(self):
        cfg = write(os.path.join(self.d, "config"), "Include config.d/*\n")
        write(os.path.join(self.d, "config.d", "work"), "Host *\n  ForwardAgent yes\n")
        data = json.loads(run_main(cfg, "--json")[1])[0]["findings"]
        self.assertEqual([f["key"] for f in data], ["ForwardAgent"])


class JsonTests(unittest.TestCase):
    def test_json_structure_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            p = write(os.path.join(d, "sshd_config"), "PermitRootLogin yes\n" + GOOD_SSHD)
            code, out, _ = run_main(p, "--json")
        data = json.loads(out)
        self.assertEqual((code, data[0]["type"]), (1, "sshd"))
        f = data[0]["findings"][0]
        self.assertEqual(set(f), {"severity", "key", "file", "line", "message", "fix"})
        self.assertEqual((f["severity"], f["line"]), ("HIGH", 1))

    def test_min_severity_applies(self):
        with tempfile.TemporaryDirectory() as d:
            p = write(os.path.join(d, "sshd_config"), "X11Forwarding yes\n" + GOOD_SSHD.replace("X11Forwarding no\n", ""))
            self.assertEqual(run_main(p, "--min-severity", "MEDIUM")[0], 0)
            self.assertEqual(run_main(p)[0], 1)


if __name__ == "__main__":
    unittest.main()
