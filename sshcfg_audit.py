#!/usr/bin/env python3
"""sshcfg-audit - audit sshd_config and ssh client config for risky settings.

Reads configuration files offline (no network, no changes) and explains each
finding with a recommended value. Standard library only.
Exit code 0 = no findings, 1 = findings, 2 = error.

Note: only the global section of sshd_config is evaluated; settings inside
`Match` blocks are ignored. Defaults are for recent OpenSSH releases.
"""
import argparse
import os
import re
import sys

__version__ = "1.0.0"

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
WEAK_ALGS = (
    (re.compile(r"(?i)^(3des-cbc|arcfour\w*|blowfish-cbc|cast128-cbc|aes\d+-cbc|rijndael-cbc@lysator\.liu\.se)$"),
     "HIGH", "weak or CBC cipher"),
    (re.compile(r"(?i)^(hmac-md5\w*(-etm@openssh\.com)?|umac-64(-etm)?@openssh\.com|hmac-ripemd160\S*)$"),
     "HIGH", "weak MAC"),
    (re.compile(r"(?i)^hmac-sha1(-etm@openssh\.com)?$"), "MEDIUM", "SHA-1 based MAC"),
    (re.compile(r"(?i)^(diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1)$"),
     "HIGH", "weak key exchange"),
    (re.compile(r"(?i)^diffie-hellman-group14-sha1$"), "MEDIUM", "SHA-1 key exchange"),
    (re.compile(r"(?i)^ssh-dss$"), "HIGH", "DSA algorithm"),
)


def parse(text):
    """Yield (lineno, keyword_lower, value, context) for each directive.

    context is 'global', the Host pattern, or 'match' for sshd Match blocks.
    """
    context = "global"
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$", line)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip().strip('"')
        if key == "host":
            context = value
            continue
        if key == "match":
            context = "match"
            continue
        yield no, key, value, context


def to_seconds(value):
    m = re.match(r"^(\d+)([smhdw]?)$", value.strip().lower())
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]


def weak_algorithms(value):
    if value[:1] == "-":  # removal list
        return []
    out = []
    for tok in value.lstrip("+^").split(","):
        tok = tok.strip()
        for rx, sev, why in WEAK_ALGS:
            if rx.match(tok):
                out.append((sev, tok, why))
    return out


def audit_sshd(text):
    findings, first = [], {}
    for no, key, value, ctx in parse(text):
        if ctx == "match" or key in first:
            continue  # first occurrence wins; Match blocks not evaluated
        first[key] = (no, value)
    v = lambda k: first.get(k, (None, None))
    add = lambda sev, no, key, msg, fix: findings.append((sev, no, key, msg, fix))

    no, val = v("permitrootlogin")
    if val and val.lower() == "yes":
        add("HIGH", no, "PermitRootLogin", "root can log in with a password", "PermitRootLogin prohibit-password (or no)")
    no, val = v("passwordauthentication")
    if val is None:
        add("LOW", None, "PasswordAuthentication", "not set; the default allows passwords", "PasswordAuthentication no (use keys)")
    elif val.lower() != "no":
        add("MEDIUM", no, "PasswordAuthentication", "password logins are enabled", "PasswordAuthentication no (use keys)")
    for key, label, fix in (("permitemptypasswords", "PermitEmptyPasswords", "PermitEmptyPasswords no"),
                            ("permituserenvironment", "PermitUserEnvironment", "PermitUserEnvironment no"),
                            ("hostbasedauthentication", "HostbasedAuthentication", "HostbasedAuthentication no")):
        no, val = v(key)
        if val and val.lower() == "yes":
            add("HIGH", no, label, "enabled; this weakens authentication", fix)
    no, val = v("ignorerhosts")
    if val and val.lower() == "no":
        add("HIGH", no, "IgnoreRhosts", "rhosts files are honoured", "IgnoreRhosts yes")
    no, val = v("strictmodes")
    if val and val.lower() == "no":
        add("MEDIUM", no, "StrictModes", "file permission checks are disabled", "StrictModes yes")
    no, val = v("protocol")
    if val and "1" in val.split(","):
        add("HIGH", no, "Protocol", "SSH protocol 1 is insecure", "Protocol 2")
    no, val = v("x11forwarding")
    if val and val.lower() == "yes":
        add("LOW", no, "X11Forwarding", "X11 forwarding enlarges the attack surface", "X11Forwarding no")
    no, val = v("gatewayports")
    if val and val.lower() in ("yes", "clientspecified"):
        add("MEDIUM", no, "GatewayPorts", "forwarded ports may be exposed to the network", "GatewayPorts no")
    no, val = v("maxauthtries")
    if val and val.isdigit() and int(val) > 6:
        add("MEDIUM", no, "MaxAuthTries", "many guesses allowed per connection (%s)" % val, "MaxAuthTries 3")
    no, val = v("logingracetime")
    if val is not None:
        secs = to_seconds(val)
        if secs == 0:
            add("MEDIUM", no, "LoginGraceTime", "no time limit for authentication", "LoginGraceTime 30")
        elif secs is not None and secs > 60:
            add("LOW", no, "LoginGraceTime", "long window for unauthenticated connections (%s)" % val, "LoginGraceTime 30")
    no, val = v("clientaliveinterval")
    if val is None or val == "0":
        add("LOW", no, "ClientAliveInterval", "idle sessions are never dropped", "ClientAliveInterval 300 and ClientAliveCountMax 2")
    for key, label in (("ciphers", "Ciphers"), ("macs", "MACs"), ("kexalgorithms", "KexAlgorithms"),
                       ("hostkeyalgorithms", "HostKeyAlgorithms"), ("pubkeyacceptedalgorithms", "PubkeyAcceptedAlgorithms")):
        no, val = v(key)
        if val:
            for sev, tok, why in weak_algorithms(val):
                add(sev, no, label, "%s: %s" % (why, tok), "remove %s from %s" % (tok, label))
    return findings


def audit_ssh_client(text):
    findings = []
    add = lambda sev, no, key, msg, fix: findings.append((sev, no, key, msg, fix))
    for no, key, value, ctx in parse(text):
        where = "" if ctx == "global" else " (Host %s)" % ctx
        broad = ctx in ("global", "*")
        val = value.lower()
        if key == "stricthostkeychecking" and val in ("no", "off"):
            add("HIGH", no, "StrictHostKeyChecking", "host keys are not verified%s" % where, "StrictHostKeyChecking accept-new (or yes)")
        elif key == "userknownhostsfile" and value == "/dev/null":
            add("MEDIUM", no, "UserKnownHostsFile", "known hosts are discarded%s" % where, "remove this line")
        elif key == "forwardagent" and val == "yes":
            add("MEDIUM" if broad else "LOW", no, "ForwardAgent",
                "agent forwarding%s lets the remote host use your keys" % where, "ForwardAgent no; use ProxyJump instead")
        elif key in ("forwardx11", "forwardx11trusted") and val == "yes":
            add("MEDIUM", no, key, "X11 forwarding enabled%s" % where, "ForwardX11 no")
        elif key == "hashknownhosts" and val == "no":
            add("LOW", no, "HashKnownHosts", "host names in known_hosts are readable", "HashKnownHosts yes")
        elif key == "checkhostip" and val == "no":
            add("LOW", no, "CheckHostIP", "IP address checks disabled%s" % where, "CheckHostIP yes")
        elif key in ("ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"):
            for sev, tok, why in weak_algorithms(value):
                add(sev, no, key, "%s: %s%s" % (why, tok, where), "remove %s" % tok)
    return findings


def audit(text, kind):
    f = audit_sshd(text) if kind == "sshd" else audit_ssh_client(text)
    return sorted(f, key=lambda x: (SEV_ORDER[x[0]], x[1] or 0))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit sshd_config / ssh client config (read-only).")
    ap.add_argument("files", nargs="*", help="config files (default: /etc/ssh/sshd_config, ~/.ssh/config)")
    ap.add_argument("--type", choices=("sshd", "ssh"), help="force file type (default: guess from name)")
    ap.add_argument("--min-severity", choices=("LOW", "MEDIUM", "HIGH"), default="LOW")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    files = args.files or [p for p in ("/etc/ssh/sshd_config", os.path.expanduser("~/.ssh/config"))
                           if os.path.isfile(p)]
    if not files:
        print("sshcfg-audit: no config files given or found", file=sys.stderr)
        return 2
    limit = SEV_ORDER[args.min_severity]
    count = 0
    for path in files:
        try:
            with open(path, errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("sshcfg-audit: %s" % exc, file=sys.stderr)
            return 2
        kind = args.type or ("sshd" if "sshd" in os.path.basename(path) else "ssh")
        print("== %s (%s)" % (path, kind))
        for sev, no, key, msg, fix in audit(text, kind):
            if SEV_ORDER[sev] > limit:
                continue
            count += 1
            print("%-6s %s%s: %s\n         fix: %s" % (sev, key, ":%d" % no if no else "", msg, fix))
    print("sshcfg-audit: %d finding(s)" % count, file=sys.stderr)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
