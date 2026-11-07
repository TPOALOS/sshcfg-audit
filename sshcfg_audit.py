#!/usr/bin/env python3
"""sshcfg-audit - audit sshd_config and ssh client config for risky settings.

Reads configuration files offline (no network, no changes) and explains each
finding with a recommended value. Standard library only.
Exit code 0 = no findings, 1 = findings, 2 = error.

Match blocks are checked too (a Match block can switch password logins or root login back on),
and `Include` files are followed when they live inside the config's own directory.
Defaults are for recent OpenSSH releases.
"""
import argparse
import glob
import json
import os
import re
import shlex
import sys

__version__ = "1.1.0"

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


def _parse(text):
    """Yield (lineno, keyword_lower, value, context, match_condition)."""
    context, cond = "global", ""
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$", line)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip().strip('"')
        if key == "host":
            context, cond = value, ""
            continue
        if key == "match":
            context, cond = "match", value
            continue
        yield no, key, value, context, cond


def parse(text):
    """Yield (lineno, keyword_lower, value, context) for each directive.

    context is 'global', the Host pattern, or 'match' for sshd Match blocks.
    """
    for no, key, value, ctx, _ in _parse(text):
        yield no, key, value, ctx


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


def value_findings(key, val):
    """(severity, label, message, fix) for one sshd directive value; absence checks live elsewhere."""
    out, low = [], val.lower()
    if key == "permitrootlogin" and low == "yes":
        out.append(("HIGH", "PermitRootLogin", "root can log in with a password", "PermitRootLogin prohibit-password (or no)"))
    elif key == "passwordauthentication" and low != "no":
        out.append(("MEDIUM", "PasswordAuthentication", "password logins are enabled", "PasswordAuthentication no (use keys)"))
    elif key in ("permitemptypasswords", "permituserenvironment", "hostbasedauthentication") and low == "yes":
        label = {"permitemptypasswords": "PermitEmptyPasswords", "permituserenvironment": "PermitUserEnvironment",
                 "hostbasedauthentication": "HostbasedAuthentication"}[key]
        out.append(("HIGH", label, "enabled; this weakens authentication", "%s no" % label))
    elif key == "ignorerhosts" and low == "no":
        out.append(("HIGH", "IgnoreRhosts", "rhosts files are honoured", "IgnoreRhosts yes"))
    elif key == "strictmodes" and low == "no":
        out.append(("MEDIUM", "StrictModes", "file permission checks are disabled", "StrictModes yes"))
    elif key == "protocol" and "1" in val.split(","):
        out.append(("HIGH", "Protocol", "SSH protocol 1 is insecure", "Protocol 2"))
    elif key == "x11forwarding" and low == "yes":
        out.append(("LOW", "X11Forwarding", "X11 forwarding enlarges the attack surface", "X11Forwarding no"))
    elif key == "gatewayports" and low in ("yes", "clientspecified"):
        out.append(("MEDIUM", "GatewayPorts", "forwarded ports may be exposed to the network", "GatewayPorts no"))
    elif key == "maxauthtries" and val.isdigit() and int(val) > 6:
        out.append(("MEDIUM", "MaxAuthTries", "many guesses allowed per connection (%s)" % val, "MaxAuthTries 3"))
    elif key == "logingracetime":
        secs = to_seconds(val)
        if secs == 0:
            out.append(("MEDIUM", "LoginGraceTime", "no time limit for authentication", "LoginGraceTime 30"))
        elif secs is not None and secs > 60:
            out.append(("LOW", "LoginGraceTime", "long window for unauthenticated connections (%s)" % val, "LoginGraceTime 30"))
    elif key == "clientaliveinterval" and val == "0":
        out.append(("LOW", "ClientAliveInterval", "idle sessions are never dropped",
                    "ClientAliveInterval 300 and ClientAliveCountMax 2"))
    elif key in ALG_KEYS:
        for sev, tok, why in weak_algorithms(val):
            out.append((sev, ALG_KEYS[key], "%s: %s" % (why, tok), "remove %s from %s" % (tok, ALG_KEYS[key])))
    return out


ALG_KEYS = {"ciphers": "Ciphers", "macs": "MACs", "kexalgorithms": "KexAlgorithms",
            "hostkeyalgorithms": "HostKeyAlgorithms", "pubkeyacceptedalgorithms": "PubkeyAcceptedAlgorithms"}


def audit_sshd(text):
    findings, first = [], {}
    for no, key, value, ctx, cond in _parse(text):
        if ctx == "match":
            # a Match block can undo a hardened global setting, so judge its values on their own
            for sev, label, msg, fix in value_findings(key, value):
                findings.append((sev, no, label, "%s (in Match %s)" % (msg, cond), fix))
            continue
        if key in first:
            continue  # first occurrence wins
        first[key] = (no, value)
    for key, (no, val) in first.items():
        for sev, label, msg, fix in value_findings(key, val):
            findings.append((sev, no, label, msg, fix))
    if "passwordauthentication" not in first:
        findings.append(("LOW", None, "PasswordAuthentication", "not set; the default allows passwords",
                         "PasswordAuthentication no (use keys)"))
    if first.get("clientaliveinterval", (None, None))[1] is None:
        findings.append(("LOW", None, "ClientAliveInterval", "idle sessions are never dropped",
                         "ClientAliveInterval 300 and ClientAliveCountMax 2"))
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


INCLUDE_RE = re.compile(r"(?i)^\s*include\s+(.+?)\s*$")
MAX_INCLUDE_DEPTH = 5


def load_config(path, follow=True, warn=lambda msg: None):
    """Config text with Include files spliced in, plus origins[i] = (file, lineno) for combined line i+1.

    Includes are followed only when they resolve inside the main file's directory (symlinks that leave it
    are refused) so that auditing a copied config never reads unrelated files.
    """
    root = os.path.dirname(os.path.realpath(path))
    lines, origins, seen = [], [], set()

    def visit(p, depth):
        real = os.path.realpath(p)
        if real in seen:
            return
        seen.add(real)
        with open(p, errors="replace") as fh:
            raw_lines = fh.read().splitlines()
        for n, raw in enumerate(raw_lines, 1):
            m = INCLUDE_RE.match(raw) if follow else None
            if not m or raw.lstrip().startswith("#"):
                lines.append(raw)
                origins.append((p, n))
                continue
            try:
                patterns = shlex.split(m.group(1))
            except ValueError:
                patterns = m.group(1).split()
            for pat in patterns:
                pat = os.path.expanduser(pat)
                target = pat if os.path.isabs(pat) else os.path.join(root, pat)
                hits = sorted(glob.glob(target))
                if not hits:
                    warn("%s:%d: Include %s matched no files" % (p, n, pat))
                for hit in hits:
                    real_hit = os.path.realpath(hit)
                    if not os.path.isfile(real_hit):
                        continue
                    if not (real_hit == root or real_hit.startswith(root + os.sep)):
                        warn("%s:%d: not following %s: outside %s" % (p, n, hit, root))
                    elif depth >= MAX_INCLUDE_DEPTH:
                        warn("%s:%d: includes nested too deeply" % (p, n))
                    else:
                        visit(hit, depth + 1)

    visit(path, 0)
    return "\n".join(lines), origins


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit sshd_config / ssh client config (read-only).")
    ap.add_argument("files", nargs="*", help="config files (default: /etc/ssh/sshd_config, ~/.ssh/config)")
    ap.add_argument("--type", choices=("sshd", "ssh"), help="force file type (default: guess from name)")
    ap.add_argument("--min-severity", choices=("LOW", "MEDIUM", "HIGH"), default="LOW")
    ap.add_argument("--no-follow", action="store_true", help="do not follow Include lines")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    files = args.files or [p for p in ("/etc/ssh/sshd_config", os.path.expanduser("~/.ssh/config"))
                           if os.path.isfile(p)]
    if not files:
        print("sshcfg-audit: no config files given or found", file=sys.stderr)
        return 2
    limit = SEV_ORDER[args.min_severity]
    results = []
    for path in files:
        try:
            text, origins = load_config(path, not args.no_follow, lambda m: print("sshcfg-audit: warning: %s" % m, file=sys.stderr))
        except OSError as exc:
            print("sshcfg-audit: %s" % exc, file=sys.stderr)
            return 2
        kind = args.type or ("sshd" if "sshd" in os.path.basename(path) else "ssh")
        found = []
        for sev, no, key, msg, fix in audit(text, kind):
            if SEV_ORDER[sev] > limit:
                continue
            src, line = origins[no - 1] if no and no <= len(origins) else (path, no)
            found.append({"severity": sev, "key": key, "file": src, "line": line, "message": msg, "fix": fix})
        results.append({"path": path, "type": kind, "findings": found})
    count = sum(len(r["findings"]) for r in results)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print("== %s (%s)" % (r["path"], r["type"]))
            for f in r["findings"]:
                where = ""
                if f["line"]:
                    where = ":%d" % f["line"] if f["file"] == r["path"] else " (%s:%d)" % (f["file"], f["line"])
                print("%-6s %s%s: %s\n         fix: %s" % (f["severity"], f["key"], where, f["message"], f["fix"]))
    print("sshcfg-audit: %d finding(s)" % count, file=sys.stderr)
    return 1 if count else 0

if __name__ == "__main__":
    sys.exit(main())
