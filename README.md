# sshcfg-audit

Audit your `sshd_config` (server) and `~/.ssh/config` (client) for risky settings.
It reads files **offline**: no network access, no changes. For every finding it explains
the problem and gives a recommended value. One file, standard library only.

## Usage

```bash
python3 sshcfg_audit.py                      # /etc/ssh/sshd_config and ~/.ssh/config if present
python3 sshcfg_audit.py /etc/ssh/sshd_config
python3 sshcfg_audit.py ./my_config --type ssh --min-severity MEDIUM
python3 sshcfg_audit.py /etc/ssh/sshd_config --json
# or: pip install git+https://github.com/TPOALOS/sshcfg-audit && sshcfg-audit /etc/ssh/sshd_config
```

On Debian/Ubuntu `sshd_config` starts with `Include /etc/ssh/sshd_config.d/*.conf`, and a file there can silently re-enable
password logins. Those files are audited too, and each finding names the file it came from.

The file type is guessed from the name (`sshd` in the file name means server config);
use `--type sshd|ssh` to force it.

Example output on a sample server config:

```
HIGH   PermitRootLogin:1: root can log in with a password
         fix: PermitRootLogin prohibit-password (or no)
HIGH   Ciphers:4: weak or CBC cipher: 3des-cbc
         fix: remove 3des-cbc from Ciphers
MEDIUM PasswordAuthentication:2: password logins are enabled
         fix: PasswordAuthentication no (use keys)
MEDIUM MaxAuthTries:3: many guesses allowed per connection (10)
         fix: MaxAuthTries 3
```

## Checks

**Server (`sshd_config`):** `PermitRootLogin yes`, password authentication,
empty passwords, `PermitUserEnvironment`, host-based auth, `IgnoreRhosts no`,
`StrictModes no`, protocol 1, X11 forwarding, `GatewayPorts`, high `MaxAuthTries`,
long or unlimited `LoginGraceTime`, missing `ClientAliveInterval`, and weak
ciphers, MACs, key exchange and host key algorithms (3DES, CBC, arcfour, MD5/SHA-1 MACs, DSA, group1).

**Client (`ssh_config`):** `StrictHostKeyChecking no`, `UserKnownHostsFile /dev/null`,
`ForwardAgent yes` (more severe under `Host *`), X11 forwarding, `HashKnownHosts no`,
`CheckHostIP no`, and weak algorithms.

## Limits

- `Match` blocks are judged on their own values: a `Match` block that turns a risky setting on is reported with its
  condition, one that only hardens is not. Whether a `Match` condition ever applies to a real connection is not evaluated.
- `Include` lines are followed (glob patterns, nested up to 5 levels) when the file lives inside the config's own
  directory; anything outside it, including symlinks that leave it, is refused with a warning. `--no-follow` turns this off.
- The first occurrence of a setting wins, as in OpenSSH, including across included files.
- Defaults assume a recent OpenSSH. Review each recommendation for your environment
  before applying it, and keep a second session open when changing `sshd_config`.

Exit codes: `0` no findings, `1` findings, `2` unreadable or missing file.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
