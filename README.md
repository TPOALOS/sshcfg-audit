# sshcfg-audit

Audit your `sshd_config` (server) and `~/.ssh/config` (client) for risky settings.
It reads files **offline**: no network access, no changes. For every finding it explains
the problem and gives a recommended value. One file, standard library only.

## Usage

```bash
python3 sshcfg_audit.py                      # /etc/ssh/sshd_config and ~/.ssh/config if present
python3 sshcfg_audit.py /etc/ssh/sshd_config
python3 sshcfg_audit.py ./my_config --type ssh --min-severity MEDIUM
```

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

- Only the global part of `sshd_config` is evaluated; `Match` blocks and `Include`d files are not.
- The first occurrence of a setting wins, as in OpenSSH.
- Defaults assume a recent OpenSSH. Review each recommendation for your environment
  before applying it, and keep a second session open when changing `sshd_config`.

Exit codes: `0` no findings, `1` findings, `2` unreadable or missing file.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
