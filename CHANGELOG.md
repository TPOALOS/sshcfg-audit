# Changelog

## 1.1.0

- `Match` blocks are now audited (they can switch password or root login back on)
- `Include` files are followed (contained to the config directory, symlink and cycle safe); `--no-follow`
- `--json` output; findings from included files name their source file
- Installable with pip (`sshcfg-audit` command), CI on Linux and macOS

## 1.0.0

Initial release.
