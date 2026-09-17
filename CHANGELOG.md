# Changelog

## 1.0.0

- Initial public release of `pgpjs-cli`.
- OpenPGP.js 6.3.1 (RFC 9580) for all cryptographic operations.
- Terminal UI: `pgpjs` / `pgpjs --help` print a dark-terminal splash (key icon, examples, footer). Subcommand help and human command output use the same chrome — not a web page.
- JSON envelope `{ ok, version, command, data | error }` with documented exit codes 0–12.
- MCP stdio + optional HTTP, hashed tokens, permission intersection, no private-key export path.
