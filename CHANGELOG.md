# Changelog

## 1.0.0

- Initial public release of `pgpjs-cli`.
- OpenPGP.js 6.3.1 (RFC 9580) for all cryptographic operations.
- Terminal UI: grouped Core / Developer / AI·MCP commands. `token` is top-level (`pgpjs token create|list|revoke|rotate`). `pgpjs mcp start|status|config`. `pgpjs install react` and `pgpjs install node` (loopback network).
- Global flags (`--json`, `--no-input`, `--no-color`, …) work after the subcommand (`pgpjs key list --json`).
- Node network scaffold uses explicit `.ts` imports so `node --experimental-strip-types src/lib/pgpjs/http.ts` runs.
- JSON envelope `{ ok, version, command, data | error }` with documented exit codes 0–12.
- MCP stdio + optional HTTP, hashed tokens, permission intersection, no private-key export path.
