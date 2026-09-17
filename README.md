# PGPJS CLI

**OpenPGP encryption toolkit** for modern JavaScript and TypeScript developers.

Install once, then initialize a Next.js or Node.js project, manage OpenPGP keys, encrypt and sign data, and expose a least-privilege MCP server to AI agents.

```bash
npm install -g pgpjs-cli

cd my-next-app
pgpjs init
pgpjs install next
pgpjs doctor
```

Cryptography is **OpenPGP.js v6.3.1** (RFC 9580). This CLI does not invent algorithms, does not talk to the network, and does not ship telemetry.

## What this is

`pgpjs` is `npm` + OpenPGP + a developer SDK + an MCP interface.

It is **not** a GnuPG replacement. There is no keyserver, WKD, Web-of-Trust, smartcard, key escrow, or cloud sync in v1. It encrypts data; it does not broker access to it.

## Packages

| Package | Role |
|---|---|
| `pgpjs-cli` | The `pgpjs` binary |
| `@pgpjs/core` | Typed OpenPGP.js wrapper, keystore, errors |
| `@pgpjs/config` | Config discovery and Zod schemas |
| `@pgpjs/security` | Redaction, `security scan`, MCP permission intersection |
| `@pgpjs/mcp` | MCP server, tools, hashed token store |

## Quickstart

```bash
pgpjs init
pgpjs key generate --name "Alice" --email alice@example.com --passphrase-file ./pass.txt
pgpjs encrypt message.txt --recipient alice@example.com --armor --output message.asc
pgpjs decrypt message.asc --output message.txt
pgpjs sign message.txt --detached
pgpjs verify message.txt --signature message.txt.asc
```

Machine-readable mode (CI and agents):

```bash
pgpjs key list --json
```

```json
{
  "ok": true,
  "version": 1,
  "command": "key.list",
  "data": {
    "keys": []
  }
}
```

## Commands

```
pgpjs <command> [options]

Commands:
  init          Initialize PGPJS in a project
  install       Install PGPJS integrations (next, node)
  key           Manage OpenPGP keys
  encrypt       Encrypt data
  decrypt       Decrypt data
  sign          Sign data (detached by default)
  verify        Verify signatures
  doctor        Diagnose project configuration
  security      Security checks
  mcp           Run and configure MCP
  config        Show effective configuration
  version       Show version

Options:
  --json        Machine-readable output
  --quiet       Minimal output
  --verbose     Verbose output
  --no-color    Disable colour
  --no-input    Never prompt
  --help        Show help
```

## Next.js

```bash
pgpjs install next
```

Generates `src/lib/pgpjs/{client,server,keys,encryption}.ts` with a hard client/server split. Private keys stay on the server. See [docs/nextjs.md](docs/nextjs.md).

## MCP / AI agents

```bash
pgpjs mcp start
pgpjs mcp token create --name "Development Agent" --scope encrypt --scope verify
pgpjs mcp config
```

Private-key export is **not implementable** over MCP. Decrypt and sign are off by default. Effective permission is `config ∩ token.scopes`. See [docs/mcp.md](docs/mcp.md) and [docs/ai-agents.md](docs/ai-agents.md).

## Security defaults

- Curve25519 (Ed25519 + X25519) keys, 2-year expiry
- Passphrase-protected private keys (Argon2id S2K via OpenPGP.js)
- No `--passphrase` flag (it would leak in `ps`, shell history, and CI logs)
- Private keys never printed unless `key export --private` is explicitly allowed
- `.pgpjs/` gitignored at init
- `pgpjs security scan` is a CI gate (exit 12)

See [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

## Requirements

- Node.js **>= 20.10**
- macOS, Linux, or Windows

## License

Apache-2.0
