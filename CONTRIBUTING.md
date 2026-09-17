# Contributing

## Setup

```bash
git clone https://github.com/pgpjs/cli.git
cd cli
pnpm install
pnpm build
pnpm test
```

Node.js >= 20.10 is required.

## Layout

```
packages/core       @pgpjs/core      crypto wrapper + keystore (no CLI I/O)
packages/config     @pgpjs/config    discovery, Zod, precedence
packages/security   @pgpjs/security  redact, scan, permission intersection
packages/mcp        @pgpjs/mcp       MCP server, tools, tokens
packages/cli        pgpjs-cli        Commander, prompts, renderers
```

Layering (enforced by dependency-cruiser):

```
cli ──▶ mcp ──▶ security ──▶ core ──▶ openpgp
  └──────────────▶ config ◀────────┘
```

`core` must not import `chalk`, `commander`, `ora`, or `@inquirer/*`.

## Rules

- Conventional commits: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`.
- No placeholders, no `TODO` that hides a missing implementation, no custom crypto.
- JSON envelopes, exit codes, and error codes are public API.
- Do not add telemetry.
- Do not add a `--passphrase` flag.
- Tests that capture CLI output must not contain fixture private keys, passphrases, or `pgpjs_mcp_` tokens (see `vitest.setup.ts`).

## PR checklist

- [ ] `pnpm typecheck`
- [ ] `pnpm test`
- [ ] `pnpm lint:boundaries`
- [ ] Docs samples still compile if you changed them
- [ ] SECURITY.md updated if `openpgp` was bumped
