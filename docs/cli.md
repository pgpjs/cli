# CLI reference

All commands accept the global flags `--json`, `--quiet`, `--verbose`, `--no-color`, `--no-input`, `--config <path>`, `--home <path>`, `--config-format json|any`.

`--json` writes a single JSON document to stdout and nothing else. Diagnostics go to stderr. Non-interactive mode is also entered when `--json`, `--no-input`, `CI=true`, `PGPJS_NON_INTERACTIVE=1`, or stdin is not a TTY.

## Exit codes

| Code | Name | Meaning |
|---:|---|---|
| 0 | OK | Success |
| 1 | GENERIC_ERROR | Unclassified failure |
| 2 | USAGE_ERROR | Bad flags/arguments |
| 3 | CONFIG_ERROR | Config missing or invalid |
| 4 | KEY_ERROR | Key not found, malformed, expired, revoked, ambiguous |
| 5 | CRYPTO_ERROR | Encrypt/decrypt/sign failed |
| 6 | VERIFY_FAILED | Signature invalid or missing |
| 7 | VERIFY_UNTRUSTED | Signature valid, signer unknown/untrusted |
| 8 | PERMISSION_DENIED | Capability or FS permission denied |
| 9 | IO_ERROR | File read/write failure |
| 10 | ENVIRONMENT_ERROR | Unsupported Node or missing runtime |
| 11 | INTERACTION_REQUIRED | Prompt needed in a non-interactive session |
| 12 | SECURITY_FINDINGS | `security scan` failed the threshold |

## Commands

### `pgpjs init`

Detects Next.js (App vs Pages), Nuxt, Remix, Vite, React, Express, Hono, Astro, or plain Node; TypeScript vs JavaScript; npm/pnpm/yarn/bun. Writes `pgpjs.config.ts`, `.env.example`, `.pgpjs/`, and appends `.pgpjs/` to `.gitignore`. `--dry-run` prints the plan.

### `pgpjs install next`

Scaffolds `src/lib/pgpjs/{client,server,keys,encryption}.ts` and an example App Router handler. Installs `openpgp@6.3.1` and `server-only`. Refuses non-Next projects unless `--force`.

### `pgpjs key generate`

`--name`, `--email`, `--algorithm ed25519|rsa3072|rsa4096`, `--expires 30d|1y|2y|never` (default 2y), `--passphrase-file`, `--passphrase-fd`, `--no-passphrase` (explicit, always warns). Also writes a revocation certificate.

### `pgpjs key list|show|export|import|delete|reindex`

Identity is a full fingerprint, 64-bit long key ID, or user ID / email. Short 32-bit key IDs are rejected. Multiple matches → `KEY_AMBIGUOUS`. Private export requires `security.allowPrivateKeyExport`, `--private`, and `--yes` or an interactive confirmation. Private keys are never written to a TTY.

### `pgpjs encrypt [file|-]`

`--recipient` (repeatable, required), `--sign [--key]`, `--armor|--binary`, `--output`, `--force`. Stdin when the path is `-` or omitted and stdin is a pipe. Both a path and a pipe → usage error. Existing outputs are not overwritten without `--force`.

### `pgpjs decrypt [file|-]`

`--key`, `--output`, `--allow-unauthenticated` (dangerous), `--emit-plaintext` (only then does `--json` include plaintext). Embedded filenames are treated as hostile.

### `pgpjs sign [file|-]`

Default **detached**. `--inline`, `--cleartext`. Detached signature goes to `<file>.asc` / `<file>.sig`.

### `pgpjs verify <file>`

`--signature`, `--signer` (pins expected signer; anyone else is invalid). Status: `valid` / `untrusted` / `invalid` / `missing`.

### `pgpjs doctor`

Pass / warn / fail checks. Exit 0 if no fail.

### `pgpjs security scan`

`--fix`, `--fail-on critical|high|medium|low` (default high). Exit 12 when findings meet the threshold. Findings report file and line, never the secret.

### `pgpjs mcp start`

stdio by default. `--http --port --host --allow-remote`. HTTP requires `PGPJS_MCP_TOKEN` and binds 127.0.0.1 unless `--allow-remote`.

### `pgpjs mcp token create|list|revoke|rotate`

Tokens are `pgpjs_mcp_<id>_<secret>_<checksum>`. Only a SHA-256 is stored. The full token is printed once.

### `pgpjs mcp config`

Prints a generic MCP client snippet with the resolved binary path.

### `pgpjs config show`

Effective config plus the origin of each value.

## Passphrases

Precedence: `--passphrase-file` → `--passphrase-fd` → `PGPJS_PASSPHRASE_FILE` → interactive prompt. There is no `--passphrase` flag.
