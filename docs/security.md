# Security guide

Pinned library: **openpgp@6.3.1**.

## Key hygiene

- Default algorithm: Ed25519 (sign) / X25519 (encrypt). RSA 3072/4096 is for interop.
- Default expiry: 2 years. `never` is explicit.
- A revocation certificate is written at generation. Back it up off-machine.
- Private keys live in `.pgpjs/keys/<prefix>.sec.asc` mode 0600, encrypted with OpenPGP S2K.
- Short key IDs are rejected.

## Passphrases

Never on argv, never in `PGPJS_PASSPHRASE`, never in config. File or fd only.

## `pgpjs security scan`

Critical: private key blocks in tracked files, MCP tokens outside `tokens.json`, `.pgpjs/` not gitignored, keys in git history, `NEXT_PUBLIC_*` key-shaped values, client imports of server modules.

High: wrong permissions, unencrypted private keys, MCP decrypt/sign enabled.

`--fix` only appends gitignore entries and tightens file modes. `--fail-on high` (default) exits 12.

## Client/server boundary

`@pgpjs/core/server` starts with `import "server-only"`. `@pgpjs/core/client` cannot load the keystore. Generated Next.js `server.ts` throws if `typeof window !== "undefined"`.

## If a key leaks

Revoke, notify, rotate. Ciphertext already produced for that public key remains readable to the thief. See SECURITY.md.
