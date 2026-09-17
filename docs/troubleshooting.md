# Troubleshooting

| Symptom | Fix |
|---|---|
| `NODE_VERSION_UNSUPPORTED` (exit 10) | Use Node >= 20.10 |
| `NON_INTERACTIVE` (exit 11) | Pass the named flag (`--name`, `--yes`, `--passphrase-file`, …) |
| `KEY_AMBIGUOUS` | Use the full fingerprint from `pgpjs key list` |
| `KEYSTORE_LOCKED` | Another `pgpjs` process holds `.pgpjs/.lock` |
| MCP client cannot find `pgpjs` | Use `pgpjs mcp config` (absolute path) instead of a bare `pgpjs` |
| Colour / spinners in CI | `NO_COLOR=1`; non-TTY disables them automatically |
| Decrypt JSON has no plaintext | Pass `--emit-plaintext` (off by default on purpose) |
| Next.js client bundle error | Import `@/lib/pgpjs/client`, never `server.ts` |
| `OUTPUT_EXISTS` | Pass `--force` |

`pgpjs doctor --json` and `pgpjs config show --json` are the first things to run.
