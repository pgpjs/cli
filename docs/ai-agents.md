# AI agents

Use `--json` for every invocation. Do not scrape human output.

```bash
pgpjs encrypt message.txt --recipient alice@example.com --json
```

```json
{
  "ok": true,
  "version": 1,
  "command": "encrypt",
  "data": {
    "operation": "encrypt",
    "output": "message.txt.asc",
    "recipients": ["...fingerprint..."],
    "armored": true
  }
}
```

Errors:

```json
{
  "ok": false,
  "version": 1,
  "command": "encrypt",
  "error": {
    "code": "KEY_NOT_FOUND",
    "message": "No key matches recipient 'alice@example.com'.",
    "details": { "identity": "alice@example.com" },
    "hint": "Run `pgpjs key list` to see available keys."
  }
}
```

`details` never contains key material, passphrases, or tokens.

## Non-interactive

The CLI will not prompt when `--json`, `--no-input`, stdin is not a TTY, `CI=true`, or `PGPJS_NON_INTERACTIVE=1`. Missing input is exit 11 (`NON_INTERACTIVE`) naming the flag that would have supplied it.

Decrypt JSON does **not** include plaintext unless `--emit-plaintext` is passed. Agents and CI logs are the audience for `--json`.

## MCP

Prefer MCP over shelling out when the agent is long-lived. Start with encrypt/verify/list only. Do not enable decrypt unless you accept that plaintext will enter the model context. Never ask the server for a private key — that tool does not exist.

Schemas: `schemas/v1/*.json`.
