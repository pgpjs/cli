# MCP

The CLI exposes a Model Context Protocol server so an AI agent can encrypt, verify, list keys, and run a security scan **without** unrestricted private-key access.

## Start

```bash
pgpjs mcp start          # stdio (default)
pgpjs mcp start --http --port 8787
```

stdio trusts local file permissions plus `.pgpjs/mcp.config.json`. HTTP **requires** a bearer token (`PGPJS_MCP_TOKEN`) and binds `127.0.0.1` unless `--allow-remote` is set (print a warning; put TLS in front).

## Client config

```bash
pgpjs mcp config
```

```json
{
  "mcpServers": {
    "pgpjs": {
      "command": "/absolute/path/to/pgpjs",
      "args": ["mcp", "start"]
    }
  }
}
```

No provider-specific keys are hard-coded. Point any MCP-compatible client at that snippet.

## Permissions

`.pgpjs/mcp.config.json` defaults:

```json
{
  "version": 1,
  "permissions": {
    "readKeys": true,
    "encrypt": true,
    "verify": true,
    "exportPublicKey": true,
    "securityScan": true,
    "decrypt": false,
    "sign": false,
    "generateKeys": false,
    "exportPrivateKeys": false
  },
  "allowedKeys": [],
  "requireConfirmation": ["decrypt", "sign"],
  "audit": { "enabled": true, "path": ".pgpjs/audit.log" }
}
```

`effective = config.permissions ∩ token.scopes`. A token cannot grant what config denies; a permissive config cannot widen a narrow token.

**Private-key export is not implemented over MCP.** There is no tool and no code path. `exportPrivateKeys: true` is still reported by `security scan` and still denied.

## Tools

| Tool | Capability | Risk |
|---|---|---|
| `pgpjs_key_list` | READ_KEYS | Public metadata only |
| `pgpjs_key_info` | READ_KEYS | Fingerprint, UIDs, algo, expiry |
| `pgpjs_encrypt` | ENCRYPT | Echoes resolved recipient fingerprints |
| `pgpjs_verify` | VERIFY | `valid` / `untrusted` / `invalid` |
| `pgpjs_sign` | SIGN | Off by default |
| `pgpjs_decrypt` | DECRYPT | Off by default; returns plaintext to the agent |
| `pgpjs_key_generate` | GENERATE_KEYS | Off by default (state mutation) |
| `pgpjs_export_public_key` | EXPORT_PUBLIC_KEY | Armored public key |
| `pgpjs_security_scan` | SECURITY_SCAN | Redacted findings |

When `allowedKeys` is non-empty, recipients outside it are denied. Encrypt responses always echo the fingerprint actually used.

Rate limits: 60 ops/min/token, 10 key generations/hour.

## Tokens

```bash
pgpjs mcp token create --name "Claude" --scope encrypt --scope verify --expires 30d
pgpjs mcp token list
pgpjs mcp token revoke <id>
pgpjs mcp token rotate <id>
```

Format: `pgpjs_mcp_<8-char id>_<43-char secret>_<4-char checksum>`. Only `sha256(token)` is stored. The full token is printed once. Comparison is constant-time.

## Audit

Append-only JSONL at `.pgpjs/audit.log`: timestamp, token id, tool, allow/deny, reason, fingerprints, byte counts. No plaintext, ciphertext, key material, or token secret. `pgpjs mcp audit --json`.
