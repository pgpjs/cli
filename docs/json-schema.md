# JSON schema

Every `--json` response is one of:

```json
{ "ok": true,  "version": 1, "command": "key.list", "data": { } }
{ "ok": false, "version": 1, "command": "encrypt",  "error": {
    "code": "KEY_NOT_FOUND",
    "message": "...",
    "details": {},
    "hint": "..."
} }
```

`version` is an integer and bumps only on a breaking schema change.

Canonical schemas: [`schemas/v1/`](../schemas/v1/).

`ok`, not `success`. `details` must not contain key material, passphrases, or tokens.
