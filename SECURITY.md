# Security Policy

## Supported versions

| Version | OpenPGP.js | Node | Support |
|---|---|---|---|
| 1.x | **6.3.1** (pinned) | >= 20.10 | current |

The pinned `openpgp` version is part of the security posture. Bumping it is a conscious change, recorded here and in the lockfile.

## Threat model

**In scope**

- Private key theft from disk or logs
- Accidental commit of keys or MCP tokens
- A malicious or confused AI agent with MCP access
- Algorithm downgrade
- Unauthenticated ciphertext
- Wrong-recipient encryption
- 32-bit key-ID collision
- Path traversal via OpenPGP embedded filenames

**Out of scope**

- A compromised host or Node runtime
- A malicious `openpgp` supply chain (mitigated by pinning and npm provenance, not eliminated)
- Side-channel attacks against OpenPGP.js
- Physical access

## Invariants

- Private key material never reaches stdout, stderr, logs, error messages, stack traces, or JSON output except through `pgpjs key export --private` under the documented triple gate.
- There is no `--passphrase` CLI flag. Use `--passphrase-file`, `--passphrase-fd`, or `PGPJS_PASSPHRASE_FILE`.
- No custom cryptography. Primitives come from `openpgp` 6.3.1 or Node `crypto`.
- `Math.random` is banned.
- No telemetry and no network calls except those the user starts (npm install). The CLI runs fully offline.
- Failures fail closed.
- MCP `EXPORT_PRIVATE_KEY` is a hard deny with no code path that returns key material.

JavaScript strings cannot be reliably wiped from memory. Passphrases are held only for the operation; we do not claim otherwise.

## Disclosures

Report vulnerabilities privately via GitHub Security Advisories on [pgpjs/cli](https://github.com/pgpjs/cli/security/advisories/new).

Please do **not** open a public issue for a key-exfiltration or MCP-permission bypass.

We aim to acknowledge reports within 3 business days and to ship a fix for in-scope, exploitable issues as a patch release.

The MCP permission model is the novel part of this design and should be treated as such by reviewers.

## What to do if a private key is exposed

1. Generate a revocation certificate if you do not already have `.pgpjs/revocations/<fp>.rev`.
2. Publish / share the revocation with anyone who had the public key.
3. Generate a new key. Data already encrypted to the old public key stays readable by anyone who has the leaked private key — rotating does not un-compromise old ciphertext.
4. Revoke MCP tokens (`pgpjs mcp token revoke` / `rotate`).
5. Search git history (`pgpjs security scan`) and CI logs. Assume they are public.

## Maintainer of record

PGPJS maintainers via GitHub Security Advisories on this repository.
