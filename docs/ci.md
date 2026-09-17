# CI/CD

The CLI is non-interactive in CI (`CI=true`). `NO_COLOR` keeps logs clean. Never `echo` a private key or token.

## GitHub Actions

```yaml
name: pgpjs
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g pgpjs-cli
      - run: pgpjs security scan --fail-on high --json
      - run: pgpjs verify release.tar --signature release.tar.asc --json
```

## GitLab CI

```yaml
pgpjs:
  image: node:22
  script:
    - npm install -g pgpjs-cli
    - pgpjs security scan --fail-on high --json
```

## Supplying a private key in CI

1. Store the armored key as a **masked** secret, base64-encoded.
2. Write it to a 0600 temp file.
3. `pgpjs key import "$TMP"` then `pgpjs decrypt ... --passphrase-file "$PASSFILE"`.
4. Delete the temp files in an `always()` / `after_script` step.
5. Never print the file.

## Docker

No native modules are required.

```dockerfile
FROM node:22-alpine
RUN npm install -g pgpjs-cli
WORKDIR /work
ENTRYPOINT ["pgpjs"]
```

## Environment

| Variable | Purpose |
|---|---|
| `PGPJS_HOME` | Global config directory |
| `PGPJS_CONFIG` | Config file path |
| `PGPJS_PASSPHRASE_FILE` | Passphrase file (not the passphrase itself) |
| `PGPJS_MCP_TOKEN` | Bearer token for HTTP MCP |
| `PGPJS_NON_INTERACTIVE` | Force non-interactive |
| `PGPJS_LOG_LEVEL` | `error` / `warn` / `info` / `debug` |
| `NO_COLOR` / `FORCE_COLOR` / `TERM=dumb` | Colour |
