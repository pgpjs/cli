const PGP_PRIVATE = /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g;
const PGP_PRIVATE_HEADER = /-----BEGIN PGP PRIVATE KEY BLOCK-----/g;
const MCP_TOKEN = /pgpjs_mcp_[A-Za-z0-9_-]+/g;
const PASSPHRASE_ASSIGN = /(?:passphrase|password)\s*[:=]\s*["'][^"']{4,}["']/gi;

const extra = new Set<string>();

export function registerSensitive(value: string): void {
  if (value.length >= 4) extra.add(value);
}

export function clearSensitiveRegistry(): void {
  extra.clear();
}

export function redact(input: string): string {
  let out = input.replace(PGP_PRIVATE, "[REDACTED PRIVATE KEY]");
  out = out.replace(PGP_PRIVATE_HEADER, "[REDACTED PRIVATE KEY HEADER]");
  out = out.replace(MCP_TOKEN, "pgpjs_mcp_[REDACTED]");
  out = out.replace(PASSPHRASE_ASSIGN, (m) => m.replace(/["'][^"']+["']/, '"[REDACTED]"'));
  for (const value of extra) {
    if (!value) continue;
    out = out.split(value).join("[REDACTED]");
  }
  return out;
}

export function containsSecret(input: string): boolean {
  return (
    /-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(input) ||
    /pgpjs_mcp_[A-Za-z0-9_-]+/.test(input) ||
    [...extra].some((v) => input.includes(v))
  );
}
