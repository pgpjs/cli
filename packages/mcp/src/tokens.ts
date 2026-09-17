import { createHash } from "node:crypto";
import { readFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import {
  getSecureRandomBytes,
  PgpjsError,
  sha256Hex,
  timingSafeEqualHex,
  toBase64Url,
  atomicWriteFile
} from "@pgpjs/core";
import type { ScopeName } from "@pgpjs/security";
import { ALL_SCOPES } from "@pgpjs/security";

export interface TokenRecord {
  id: string;
  name: string;
  hash: string;
  checksum: string;
  scopes: ScopeName[];
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  lastUsedAt: string | null;
}

export interface TokenStoreFile {
  version: 1;
  tokens: TokenRecord[];
}

const PREFIX = "pgpjs_mcp_";

export function parseExpires(input: string | undefined, defaultDays = 90): Date {
  const now = Date.now();
  if (!input) {
    return new Date(now + defaultDays * 24 * 60 * 60 * 1000);
  }
  const m = /^(\d+)([smhdwy])$/.exec(input.trim());
  if (!m || m[1] === undefined || m[2] === undefined) {
    throw new PgpjsError("USAGE_ERROR", `Invalid --expires value '${input}'. Use 30d, 12h, 1y.`);
  }
  const n = Number(m[1]);
  const mul: Record<string, number> = {
    s: 1000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
    w: 604_800_000,
    y: 31_536_000_000
  };
  const ms = mul[m[2]];
  if (ms === undefined) {
    throw new PgpjsError("USAGE_ERROR", `Unknown duration unit '${m[2]}'.`);
  }
  return new Date(now + n * ms);
}

function checksumFor(id: string, secret: string): string {
  const digest = createHash("sha256").update(`${id}.${secret}`).digest();
  return toBase64Url(digest).slice(0, 4);
}

export function formatToken(id: string, secret: string, checksum: string): string {
  return `${PREFIX}${id}_${secret}_${checksum}`;
}

export function parseToken(token: string): { id: string; secret: string; checksum: string } {
  if (!token.startsWith(PREFIX)) {
    throw new PgpjsError("TOKEN_INVALID", "Token does not use the pgpjs_mcp_ prefix.");
  }
  const rest = token.slice(PREFIX.length);
  // id (8) + '_' + secret (43) + '_' + checksum (4)
  if (rest.length !== 8 + 1 + 43 + 1 + 4) {
    throw new PgpjsError("TOKEN_INVALID", "Token format is invalid.");
  }
  if (rest[8] !== "_" || rest[52] !== "_") {
    throw new PgpjsError("TOKEN_INVALID", "Token format is invalid.");
  }
  const id = rest.slice(0, 8);
  const secret = rest.slice(9, 52);
  const checksum = rest.slice(53);
  if (checksumFor(id, secret) !== checksum) {
    throw new PgpjsError("TOKEN_INVALID", "Token checksum mismatch.");
  }
  return { id, secret, checksum };
}

export async function loadTokenStore(path: string): Promise<TokenStoreFile> {
  try {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw) as TokenStoreFile;
    if (parsed.version !== 1 || !Array.isArray(parsed.tokens)) {
      throw new Error("bad");
    }
    return parsed;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { version: 1, tokens: [] };
    }
    throw new PgpjsError("CONFIG_INVALID", "Token store is corrupt.", { cause: err });
  }
}

export async function saveTokenStore(path: string, store: TokenStoreFile): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await atomicWriteFile(path, `${JSON.stringify(store, null, 2)}\n`, 0o600);
}

export async function createToken(options: {
  storePath: string;
  name: string;
  scopes: ScopeName[];
  expires: Date;
}): Promise<{ record: TokenRecord; token: string }> {
  const store = await loadTokenStore(options.storePath);
  const id = toBase64Url(getSecureRandomBytes(6)).slice(0, 8);
  const secret = toBase64Url(getSecureRandomBytes(32));
  const checksum = checksumFor(id, secret);
  const token = formatToken(id, secret, checksum);
  const record: TokenRecord = {
    id,
    name: options.name,
    hash: sha256Hex(token),
    checksum,
    scopes: options.scopes.length > 0 ? options.scopes : [...ALL_SCOPES],
    createdAt: new Date().toISOString(),
    expiresAt: options.expires.toISOString(),
    revokedAt: null,
    lastUsedAt: null
  };
  store.tokens.push(record);
  await saveTokenStore(options.storePath, store);
  return { record, token };
}

export async function listTokens(storePath: string): Promise<TokenRecord[]> {
  const store = await loadTokenStore(storePath);
  return store.tokens;
}

export async function revokeToken(storePath: string, id: string): Promise<TokenRecord> {
  const store = await loadTokenStore(storePath);
  const rec = store.tokens.find((t) => t.id === id);
  if (!rec) {
    throw new PgpjsError("TOKEN_INVALID", `No token with id '${id}'.`);
  }
  rec.revokedAt = new Date().toISOString();
  await saveTokenStore(storePath, store);
  return rec;
}

export async function rotateToken(
  storePath: string,
  id: string
): Promise<{ record: TokenRecord; token: string }> {
  const store = await loadTokenStore(storePath);
  const rec = store.tokens.find((t) => t.id === id);
  if (!rec) {
    throw new PgpjsError("TOKEN_INVALID", `No token with id '${id}'.`);
  }
  rec.revokedAt = new Date().toISOString();
  await saveTokenStore(storePath, store);
  return createToken({
    storePath,
    name: rec.name,
    scopes: rec.scopes,
    expires: new Date(rec.expiresAt)
  });
}

export async function authenticateToken(
  storePath: string,
  token: string
): Promise<TokenRecord> {
  const parsed = parseToken(token);
  const store = await loadTokenStore(storePath);
  const rec = store.tokens.find((t) => t.id === parsed.id);
  if (!rec) {
    throw new PgpjsError("TOKEN_INVALID", "Unknown MCP token.");
  }
  const hash = sha256Hex(token);
  if (!timingSafeEqualHex(hash, rec.hash)) {
    throw new PgpjsError("TOKEN_INVALID", "Unknown MCP token.");
  }
  if (rec.revokedAt) {
    throw new PgpjsError("TOKEN_REVOKED", "This MCP token has been revoked.");
  }
  if (Date.parse(rec.expiresAt) <= Date.now()) {
    throw new PgpjsError("TOKEN_EXPIRED", "This MCP token has expired.");
  }
  rec.lastUsedAt = new Date().toISOString();
  await saveTokenStore(storePath, store);
  return rec;
}

export function publicTokenView(rec: TokenRecord): {
  id: string;
  name: string;
  scopes: ScopeName[];
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  lastUsedAt: string | null;
  status: "active" | "revoked" | "expired";
} {
  const status = rec.revokedAt
    ? "revoked"
    : Date.parse(rec.expiresAt) <= Date.now()
      ? "expired"
      : "active";
  return {
    id: rec.id,
    name: rec.name,
    scopes: rec.scopes,
    createdAt: rec.createdAt,
    expiresAt: rec.expiresAt,
    revokedAt: rec.revokedAt,
    lastUsedAt: rec.lastUsedAt,
    status
  };
}
