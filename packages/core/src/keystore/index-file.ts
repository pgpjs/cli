import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PgpjsError } from "../errors.js";
import type { KeystoreIndex, StoredKeyRecord } from "../types.js";
import { atomicWriteFile } from "./fs-safe.js";
import { readArmoredKey, toKeyMetadata } from "../crypto/keys.js";
import { normalizeFingerprint } from "../fingerprint.js";

export async function readIndex(indexPath: string): Promise<KeystoreIndex> {
  try {
    const raw = await readFile(indexPath, "utf8");
    const parsed = JSON.parse(raw) as KeystoreIndex;
    if (parsed.version !== 1 || !Array.isArray(parsed.keys)) {
      throw new Error("bad shape");
    }
    return parsed;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { version: 1, keys: [] };
    }
    throw new PgpjsError("KEYSTORE_CORRUPT", "keystore index.json is unreadable or invalid.", {
      cause: err
    });
  }
}

export async function writeIndex(indexPath: string, index: KeystoreIndex): Promise<void> {
  await atomicWriteFile(indexPath, `${JSON.stringify(index, null, 2)}\n`, 0o644);
}

export async function rebuildIndex(keysDir: string): Promise<KeystoreIndex> {
  let files: string[] = [];
  try {
    files = await readdir(keysDir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { version: 1, keys: [] };
    }
    throw err;
  }

  const byFp = new Map<string, StoredKeyRecord>();

  for (const file of files) {
    if (!file.endsWith(".asc") && !file.endsWith(".gpg")) continue;
    const full = join(keysDir, file);
    let armored: string;
    try {
      armored = await readFile(full, "utf8");
    } catch {
      continue;
    }
    try {
      const key = await readArmoredKey(armored);
      const meta = await toKeyMetadata(key);
      const fp = normalizeFingerprint(meta.fingerprint);
      const existing = byFp.get(fp);
      const isSec = file.includes(".sec.") || file.endsWith(".sec.asc");
      const isPub = file.includes(".pub.") || file.endsWith(".pub.asc");
      const record: StoredKeyRecord = existing ?? {
        fingerprint: fp,
        keyId: meta.keyId,
        userIds: meta.userIds,
        emails: meta.email ? [meta.email] : [],
        algorithm: meta.algorithm,
        createdAt: meta.createdAt,
        expiresAt: meta.expiresAt,
        revoked: meta.revoked,
        hasPrivate: false,
        hasPublic: false
      };
      if (isSec || key.isPrivate()) record.hasPrivate = true;
      if (isPub || !key.isPrivate()) record.hasPublic = true;
      byFp.set(fp, record);
    } catch {
      continue;
    }
  }

  return { version: 1, keys: [...byFp.values()] };
}
