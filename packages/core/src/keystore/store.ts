import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import * as openpgp from "openpgp";
import { PgpjsError } from "../errors.js";
import { classifyIdentity, fingerprintPrefix, normalizeFingerprint, rejectShortKeyId } from "../fingerprint.js";
import type { KeyMetadata, StoredKeyRecord } from "../types.js";
import { decryptPrivateKey, readArmoredKey, readKeyAuto, toKeyMetadata, warnWeakOnImport } from "../crypto/keys.js";
import { atomicWriteFile, ensureDir, isModeAtMost, removeFile } from "./fs-safe.js";
import { rebuildIndex, writeIndex } from "./index-file.js";
import { withKeystoreLock } from "./lock.js";

export interface KeystorePaths {
  root: string;
  keys: string;
  revocations: string;
  index: string;
  lock: string;
}

export function keystorePaths(root: string): KeystorePaths {
  return {
    root,
    keys: join(root, "keys"),
    revocations: join(root, "revocations"),
    index: join(root, "index.json"),
    lock: join(root, ".lock")
  };
}

export class Keystore {
  readonly paths: KeystorePaths;

  constructor(root: string) {
    this.paths = keystorePaths(root);
  }

  async init(): Promise<void> {
    await ensureDir(this.paths.root);
    await ensureDir(this.paths.keys);
    await ensureDir(this.paths.revocations);
    await this.reindex();
  }

  async reindex(): Promise<StoredKeyRecord[]> {
    const index = await rebuildIndex(this.paths.keys);
    await writeIndex(this.paths.index, index);
    return index.keys;
  }

  private pubPath(fp: string): string {
    return join(this.paths.keys, `${fingerprintPrefix(fp)}.pub.asc`);
  }

  private secPath(fp: string): string {
    return join(this.paths.keys, `${fingerprintPrefix(fp)}.sec.asc`);
  }

  private revPath(fp: string): string {
    return join(this.paths.revocations, `${fingerprintPrefix(fp)}.rev`);
  }

  async list(): Promise<StoredKeyRecord[]> {
    const index = await rebuildIndex(this.paths.keys);
    await writeIndex(this.paths.index, index);
    return index.keys;
  }

  async resolve(identity: string): Promise<StoredKeyRecord> {
    rejectShortKeyId(identity);
    const keys = await this.list();
    const matches = keys.filter((k) => matchesIdentity(k, identity));
    if (matches.length === 0) {
      throw new PgpjsError("KEY_NOT_FOUND", `No key matches '${identity}'.`, {
        details: { identity },
        hint: "Run `pgpjs key list` to see available keys."
      });
    }
    if (matches.length > 1) {
      throw new PgpjsError(
        "KEY_AMBIGUOUS",
        `Multiple keys match '${identity}'. Specify a full fingerprint.`,
        {
          details: {
            identity,
            fingerprints: matches.map((m) => m.fingerprint)
          }
        }
      );
    }
    return matches[0] as StoredKeyRecord;
  }

  async readPublic(identity: string): Promise<{ key: openpgp.Key; armored: string; meta: KeyMetadata }> {
    const record = await this.resolve(identity);
    const armored = await readFile(this.pubPath(record.fingerprint), "utf8").catch(async () => {
      if (record.hasPrivate) {
        const sec = await readFile(this.secPath(record.fingerprint), "utf8");
        const key = await readArmoredKey(sec);
        return key.toPublic().armor();
      }
      throw new PgpjsError("KEY_NOT_FOUND", "Public key file is missing.", {
        details: { fingerprint: record.fingerprint }
      });
    });
    const key = await readArmoredKey(armored);
    return { key, armored, meta: await toKeyMetadata(key, { hasPrivate: record.hasPrivate }) };
  }

  async readPrivate(identity: string, passphrase?: string): Promise<{
    key: openpgp.PrivateKey;
    armored: string;
    meta: KeyMetadata;
  }> {
    const record = await this.resolve(identity);
    if (!record.hasPrivate) {
      throw new PgpjsError("KEY_NOT_FOUND", "No private key is stored for this identity.", {
        details: { fingerprint: record.fingerprint }
      });
    }
    const armored = await readFile(this.secPath(record.fingerprint), "utf8");
    const raw = await readArmoredKey(armored);
    if (!raw.isPrivate()) {
      throw new PgpjsError("KEY_MALFORMED", "Stored secret file is not a private key.");
    }
    let unlocked = raw as openpgp.PrivateKey;
    if (!unlocked.isDecrypted()) {
      if (!passphrase) {
        throw new PgpjsError("PASSPHRASE_REQUIRED", "A passphrase is required to unlock this private key.", {
          hint: "Pass --passphrase-file or set PGPJS_PASSPHRASE_FILE."
        });
      }
      unlocked = await decryptPrivateKey(unlocked, passphrase);
    }
    return {
      key: unlocked,
      armored,
      meta: await toKeyMetadata(unlocked, { hasPrivate: true, encrypted: Boolean(passphrase) })
    };
  }

  async saveGenerated(opts: {
    fingerprint: string;
    publicKeyArmored: string;
    privateKeyArmored: string;
    revocationCertificate: string;
  }): Promise<{ publicPath: string; revocationPath: string }> {
    return withKeystoreLock(this.paths.lock, async () => {
      await this.init();
      const fp = normalizeFingerprint(opts.fingerprint);
      const pub = this.pubPath(fp);
      const sec = this.secPath(fp);
      const rev = this.revPath(fp);
      try {
        await access(sec);
        throw new PgpjsError("KEY_EXISTS", "A key with this fingerprint already exists in the keystore.", {
          details: { fingerprint: fp }
        });
      } catch (err) {
        if (err instanceof PgpjsError) throw err;
      }
      await atomicWriteFile(pub, opts.publicKeyArmored.endsWith("\n") ? opts.publicKeyArmored : `${opts.publicKeyArmored}\n`, 0o644);
      await atomicWriteFile(sec, opts.privateKeyArmored.endsWith("\n") ? opts.privateKeyArmored : `${opts.privateKeyArmored}\n`, 0o600);
      await atomicWriteFile(rev, opts.revocationCertificate.endsWith("\n") ? opts.revocationCertificate : `${opts.revocationCertificate}\n`, 0o600);
      await this.reindex();
      return { publicPath: pub, revocationPath: rev };
    });
  }

  async importKey(data: string | Uint8Array): Promise<{
    metadata: KeyMetadata;
    warnings: string[];
    fingerprint: string;
  }> {
    return withKeystoreLock(this.paths.lock, async () => {
      await this.init();
      const key = await readKeyAuto(data);
      const warnings = warnWeakOnImport(key);
      const meta = await toKeyMetadata(key);
      const fp = normalizeFingerprint(meta.fingerprint);
      if (key.isPrivate()) {
        await atomicWriteFile(this.secPath(fp), `${key.armor()}\n`, 0o600);
        await atomicWriteFile(this.pubPath(fp), `${key.toPublic().armor()}\n`, 0o644);
      } else {
        await atomicWriteFile(this.pubPath(fp), `${key.armor()}\n`, 0o644);
      }
      await this.reindex();
      return { metadata: meta, warnings, fingerprint: fp };
    });
  }

  async deleteKey(identity: string): Promise<{ fingerprint: string }> {
    return withKeystoreLock(this.paths.lock, async () => {
      const record = await this.resolve(identity);
      const fp = record.fingerprint;
      await removeFile(this.pubPath(fp));
      await removeFile(this.secPath(fp));
      await this.reindex();
      return { fingerprint: fp };
    });
  }

  async exportPublic(identity: string): Promise<string> {
    const { armored } = await this.readPublic(identity);
    return armored;
  }

  async exportPrivateArmored(identity: string): Promise<string> {
    const record = await this.resolve(identity);
    if (!record.hasPrivate) {
      throw new PgpjsError("KEY_NOT_FOUND", "No private key is stored for this identity.");
    }
    return readFile(this.secPath(record.fingerprint), "utf8");
  }

  async permissionProblems(): Promise<string[]> {
    const issues: string[] = [];
    const keys = await this.list();
    for (const k of keys) {
      if (k.hasPrivate) {
        const ok = await isModeAtMost(this.secPath(k.fingerprint), 0o600);
        if (!ok) {
          issues.push(this.secPath(k.fingerprint));
        }
      }
    }
    return issues;
  }
}

function matchesIdentity(record: StoredKeyRecord, raw: string): boolean {
  const { kind, value } = classifyIdentity(raw);
  const fp = normalizeFingerprint(record.fingerprint);
  if (kind === "fingerprint") return fp === value;
  if (kind === "long-key-id") return record.keyId === value || fp.endsWith(value);
  const needle = value.toLowerCase();
  if (record.emails.some((e) => e.toLowerCase() === needle)) return true;
  return record.userIds.some((uid) => uid.toLowerCase().includes(needle));
}

export async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
