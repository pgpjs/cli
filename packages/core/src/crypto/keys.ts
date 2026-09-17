import * as openpgp from "openpgp";
import { algorithmFromOpenPgp, isWeakPublicAlgo, isWeakRsaBits } from "../algorithms.js";
import { PgpjsError } from "../errors.js";
import { classifyIdentity, normalizeFingerprint, rejectShortKeyId } from "../fingerprint.js";
import type { KeyMetadata, SubkeyMetadata } from "../types.js";

export async function readArmoredKey(armored: string): Promise<openpgp.Key> {
  try {
    return await openpgp.readKey({ armoredKey: armored });
  } catch (err) {
    throw new PgpjsError("KEY_MALFORMED", "The provided key could not be parsed.", {
      cause: err
    });
  }
}

export async function readBinaryKey(binary: Uint8Array): Promise<openpgp.Key> {
  try {
    return await openpgp.readKey({ binaryKey: binary });
  } catch (err) {
    throw new PgpjsError("KEY_MALFORMED", "The provided binary key could not be parsed.", {
      cause: err
    });
  }
}

export async function readKeyAuto(input: string | Uint8Array): Promise<openpgp.Key> {
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.includes("-----BEGIN PGP")) {
      return readArmoredKey(trimmed);
    }
    try {
      return await readArmoredKey(trimmed);
    } catch {
      return readBinaryKey(Buffer.from(trimmed, "base64"));
    }
  }
  return readBinaryKey(input);
}

export async function decryptPrivateKey(
  key: openpgp.Key,
  passphrase: string
): Promise<openpgp.PrivateKey> {
  if (!key.isPrivate()) {
    throw new PgpjsError("KEY_MALFORMED", "Expected a private key.");
  }
  const privateKey = key as openpgp.PrivateKey;
  if (privateKey.isDecrypted()) {
    return privateKey;
  }
  try {
    return await openpgp.decryptKey({ privateKey, passphrase });
  } catch (err) {
    throw new PgpjsError("PASSPHRASE_INCORRECT", "The passphrase is incorrect or the key cannot be decrypted.", {
      cause: err
    });
  }
}

export async function toKeyMetadata(
  key: openpgp.Key,
  extras: { hasPrivate?: boolean; encrypted?: boolean } = {}
): Promise<KeyMetadata> {
  const fingerprint = normalizeFingerprint(key.getFingerprint());
  const keyId = key.getKeyID().toHex().toUpperCase();
  const userIds = key.getUserIDs();
  const emails = userIds
    .map((uid) => {
      const m = /<([^>]+)>/.exec(uid);
      return m?.[1];
    })
    .filter((v): v is string => Boolean(v));

  const algoInfo = key.getAlgorithmInfo();
  const algorithm = algorithmFromOpenPgp(
    algoInfo.bits === undefined
      ? { algorithm: String(algoInfo.algorithm) }
      : { algorithm: String(algoInfo.algorithm), bits: algoInfo.bits }
  );

  let expiresAt: string | null = null;
  let expired = false;
  try {
    const exp = await key.getExpirationTime();
    if (exp instanceof Date) {
      expiresAt = exp.toISOString();
      expired = exp.getTime() <= Date.now();
    }
  } catch {
    expiresAt = null;
  }

  let revoked = false;
  try {
    revoked = await key.isRevoked();
  } catch {
    revoked = false;
  }

  const subkeys: SubkeyMetadata[] = [];
  for (const sub of key.getSubkeys()) {
    const sAlgo = sub.getAlgorithmInfo();
    let sExp: string | null = null;
    try {
      const t = await sub.getExpirationTime();
      if (t instanceof Date) sExp = t.toISOString();
    } catch {
      sExp = null;
    }
    subkeys.push({
      keyId: sub.getKeyID().toHex().toUpperCase(),
      algorithm: algorithmFromOpenPgp(
        sAlgo.bits === undefined
          ? { algorithm: String(sAlgo.algorithm) }
          : { algorithm: String(sAlgo.algorithm), bits: sAlgo.bits }
      ),
      expiresAt: sExp,
      capabilities: []
    });
  }

  const capabilities: string[] = [];
  try {
    if (key.getKeys().some((k) => k.getAlgorithmInfo())) {
      capabilities.push("certify");
    }
  } catch {
    /* ignore */
  }

  return {
    id: fingerprint,
    fingerprint,
    keyId,
    userIds,
    email: emails[0],
    algorithm,
    createdAt: key.getCreationTime().toISOString(),
    expiresAt,
    revoked,
    expired,
    isPrivate: key.isPrivate(),
    encrypted: extras.encrypted ?? (key.isPrivate() && !(key as openpgp.PrivateKey).isDecrypted()),
    capabilities,
    subkeys
  };
}

export function warnWeakOnImport(key: openpgp.Key): string[] {
  const warnings: string[] = [];
  const info = key.getAlgorithmInfo();
  if (isWeakPublicAlgo(String(info.algorithm))) {
    warnings.push(`Imported key uses a weak algorithm (${String(info.algorithm)}).`);
  }
  if (isWeakRsaBits(info.bits)) {
    warnings.push(`Imported RSA key is smaller than 3072 bits (${info.bits}).`);
  }
  return warnings;
}

export function matchKeyIdentity(meta: KeyMetadata, raw: string): boolean {
  rejectShortKeyId(raw);
  const { kind, value } = classifyIdentity(raw);
  const fp = normalizeFingerprint(meta.fingerprint);
  const keyId = meta.keyId.toUpperCase();
  if (kind === "fingerprint") {
    return fp === value;
  }
  if (kind === "long-key-id") {
    return keyId === value || fp.endsWith(value);
  }
  const needle = value.toLowerCase();
  if (meta.email?.toLowerCase() === needle) {
    return true;
  }
  return meta.userIds.some((uid) => uid.toLowerCase().includes(needle));
}

export async function assertUsableEncryptionKey(
  key: openpgp.Key,
  opts: { allowExpired?: boolean } = {}
): Promise<void> {
  const meta = await toKeyMetadata(key);
  if (meta.revoked) {
    throw new PgpjsError("KEY_REVOKED", "The recipient key has been revoked.", {
      details: { fingerprint: meta.fingerprint }
    });
  }
  if (meta.expired && !opts.allowExpired) {
    throw new PgpjsError("KEY_EXPIRED", "The recipient key has expired.", {
      details: { fingerprint: meta.fingerprint, expiresAt: meta.expiresAt },
      hint: "Pass --allow-expired to override (not recommended)."
    });
  }
}
