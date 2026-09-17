/**
 * Browser-safe OpenPGP operations. This module MUST NOT load private keys
 * from the keystore or decrypt passphrase-protected material.
 */
import * as openpgp from "openpgp";
import { PgpjsError } from "../errors.js";
import { normalizeFingerprint } from "../fingerprint.js";

export async function parseArmoredPublicKey(armored: string): Promise<openpgp.Key> {
  const key = await openpgp.readKey({ armoredKey: armored });
  if (key.isPrivate()) {
    throw new PgpjsError(
      "PERMISSION_DENIED",
      "A private key cannot be used in client-safe code. Pass a public key."
    );
  }
  return key;
}

export async function encryptToPublicKey(
  message: string | Uint8Array,
  publicKeyArmored: string
): Promise<string> {
  const key = await parseArmoredPublicKey(publicKeyArmored);
  const msg =
    typeof message === "string"
      ? await openpgp.createMessage({ text: message })
      : await openpgp.createMessage({ binary: message });
  const encrypted = await openpgp.encrypt({
    message: msg,
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted as string;
}

export async function verifySignature(options: {
  message: string;
  publicKeyArmored: string;
  detachedSignature?: string;
}): Promise<{ valid: boolean; fingerprint: string | undefined }> {
  const key = await parseArmoredPublicKey(options.publicKeyArmored);
  if (options.detachedSignature) {
    const signature = await openpgp.readSignature({ armoredSignature: options.detachedSignature });
    const message = await openpgp.createMessage({ text: options.message });
    const result = await openpgp.verify({ message, signature, verificationKeys: key });
    const sig = result.signatures[0];
    if (!sig) return { valid: false, fingerprint: undefined };
    try {
      await sig.verified;
      return { valid: true, fingerprint: normalizeFingerprint(key.getFingerprint()) };
    } catch {
      return { valid: false, fingerprint: normalizeFingerprint(key.getFingerprint()) };
    }
  }

  const cleartext = await openpgp.readCleartextMessage({ cleartextMessage: options.message });
  const result = await openpgp.verify({ message: cleartext, verificationKeys: key });
  const sig = result.signatures[0];
  if (!sig) return { valid: false, fingerprint: undefined };
  try {
    await sig.verified;
    return { valid: true, fingerprint: normalizeFingerprint(key.getFingerprint()) };
  } catch {
    return { valid: false, fingerprint: normalizeFingerprint(key.getFingerprint()) };
  }
}
