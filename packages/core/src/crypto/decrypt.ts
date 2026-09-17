import * as openpgp from "openpgp";
import { PgpjsError } from "../errors.js";
import { normalizeFingerprint } from "../fingerprint.js";
import type { DecryptResultMeta, SignatureInfo } from "../types.js";

export interface DecryptInput {
  armored?: string | undefined;
  binary?: Uint8Array | undefined;
  stream?: ReadableStream<Uint8Array> | undefined;
  decryptionKeys: openpgp.PrivateKey[];
  verificationKeys?: openpgp.Key[] | undefined;
  allowUnauthenticated?: boolean | undefined;
}

export interface DecryptOutput {
  data: Uint8Array;
  text: string | undefined;
  meta: DecryptResultMeta;
}

function isProbablyText(bytes: Uint8Array): boolean {
  if (bytes.byteLength === 0) return true;
  const sample = bytes.subarray(0, Math.min(bytes.byteLength, 4096));
  let odd = 0;
  for (const b of sample) {
    if (b === 0) return false;
    if (b < 9 || (b > 13 && b < 32)) odd += 1;
  }
  return odd / sample.byteLength < 0.1;
}

export async function decryptData(input: DecryptInput): Promise<DecryptOutput> {
  if (input.decryptionKeys.length === 0) {
    throw new PgpjsError("KEY_NOT_FOUND", "No private key is available to decrypt this message.");
  }

  let message: openpgp.Message<string | Uint8Array>;
  try {
    if (input.stream) {
      message = await openpgp.readMessage({ binaryMessage: input.stream });
    } else if (input.armored) {
      message = await openpgp.readMessage({ armoredMessage: input.armored });
    } else if (input.binary) {
      message = await openpgp.readMessage({ binaryMessage: input.binary });
    } else {
      throw new PgpjsError("USAGE_ERROR", "No ciphertext was provided.");
    }
  } catch (err) {
    if (err instanceof PgpjsError) throw err;
    throw new PgpjsError("DECRYPT_FAILED", "The message could not be parsed as OpenPGP ciphertext.", {
      cause: err
    });
  }

  const decryptOpts: Parameters<typeof openpgp.decrypt>[0] = {
    message,
    decryptionKeys: input.decryptionKeys,
    format: "binary"
  };
  if (input.verificationKeys) {
    decryptOpts.verificationKeys = input.verificationKeys;
  }
  if (input.allowUnauthenticated) {
    decryptOpts.config = { allowUnauthenticatedMessages: true };
  }

  try {
    const decrypted = await openpgp.decrypt(decryptOpts);

    const data =
      decrypted.data instanceof Uint8Array
        ? decrypted.data
        : new TextEncoder().encode(String(decrypted.data));

    const signatures: SignatureInfo[] = [];
    for (const sig of decrypted.signatures ?? []) {
      let valid = false;
      try {
        await sig.verified;
        valid = true;
      } catch {
        valid = false;
      }
      signatures.push({
        keyId: sig.keyID?.toHex().toUpperCase(),
        fingerprint: undefined,
        createdAt: undefined,
        valid
      });
    }

    const filename = decrypted.filename && decrypted.filename.length > 0 ? decrypted.filename : undefined;
    const text = isProbablyText(data) ? new TextDecoder().decode(data) : undefined;

    return {
      data,
      text,
      meta: {
        signatures,
        wasSigned: signatures.length > 0,
        filename,
        integrityProtected: true
      }
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/mdc|integrity|unauthenticated/i.test(msg) && !input.allowUnauthenticated) {
      throw new PgpjsError(
        "DECRYPT_FAILED",
        "Message lacks MDC/AEAD integrity protection. Refusing to decrypt.",
        {
          cause: err,
          hint: "Pass --allow-unauthenticated to override. This is dangerous."
        }
      );
    }
    throw new PgpjsError("DECRYPT_FAILED", "Decryption failed.", { cause: err });
  }
}

export function sanitizeEmbeddedFilename(name: string | undefined): string | undefined {
  if (!name) return undefined;
  if (name.includes("\0")) {
    throw new PgpjsError("OUTPUT_UNSAFE_PATH", "Embedded filename contains a NUL byte.");
  }
  const replaced = name.replace(/\\/g, "/");
  if (replaced.startsWith("/") || /^[a-zA-Z]:/.test(replaced) || replaced.includes("..")) {
    throw new PgpjsError(
      "OUTPUT_UNSAFE_PATH",
      "Embedded filename is not safe to use as an output path.",
      { details: { filename: name } }
    );
  }
  const base = replaced.split("/").pop() ?? "decrypted";
  return base.length > 0 ? base : "decrypted";
}

export function signingFingerprints(meta: DecryptResultMeta): string[] {
  return meta.signatures
    .map((s) => s.fingerprint)
    .filter((v): v is string => Boolean(v))
    .map(normalizeFingerprint);
}
