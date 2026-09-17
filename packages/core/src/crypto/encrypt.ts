import * as openpgp from "openpgp";
import { PgpjsError } from "../errors.js";
import { normalizeFingerprint } from "../fingerprint.js";
import type { EncryptResult } from "../types.js";
import { assertUsableEncryptionKey, toKeyMetadata } from "./keys.js";

export interface EncryptInput {
  text?: string | undefined;
  binary?: Uint8Array | undefined;
  stream?: ReadableStream<Uint8Array> | undefined;
  encryptionKeys: openpgp.Key[];
  signingKeys?: openpgp.PrivateKey[] | undefined;
  armor: boolean;
  filename?: string | undefined;
  allowExpired?: boolean | undefined;
  allowWeak?: boolean | undefined;
}

export async function encryptData(input: EncryptInput): Promise<{
  output: string | Uint8Array | ReadableStream<Uint8Array>;
  result: EncryptResult;
}> {
  if (input.encryptionKeys.length === 0) {
    throw new PgpjsError("RECIPIENT_UNRESOLVED", "At least one recipient is required.");
  }

  for (const key of input.encryptionKeys) {
    if (input.allowExpired) {
      await assertUsableEncryptionKey(key, { allowExpired: true });
    } else {
      await assertUsableEncryptionKey(key);
    }
  }

  const fingerprints: string[] = [];
  for (const key of input.encryptionKeys) {
    fingerprints.push(normalizeFingerprint(key.getFingerprint()));
  }

  let message: openpgp.Message<string | Uint8Array>;
  try {
    if (input.stream) {
      const opts: { binary: ReadableStream<Uint8Array>; filename?: string } = { binary: input.stream };
      if (input.filename !== undefined) opts.filename = input.filename;
      message = await openpgp.createMessage(opts);
    } else if (input.binary) {
      const opts: { binary: Uint8Array; filename?: string } = { binary: input.binary };
      if (input.filename !== undefined) opts.filename = input.filename;
      message = await openpgp.createMessage(opts);
    } else if (input.text !== undefined) {
      const opts: { text: string; filename?: string } = { text: input.text };
      if (input.filename !== undefined) opts.filename = input.filename;
      message = await openpgp.createMessage(opts);
    } else {
      throw new PgpjsError("USAGE_ERROR", "No plaintext was provided.");
    }
  } catch (err) {
    if (err instanceof PgpjsError) throw err;
    throw new PgpjsError("CRYPTO_ERROR", "Failed to create OpenPGP message.", { cause: err });
  }

  try {
    const encrypted = input.armor
      ? await openpgp.encrypt({
          message,
          encryptionKeys: input.encryptionKeys,
          ...(input.signingKeys ? { signingKeys: input.signingKeys } : {}),
          format: "armored" as const
        })
      : await openpgp.encrypt({
          message,
          encryptionKeys: input.encryptionKeys,
          ...(input.signingKeys ? { signingKeys: input.signingKeys } : {}),
          format: "binary" as const
        });

    let signedBy: string | undefined;
    if (input.signingKeys?.[0]) {
      signedBy = normalizeFingerprint(input.signingKeys[0].getFingerprint());
    }

    const output = encrypted as unknown as string | Uint8Array | ReadableStream<Uint8Array>;
    const bytes =
      typeof output === "string"
        ? Buffer.byteLength(output)
        : output instanceof Uint8Array
          ? output.byteLength
          : 0;

    return {
      output,
      result: {
        armored: input.armor,
        bytes,
        recipientFingerprints: fingerprints,
        signedBy
      }
    };
  } catch (err) {
    throw new PgpjsError("CRYPTO_ERROR", "Encryption failed.", { cause: err });
  }
}

export async function recipientSummaries(keys: openpgp.Key[]): Promise<
  Array<{ fingerprint: string; email: string | undefined; userIds: string[] }>
> {
  const out: Array<{ fingerprint: string; email: string | undefined; userIds: string[] }> = [];
  for (const key of keys) {
    const meta = await toKeyMetadata(key);
    out.push({ fingerprint: meta.fingerprint, email: meta.email, userIds: meta.userIds });
  }
  return out;
}
