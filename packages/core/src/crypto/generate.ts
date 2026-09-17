import * as openpgp from "openpgp";
import { assertGenerateAlgorithm, describeGenerateAlgorithm } from "../algorithms.js";
import { PgpjsError } from "../errors.js";
import { formatFingerprint, normalizeFingerprint } from "../fingerprint.js";
import { DEFAULT_KEY_EXPIRY_SECONDS } from "../types.js";
import type { GenerateAlgorithm, KeyMetadata } from "../types.js";
import { readArmoredKey, toKeyMetadata } from "./keys.js";

export interface GenerateKeyInput {
  name: string;
  email: string;
  passphrase?: string | undefined;
  algorithm?: string | undefined;
  expiresInSeconds?: number | null | undefined;
}

export interface GenerateKeyOutput {
  publicKeyArmored: string;
  privateKeyArmored: string;
  revocationCertificate: string;
  fingerprint: string;
  formattedFingerprint: string;
  algorithm: GenerateAlgorithm;
  algorithmLabel: string;
  expiresAt: string | null;
  metadata: KeyMetadata;
}

export async function generateKey(input: GenerateKeyInput): Promise<GenerateKeyOutput> {
  const algorithm = assertGenerateAlgorithm(input.algorithm ?? "ed25519");
  const expiry =
    input.expiresInSeconds === undefined ? DEFAULT_KEY_EXPIRY_SECONDS : input.expiresInSeconds;

  const userIDs = [{ name: input.name, email: input.email }];
  const base: {
    userIDs: Array<{ name: string; email: string }>;
    format: "armored";
    passphrase?: string;
    keyExpirationTime?: number;
    type?: "ecc" | "rsa" | "curve25519" | "curve448";
    rsaBits?: number;
  } = {
    userIDs,
    format: "armored"
  };
  if (input.passphrase !== undefined) {
    base.passphrase = input.passphrase;
  }
  if (expiry !== null) {
    base.keyExpirationTime = expiry;
  }

  try {
    const generated =
      algorithm === "ed25519"
        ? await openpgp.generateKey({ ...base, type: "curve25519" })
        : await openpgp.generateKey({
            ...base,
            type: "rsa",
            rsaBits: algorithm === "rsa4096" ? 4096 : 3072
          });

    const publicKey = await readArmoredKey(generated.publicKey);
    const metadata = await toKeyMetadata(publicKey, { hasPrivate: true });
    const fingerprint = normalizeFingerprint(publicKey.getFingerprint());

    return {
      publicKeyArmored: generated.publicKey,
      privateKeyArmored: generated.privateKey,
      revocationCertificate: generated.revocationCertificate,
      fingerprint,
      formattedFingerprint: formatFingerprint(fingerprint),
      algorithm,
      algorithmLabel: describeGenerateAlgorithm(algorithm),
      expiresAt: metadata.expiresAt,
      metadata
    };
  } catch (err) {
    throw new PgpjsError("CRYPTO_ERROR", "Key generation failed.", {
      cause: err,
      details: { algorithm }
    });
  }
}
