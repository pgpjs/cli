import * as openpgp from "openpgp";
import { PgpjsError } from "../errors.js";
import { normalizeFingerprint } from "../fingerprint.js";
import type { SignatureInfo, VerifyStatus } from "../types.js";

export interface VerifyInput {
  text?: string | undefined;
  binary?: Uint8Array | undefined;
  armoredMessage?: string | undefined;
  detachedSignature?: string | undefined;
  verificationKeys: openpgp.Key[];
  expectedSignerFingerprint?: string | undefined;
}

export interface VerifyOutput {
  status: VerifyStatus;
  signatures: SignatureInfo[];
  signerFingerprint: string | undefined;
}

export async function verifyData(input: VerifyInput): Promise<VerifyOutput> {
  try {
    let verificationResult: openpgp.VerifyMessageResult<string | Uint8Array>;

    if (input.detachedSignature) {
      const signature = input.detachedSignature.includes("-----BEGIN PGP")
        ? await openpgp.readSignature({ armoredSignature: input.detachedSignature })
        : await openpgp.readSignature({
            binarySignature: input.binary ?? new TextEncoder().encode(input.detachedSignature)
          });

      const message =
        input.binary !== undefined
          ? await openpgp.createMessage({ binary: input.binary })
          : await openpgp.createMessage({ text: input.text ?? "" });

      verificationResult = await openpgp.verify({
        message,
        signature,
        verificationKeys: input.verificationKeys
      });
    } else if (input.armoredMessage?.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
      const cleartext = await openpgp.readCleartextMessage({
        cleartextMessage: input.armoredMessage
      });
      verificationResult = await openpgp.verify({
        message: cleartext,
        verificationKeys: input.verificationKeys
      });
    } else if (input.armoredMessage) {
      const message = await openpgp.readMessage({ armoredMessage: input.armoredMessage });
      verificationResult = await openpgp.verify({
        message,
        verificationKeys: input.verificationKeys
      });
    } else {
      throw new PgpjsError("SIGNATURE_MISSING", "No signature was provided.");
    }

    const signatures: SignatureInfo[] = [];
    let anyValid = false;
    let knownSigner: string | undefined;

    for (const sig of verificationResult.signatures) {
      let valid = false;
      try {
        await sig.verified;
        valid = true;
        anyValid = true;
      } catch {
        valid = false;
      }
      const keyId = sig.keyID?.toHex().toUpperCase();
      const matching = input.verificationKeys.find(
        (k) => k.getKeyID().toHex().toUpperCase() === keyId || k.getKeys().some((sk) => sk.getKeyID().toHex().toUpperCase() === keyId)
      );
      const fingerprint = matching ? normalizeFingerprint(matching.getFingerprint()) : undefined;
      if (valid && fingerprint) {
        knownSigner = fingerprint;
      }
      signatures.push({
        keyId,
        fingerprint,
        createdAt: undefined,
        valid
      });
    }

    if (verificationResult.signatures.length === 0) {
      return { status: "missing", signatures, signerFingerprint: undefined };
    }

    if (!anyValid) {
      return { status: "invalid", signatures, signerFingerprint: knownSigner };
    }

    if (input.expectedSignerFingerprint) {
      const expected = normalizeFingerprint(input.expectedSignerFingerprint);
      const pinned = signatures.some((s) => s.valid && s.fingerprint === expected);
      if (!pinned) {
        return { status: "invalid", signatures, signerFingerprint: knownSigner };
      }
    }

    if (!knownSigner) {
      return { status: "untrusted", signatures, signerFingerprint: undefined };
    }

    return { status: "valid", signatures, signerFingerprint: knownSigner };
  } catch (err) {
    if (err instanceof PgpjsError) throw err;
    throw new PgpjsError("SIGNATURE_INVALID", "Signature verification failed.", { cause: err });
  }
}

export function verifyStatusToError(status: VerifyStatus): never | void {
  if (status === "valid") return;
  if (status === "untrusted") {
    throw new PgpjsError(
      "SIGNATURE_UNTRUSTED",
      "Signature is cryptographically valid but the signing key is unknown or untrusted."
    );
  }
  if (status === "missing") {
    throw new PgpjsError("SIGNATURE_MISSING", "No signature was found.");
  }
  throw new PgpjsError("SIGNATURE_INVALID", "The signature is invalid or the content was tampered with.");
}
