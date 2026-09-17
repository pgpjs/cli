import * as openpgp from "openpgp";
import { PgpjsError } from "../errors.js";
import { normalizeFingerprint } from "../fingerprint.js";
import type { SignMode } from "../types.js";

export interface SignInput {
  text?: string | undefined;
  binary?: Uint8Array | undefined;
  signingKey: openpgp.PrivateKey;
  mode: SignMode;
  armor: boolean;
}

export interface SignOutput {
  output: string | Uint8Array;
  fingerprint: string;
  mode: SignMode;
}

export async function signData(input: SignInput): Promise<SignOutput> {
  const fingerprint = normalizeFingerprint(input.signingKey.getFingerprint());

  try {
    if (input.mode === "cleartext") {
      const message = await openpgp.createCleartextMessage({
        text: input.text ?? new TextDecoder().decode(input.binary ?? new Uint8Array())
      });
      const signed = await openpgp.sign({
        message,
        signingKeys: input.signingKey,
        format: "armored"
      });
      return { output: signed as unknown as string, fingerprint, mode: input.mode };
    }

    const message =
      input.binary !== undefined
        ? await openpgp.createMessage({ binary: input.binary })
        : await openpgp.createMessage({ text: input.text ?? "" });

    const signed = input.armor
      ? await openpgp.sign({
          message,
          signingKeys: input.signingKey,
          detached: input.mode === "detached",
          format: "armored" as const
        })
      : await openpgp.sign({
          message,
          signingKeys: input.signingKey,
          detached: input.mode === "detached",
          format: "binary" as const
        });

    return {
      output: signed as unknown as string | Uint8Array,
      fingerprint,
      mode: input.mode
    };
  } catch (err) {
    throw new PgpjsError("CRYPTO_ERROR", "Signing failed.", { cause: err });
  }
}
