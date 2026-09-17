import { access, readFile } from "node:fs/promises";
import { EXIT_CODES, PgpjsError, verifyData } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { kvLine, statusLine } from "../render/terminal.js";
import { looksArmored, resolveInput } from "../io.js";

export async function runVerify(
  ctx: CliContext,
  file: string,
  opts: { signature?: string; signer?: string },
  mode: OutputMode
): Promise<number> {
  const input = await resolveInput(file);
  if (input.kind !== "file" || !input.path) {
    throw new PgpjsError("USAGE_ERROR", "verify requires a file path.");
  }
  const data = await readFile(input.path);
  const text = looksArmored(data) ? data.toString("utf8") : undefined;

  let detached: string | undefined = opts.signature
    ? await readFile(opts.signature, "utf8")
    : undefined;
  if (!detached) {
    for (const candidate of [`${input.path}.sig`, `${input.path}.asc`]) {
      try {
        await access(candidate);
        detached = await readFile(candidate, "utf8");
        break;
      } catch {
        continue;
      }
    }
  }

  const stored = await ctx.keystore.list();
  const verificationKeys = [];
  for (const rec of stored) {
    const { key } = await ctx.keystore.readPublic(rec.fingerprint);
    verificationKeys.push(key);
  }

  const result = await verifyData({
    text: detached ? data.toString("utf8") : text,
    binary: detached && !looksArmored(data) ? data : undefined,
    armoredMessage: !detached && text ? text : undefined,
    detachedSignature: detached,
    verificationKeys,
    expectedSignerFingerprint: opts.signer
  });

  emitSuccess(
    mode,
    { operation: "verify", status: result.status, signatures: result.signatures, signer: result.signerFingerprint },
    () => {
      const color = mode.color;
      if (result.status === "valid") {
        const lines = [statusLine(color, "ok", "Signature valid")];
        if (result.signerFingerprint) lines.push(kvLine(color, "signer", result.signerFingerprint));
        return lines;
      }
      if (result.status === "untrusted") {
        return [statusLine(color, "warn", "Signature is valid but the signer is unknown or untrusted")];
      }
      if (result.status === "missing") {
        return [statusLine(color, "fail", "No signature found")];
      }
      return [statusLine(color, "fail", "Signature invalid")];
    }
  );

  if (result.status === "valid") return EXIT_CODES.OK;
  if (result.status === "untrusted") return EXIT_CODES.VERIFY_UNTRUSTED;
  return EXIT_CODES.VERIFY_FAILED;
}
