import { access, readFile } from "node:fs/promises";
import { EXIT_CODES, PgpjsError, verifyData } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { emitSuccess, green, yellow, type OutputMode } from "../render/output.js";
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
      if (result.status === "valid") {
        console.log(`${green(mode, "✓")} Signature valid`);
        if (result.signerFingerprint) console.log(`  signer  ${result.signerFingerprint}`);
      } else if (result.status === "untrusted") {
        console.log(`${yellow(mode, "⚠")} Signature is valid but the signer is unknown or untrusted`);
      } else if (result.status === "missing") {
        console.log("✗ No signature found");
      } else {
        console.log("✗ Signature invalid");
      }
    }
  );

  if (result.status === "valid") return EXIT_CODES.OK;
  if (result.status === "untrusted") return EXIT_CODES.VERIFY_UNTRUSTED;
  return EXIT_CODES.VERIFY_FAILED;
}
