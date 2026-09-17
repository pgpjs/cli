import { readFile, writeFile, stat } from "node:fs/promises";
import { encryptData, PgpjsError } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { emitSuccess, green, type OutputMode } from "../render/output.js";
import { assertOutputPath, derivedOutputName, readStdinBytes, resolveInput } from "../io.js";
import { readPassphrase } from "../context.js";
import { promptMasked } from "../prompts.js";

export async function runEncrypt(
  ctx: CliContext,
  file: string | undefined,
  opts: {
    recipient?: string[];
    sign?: boolean;
    key?: string;
    armor?: boolean;
    binary?: boolean;
    output?: string;
    force?: boolean;
    allowExpired?: boolean;
    passphraseFile?: string;
    passphraseFd?: string;
  },
  mode: OutputMode
): Promise<void> {
  const recipients = opts.recipient ?? [];
  if (recipients.length === 0) {
    throw new PgpjsError("USAGE_ERROR", "At least one --recipient is required.");
  }
  if (opts.armor && opts.binary) {
    throw new PgpjsError("USAGE_ERROR", "--armor and --binary are mutually exclusive.");
  }

  const input = await resolveInput(file);
  const armor = opts.binary ? false : opts.armor ?? ctx.resolved.config.defaultArmor;

  const encryptionKeys = [];
  const fingerprints: string[] = [];
  for (const r of recipients) {
    const { key, meta } = await ctx.keystore.readPublic(r);
    encryptionKeys.push(key);
    fingerprints.push(meta.fingerprint);
  }

  let signingKeys = undefined;
  if (opts.sign) {
    const id = opts.key ?? ctx.resolved.config.defaultKey;
    if (!id) {
      throw new PgpjsError("KEY_NOT_FOUND", "Signing requires --key or config.defaultKey.");
    }
    const passphrase = await readPassphrase({
      passphraseFile: opts.passphraseFile,
      passphraseFd: opts.passphraseFd,
      interactive: ctx.interactive,
      prompt: () => promptMasked("Passphrase")
    });
    const { key } = await ctx.keystore.readPrivate(id, passphrase);
    signingKeys = [key];
  }

  let text: string | undefined;
  let binary: Uint8Array | undefined;
  if (input.kind === "stdin") {
    const bytes = await readStdinBytes();
    binary = bytes;
  } else {
    const st = await stat(input.path!);
    if (st.size > ctx.maxFileSize) {
      throw new PgpjsError("FILE_TOO_LARGE", `File exceeds maxFileSize (${ctx.resolved.config.maxFileSize}).`);
    }
    const buf = await readFile(input.path!);
    binary = buf;
  }

  const result = await encryptData({
    binary,
    text,
    encryptionKeys,
    signingKeys,
    armor,
    allowExpired: opts.allowExpired
  });

  const outBytes =
    typeof result.output === "string" ? Buffer.from(result.output) : (result.output as Uint8Array);

  if (input.kind === "stdin" && !opts.output) {
    process.stdout.write(outBytes);
    if (mode.json) {
      process.stderr.write(""); // diagnostics only
    }
    return;
  }

  const output =
    opts.output ?? derivedOutputName(input.path ?? "message", armor, "encrypt");
  await assertOutputPath(output, Boolean(opts.force));
  await writeFile(output, outBytes);

  emitSuccess(
    mode,
    {
      operation: "encrypt",
      output,
      recipients: fingerprints,
      armored: armor
    },
    () => {
      console.log(`${green(mode, "✓")} Encrypted ${output}`);
      for (const fp of fingerprints) {
        console.log(`  recipient  ${fp}`);
      }
    }
  );
}
