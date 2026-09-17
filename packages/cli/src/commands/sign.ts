import { readFile, writeFile, stat } from "node:fs/promises";
import { PgpjsError, signData, type SignMode } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { kvLine, statusLine } from "../render/terminal.js";
import { assertOutputPath, derivedOutputName, readStdinBytes, resolveInput } from "../io.js";
import { readPassphrase } from "../context.js";
import { promptMasked } from "../prompts.js";

export async function runSign(
  ctx: CliContext,
  file: string | undefined,
  opts: {
    key?: string;
    detached?: boolean;
    inline?: boolean;
    cleartext?: boolean;
    armor?: boolean;
    binary?: boolean;
    output?: string;
    force?: boolean;
    passphraseFile?: string;
    passphraseFd?: string;
  },
  mode: OutputMode
): Promise<void> {
  if ([opts.detached, opts.inline, opts.cleartext].filter(Boolean).length > 1) {
    throw new PgpjsError("USAGE_ERROR", "Choose one of --detached, --inline, or --cleartext.");
  }
  const modeSign: SignMode = opts.inline ? "inline" : opts.cleartext ? "cleartext" : "detached";
  const armor = opts.binary ? false : opts.armor ?? ctx.resolved.config.defaultArmor;
  const input = await resolveInput(file);

  const keyId = opts.key ?? ctx.resolved.config.defaultKey;
  if (!keyId) {
    throw new PgpjsError("KEY_NOT_FOUND", "Pass --key or set config.defaultKey.");
  }
  const passphrase = await readPassphrase({
    passphraseFile: opts.passphraseFile,
    passphraseFd: opts.passphraseFd,
    interactive: ctx.interactive,
    prompt: () => promptMasked("Passphrase")
  });
  const { key } = await ctx.keystore.readPrivate(keyId, passphrase);

  let text: string | undefined;
  let binary: Uint8Array | undefined;
  if (input.kind === "stdin") {
    binary = await readStdinBytes();
  } else {
    const st = await stat(input.path!);
    if (st.size > ctx.maxFileSize) {
      throw new PgpjsError("FILE_TOO_LARGE", `File exceeds maxFileSize.`);
    }
    binary = await readFile(input.path!);
  }

  const signed = await signData({
    binary,
    text,
    signingKey: key,
    mode: modeSign,
    armor: modeSign === "cleartext" ? true : armor
  });

  if (input.kind === "stdin" && !opts.output) {
    process.stdout.write(signed.output);
    return;
  }

  const output =
    opts.output ?? derivedOutputName(input.path ?? "message", armor || modeSign === "cleartext", "sign");
  await assertOutputPath(output, Boolean(opts.force));
  await writeFile(output, signed.output);

  emitSuccess(
    mode,
    { operation: "sign", output, mode: modeSign, fingerprint: signed.fingerprint },
    () => [
      statusLine(mode.color, "ok", `Signed (${modeSign}) → ${output}`),
      kvLine(mode.color, "fingerprint", signed.fingerprint)
    ]
  );
}
