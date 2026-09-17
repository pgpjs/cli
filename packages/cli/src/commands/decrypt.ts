import { readFile, writeFile, stat } from "node:fs/promises";
import { decryptData, PgpjsError, sanitizeEmbeddedFilename } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { kvLine, statusLine } from "../render/terminal.js";
import { assertOutputPath, looksArmored, readStdinBytes, resolveInput } from "../io.js";
import { readPassphrase } from "../context.js";
import { promptMasked } from "../prompts.js";

export async function runDecrypt(
  ctx: CliContext,
  file: string | undefined,
  opts: {
    key?: string;
    output?: string;
    force?: boolean;
    passphraseFile?: string;
    passphraseFd?: string;
    allowUnauthenticated?: boolean;
    emitPlaintext?: boolean;
  },
  mode: OutputMode
): Promise<void> {
  const input = await resolveInput(file);
  let data: Uint8Array;
  if (input.kind === "stdin") {
    data = await readStdinBytes();
  } else {
    const st = await stat(input.path!);
    if (st.size > ctx.maxFileSize) {
      throw new PgpjsError("FILE_TOO_LARGE", `File exceeds maxFileSize (${ctx.resolved.config.maxFileSize}).`);
    }
    data = await readFile(input.path!);
  }

  const passphrase = await readPassphrase({
    passphraseFile: opts.passphraseFile,
    passphraseFd: opts.passphraseFd,
    interactive: ctx.interactive,
    prompt: () => promptMasked("Passphrase")
  });

  const stored = await ctx.keystore.list();
  const decryptionKeys = [];
  for (const rec of stored.filter((k) => k.hasPrivate)) {
    if (opts.key && rec.fingerprint !== opts.key && !rec.emails.includes(opts.key) && rec.keyId !== opts.key) {
      continue;
    }
    try {
      const { key } = await ctx.keystore.readPrivate(rec.fingerprint, passphrase);
      decryptionKeys.push(key);
    } catch {
      continue;
    }
  }
  if (decryptionKeys.length === 0) {
    throw new PgpjsError("KEY_NOT_FOUND", "No matching private key could be unlocked.");
  }

  const armored = looksArmored(data);
  const decrypted = await decryptData({
    armored: armored ? Buffer.from(data).toString("utf8") : undefined,
    binary: armored ? undefined : data,
    decryptionKeys,
    allowUnauthenticated: opts.allowUnauthenticated
  });

  if (opts.allowUnauthenticated && !mode.json) {
    process.stderr.write(
      `${statusLine(mode.color, "warn", "Decrypting a message without integrity protection.")}\n`
    );
  }

  const embedded = sanitizeEmbeddedFilename(decrypted.meta.filename);

  if (input.kind === "stdin" && !opts.output) {
    process.stdout.write(decrypted.data);
    return;
  }

  const output = opts.output ?? (input.path ? stripPgpExt(input.path) : embedded ?? "decrypted");
  await assertOutputPath(output, Boolean(opts.force));
  await writeFile(output, decrypted.data);

  const jsonData: Record<string, unknown> = {
    operation: "decrypt",
    output,
    wasSigned: decrypted.meta.wasSigned,
    signatures: decrypted.meta.signatures,
    decryptedTo: output
  };
  if (opts.emitPlaintext) {
    jsonData["plaintext"] = decrypted.text ?? Buffer.from(decrypted.data).toString("base64");
    jsonData["encoding"] = decrypted.text ? "utf8" : "base64";
  }

  emitSuccess(mode, jsonData, () => {
    const lines = [statusLine(mode.color, "ok", `Decrypted to ${output}`)];
    if (decrypted.meta.wasSigned) {
      lines.push(kvLine(mode.color, "signatures", String(decrypted.meta.signatures.length)));
    }
    return lines;
  });
}

function stripPgpExt(path: string): string {
  return path.replace(/(\.asc|\.gpg|\.pgp)$/i, "") || "decrypted";
}
