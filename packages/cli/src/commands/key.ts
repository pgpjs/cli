import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  formatFingerprint,
  generateKey,
  parseDuration,
  PgpjsError,
  applySecureMode
} from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { heading, kvLine, muted, statusLine } from "../render/terminal.js";
import { promptMasked, promptSelect, promptText, missingFlag } from "../prompts.js";
import { readPassphrase } from "../context.js";
import { promptConfirm } from "../prompts.js";

export async function runKeyGenerate(
  ctx: CliContext,
  opts: {
    name?: string;
    email?: string;
    algorithm?: string;
    expires?: string;
    passphraseFile?: string;
    passphraseFd?: string;
    noPassphrase?: boolean;
  },
  mode: OutputMode
): Promise<void> {
  await ctx.keystore.init();

  const name = opts.name ?? (ctx.interactive ? await promptText("Name") : missingFlag("--name"));
  const email = opts.email ?? (ctx.interactive ? await promptText("Email") : missingFlag("--email"));
  const algorithm =
    opts.algorithm ??
    (ctx.interactive
      ? await promptSelect("Algorithm", [
          { value: "ed25519", name: "ed25519 / x25519 (recommended)" },
          { value: "rsa3072", name: "RSA 3072 (interop)" },
          { value: "rsa4096", name: "RSA 4096 (interop)" }
        ])
      : "ed25519");
  const expiresInput =
    opts.expires ?? (ctx.interactive ? await promptText("Expiration", "2y") : "2y");
  const expiresInSeconds = parseDuration(expiresInput);

  let passphrase: string | undefined;
  if (opts.noPassphrase) {
    if (!mode.json) {
      process.stderr.write(
        `${statusLine(mode.color, "warn", "Generating a private key WITHOUT a passphrase. This is strongly discouraged.")}\n`
      );
    }
  } else {
    passphrase = await readPassphrase({
      passphraseFile: opts.passphraseFile,
      passphraseFd: opts.passphraseFd,
      interactive: ctx.interactive,
      prompt: async () => {
        const a = await promptMasked("Passphrase");
        const b = await promptMasked("Confirm passphrase");
        if (a !== b) throw new PgpjsError("PASSPHRASE_INCORRECT", "Passphrases did not match.");
        return a;
      }
    });
    if (!passphrase) {
      throw new PgpjsError("PASSPHRASE_REQUIRED", "A passphrase is required unless --no-passphrase is set.", {
        hint: "Pass --passphrase-file, --passphrase-fd, or --no-passphrase."
      });
    }
  }

  const generated = await generateKey({
    name,
    email,
    passphrase,
    algorithm,
    expiresInSeconds
  });

  const saved = await ctx.keystore.saveGenerated({
    fingerprint: generated.fingerprint,
    publicKeyArmored: generated.publicKeyArmored,
    privateKeyArmored: generated.privateKeyArmored,
    revocationCertificate: generated.revocationCertificate
  });

  emitSuccess(
    mode,
    {
      fingerprint: generated.fingerprint,
      userId: `${name} <${email}>`,
      algorithm: generated.algorithm,
      expiresAt: generated.expiresAt,
      publicKey: saved.publicPath,
      revocation: saved.revocationPath
    },
    () => {
      const color = mode.color;
      return [
        statusLine(color, "ok", "Key generated"),
        "",
        kvLine(color, "Fingerprint", formatFingerprint(generated.fingerprint)),
        kvLine(color, "User ID", `${name} <${email}>`),
        kvLine(color, "Algorithm", generated.algorithmLabel),
        kvLine(color, "Expires", generated.expiresAt ?? "never"),
        "",
        kvLine(color, "Public key", saved.publicPath),
        kvLine(color, "Private key", "stored in keystore, passphrase-protected"),
        kvLine(color, "Revocation", saved.revocationPath),
        muted(color, "Back up the revocation certificate off-machine.")
      ];
    }
  );
}

export async function runKeyList(ctx: CliContext, mode: OutputMode): Promise<void> {
  const keys = await ctx.keystore.list();
  emitSuccess(
    mode,
    {
      keys: keys.map((k) => ({
        id: k.fingerprint,
        fingerprint: k.fingerprint,
        email: k.emails[0],
        algorithm: k.algorithm,
        expiresAt: k.expiresAt,
        hasPrivate: k.hasPrivate
      }))
    },
    () => {
      const color = mode.color;
      if (keys.length === 0) {
        return [
          heading(color, "Keys"),
          muted(color, "No keys in the keystore."),
          muted(color, "Run `pgpjs key generate`.")
        ];
      }
      return [
        heading(color, `Keys (${keys.length})`),
        "",
        ...keys.map((k) =>
          kvLine(color, formatFingerprint(k.fingerprint), `${k.emails[0] ?? k.userIds[0] ?? ""}  ${k.algorithm}`, 20)
        )
      ];
    }
  );
}

export async function runKeyShow(ctx: CliContext, id: string, mode: OutputMode): Promise<void> {
  const { meta } = await ctx.keystore.readPublic(id);
  emitSuccess(mode, { key: meta }, () => {
    const color = mode.color;
    const lines = [
      heading(color, "Key"),
      "",
      kvLine(color, "Fingerprint", formatFingerprint(meta.fingerprint)),
      kvLine(color, "Key ID", meta.keyId),
      kvLine(color, "User IDs", meta.userIds.join(", ")),
      kvLine(color, "Algorithm", meta.algorithm),
      kvLine(color, "Created", meta.createdAt),
      kvLine(color, "Expires", meta.expiresAt ?? "never"),
      kvLine(color, "Revoked", meta.revoked ? "yes" : "no"),
      kvLine(color, "Private", String(meta.isPrivate || "see keystore"))
    ];
    for (const s of meta.subkeys) {
      lines.push(kvLine(color, "Subkey", `${s.keyId} (${s.algorithm})`));
    }
    return lines;
  });
}

export async function runKeyExport(
  ctx: CliContext,
  id: string,
  opts: { private?: boolean; output?: string; stdout?: boolean; yes?: boolean },
  mode: OutputMode
): Promise<void> {
  if (opts.private) {
    if (!ctx.resolved.config.security.allowPrivateKeyExport) {
      throw new PgpjsError(
        "PERMISSION_DENIED",
        "Private key export is disabled. Set security.allowPrivateKeyExport to true in config."
      );
    }
    if (ctx.interactive && !opts.yes) {
      const ok = await promptConfirm("Export the PRIVATE key? This is dangerous. Continue?");
      if (!ok) return;
    } else if (!opts.yes) {
      throw new PgpjsError("NON_INTERACTIVE", "Private export requires --yes in non-interactive mode.");
    }
    const armored = await ctx.keystore.exportPrivateArmored(id);
    if (opts.stdout) {
      if (process.stdout.isTTY) {
        throw new PgpjsError(
          "PERMISSION_DENIED",
          "Refusing to print a private key to a TTY. Redirect stdout or write to a file."
        );
      }
      process.stdout.write(armored.endsWith("\n") ? armored : `${armored}\n`);
      return;
    }
    const out = opts.output ?? join(ctx.resolved.projectRoot, `${id}.sec.asc`);
    await writeFile(out, armored, { mode: 0o600 });
    await applySecureMode(out, 0o600);
    emitSuccess(mode, { output: out, private: true }, () => [
      statusLine(mode.color, "ok", `Private key written to ${out} (mode 0600)`),
      statusLine(mode.color, "warn", "This export is recorded as a sensitive operation. Rotate if it may have leaked.")
    ]);
    return;
  }

  const armored = await ctx.keystore.exportPublic(id);
  if (opts.stdout || !opts.output) {
    if (mode.json) {
      emitSuccess(mode, { publicKey: armored }, () => undefined);
      return;
    }
    process.stdout.write(armored.endsWith("\n") ? armored : `${armored}\n`);
    return;
  }
  await writeFile(opts.output, armored, { mode: 0o644 });
  emitSuccess(mode, { output: opts.output, private: false }, () => [
    statusLine(mode.color, "ok", `Public key written to ${opts.output}`)
  ]);
}

export async function runKeyImport(ctx: CliContext, file: string, mode: OutputMode): Promise<void> {
  const { readFile } = await import("node:fs/promises");
  const data = await readFile(file);
  const result = await ctx.keystore.importKey(data);
  emitSuccess(
    mode,
    { fingerprint: result.fingerprint, warnings: result.warnings },
    () => {
      const color = mode.color;
      return [
        statusLine(color, "ok", `Imported ${formatFingerprint(result.fingerprint)}`),
        ...result.warnings.map((w) => statusLine(color, "warn", w))
      ];
    }
  );
}

export async function runKeyDelete(
  ctx: CliContext,
  id: string,
  opts: { yes?: boolean },
  mode: OutputMode
): Promise<void> {
  if (ctx.interactive && !opts.yes) {
    const ok = await promptConfirm(`Delete key ${id} from the keystore?`);
    if (!ok) return;
  } else if (!opts.yes) {
    throw new PgpjsError("NON_INTERACTIVE", "Pass --yes to delete a key in non-interactive mode.");
  }
  const result = await ctx.keystore.deleteKey(id);
  emitSuccess(mode, { fingerprint: result.fingerprint }, () => [
    statusLine(mode.color, "ok", `Deleted ${formatFingerprint(result.fingerprint)}`)
  ]);
}

export async function runKeyReindex(ctx: CliContext, mode: OutputMode): Promise<void> {
  const keys = await ctx.keystore.reindex();
  emitSuccess(mode, { count: keys.length }, () => [
    statusLine(mode.color, "ok", `Rebuilt keystore index (${keys.length} key(s))`)
  ]);
}
