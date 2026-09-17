import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ProjectInfo } from "../detect/project.js";

export interface PlannedFile {
  relativePath: string;
  content: string;
  action: "create" | "skip" | "append";
}

export function planInit(info: ProjectInfo): PlannedFile[] {
  const ext = info.isTypeScript ? "ts" : "js";
  const files: PlannedFile[] = [];

  files.push({
    relativePath: `pgpjs.config.${ext}`,
    action: existsSync(join(info.cwd, `pgpjs.config.${ext}`)) ? "skip" : "create",
    content: `/**
 * PGPJS project configuration.
 * Optional: wrap with defineConfig from "pgpjs-cli/config" for type inference.
 */
export default {
  keyDirectory: ".pgpjs/keys",
  defaultArmor: true,
  security: {
    allowPrivateKeyExport: false,
    requireEncryptedPrivateKeys: true,
    warnOnUnprotectedKeystore: true
  }
};
`
  });

  files.push({
    relativePath: ".env.example",
    action: existsSync(join(info.cwd, ".env.example")) ? "skip" : "create",
    content: `# PGPJS environment template
# Never put private keys or passphrases in .env files committed to git.
# Use PGPJS_PASSPHRASE_FILE pointing at a 0600 file instead.

# PGPJS_HOME=
# PGPJS_CONFIG=
# PGPJS_PASSPHRASE_FILE=
# PGPJS_NON_INTERACTIVE=1

# Server-side only. Do NOT prefix with NEXT_PUBLIC_.
# PGPJS_SERVER_PUBLIC_KEY_FILE=.pgpjs/keys/example.pub.asc
`
  });

  files.push(gitignorePlan(info.cwd));
  return files;
}

export function gitignorePlan(cwd: string): PlannedFile {
  const gi = join(cwd, ".gitignore");
  const block = `# PGPJS keystore (private keys, tokens, audit log)
.pgpjs/
!.pgpjs/keys/*.pub.asc
`;
  if (!existsSync(gi)) {
    return { relativePath: ".gitignore", action: "create", content: block };
  }
  const existing = readFileSync(gi, "utf8");
  if (existing.split(/\r?\n/).some((l) => l.trim() === ".pgpjs/" || l.trim() === ".pgpjs")) {
    return { relativePath: ".gitignore", action: "skip", content: existing };
  }
  const nl = existing.endsWith("\n") ? "" : "\n";
  return { relativePath: ".gitignore", action: "append", content: `${nl}\n${block}` };
}

export function writePlan(cwd: string, files: PlannedFile[], dryRun: boolean): string[] {
  const written: string[] = [];
  for (const file of files) {
    if (file.action === "skip") continue;
    const full = join(cwd, file.relativePath);
    if (dryRun) {
      written.push(`${file.action}:${file.relativePath}`);
      continue;
    }
    mkdirSync(dirname(full), { recursive: true });
    if (file.action === "append") {
      const prev = existsSync(full) ? readFileSync(full, "utf8") : "";
      writeFileSync(full, prev + file.content, "utf8");
    } else {
      writeFileSync(full, file.content, "utf8");
    }
    written.push(`${file.action}:${file.relativePath}`);
  }
  return written;
}

export function nextLibFiles(info: ProjectInfo): PlannedFile[] {
  const ext = info.isTypeScript ? "ts" : "js";
  const base = info.hasSrcDir ? "src/lib/pgpjs" : "lib/pgpjs";
  const files: PlannedFile[] = [];

  files.push({
    relativePath: `${base}/client.${ext}`,
    action: "create",
    content: `"use client";

/**
 * Browser-safe PGPJS helpers.
 * NEVER import private keys, keystore loaders, or server.ts from this module.
 */
import * as openpgp from "openpgp";

export async function encryptToPublicKey(message: string, publicKeyArmored: string): Promise<string> {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  if (key.isPrivate()) {
    throw new Error("Security violation: a private key must never be used in the client bundle.");
  }
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted as string;
}

export async function verifySignature(options: {
  message: string;
  publicKeyArmored: string;
  detachedSignature?: string;
}): Promise<{ valid: boolean }> {
  const key = await openpgp.readKey({ armoredKey: options.publicKeyArmored });
  if (options.detachedSignature) {
    const signature = await openpgp.readSignature({ armoredSignature: options.detachedSignature });
    const message = await openpgp.createMessage({ text: options.message });
    const result = await openpgp.verify({ message, signature, verificationKeys: key });
    try {
      await result.signatures[0]?.verified;
      return { valid: true };
    } catch {
      return { valid: false };
    }
  }
  const cleartext = await openpgp.readCleartextMessage({ cleartextMessage: options.message });
  const result = await openpgp.verify({ message: cleartext, verificationKeys: key });
  try {
    await result.signatures[0]?.verified;
    return { valid: true };
  } catch {
    return { valid: false };
  }
}
`
  });

  files.push({
    relativePath: `${base}/server.${ext}`,
    action: "create",
    content: `import "server-only";
import * as openpgp from "openpgp";
import { loadPrivateKey, loadPublicKey } from "./keys";

if (typeof window !== "undefined") {
  throw new Error("src/lib/pgpjs/server.ts is server-only and must not run in the browser.");
}

export async function encryptMessage(message: string, publicKeyArmored: string): Promise<string> {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted as string;
}

export async function decryptMessage(ciphertext: string, passphrase?: string): Promise<string> {
  const privateKey = await loadPrivateKey(passphrase);
  const message = await openpgp.readMessage({ armoredMessage: ciphertext });
  const decrypted = await openpgp.decrypt({
    message,
    decryptionKeys: privateKey
  });
  return decrypted.data as string;
}

export { loadPrivateKey, loadPublicKey };
`
  });

  files.push({
    relativePath: `${base}/keys.${ext}`,
    action: "create",
    content: `import "server-only";
import { readFile } from "node:fs/promises";
import * as openpgp from "openpgp";

if (typeof window !== "undefined") {
  throw new Error("keys.ts is server-only. Do not import it from a Client Component.");
}

export async function loadPublicKey(file = process.env.PGPJS_SERVER_PUBLIC_KEY_FILE): Promise<openpgp.Key> {
  if (!file) {
    throw new Error("PGPJS_SERVER_PUBLIC_KEY_FILE is not set.");
  }
  const armored = await readFile(file, "utf8");
  return openpgp.readKey({ armoredKey: armored });
}

export async function loadPrivateKey(passphrase?: string): Promise<openpgp.PrivateKey> {
  const file = process.env.PGPJS_SERVER_PRIVATE_KEY_FILE;
  if (!file) {
    throw new Error("PGPJS_SERVER_PRIVATE_KEY_FILE is not set. Never inline a private key.");
  }
  const armored = await readFile(file, "utf8");
  const key = await openpgp.readPrivateKey({ armoredKey: armored });
  if (key.isDecrypted()) return key;
  const pass = passphrase ?? (process.env.PGPJS_PASSPHRASE_FILE
    ? (await readFile(process.env.PGPJS_PASSPHRASE_FILE, "utf8")).trim()
    : undefined);
  if (!pass) {
    throw new Error("Private key is encrypted. Set PGPJS_PASSPHRASE_FILE.");
  }
  return openpgp.decryptKey({ privateKey: key, passphrase: pass });
}
`
  });

  files.push({
    relativePath: `${base}/encryption.${ext}`,
    action: "create",
    content: `import "server-only";
import { encryptMessage, decryptMessage } from "./server";

export { encryptMessage, decryptMessage };

export async function encryptJson(data: unknown, publicKeyArmored: string): Promise<string> {
  return encryptMessage(JSON.stringify(data), publicKeyArmored);
}

export async function decryptJson<T>(ciphertext: string, passphrase?: string): Promise<T> {
  const text = await decryptMessage(ciphertext, passphrase);
  return JSON.parse(text) as T;
}
`
  });

  const routeBase = info.hasSrcDir ? "src/app" : "app";
  if (info.framework === "next-app") {
    files.push({
      relativePath: `${routeBase}/api/pgpjs/echo/route.${ext}`,
      action: "create",
      content: `import { decryptMessage, encryptMessage } from "@/lib/pgpjs/server";
import { loadPublicKey } from "@/lib/pgpjs/keys";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  const body = await request.text();
  const plaintext = await decryptMessage(body);
  const reply = JSON.stringify({ ok: true, echo: plaintext });
  const pub = await loadPublicKey();
  const encrypted = await encryptMessage(reply, pub.armor());
  return new Response(encrypted, {
    status: 200,
    headers: { "Content-Type": "application/pgp-encrypted" }
  });
}
`
    });
  }

  return files.map((f) => ({
    ...f,
    action: existsSync(join(info.cwd, f.relativePath)) ? "skip" : "create"
  }));
}

export function nodeLibFiles(info: ProjectInfo): PlannedFile[] {
  const ext = info.isTypeScript ? "ts" : "js";
  const base = info.hasSrcDir ? "src/lib/pgpjs" : "lib/pgpjs";
  return [
    {
      relativePath: `${base}/index.${ext}`,
      action: existsSync(join(info.cwd, `${base}/index.${ext}`)) ? "skip" : "create",
      content: `import * as openpgp from "openpgp";
import { readFile } from "node:fs/promises";

export async function encryptMessage(message: string, publicKeyArmored: string): Promise<string> {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted as string;
}

export async function decryptMessage(ciphertext: string, privateKeyPath: string, passphrase?: string): Promise<string> {
  const armored = await readFile(privateKeyPath, "utf8");
  let key = await openpgp.readPrivateKey({ armoredKey: armored });
  if (!key.isDecrypted()) {
    if (!passphrase) throw new Error("Passphrase required");
    key = await openpgp.decryptKey({ privateKey: key, passphrase });
  }
  const message = await openpgp.readMessage({ armoredMessage: ciphertext });
  const decrypted = await openpgp.decrypt({ message, decryptionKeys: key });
  return decrypted.data as string;
}
`
    }
  ];
}
