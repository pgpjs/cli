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
  const ts = info.isTypeScript;
  const base = info.hasSrcDir ? "src/lib/pgpjs" : "lib/pgpjs";
  const files: PlannedFile[] = [];

  files.push({
    relativePath: `${base}/keys.${ext}`,
    action: existsSync(join(info.cwd, `${base}/keys.${ext}`)) ? "skip" : "create",
    content: `import { readFile } from "node:fs/promises";
import * as openpgp from "openpgp";

if (typeof window !== "undefined") {
  throw new Error("keys.ts is server-only. Do not import it from React or the browser.");
}

export async function loadPublicKey(file = process.env.PGPJS_SERVER_PUBLIC_KEY_FILE)${ts ? ": Promise<openpgp.Key>" : ""} {
  if (!file) throw new Error("PGPJS_SERVER_PUBLIC_KEY_FILE is not set.");
  return openpgp.readKey({ armoredKey: await readFile(file, "utf8") });
}

export async function loadPrivateKey(passphrase${ts ? "?: string" : ""})${ts ? ": Promise<openpgp.PrivateKey>" : ""} {
  const file = process.env.PGPJS_SERVER_PRIVATE_KEY_FILE;
  if (!file) throw new Error("PGPJS_SERVER_PRIVATE_KEY_FILE is not set. Never inline a private key.");
  const key = await openpgp.readPrivateKey({ armoredKey: await readFile(file, "utf8") });
  if (key.isDecrypted()) return key;
  const pass = passphrase ?? (process.env.PGPJS_PASSPHRASE_FILE
    ? (await readFile(process.env.PGPJS_PASSPHRASE_FILE, "utf8")).trim()
    : undefined);
  if (!pass) throw new Error("Private key is encrypted. Set PGPJS_PASSPHRASE_FILE.");
  return openpgp.decryptKey({ privateKey: key, passphrase: pass });
}
`
  });

  files.push({
    relativePath: `${base}/server.${ext}`,
    action: existsSync(join(info.cwd, `${base}/server.${ext}`)) ? "skip" : "create",
    content: `import * as openpgp from "openpgp";
import { loadPrivateKey, loadPublicKey } from "./keys.${ext}";

if (typeof window !== "undefined") {
  throw new Error("server.ts is Node-only. Private keys must stay on the network server.");
}

export async function encryptMessage(message${ts ? ": string" : ""}, publicKeyArmored${ts ? ": string" : ""})${ts ? ": Promise<string>" : ""} {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted${ts ? " as string" : ""};
}

export async function decryptMessage(ciphertext${ts ? ": string" : ""}, passphrase${ts ? "?: string" : ""})${ts ? ": Promise<string>" : ""} {
  const privateKey = await loadPrivateKey(passphrase);
  const message = await openpgp.readMessage({ armoredMessage: ciphertext });
  const decrypted = await openpgp.decrypt({ message, decryptionKeys: privateKey });
  return decrypted.data${ts ? " as string" : ""};
}

export async function signMessage(message${ts ? ": string" : ""}, passphrase${ts ? "?: string" : ""})${ts ? ": Promise<string>" : ""} {
  const privateKey = await loadPrivateKey(passphrase);
  const signed = await openpgp.sign({
    message: await openpgp.createMessage({ text: message }),
    signingKeys: privateKey,
    detached: true,
    format: "armored"
  });
  return signed${ts ? " as string" : ""};
}

export { loadPrivateKey, loadPublicKey };
`
  });

  files.push({
    relativePath: `${base}/http.${ext}`,
    action: existsSync(join(info.cwd, `${base}/http.${ext}`)) ? "skip" : "create",
    content: `/**
 * Loopback HTTP API for a React (or other) client.
 * Private keys never leave this Node process.
 * CORS is limited to http(s)://127.0.0.1 and http(s)://localhost.
 *
 *   PGPJS_SERVER_PRIVATE_KEY_FILE=.pgpjs/keys/<fp>.sec.asc \\
 *   PGPJS_PASSPHRASE_FILE=./pass.txt \\
 *   node --experimental-strip-types src/lib/pgpjs/http.ts
 */
import { createServer${ts ? ", type IncomingMessage, type ServerResponse" : ""} } from "node:http";
import { pathToFileURL } from "node:url";
import { decryptMessage, encryptMessage, signMessage } from "./server.${ext}";
import { loadPublicKey } from "./keys.${ext}";

const HOST = process.env.PGPJS_HTTP_HOST ?? "127.0.0.1";
const PORT = Number(process.env.PGPJS_HTTP_PORT ?? "8788");

function loopbackOrigin(origin${ts ? "?: string" : ""}) {
  if (!origin) return null;
  try {
    const u = new URL(origin);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (u.hostname === "127.0.0.1" || u.hostname === "localhost") return origin;
  } catch {
    return null;
  }
  return null;
}

function setCors(req${ts ? ": IncomingMessage" : ""}, res${ts ? ": ServerResponse" : ""}) {
  const allowed = loopbackOrigin(typeof req.headers.origin === "string" ? req.headers.origin : undefined);
  if (allowed) {
    res.setHeader("Access-Control-Allow-Origin", allowed);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "content-type");
    res.setHeader("Vary", "Origin");
  }
}

async function readBody(req${ts ? ": IncomingMessage" : ""}) {
  const chunks${ts ? ": Buffer[]" : ""} = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

export function startPgpjsNetworkServer() {
  if (HOST !== "127.0.0.1" && HOST !== "localhost" && process.env.PGPJS_ALLOW_REMOTE !== "1") {
    throw new Error("Refusing non-loopback bind. Set PGPJS_ALLOW_REMOTE=1 only behind TLS.");
  }
  const server = createServer(async (req, res) => {
    try {
      setCors(req, res);
      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }
      if (req.method === "GET" && req.url === "/health") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, service: "pgpjs-node" }));
        return;
      }
      if (req.method === "POST" && req.url === "/pgpjs/decrypt") {
        const plaintext = await decryptMessage(await readBody(req));
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
        res.end(plaintext);
        return;
      }
      if (req.method === "POST" && req.url === "/pgpjs/sign") {
        const signature = await signMessage(await readBody(req));
        res.writeHead(200, { "content-type": "application/pgp-signature" });
        res.end(signature);
        return;
      }
      if (req.method === "POST" && req.url === "/pgpjs/encrypt") {
        const pub = await loadPublicKey();
        const encrypted = await encryptMessage(await readBody(req), pub.armor());
        res.writeHead(200, { "content-type": "application/pgp-encrypted" });
        res.end(encrypted);
        return;
      }
      res.writeHead(404);
      res.end("not found");
    } catch (err) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end(err instanceof Error ? err.message : "error");
    }
  });
  server.listen(PORT, HOST, () => {
    process.stderr.write(\`PGPJS node network listening on \${HOST}:\${PORT}\\n\`);
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startPgpjsNetworkServer();
}
`
  });

  files.push({
    relativePath: `${base}/index.${ext}`,
    action: existsSync(join(info.cwd, `${base}/index.${ext}`)) ? "skip" : "create",
    content: `export { encryptMessage, decryptMessage, signMessage } from "./server.${ext}";
export { startPgpjsNetworkServer } from "./http.${ext}";
`
  });

  return files;
}

export function reactLibFiles(info: ProjectInfo): PlannedFile[] {
  const ext = info.isTypeScript ? "ts" : "js";
  const base = info.hasSrcDir ? "src/lib/pgpjs" : "lib/pgpjs";
  return [
    {
      relativePath: `${base}/client.${ext}`,
      action: existsSync(join(info.cwd, `${base}/client.${ext}`)) ? "skip" : "create",
      content: `/**
 * Browser-safe PGPJS helpers for React.
 * NEVER import private keys, keystore loaders, or server.ts from this module.
 * Decrypt/sign over the network with pgpjs install node (127.0.0.1).
 */
import * as openpgp from "openpgp";

export async function encryptToPublicKey(message${info.isTypeScript ? ": string" : ""}, publicKeyArmored${info.isTypeScript ? ": string" : ""})${info.isTypeScript ? ": Promise<string>" : ""} {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  if (key.isPrivate()) {
    throw new Error("Security violation: a private key must never be used in the React bundle.");
  }
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted${info.isTypeScript ? " as string" : ""};
}

export async function postToNodeNetwork(path${info.isTypeScript ? ": string" : ""}, body${info.isTypeScript ? ": string" : ""}, baseUrl = "http://127.0.0.1:8788")${info.isTypeScript ? ": Promise<string>" : ""} {
  const res = await fetch(\`\${baseUrl}\${path}\`, {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body
  });
  if (!res.ok) throw new Error(\`PGPJS node network \${res.status}\`);
  return res.text();
}

export function decryptViaNode(ciphertext${info.isTypeScript ? ": string" : ""}, baseUrl = "http://127.0.0.1:8788")${info.isTypeScript ? ": Promise<string>" : ""} {
  return postToNodeNetwork("/pgpjs/decrypt", ciphertext, baseUrl);
}

export function signViaNode(message${info.isTypeScript ? ": string" : ""}, baseUrl = "http://127.0.0.1:8788")${info.isTypeScript ? ": Promise<string>" : ""} {
  return postToNodeNetwork("/pgpjs/sign", message, baseUrl);
}
`
    }
  ];
}
