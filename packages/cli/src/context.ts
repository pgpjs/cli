import { resolveConfig, type ResolvedConfig } from "@pgpjs/config";
import { Keystore, PgpjsError, parseByteSize, assertNodeVersion } from "@pgpjs/core";
import { readFile } from "node:fs/promises";
import { stdin as stdinFd } from "node:process";

export interface GlobalFlags {
  json?: boolean;
  quiet?: boolean;
  verbose?: boolean;
  noColor?: boolean;
  noInput?: boolean;
  config?: string;
  home?: string;
  configFormat?: "any" | "json";
}

export interface CliContext {
  flags: GlobalFlags;
  json: boolean;
  quiet: boolean;
  verbose: boolean;
  color: boolean;
  interactive: boolean;
  resolved: ResolvedConfig;
  keystore: Keystore;
  maxFileSize: number;
}

export function detectNonInteractive(flags: GlobalFlags): boolean {
  if (flags.json) return true;
  if (flags.noInput) return true;
  if (process.stdin.isTTY === false) return true;
  if (process.env["CI"] === "true") return true;
  if (process.env["PGPJS_NON_INTERACTIVE"] === "1") return true;
  return false;
}

export function detectColor(flags: GlobalFlags): boolean {
  if (flags.noColor) return false;
  if (process.env["NO_COLOR"]) return false;
  if (process.env["TERM"] === "dumb") return false;
  if (process.env["FORCE_COLOR"] === "0") return false;
  if (process.env["FORCE_COLOR"]) return true;
  return Boolean(process.stdout.isTTY);
}

export async function createContext(flags: GlobalFlags): Promise<CliContext> {
  assertNodeVersion("20.10.0");
  const resolved = await resolveConfig({
    home: flags.home,
    configPath: flags.config,
    configFormat: flags.configFormat ?? "any"
  });
  const keystore = new Keystore(resolved.keystoreRoot);
  const json = Boolean(flags.json);
  const interactive = !detectNonInteractive(flags);
  return {
    flags,
    json,
    quiet: Boolean(flags.quiet),
    verbose: Boolean(flags.verbose),
    color: detectColor(flags) && !json,
    interactive,
    resolved,
    keystore,
    maxFileSize: parseByteSize(resolved.config.maxFileSize)
  };
}

export async function readPassphrase(options: {
  passphraseFile?: string | undefined;
  passphraseFd?: string | undefined;
  interactive: boolean;
  prompt: () => Promise<string>;
}): Promise<string | undefined> {
  if (options.passphraseFile) {
    const text = await readFile(options.passphraseFile, "utf8");
    return text.replace(/\r?\n$/, "");
  }
  if (options.passphraseFd) {
    const fd = Number(options.passphraseFd);
    const { readSync, fstatSync } = await import("node:fs");
    const size = fstatSync(fd).size || 4096;
    const buf = Buffer.alloc(size);
    const n = readSync(fd, buf, 0, buf.length, null);
    return buf.subarray(0, n).toString("utf8").replace(/\r?\n$/, "");
  }
  if (process.env["PGPJS_PASSPHRASE_FILE"]) {
    const text = await readFile(process.env["PGPJS_PASSPHRASE_FILE"], "utf8");
    return text.replace(/\r?\n$/, "");
  }
  if (options.interactive) {
    return options.prompt();
  }
  return undefined;
}

export function requireInteractive(ctx: CliContext, flagHint: string): void {
  if (!ctx.interactive) {
    throw new PgpjsError(
      "NON_INTERACTIVE",
      `This operation needs input but the session is non-interactive. Provide ${flagHint}.`
    );
  }
}

export { stdinFd };
