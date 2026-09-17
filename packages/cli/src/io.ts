import { fstatSync } from "node:fs";
import { stat } from "node:fs/promises";
import { PgpjsError } from "@pgpjs/core";

function stdinIsPipe(): boolean {
  try {
    const st = fstatSync(0);
    return st.isFIFO() || st.isSocket();
  } catch {
    return false;
  }
}

export async function resolveInput(positional: string | undefined): Promise<{
  kind: "file" | "stdin";
  path?: string;
}> {
  const piped = stdinIsPipe();
  if (positional && positional !== "-" && piped) {
    throw new PgpjsError(
      "USAGE_ERROR",
      "Provide either a file path or piped stdin, not both."
    );
  }
  if (!positional || positional === "-") {
    if (!piped && positional !== "-") {
      throw new PgpjsError("USAGE_ERROR", "No input file. Pass a path or pipe stdin.");
    }
    return { kind: "stdin" };
  }
  try {
    await stat(positional);
  } catch {
    throw new PgpjsError("INPUT_NOT_FOUND", `Input file not found: ${positional}`, {
      details: { path: positional }
    });
  }
  return { kind: "file", path: positional };
}

export async function readStdinBytes(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

export function derivedOutputName(inputPath: string, armor: boolean, kind: "encrypt" | "sign"): string {
  if (kind === "sign") {
    return armor ? `${inputPath}.asc` : `${inputPath}.sig`;
  }
  return armor ? `${inputPath}.asc` : `${inputPath}.gpg`;
}

export async function assertOutputPath(path: string, force: boolean): Promise<void> {
  try {
    await stat(path);
    if (!force) {
      throw new PgpjsError("OUTPUT_EXISTS", `Output file already exists: ${path}`, {
        details: { path },
        hint: "Pass --force to overwrite."
      });
    }
  } catch (err) {
    if (err instanceof PgpjsError) throw err;
  }
}

export function looksArmored(data: Uint8Array | string): boolean {
  const text = typeof data === "string" ? data : new TextDecoder().decode(data.subarray(0, 64));
  return text.includes("-----BEGIN PGP");
}
