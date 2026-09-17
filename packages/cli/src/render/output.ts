import chalk from "chalk";
import { redact } from "@pgpjs/security";
import { EXIT_CODES, JSON_SCHEMA_VERSION, PgpjsError, isPgpjsError, type ExitCode } from "@pgpjs/core";

export interface OutputMode {
  json: boolean;
  quiet: boolean;
  verbose: boolean;
  color: boolean;
  command: string;
}

export function isJsonMode(mode: OutputMode): boolean {
  return mode.json;
}

export function writeStdout(text: string, mode: OutputMode): void {
  const payload = mode.json ? text : redact(text);
  process.stdout.write(payload.endsWith("\n") ? payload : `${payload}\n`);
}

export function writeStderr(text: string): void {
  process.stderr.write(`${redact(text)}\n`);
}

export function jsonOk(command: string, data: unknown): string {
  return JSON.stringify({ ok: true, version: JSON_SCHEMA_VERSION, command, data });
}

export function jsonErr(command: string, error: PgpjsError): string {
  return JSON.stringify({
    ok: false,
    version: JSON_SCHEMA_VERSION,
    command,
    error: error.toJSON()
  });
}

export function emitSuccess(mode: OutputMode, data: unknown, human: () => void): void {
  if (mode.json) {
    writeStdout(jsonOk(mode.command, data), mode);
    return;
  }
  if (!mode.quiet) human();
}

export function emitError(mode: OutputMode, err: unknown): ExitCode {
  const mapped = toPgpjsError(err);
  if (mode.json) {
    writeStdout(jsonErr(mode.command, mapped), mode);
  } else {
    const accent = mode.color ? chalk.red : (s: string) => s;
    writeStderr(accent(`✗ ${mapped.message}`));
    if (mapped.hint && !mode.quiet) {
      writeStderr(`  ${mapped.hint}`);
    }
    if (mode.verbose && mapped.details && Object.keys(mapped.details).length > 0) {
      writeStderr(`  ${JSON.stringify(mapped.details)}`);
    }
  }
  return mapped.exitCode;
}

export function toPgpjsError(err: unknown): PgpjsError {
  if (isPgpjsError(err)) return err;
  if (err && typeof err === "object" && "code" in err) {
    const code = String((err as { code: string }).code);
    if (code === "CONFIG_INVALID" || code === "CONFIG_NOT_FOUND") {
      return new PgpjsError(code, err instanceof Error ? err.message : "Configuration error.");
    }
  }
  if (err instanceof Error) {
    return new PgpjsError("GENERIC_ERROR", err.message, { cause: err });
  }
  return new PgpjsError("GENERIC_ERROR", "An unexpected error occurred.");
}

export function blue(mode: OutputMode, text: string): string {
  if (!mode.color) return text;
  return chalk.hex("#3B82F6")(text);
}

export function green(mode: OutputMode, text: string): string {
  if (!mode.color) return text;
  return chalk.green(text);
}

export function yellow(mode: OutputMode, text: string): string {
  if (!mode.color) return text;
  return chalk.yellow(text);
}

export function banner(mode: OutputMode): void {
  if (mode.json || mode.quiet) return;
  process.stderr.write(`${blue(mode, "PGPJS CLI")}\n`);
  process.stderr.write(`${blue(mode, "OpenPGP encryption toolkit")}\n\n`);
}

export { EXIT_CODES };
