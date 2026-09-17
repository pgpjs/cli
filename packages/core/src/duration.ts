import { PgpjsError } from "./errors.js";

const UNITS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 60 * 60 * 24,
  w: 60 * 60 * 24 * 7,
  y: 60 * 60 * 24 * 365
};

/**
 * Parse a duration like `30d`, `12h`, `1y`, or `never`.
 * Returns seconds, or `null` for never.
 */
export function parseDuration(input: string): number | null {
  const trimmed = input.trim().toLowerCase();
  if (trimmed === "never") {
    return null;
  }
  const match = /^(\d+)([smhdwy])$/.exec(trimmed);
  if (!match || match[1] === undefined || match[2] === undefined) {
    throw new PgpjsError("USAGE_ERROR", `Invalid duration '${input}'. Use e.g. 30d, 12h, 1y, or never.`, {
      details: { input }
    });
  }
  const n = Number(match[1]);
  const unit = match[2];
  const seconds = UNITS[unit];
  if (seconds === undefined) {
    throw new PgpjsError("USAGE_ERROR", `Unknown duration unit '${unit}'.`, { details: { input } });
  }
  return n * seconds;
}

export function durationToDate(input: string, from: Date = new Date()): Date | null {
  const seconds = parseDuration(input);
  if (seconds === null) {
    return null;
  }
  return new Date(from.getTime() + seconds * 1000);
}

export function formatIso(date: Date | null | undefined): string | null {
  if (!date) {
    return null;
  }
  return date.toISOString();
}
