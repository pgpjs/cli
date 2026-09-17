import { PgpjsError } from "./errors.js";

const FINGERPRINT_LENGTHS = new Set([32, 40, 64]);

export function normalizeFingerprint(input: string): string {
  return input.replace(/^0x/i, "").replace(/[\s:]/g, "").toUpperCase();
}

export function formatFingerprint(input: string): string {
  const hex = normalizeFingerprint(input);
  const groups = hex.match(/.{1,4}/g);
  return groups ? groups.join(" ") : hex;
}

export function isHex(value: string): boolean {
  return /^[0-9A-F]+$/.test(value);
}

export type IdentityKind = "fingerprint" | "long-key-id" | "short-key-id" | "userid";

export function classifyIdentity(raw: string): { kind: IdentityKind; value: string } {
  const trimmed = raw.trim();
  const hex = normalizeFingerprint(trimmed);
  if (isHex(hex)) {
    if (hex.length === 8) {
      return { kind: "short-key-id", value: hex };
    }
    if (hex.length === 16) {
      return { kind: "long-key-id", value: hex };
    }
    if (FINGERPRINT_LENGTHS.has(hex.length)) {
      return { kind: "fingerprint", value: hex };
    }
  }
  return { kind: "userid", value: trimmed };
}

export function rejectShortKeyId(raw: string): void {
  const { kind } = classifyIdentity(raw);
  if (kind === "short-key-id") {
    throw new PgpjsError(
      "KEY_MALFORMED",
      "32-bit short key IDs are rejected because they are trivially collidable. Use a full fingerprint or 64-bit long key ID.",
      { details: { input: raw } }
    );
  }
}

export function fingerprintsEqual(a: string, b: string): boolean {
  return normalizeFingerprint(a) === normalizeFingerprint(b);
}

export function fingerprintPrefix(fp: string, chars = 8): string {
  return normalizeFingerprint(fp).slice(0, chars);
}
