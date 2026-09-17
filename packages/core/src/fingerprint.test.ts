import { describe, expect, it } from "vitest";
import { classifyIdentity, formatFingerprint, normalizeFingerprint, rejectShortKeyId } from "./fingerprint.js";
import { PgpjsError } from "./errors.js";

describe("fingerprint", () => {
  it("formats spaced hex groups", () => {
    expect(formatFingerprint("a1b2c3d4e5f6071890abcdef123456789abcdef0")).toBe(
      "A1B2 C3D4 E5F6 0718 90AB CDEF 1234 5678 9ABC DEF0"
    );
  });

  it("normalizes 0x and spaces", () => {
    expect(normalizeFingerprint("0xA1B2 C3D4")).toBe("A1B2C3D4");
  });

  it("rejects 32-bit short key IDs", () => {
    expect(() => rejectShortKeyId("A1B2C3D4")).toThrow(PgpjsError);
    expect(() => rejectShortKeyId("A1B2C3D4")).toThrow(/collidable/);
  });

  it("classifies email as userid", () => {
    expect(classifyIdentity("alice@example.com").kind).toBe("userid");
  });

  it("classifies 64-bit long key IDs", () => {
    expect(classifyIdentity("A1B2C3D4E5F60718").kind).toBe("long-key-id");
  });
});
