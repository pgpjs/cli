import { describe, expect, it } from "vitest";
import { redact, registerSensitive, clearSensitiveRegistry } from "./redact.js";

describe("redact", () => {
  it("redacts private key blocks", () => {
    const input = "x -----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET\n-----END PGP PRIVATE KEY BLOCK----- y";
    const out = redact(input);
    expect(out).not.toContain("SECRET");
    expect(out).toContain("[REDACTED PRIVATE KEY]");
    expect(out.startsWith("x ")).toBe(true);
  });

  it("redacts MCP tokens", () => {
    const token = "pgpjs_mcp_abcd1234_" + "A".repeat(43) + "_wxyz";
    expect(redact(`token=${token}`)).toBe("token=pgpjs_mcp_[REDACTED]");
  });

  it("redacts registered secrets", () => {
    registerSensitive("correct-horse-battery-staple-test-only");
    expect(redact("pw=correct-horse-battery-staple-test-only")).toBe("pw=[REDACTED]");
    clearSensitiveRegistry();
  });
});
