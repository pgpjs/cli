import { describe, expect, it } from "vitest";
import { capabilityAllowed, denyReason, effectivePermissions, DEFAULT_PERMISSIONS } from "./permissions.js";

describe("MCP permission intersection", () => {
  it("token cannot widen a narrow config", () => {
    const config = { ...DEFAULT_PERMISSIONS, decrypt: false };
    const effective = effectivePermissions(config, ["decrypt", "encrypt"]);
    expect(effective.decrypt).toBe(false);
    expect(effective.encrypt).toBe(true);
    expect(denyReason("DECRYPT", config, ["decrypt"])).toEqual({ side: "config", capability: "DECRYPT" });
  });

  it("narrow token cannot use a permissive config", () => {
    const config = { ...DEFAULT_PERMISSIONS, decrypt: true };
    const effective = effectivePermissions(config, ["encrypt"]);
    expect(effective.decrypt).toBe(false);
    expect(effective.encrypt).toBe(true);
    expect(denyReason("DECRYPT", config, ["encrypt"])).toEqual({ side: "token", capability: "DECRYPT" });
  });

  it("EXPORT_PRIVATE_KEY is always denied", () => {
    const config = { ...DEFAULT_PERMISSIONS, exportPrivateKeys: true };
    const effective = effectivePermissions(config, "all");
    expect(effective.exportPrivateKeys).toBe(false);
    expect(capabilityAllowed(effective, "EXPORT_PRIVATE_KEY")).toBe(false);
    expect(denyReason("EXPORT_PRIVATE_KEY", config, "all")?.side).toBe("hard-limit");
  });
});
