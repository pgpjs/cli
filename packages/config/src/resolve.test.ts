import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveConfig } from "./resolve.js";
import { defineConfig, pgpjsConfigSchema } from "./schema.js";

describe("config", () => {
  it("defineConfig is identity", () => {
    const c = defineConfig({ defaultArmor: false, keyDirectory: ".pgpjs/keys" });
    expect(c.defaultArmor).toBe(false);
  });

  it("rejects secrets in config", () => {
    const parsed = pgpjsConfigSchema.safeParse({
      defaultKey: "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    });
    expect(parsed.success).toBe(false);
  });

  it("project config wins over defaults and records origin", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pgpjs-cfg-"));
    try {
      writeFileSync(join(dir, "pgpjs.config.json"), JSON.stringify({ defaultArmor: false }));
      const resolved = await resolveConfig({ cwd: dir, home: join(dir, "home") });
      expect(resolved.config.defaultArmor).toBe(false);
      expect(resolved.origins["defaultArmor"]).toBe("project");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("env overrides project", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pgpjs-cfg-"));
    try {
      mkdirSync(join(dir, "home"));
      writeFileSync(join(dir, "pgpjs.config.json"), JSON.stringify({ defaultArmor: false }));
      process.env["PGPJS_DEFAULT_ARMOR"] = "true";
      const resolved = await resolveConfig({ cwd: dir, home: join(dir, "home") });
      expect(resolved.config.defaultArmor).toBe(true);
      expect(resolved.origins["defaultArmor"]).toBe("env");
    } finally {
      delete process.env["PGPJS_DEFAULT_ARMOR"];
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
