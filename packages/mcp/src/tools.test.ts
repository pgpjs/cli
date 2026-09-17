import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { generateKey, Keystore } from "@pgpjs/core";
import { DEFAULT_MCP_CONFIG } from "./config.js";
import { executeTool, PRIVATE_KEY_EXPORT_IMPLEMENTED, toolSchemas, TOOL_CAPABILITY } from "./tools.js";
import { RateLimiter } from "./rate-limit.js";
import type { ToolContext } from "./tools.js";

const PASS = "correct-horse-battery-staple-test-only";

async function ctx(overrides: Partial<typeof DEFAULT_MCP_CONFIG.permissions> = {}): Promise<{
  ctx: ToolContext;
  dir: string;
  fingerprint: string;
}> {
  const dir = await mkdtemp(join(tmpdir(), "pgpjs-tool-"));
  const keystore = new Keystore(dir);
  const generated = await generateKey({ name: "T", email: "t@example.com", passphrase: PASS });
  await keystore.saveGenerated({
    fingerprint: generated.fingerprint,
    publicKeyArmored: generated.publicKeyArmored,
    privateKeyArmored: generated.privateKeyArmored,
    revocationCertificate: generated.revocationCertificate
  });
  return {
    dir,
    fingerprint: generated.fingerprint,
    ctx: {
      cwd: dir,
      keystore,
      mcpConfig: {
        ...DEFAULT_MCP_CONFIG,
        permissions: { ...DEFAULT_MCP_CONFIG.permissions, ...overrides }
      },
      token: null,
      passphrase: PASS,
      auditPath: join(dir, "audit.log"),
      limiter: new RateLimiter()
    }
  };
}

describe("MCP tools", () => {
  it("lists advertised tools matching the permission map", () => {
    expect(Object.keys(toolSchemas).sort()).toEqual(Object.keys(TOOL_CAPABILITY).sort());
    expect(PRIVATE_KEY_EXPORT_IMPLEMENTED).toBe(false);
    expect(Object.keys(toolSchemas).some((k) => k.toLowerCase().includes("private"))).toBe(false);
  });

  it("encrypt is allowed by default and echoes fingerprint", async () => {
    const { ctx: c, dir, fingerprint } = await ctx();
    try {
      const result = await executeTool(
        "pgpjs_encrypt",
        { message: "hi", recipient: "t@example.com", armor: true },
        c
      );
      expect(result.ok).toBe(true);
      const data = result.data as { recipients: string[] };
      expect(data.recipients).toContain(fingerprint);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("decrypt is denied by default", async () => {
    const { ctx: c, dir } = await ctx();
    try {
      const result = await executeTool("pgpjs_decrypt", { message: "-----BEGIN PGP MESSAGE-----\n=\n-----END PGP MESSAGE-----" }, c);
      expect(result.ok).toBe(false);
      expect((result.error as { code: string }).code).toBe("PERMISSION_DENIED");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects invalid tool input", async () => {
    const { ctx: c, dir } = await ctx();
    try {
      const result = await executeTool("pgpjs_key_info", { id: "" }, c);
      expect(result.ok).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
