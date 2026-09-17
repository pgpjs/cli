import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  authenticateToken,
  createToken,
  parseToken,
  revokeToken,
  rotateToken
} from "./tokens.js";
import { PgpjsError } from "@pgpjs/core";

describe("MCP tokens", () => {
  it("creates a well-formed token, stores only a hash, and authenticates", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-tok-"));
    const store = join(dir, "tokens.json");
    try {
      const { token, record } = await createToken({
        storePath: store,
        name: "Claude",
        scopes: ["encrypt", "verify"],
        expires: new Date(Date.now() + 86_400_000)
      });
      expect(token.startsWith("pgpjs_mcp_")).toBe(true);
      const parsed = parseToken(token);
      expect(parsed.id).toBe(record.id);
      expect(record.hash).not.toContain(token);
      const authed = await authenticateToken(store, token);
      expect(authed.id).toBe(record.id);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("revokes and rejects the token", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-tok-"));
    const store = join(dir, "tokens.json");
    try {
      const { token, record } = await createToken({
        storePath: store,
        name: "x",
        scopes: ["encrypt"],
        expires: new Date(Date.now() + 86_400_000)
      });
      await revokeToken(store, record.id);
      await expect(authenticateToken(store, token)).rejects.toMatchObject({ code: "TOKEN_REVOKED" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rotate kills the old secret immediately", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-tok-"));
    const store = join(dir, "tokens.json");
    try {
      const first = await createToken({
        storePath: store,
        name: "rot",
        scopes: ["encrypt"],
        expires: new Date(Date.now() + 86_400_000)
      });
      const rotated = await rotateToken(store, first.record.id);
      await expect(authenticateToken(store, first.token)).rejects.toBeInstanceOf(PgpjsError);
      const authed = await authenticateToken(store, rotated.token);
      expect(authed.name).toBe("rot");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects malformed tokens", () => {
    expect(() => parseToken("not-a-token")).toThrow(PgpjsError);
    expect(() => parseToken("pgpjs_mcp_short_nope_xx")).toThrow(PgpjsError);
  });
});
