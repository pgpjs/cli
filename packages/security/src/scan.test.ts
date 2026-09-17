import { mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanProject } from "./scan.js";

describe("security scan", () => {
  it("flags a planted private key without echoing it", () => {
    const dir = mkdtempSync(join(tmpdir(), "pgpjs-scan-"));
    try {
      writeFileSync(join(dir, "oops.ts"), "const x = `-----BEGIN PGP PRIVATE KEY BLOCK-----\\nSECRET\\n-----END PGP PRIVATE KEY BLOCK-----`;\n");
      writeFileSync(join(dir, ".gitignore"), "node_modules\n");
      const result = scanProject({ cwd: dir, failOn: "high" });
      expect(result.failed).toBe(true);
      expect(result.findings.some((f) => f.id === "private-key-in-tree")).toBe(true);
      const dumped = JSON.stringify(result);
      expect(dumped).not.toContain("SECRET");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("flags MCP decrypt enabled", () => {
    const dir = mkdtempSync(join(tmpdir(), "pgpjs-scan-mcp-"));
    try {
      mkdirSync(join(dir, ".pgpjs"), { recursive: true });
      writeFileSync(join(dir, ".gitignore"), ".pgpjs/\n");
      writeFileSync(
        join(dir, ".pgpjs/mcp.config.json"),
        JSON.stringify({ version: 1, permissions: { decrypt: true, sign: false, exportPrivateKeys: false } })
      );
      const result = scanProject({ cwd: dir, failOn: "high" });
      expect(result.findings.some((f) => f.id === "mcp-decrypt-enabled")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("--fix adds gitignore entries", () => {
    const dir = mkdtempSync(join(tmpdir(), "pgpjs-scan-fix-"));
    try {
      writeFileSync(join(dir, ".gitignore"), "node_modules\n");
      scanProject({ cwd: dir, failOn: "critical", fix: true });
      const gi = readFileSync(join(dir, ".gitignore"), "utf8");
      expect(gi).toContain(".pgpjs/");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
