import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { detectProject } from "../packages/cli/src/detect/project.js";
import { nextLibFiles, nodeLibFiles, planInit, reactLibFiles, writePlan } from "../packages/cli/src/scaffold/files.js";
import { scanProject } from "../packages/security/src/scan.js";

describe("e2e scaffold", () => {
  it("init + install next is clean for security scan", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-e2e-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "app", dependencies: { next: "15.0.0" } })
      );
      await writeFile(join(dir, "tsconfig.json"), "{}");
      await mkdir(join(dir, "src/app"), { recursive: true });
      const info = detectProject(dir);
      writePlan(dir, planInit(info), false);
      writePlan(dir, nextLibFiles(info), false);
      const scan = scanProject({ cwd: dir, failOn: "high" });
      const unexpected = scan.findings.filter(
        (f) => f.id !== "missing-gitignore" && f.severity === "critical"
      );
      expect(unexpected).toEqual([]);
      expect(scan.findings.some((f) => f.id === "private-key-in-tree")).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("init + install react/node is clean for security scan", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-e2e-react-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "app", dependencies: { react: "18.0.0", vite: "6.0.0" } })
      );
      await writeFile(join(dir, "tsconfig.json"), "{}");
      await mkdir(join(dir, "src"), { recursive: true });
      const info = detectProject(dir);
      expect(info.framework).toBe("vite");
      writePlan(dir, planInit(info), false);
      writePlan(dir, reactLibFiles(info), false);
      writePlan(dir, nodeLibFiles(info), false);
      const scan = scanProject({ cwd: dir, failOn: "high" });
      const unexpected = scan.findings.filter(
        (f) => f.id !== "missing-gitignore" && f.severity === "critical"
      );
      expect(unexpected).toEqual([]);
      expect(scan.findings.some((f) => f.id === "private-key-in-tree")).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
