import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectProject } from "./detect/project.js";
import { planInit, writePlan, nextLibFiles } from "./scaffold/files.js";
import { buildProgram } from "./program.js";

describe("project detection and init plan", () => {
  const dirs: string[] = [];
  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      await rm(d, { recursive: true, force: true });
    }
  });

  it("detects Next.js App Router + TypeScript + pnpm", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-init-"));
    dirs.push(dir);
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({ name: "app", dependencies: { next: "15.0.0" }, packageManager: "pnpm@10.0.0" })
    );
    await writeFile(join(dir, "tsconfig.json"), "{}");
    await mkdir(join(dir, "src/app"), { recursive: true });
    await writeFile(join(dir, "pnpm-lock.yaml"), "");
    const info = detectProject(dir);
    expect(info.framework).toBe("next-app");
    expect(info.isTypeScript).toBe(true);
    expect(info.packageManager).toBe("pnpm");
  });

  it("init plan creates config and gitignore", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-init-"));
    dirs.push(dir);
    await writeFile(join(dir, "package.json"), JSON.stringify({ name: "x" }));
    const plan = planInit(detectProject(dir));
    const written = writePlan(dir, plan, false);
    expect(written.some((w) => w.includes("pgpjs.config"))).toBe(true);
    expect(written.some((w) => w.includes(".gitignore"))).toBe(true);
  });

  it("install next scaffolds client/server split", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-next-"));
    dirs.push(dir);
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({ name: "app", dependencies: { next: "15.0.0" } })
    );
    await mkdir(join(dir, "src/app"), { recursive: true });
    await writeFile(join(dir, "tsconfig.json"), "{}");
    const files = nextLibFiles(detectProject(dir));
    writePlan(dir, files, false);
    const names = files.map((f) => f.relativePath).join("\n");
    expect(names).toContain("src/lib/pgpjs/client.ts");
    expect(names).toContain("src/lib/pgpjs/server.ts");
    expect(names).toContain("src/lib/pgpjs/keys.ts");
  });
});

describe("CLI help", () => {
  it("prints professional help", async () => {
    const program = buildProgram();
    const text = program.helpInformation();
    expect(text).toContain("init");
    expect(text).toContain("encrypt");
    expect(text).toContain("mcp");
  });
});
