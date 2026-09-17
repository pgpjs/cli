import { mkdtemp, writeFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildProgram } from "./program.js";
import { formatRootHelp, formatVersion, stripAnsi } from "./render/terminal.js";
import { detectProject } from "./detect/project.js";
import { planInit, writePlan, nextLibFiles } from "./scaffold/files.js";

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
  it("prints a terminal splash, not a web page", () => {
    const text = formatRootHelp(false, "1.0.0");
    expect(text).toContain("PGPJS CLI");
    expect(text).toContain("OpenPGP encryption toolkit");
    expect(text).toContain("$ pgpjs key generate");
    expect(text).toContain("$ pgpjs encrypt message.txt");
    expect(text).toContain("READY • LOCAL CRYPTO");
    expect(text).toContain("init");
    expect(text).toContain("encrypt");
    expect(text).toContain("mcp");
    expect(text).toContain("pgpjs");
    expect(text).not.toContain("http://");
    expect(text).not.toContain("https://");
    expect(text).not.toContain("<html");
    expect(text).not.toContain("<!DOCTYPE");
  });

  it("aligns the CLI version badge", () => {
    const lines = formatVersion(false, "1.0.0").split("\n");
    const top = lines.find((l) => l.includes("┌"));
    const mid = lines.find((l) => l.includes("CLI 1.0.0"));
    const bot = lines.find((l) => l.includes("└"));
    expect(top).toBeDefined();
    expect(mid).toBeDefined();
    expect(bot).toBeDefined();
    expect(stripAnsi(top!).length).toBe(stripAnsi(mid!).length);
    expect(stripAnsi(bot!).length).toBe(stripAnsi(mid!).length);
  });

  it("prints a terminal version screen", () => {
    const text = formatVersion(false, "1.0.0");
    expect(text).toContain("PGPJS CLI");
    expect(text).toContain("CLI 1.0.0");
    expect(text).toContain("READY • LOCAL CRYPTO");
  });

  it("styles subcommand help as a terminal screen", () => {
    const program = buildProgram();
    const key = program.commands.find((c) => c.name() === "key");
    expect(key).toBeDefined();
    const text = key!.helpInformation();
    expect(text).toContain("PGPJS CLI");
    expect(text).toContain("READY • LOCAL CRYPTO");
    expect(text).toContain("generate");
    expect(text).toContain("$ pgpjs key generate");
    expect(text).not.toContain("http://");
    expect(text).not.toContain("https://");
  });
});
