import { spawnSync } from "node:child_process";
import { PgpjsError } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { detectProject, installArgs } from "../detect/project.js";
import { emitSuccess, green, yellow, type OutputMode } from "../render/output.js";
import { nextLibFiles, nodeLibFiles, writePlan } from "../scaffold/files.js";

export async function runInstall(
  ctx: CliContext,
  target: string,
  opts: { force?: boolean; skipInstall?: boolean },
  mode: OutputMode
): Promise<void> {
  const info = detectProject(ctx.resolved.projectRoot);
  if (target === "next") {
    if (info.framework !== "next-app" && info.framework !== "next-pages" && !opts.force) {
      throw new PgpjsError("USAGE_ERROR", "This does not look like a Next.js project.", {
        hint: "Run from a Next.js app, or pass --force."
      });
    }
  }

  const files = target === "next" ? nextLibFiles(info) : nodeLibFiles(info);
  const written = writePlan(info.cwd, files, false);

  const deps = target === "next" ? ["openpgp@6.3.1", "server-only"] : ["openpgp@6.3.1"];
  if (!opts.skipInstall && info.hasPackageJson) {
    const install = installArgs(info.packageManager, deps);
    const result = spawnSync(install.cmd, install.args, {
      cwd: info.cwd,
      stdio: mode.json ? "ignore" : "inherit"
    });
    if (result.status !== 0) {
      throw new PgpjsError("IO_ERROR", `Failed to install dependencies with ${info.packageManager}.`);
    }
  }

  emitSuccess(
    mode,
    {
      target,
      framework: info.framework,
      files: written,
      dependencies: deps,
      packageManager: info.packageManager
    },
    () => {
      console.log(`${green(mode, "✓")} Installed PGPJS ${target} integration\n`);
      for (const f of files) {
        if (f.action === "skip") console.log(`${yellow(mode, "•")} skipped ${f.relativePath}`);
        else console.log(`${green(mode, "✓")} ${f.relativePath}`);
      }
      if (target === "next") {
        console.log(`\n${yellow(mode, "┌──────────────────────────────────────────────────────────┐")}`);
        console.log(`${yellow(mode, "│  PRIVATE KEYS MUST NEVER REACH THE BROWSER BUNDLE.      │")}`);
        console.log(`${yellow(mode, "│  Import @/lib/pgpjs/server only from Server Components, │")}`);
        console.log(`${yellow(mode, "│  Route Handlers, and Server Actions.                    │")}`);
        console.log(`${yellow(mode, "│  Client Components may import @/lib/pgpjs/client only.  │")}`);
        console.log(`${yellow(mode, "└──────────────────────────────────────────────────────────┘")}`);
        console.log("\nExample:\n");
        console.log('  import { encryptMessage } from "@/lib/pgpjs/server";');
        console.log("  const encrypted = await encryptMessage(message, publicKey);\n");
      }
    }
  );
}
