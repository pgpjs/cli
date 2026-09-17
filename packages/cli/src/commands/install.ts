import { spawnSync } from "node:child_process";
import { PgpjsError } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { detectProject, installArgs } from "../detect/project.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { boxLines, heading, muted, statusLine } from "../render/terminal.js";
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
      const color = mode.color;
      const lines = [
        heading(color, `Installed PGPJS ${target} integration`),
        "",
        ...files.map((f) =>
          f.action === "skip"
            ? statusLine(color, "dot", `skipped ${f.relativePath}`)
            : statusLine(color, "ok", f.relativePath)
        )
      ];
      if (target === "next") {
        lines.push(
          "",
          ...boxLines(
            color,
            [
              "PRIVATE KEYS MUST NEVER REACH THE BROWSER BUNDLE.",
              "Import @/lib/pgpjs/server only from Server Components,",
              "Route Handlers, and Server Actions.",
              "Client Components may import @/lib/pgpjs/client only."
            ],
            "yellow"
          ),
          "",
          muted(color, "Example (server):"),
          muted(color, 'import { encryptMessage } from "@/lib/pgpjs/server";')
        );
      }
      return lines;
    }
  );
}
