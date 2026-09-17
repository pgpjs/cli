import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { CliContext } from "../context.js";
import { detectProject } from "../detect/project.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { heading, muted, promptLine, statusLine } from "../render/terminal.js";
import { promptConfirm } from "../prompts.js";
import { planInit, writePlan } from "../scaffold/files.js";
import { requireInteractive } from "../context.js";

export async function runInit(
  ctx: CliContext,
  opts: { dryRun?: boolean; yes?: boolean },
  mode: OutputMode
): Promise<void> {
  const info = detectProject(ctx.resolved.projectRoot);
  const plan = planInit(info);

  if (ctx.interactive && !opts.yes && !opts.dryRun) {
    const ok = await promptConfirm(
      `Initialize PGPJS in ${info.cwd}? This will create config files and update .gitignore.`
    );
    if (!ok) {
      emitSuccess(mode, { cancelled: true }, () => [muted(mode.color, "Cancelled.")]);
      return;
    }
  } else if (!ctx.interactive && !opts.yes && !opts.dryRun) {
    requireInteractive(ctx, "--yes");
  }

  if (!opts.dryRun) {
    await mkdir(join(info.cwd, ".pgpjs"), { recursive: true });
    await ctx.keystore.init();
  }

  const written = writePlan(info.cwd, plan, Boolean(opts.dryRun));

  emitSuccess(
    mode,
    {
      framework: info.framework,
      isTypeScript: info.isTypeScript,
      packageManager: info.packageManager,
      dryRun: Boolean(opts.dryRun),
      files: written,
      skipped: plan.filter((p) => p.action === "skip").map((p) => p.relativePath)
    },
    () => {
      const color = mode.color;
      const lines = [
        heading(color, "PGPJS CLI"),
        muted(color, "OpenPGP encryption toolkit"),
        "",
        statusLine(color, "ok", `Detected ${labelFramework(info.framework)}`),
        statusLine(color, "ok", `${info.isTypeScript ? "TypeScript" : "JavaScript"} detected`),
        statusLine(color, "ok", `Package manager: ${info.packageManager}`)
      ];
      for (const f of plan) {
        if (f.action === "skip") {
          lines.push(statusLine(color, "dot", `skipped ${f.relativePath} (exists)`));
        } else if (opts.dryRun) {
          lines.push(statusLine(color, "dot", `would ${f.action} ${f.relativePath}`));
        } else if (f.action === "append") {
          lines.push(statusLine(color, "ok", `appended ${f.relativePath}`));
        } else {
          lines.push(statusLine(color, "ok", `created ${f.relativePath}`));
        }
      }
      if (!opts.dryRun) {
        lines.push(statusLine(color, "ok", "PGPJS configuration created"));
        lines.push(statusLine(color, "ok", "Environment template created"));
        lines.push("", muted(color, "Next:"));
        lines.push(promptLine(color, "pgpjs install next"));
        lines.push(promptLine(color, "pgpjs key generate"));
        lines.push(promptLine(color, "pgpjs doctor"));
      }
      return lines;
    }
  );
}

function labelFramework(fw: string): string {
  if (fw === "next-app") return "Next.js (App Router)";
  if (fw === "next-pages") return "Next.js (Pages Router)";
  if (fw === "node") return "Node.js";
  return fw;
}
