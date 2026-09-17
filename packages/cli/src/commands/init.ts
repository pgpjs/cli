import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { CliContext } from "../context.js";
import { detectProject } from "../detect/project.js";
import { emitSuccess, green, yellow, type OutputMode } from "../render/output.js";
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
      emitSuccess(mode, { cancelled: true }, () => {
        console.log("Cancelled.");
      });
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
      console.log(green(mode, "PGPJS CLI"));
      console.log("OpenPGP encryption toolkit\n");
      console.log(`${green(mode, "✓")} Detected ${labelFramework(info.framework)}`);
      console.log(
        `${green(mode, "✓")} ${info.isTypeScript ? "TypeScript" : "JavaScript"} detected`
      );
      console.log(`${green(mode, "✓")} Package manager: ${info.packageManager}`);
      for (const f of plan) {
        if (f.action === "skip") {
          console.log(`${yellow(mode, "•")} skipped ${f.relativePath} (exists)`);
        } else if (opts.dryRun) {
          console.log(`${yellow(mode, "•")} would ${f.action} ${f.relativePath}`);
        } else if (f.action === "append") {
          console.log(`${green(mode, "✓")} appended ${f.relativePath}`);
        } else {
          console.log(`${green(mode, "✓")} created ${f.relativePath}`);
        }
      }
      if (!opts.dryRun) {
        console.log(`${green(mode, "✓")} PGPJS configuration created`);
        console.log(`${green(mode, "✓")} Environment template created`);
        console.log("\nNext:");
        console.log("  pgpjs install next     # Next.js App Router integration");
        console.log("  pgpjs key generate     # create a project key");
        console.log("  pgpjs doctor           # verify the setup");
      }
    }
  );
}

function labelFramework(fw: string): string {
  if (fw === "next-app") return "Next.js (App Router)";
  if (fw === "next-pages") return "Next.js (Pages Router)";
  if (fw === "node") return "Node.js";
  return fw;
}
