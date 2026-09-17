import { EXIT_CODES } from "@pgpjs/core";
import { scanProject, type Severity } from "@pgpjs/security";
import type { CliContext } from "../context.js";
import { emitSuccess, green, yellow, type OutputMode } from "../render/output.js";

export async function runSecurityScan(
  ctx: CliContext,
  opts: { fix?: boolean; failOn?: string },
  mode: OutputMode
): Promise<number> {
  const failOn = (opts.failOn ?? "high") as Severity;
  const result = scanProject({
    cwd: ctx.resolved.projectRoot,
    failOn,
    fix: opts.fix
  });

  emitSuccess(
    mode,
    { findings: result.findings, failed: result.failed, failOn },
    () => {
      if (result.findings.length === 0) {
        console.log(`${green(mode, "✓")} No security findings`);
        return;
      }
      console.log(`Security scan: ${result.findings.length} finding(s)\n`);
      for (const f of result.findings) {
        const mark = f.severity === "critical" || f.severity === "high" ? "✗" : yellow(mode, "⚠");
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        console.log(`  ${mark} [${f.severity}] ${f.title}`);
        console.log(`      ${loc}`);
        console.log(`      ${f.hint}`);
      }
    }
  );

  return result.failed ? EXIT_CODES.SECURITY_FINDINGS : EXIT_CODES.OK;
}
