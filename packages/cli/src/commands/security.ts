import { EXIT_CODES } from "@pgpjs/core";
import { scanProject, type Severity } from "@pgpjs/security";
import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { heading, muted, statusLine } from "../render/terminal.js";

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
      const color = mode.color;
      if (result.findings.length === 0) {
        return [statusLine(color, "ok", "No security findings")];
      }
      const lines = [heading(color, `Security scan: ${result.findings.length} finding(s)`), ""];
      for (const f of result.findings) {
        const kind = f.severity === "critical" || f.severity === "high" ? "fail" : "warn";
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        lines.push(statusLine(color, kind, `[${f.severity}] ${f.title}`));
        lines.push(muted(color, loc));
        lines.push(muted(color, f.hint));
      }
      return lines;
    }
  );

  return result.failed ? EXIT_CODES.SECURITY_FINDINGS : EXIT_CODES.OK;
}
