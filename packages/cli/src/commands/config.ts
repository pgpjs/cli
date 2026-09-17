import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { heading, kvLine } from "../render/terminal.js";

export async function runConfigShow(ctx: CliContext, mode: OutputMode): Promise<void> {
  emitSuccess(
    mode,
    {
      config: ctx.resolved.config,
      origins: ctx.resolved.origins,
      files: ctx.resolved.files,
      home: ctx.resolved.home,
      projectRoot: ctx.resolved.projectRoot,
      keystoreRoot: ctx.resolved.keystoreRoot
    },
    () => {
      const color = mode.color;
      const lines = [
        heading(color, "Effective config"),
        "",
        kvLine(color, "home", ctx.resolved.home),
        kvLine(color, "projectRoot", ctx.resolved.projectRoot),
        kvLine(color, "keystoreRoot", ctx.resolved.keystoreRoot),
        kvLine(color, "project file", ctx.resolved.files.project ?? "(none)"),
        kvLine(color, "global file", ctx.resolved.files.global ?? "(none)"),
        ""
      ];
      for (const [k, origin] of Object.entries(ctx.resolved.origins)) {
        lines.push(kvLine(color, k, origin, 40));
      }
      return lines;
    }
  );
}
