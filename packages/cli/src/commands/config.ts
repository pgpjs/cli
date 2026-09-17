import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";

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
      console.log(`home          ${ctx.resolved.home}`);
      console.log(`projectRoot   ${ctx.resolved.projectRoot}`);
      console.log(`keystoreRoot  ${ctx.resolved.keystoreRoot}`);
      console.log(`project file  ${ctx.resolved.files.project ?? "(none)"}`);
      console.log(`global file   ${ctx.resolved.files.global ?? "(none)"}`);
      console.log("");
      for (const [k, origin] of Object.entries(ctx.resolved.origins)) {
        console.log(`  ${k.padEnd(40)} ${origin}`);
      }
    }
  );
}
