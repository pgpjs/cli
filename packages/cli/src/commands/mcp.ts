import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { PgpjsError } from "@pgpjs/core";
import {
  createToken,
  listTokens,
  loadMcpConfig,
  parseExpires,
  publicTokenView,
  readAudit,
  revokeToken,
  rotateToken,
  startHttpServer,
  startStdioServer,
  writeMcpConfig,
  DEFAULT_MCP_CONFIG
} from "@pgpjs/mcp";
import type { ScopeName } from "@pgpjs/security";
import { ALL_SCOPES } from "@pgpjs/security";
import type { CliContext } from "../context.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { heading, kvLine, muted, statusLine, wantsColor, formatScreen } from "../render/terminal.js";

function tokenStore(ctx: CliContext): string {
  return join(ctx.resolved.keystoreRoot, "tokens.json");
}

export async function runMcpStart(
  ctx: CliContext,
  opts: { http?: boolean; port?: string; host?: string; allowRemote?: boolean }
): Promise<void> {
  await ctx.keystore.init();
  const existing = await loadMcpConfig(join(ctx.resolved.keystoreRoot, "mcp.config.json"));
  await writeMcpConfig(join(ctx.resolved.keystoreRoot, "mcp.config.json"), {
    ...DEFAULT_MCP_CONFIG,
    ...existing,
    permissions: { ...DEFAULT_MCP_CONFIG.permissions, ...existing.permissions }
  });

  if (opts.http) {
    const port = Number(opts.port ?? "8787");
    const host = opts.host ?? "127.0.0.1";
    if (host !== "127.0.0.1" && host !== "localhost" && !opts.allowRemote) {
      throw new PgpjsError(
        "PERMISSION_DENIED",
        "Non-loopback bind requires --allow-remote (and TLS termination in front)."
      );
    }
    process.stderr.write(
      `${formatScreen(wantsColor(), [statusLine(wantsColor(), "ok", `MCP HTTP listening on ${host}:${port}`)])}\n`
    );
    await startHttpServer({
      cwd: ctx.resolved.projectRoot,
      keystoreRoot: ctx.resolved.keystoreRoot,
      http: { port, host, allowRemote: Boolean(opts.allowRemote) },
      token: process.env["PGPJS_MCP_TOKEN"]
    });
    await new Promise(() => undefined);
    return;
  }

  await startStdioServer({
    cwd: ctx.resolved.projectRoot,
    keystoreRoot: ctx.resolved.keystoreRoot,
    token: process.env["PGPJS_MCP_TOKEN"]
  });
}

export async function runMcpTokenCreate(
  ctx: CliContext,
  opts: { name?: string; scope?: string[]; expires?: string },
  mode: OutputMode
): Promise<void> {
  if (!opts.name) {
    throw new PgpjsError("USAGE_ERROR", "--name is required.");
  }
  const scopes = (opts.scope ?? []) as ScopeName[];
  for (const s of scopes) {
    if (!ALL_SCOPES.includes(s)) {
      throw new PgpjsError("USAGE_ERROR", `Unknown scope '${s}'.`);
    }
  }
  await ctx.keystore.init();
  const { record, token } = await createToken({
    storePath: tokenStore(ctx),
    name: opts.name,
    scopes: scopes.length > 0 ? scopes : ["encrypt", "verify", "readKeys", "exportPublicKey", "securityScan"],
    expires: parseExpires(opts.expires)
  });

  emitSuccess(
    mode,
    {
      id: record.id,
      name: record.name,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      token
    },
    () => [
      heading(mode.color, "MCP token created"),
      "",
      kvLine(mode.color, "Name", record.name),
      kvLine(mode.color, "Id", record.id),
      kvLine(mode.color, "Token", token),
      "",
      statusLine(mode.color, "warn", "This is the only time the full token is displayed."),
      muted(mode.color, "Store it in a secret manager. Only a hash is saved locally.")
    ]
  );
}

export async function runMcpTokenList(ctx: CliContext, mode: OutputMode): Promise<void> {
  const tokens = (await listTokens(tokenStore(ctx))).map(publicTokenView);
  emitSuccess(mode, { tokens }, () => {
    if (tokens.length === 0) {
      return [muted(mode.color, "No MCP tokens.")];
    }
    return [
      heading(mode.color, `MCP tokens (${tokens.length})`),
      "",
      ...tokens.map(
        (t) =>
          `${statusLine(mode.color, t.status === "active" ? "ok" : "dot", t.name)}  ${t.id}  scopes=${t.scopes.join(",")}  expires=${t.expiresAt}`
      )
    ];
  });
}

export async function runMcpTokenRevoke(ctx: CliContext, id: string, mode: OutputMode): Promise<void> {
  const rec = await revokeToken(tokenStore(ctx), id);
  emitSuccess(mode, { id: rec.id, revokedAt: rec.revokedAt }, () => [
    statusLine(mode.color, "ok", `Revoked token ${rec.id} (${rec.name})`)
  ]);
}

export async function runMcpTokenRotate(ctx: CliContext, id: string, mode: OutputMode): Promise<void> {
  const { record, token } = await rotateToken(tokenStore(ctx), id);
  emitSuccess(mode, { id: record.id, name: record.name, token }, () => [
    statusLine(mode.color, "ok", `Rotated token ${record.name}`),
    kvLine(mode.color, "Token", token),
    statusLine(mode.color, "warn", "The previous secret is dead immediately. This is the only time the new token is shown.")
  ]);
}

export async function runMcpConfig(
  _ctx: CliContext,
  opts: { format?: string; http?: boolean; port?: string },
  mode: OutputMode
): Promise<void> {
  const bin = resolveBinary();
  const payload = opts.http
    ? {
        mcpServers: {
          pgpjs: {
            url: `http://127.0.0.1:${opts.port ?? "8787"}`,
            headers: { Authorization: "Bearer <PGPJS_MCP_TOKEN>" }
          }
        }
      }
    : {
        mcpServers: {
          pgpjs: {
            command: bin,
            args: ["mcp", "start"]
          }
        }
      };

  emitSuccess(mode, payload, () => {
    console.log(JSON.stringify(payload, null, 2));
  });
}

export async function runMcpAudit(ctx: CliContext, mode: OutputMode): Promise<void> {
  const events = await readAudit(join(ctx.resolved.projectRoot, ".pgpjs/audit.log"));
  emitSuccess(mode, { events }, () => {
    if (events.length === 0) return [muted(mode.color, "No audit events.")];
    return [
      heading(mode.color, "MCP audit"),
      "",
      ...events.map((e) =>
        kvLine(mode.color, e.timestamp, `${e.decision}  ${e.tool}  token=${e.tokenId ?? "-"}  ${e.reason}`, 22)
      )
    ];
  });
}

function resolveBinary(): string {
  try {
    if (process.argv[1]) {
      return realpathSync(process.argv[1]);
    }
    return fileURLToPath(import.meta.url);
  } catch {
    return "pgpjs";
  }
}
