import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Keystore, PgpjsError } from "@pgpjs/core";
import { join } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { loadMcpConfig } from "./config.js";
import { RateLimiter } from "./rate-limit.js";
import { authenticateToken } from "./tokens.js";
import { executeTool, TOOL_RISK, toolSchemas, type ToolContext } from "./tools.js";

export interface McpStartOptions {
  cwd: string;
  keystoreRoot: string;
  http?: { port: number; host: string; allowRemote: boolean } | undefined;
  token?: string | undefined;
  passphrase?: string | undefined;
}

export async function createPgpjsMcpServer(options: McpStartOptions): Promise<{
  server: McpServer;
  ctx: ToolContext;
}> {
  const mcpConfig = await loadMcpConfig(join(options.keystoreRoot, "mcp.config.json"));
  const keystore = new Keystore(options.keystoreRoot);
  await keystore.init();

  let token = null;
  if (options.token) {
    token = await authenticateToken(join(options.keystoreRoot, "tokens.json"), options.token);
  }

  const ctx: ToolContext = {
    cwd: options.cwd,
    keystore,
    mcpConfig,
    token,
    auditPath: join(options.cwd, mcpConfig.audit.path),
    limiter: new RateLimiter()
  };
  if (options.passphrase !== undefined) {
    ctx.passphrase = options.passphrase;
  }

  const server = new McpServer({
    name: "pgpjs",
    version: "1.0.0"
  });

  const names = Object.keys(toolSchemas) as (keyof typeof toolSchemas)[];
  for (const name of names) {
    server.tool(name, TOOL_RISK[name], toolSchemas[name].shape, async (args: Record<string, unknown>) => {
      const result = await executeTool(name, args, ctx);
      const isError = result.ok === false;
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
        isError
      };
    });
  }

  return { server, ctx };
}

export async function startStdioServer(options: McpStartOptions): Promise<void> {
  const { server } = await createPgpjsMcpServer(options);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

export async function startHttpServer(options: McpStartOptions): Promise<{ close: () => Promise<void> }> {
  if (!options.http) {
    throw new PgpjsError("USAGE_ERROR", "HTTP options are required.");
  }
  if (!options.token && !process.env["PGPJS_MCP_TOKEN"]) {
    throw new PgpjsError(
      "PERMISSION_DENIED",
      "HTTP MCP transport requires a bearer token. Create one with `pgpjs mcp token create` and pass PGPJS_MCP_TOKEN."
    );
  }
  const host = options.http.host;
  if (host !== "127.0.0.1" && host !== "localhost" && !options.http.allowRemote) {
    throw new PgpjsError(
      "PERMISSION_DENIED",
      "Binding a non-loopback address requires --allow-remote plus TLS termination."
    );
  }

  const startOpts: McpStartOptions = {
    cwd: options.cwd,
    keystoreRoot: options.keystoreRoot
  };
  if (options.http) startOpts.http = options.http;
  if (options.passphrase !== undefined) startOpts.passphrase = options.passphrase;
  const bearer = options.token ?? process.env["PGPJS_MCP_TOKEN"];
  if (bearer) startOpts.token = bearer;
  const { server } = await createPgpjsMcpServer(startOpts);

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const auth = req.headers.authorization ?? "";
      const presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const expected = options.token ?? process.env["PGPJS_MCP_TOKEN"] ?? "";
      if (!presented || presented !== expected) {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      if (req.method === "GET" && req.url === "/health") {
        res.statusCode = 200;
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "not_found" }));
    } catch (err) {
      res.statusCode = 500;
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : "error" }));
    }
  });

  // Attach MCP via Streamable HTTP when the SDK export is available.
  try {
    const { StreamableHTTPServerTransport } = await import(
      "@modelcontextprotocol/sdk/server/streamableHttp.js"
    );
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID()
    });
    await server.connect(transport as never);
    httpServer.removeAllListeners("request");
    httpServer.on("request", async (req, res) => {
      const auth = req.headers.authorization ?? "";
      const presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const expected = options.token ?? process.env["PGPJS_MCP_TOKEN"] ?? "";
      if (!presented || presented !== expected) {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = raw.length > 0 ? JSON.parse(raw) : undefined;
      await transport.handleRequest(req, res, body);
    });
  } catch {
    /* health-only fallback if streamable HTTP cannot be loaded */
  }

  await new Promise<void>((resolve) => {
    httpServer.listen(options.http!.port, host, () => resolve());
  });

  return {
    close: async () =>
      new Promise((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      })
  };
}
