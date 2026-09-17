import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { EXIT_CODES } from "@pgpjs/core";
import type { CliContext } from "../context.js";
import { detectProject } from "../detect/project.js";
import { emitSuccess, type OutputMode } from "../render/output.js";
import { heading, muted, statusLine } from "../render/terminal.js";

export interface DoctorCheck {
  id: string;
  status: "pass" | "warn" | "fail";
  message: string;
  fix?: string | undefined;
}

export async function runDoctor(ctx: CliContext, mode: OutputMode): Promise<number> {
  const info = detectProject(ctx.resolved.projectRoot);
  const checks: DoctorCheck[] = [];

  const major = Number(process.versions.node.split(".")[0]);
  const minor = Number(process.versions.node.split(".")[1]);
  if (major > 20 || (major === 20 && minor >= 10)) {
    checks.push({ id: "node", status: "pass", message: `Node.js ${process.version}` });
  } else {
    checks.push({
      id: "node",
      status: "fail",
      message: `Node.js ${process.version} is unsupported`,
      fix: "Install Node.js >= 20.10"
    });
  }

  const pkgPath = join(info.cwd, "package.json");
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    if (deps["openpgp"] || deps["@pgpjs/core"]) {
      checks.push({
        id: "openpgp",
        status: "pass",
        message: `openpgp ${deps["openpgp"] ?? ""} ${deps["@pgpjs/core"] ?? ""}`.trim()
      });
    } else {
      checks.push({
        id: "openpgp",
        status: "warn",
        message: "openpgp is not installed in this project",
        fix: "Run `pgpjs install react` and `pgpjs install node`, or `pgpjs install next`"
      });
    }
  }

  checks.push({
    id: "typescript",
    status: info.isTypeScript ? "pass" : "warn",
    message: info.isTypeScript ? "tsconfig.json present" : "No tsconfig.json",
    fix: info.isTypeScript ? undefined : "Add TypeScript for typed PGPJS helpers"
  });

  checks.push({
    id: "config",
    status: ctx.resolved.files.project ? "pass" : "warn",
    message: ctx.resolved.files.project
      ? `config ${ctx.resolved.files.project}`
      : "No project config file",
    fix: "Run `pgpjs init`"
  });

  const envExample = join(info.cwd, ".env.example");
  checks.push({
    id: "env",
    status: existsSync(envExample) ? "pass" : "warn",
    message: existsSync(envExample) ? ".env.example present" : ".env.example missing",
    fix: "Run `pgpjs init`"
  });

  try {
    const keys = await ctx.keystore.list();
    const expired = keys.filter((k) => k.expiresAt && Date.parse(k.expiresAt) <= Date.now());
    if (keys.length === 0) {
      checks.push({
        id: "keys",
        status: "warn",
        message: "Keystore has no keys",
        fix: "Run `pgpjs key generate`"
      });
    } else if (expired.length > 0) {
      checks.push({
        id: "keys",
        status: "warn",
        message: `${expired.length} expired key(s)`,
        fix: "Generate a replacement and revoke the old key"
      });
    } else {
      checks.push({ id: "keys", status: "pass", message: `${keys.length} key(s) in keystore` });
    }
    const perms = await ctx.keystore.permissionProblems();
    if (perms.length > 0) {
      checks.push({
        id: "key-permissions",
        status: "fail",
        message: `${perms.length} private key file(s) have loose permissions`,
        fix: "Run `pgpjs security scan --fix`"
      });
    } else {
      checks.push({ id: "key-permissions", status: "pass", message: "Private key permissions look correct" });
    }
  } catch {
    checks.push({
      id: "keys",
      status: "warn",
      message: "Keystore not initialized",
      fix: "Run `pgpjs init`"
    });
  }

  const mcp = join(ctx.resolved.keystoreRoot, "mcp.config.json");
  if (existsSync(mcp)) {
    try {
      const json = JSON.parse(readFileSync(mcp, "utf8")) as {
        permissions?: { decrypt?: boolean; sign?: boolean; exportPrivateKeys?: boolean };
      };
      if (json.permissions?.decrypt || json.permissions?.sign || json.permissions?.exportPrivateKeys) {
        checks.push({
          id: "mcp",
          status: "warn",
          message: "MCP config grants decrypt/sign/exportPrivateKeys",
          fix: "Review .pgpjs/mcp.config.json — these are high risk"
        });
      } else {
        checks.push({ id: "mcp", status: "pass", message: "MCP config present with safe defaults" });
      }
    } catch {
      checks.push({ id: "mcp", status: "fail", message: "MCP config is invalid JSON", fix: "Regenerate with pgpjs mcp config" });
    }
  } else {
    checks.push({ id: "mcp", status: "pass", message: "No MCP config (stdio will use defaults)" });
  }

  const gi = join(info.cwd, ".gitignore");
  if (!existsSync(gi) || !readFileSync(gi, "utf8").includes(".pgpjs")) {
    checks.push({
      id: "gitignore",
      status: "fail",
      message: ".pgpjs/ is not gitignored",
      fix: "Run `pgpjs init` or `pgpjs security scan --fix`"
    });
  } else {
    checks.push({ id: "gitignore", status: "pass", message: ".pgpjs/ is gitignored" });
  }

  if (
    info.framework === "next-app" ||
    info.framework === "next-pages" ||
    info.framework === "react" ||
    info.framework === "vite"
  ) {
    const clientImport = scanClientImports(info.cwd, info.hasSrcDir, info.framework);
    if (clientImport) {
      checks.push({
        id: "client-boundary",
        status: "fail",
        message: `Client module imports server-only PGPJS code (${clientImport})`,
        fix: "Import src/lib/pgpjs/client from the UI, never server.ts, keys.ts, or http.ts"
      });
    } else {
      checks.push({
        id: "client-boundary",
        status: "pass",
        message: "No client/server import violations detected"
      });
    }
  }

  const failed = checks.some((c) => c.status === "fail");
  emitSuccess(mode, { checks, ok: !failed }, () => {
    const color = mode.color;
    const lines = [heading(color, "PGPJS doctor"), ""];
    for (const c of checks) {
      const kind = c.status === "pass" ? "ok" : c.status === "warn" ? "warn" : "fail";
      lines.push(statusLine(color, kind, c.message));
      if (c.fix && c.status !== "pass") lines.push(muted(color, `→ ${c.fix}`));
    }
    lines.push("");
    lines.push(
      failed
        ? statusLine(color, "fail", "Doctor found failures.")
        : statusLine(color, "ok", "Doctor: no failures.")
    );
    return lines;
  });
  return failed ? EXIT_CODES.GENERIC_ERROR : EXIT_CODES.OK;
}

function scanClientImports(cwd: string, hasSrc: boolean, framework: string): string | undefined {
  const roots = [hasSrc ? join(cwd, "src") : join(cwd, "app"), join(cwd, "src/app"), join(cwd, "app")];
  const stack = [
    ...roots.filter((p) => {
      try {
        return statSync(p).isDirectory();
      } catch {
        return false;
      }
    })
  ];
  while (stack.length) {
    const dir = stack.pop() as string;
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (name === "node_modules" || name === ".next") continue;
        stack.push(full);
        continue;
      }
      if (!/\.(tsx|jsx|ts|js)$/.test(name)) continue;
      if (/lib\/pgpjs\/(server|keys|http|index|encryption)\.(ts|js)$/.test(full)) continue;
      let text: string;
      try {
        text = readFileSync(full, "utf8");
      } catch {
        continue;
      }
      const markedClient = text.includes('"use client"') || text.includes("'use client'");
      const spaClient = framework === "react" || framework === "vite";
      if (!markedClient && !spaClient) continue;
      if (/from\s+["'][^"']*lib\/pgpjs\/(server|keys|encryption|http)(?:\.(?:ts|js))?["']/.test(text)) {
        return full;
      }
    }
  }
  return undefined;
}
