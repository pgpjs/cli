import {
  appendFileSync,
  chmodSync,
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync
} from "node:fs";
import { execFileSync } from "node:child_process";
import { join, relative, resolve } from "node:path";
import { platform } from "node:os";

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  file: string;
  line?: number | undefined;
  hint: string;
}

export interface ScanOptions {
  cwd: string;
  failOn?: Severity | undefined;
  fix?: boolean | undefined;
}

export interface ScanResult {
  findings: Finding[];
  failed: boolean;
}

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "coverage",
  ".next",
  "build",
  ".turbo",
  ".cache"
]);

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

export function scanProject(options: ScanOptions): ScanResult {
  const cwd = resolve(options.cwd);
  const findings: Finding[] = [];
  const failOn = options.failOn ?? "high";

  scanFiles(cwd, cwd, findings);
  scanGitignore(cwd, findings);
  scanGitHistory(cwd, findings);
  scanMcpConfig(cwd, findings);
  scanEnv(cwd, findings);
  scanPermissions(cwd, findings);

  if (options.fix) {
    applySafeFixes(cwd, findings);
  }

  const failed = findings.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn]);
  return { findings, failed };
}

function scanFiles(root: string, dir: string, findings: Finding[]): void {
  let entries: string[] = [];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      scanFiles(root, full, findings);
      continue;
    }
    if (st.size > 2_000_000) continue;
    let text: string;
    try {
      text = readFileSync(full, "utf8");
    } catch {
      continue;
    }
    const rel = relative(root, full) || name;
    const lines = text.split(/\r?\n/);
    lines.forEach((line, i) => {
      if (line.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
        if (rel.startsWith(".pgpjs/keys/") && rel.endsWith(".sec.asc")) {
          return;
        }
        findings.push({
          id: "private-key-in-tree",
          severity: "critical",
          title: "Private key block found outside the keystore",
          file: rel,
          line: i + 1,
          hint: "Remove the key from the repository and rotate it. Never commit private keys."
        });
      }
      if (/pgpjs_mcp_[A-Za-z0-9_-]{20,}/.test(line) && !rel.endsWith("tokens.json")) {
        findings.push({
          id: "mcp-token-in-tree",
          severity: "critical",
          title: "MCP token found outside the token store",
          file: rel,
          line: i + 1,
          hint: "Revoke the token immediately and store only hashes in .pgpjs/tokens.json."
        });
      }
      if (/NEXT_PUBLIC_/.test(line) && /PRIVATE|SECRET|PASSPHRASE|pgpjs_mcp_/i.test(line)) {
        findings.push({
          id: "next-public-secret",
          severity: "critical",
          title: "Secret-shaped value assigned to a NEXT_PUBLIC_ variable",
          file: rel,
          line: i + 1,
          hint: "NEXT_PUBLIC_ values are inlined into the browser bundle. Keep private keys server-only."
        });
      }
    });
  }
}

function scanGitignore(root: string, findings: Finding[]): void {
  const gi = join(root, ".gitignore");
  if (!existsSync(gi)) {
    findings.push({
      id: "missing-gitignore",
      severity: "critical",
      title: ".pgpjs/ is not gitignored (no .gitignore found)",
      file: ".gitignore",
      hint: "Create a .gitignore that includes .pgpjs/ so private keys are never committed."
    });
    return;
  }
  const text = readFileSync(gi, "utf8");
  if (!text.split(/\r?\n/).some((l) => l.trim() === ".pgpjs/" || l.trim() === ".pgpjs" || l.trim() === "**/.pgpjs/")) {
    findings.push({
      id: "pgpjs-not-gitignored",
      severity: "critical",
      title: ".pgpjs/ is not listed in .gitignore",
      file: ".gitignore",
      hint: "Append `.pgpjs/` to .gitignore. Public keys may be re-included with `!.pgpjs/keys/*.pub.asc`."
    });
  }
}

function scanGitHistory(root: string, findings: Finding[]): void {
  if (!existsSync(join(root, ".git"))) return;
  try {
    const out = execFileSync(
      "git",
      ["log", "--all", "-S", "BEGIN PGP PRIVATE KEY BLOCK", "--pretty=format:%H", "-n", "1"],
      { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
    ).trim();
    if (out.length > 0) {
      findings.push({
        id: "private-key-in-git-history",
        severity: "critical",
        title: "A private key block appears in git history",
        file: ".git",
        hint: "Rotate the key. History rewrite does not undo exposure; treat the key as compromised."
      });
    }
  } catch {
    /* git not available or not a repo */
  }
}

function scanMcpConfig(root: string, findings: Finding[]): void {
  const file = join(root, ".pgpjs", "mcp.config.json");
  if (!existsSync(file)) return;
  try {
    const json = JSON.parse(readFileSync(file, "utf8")) as {
      permissions?: { decrypt?: boolean; sign?: boolean; exportPrivateKeys?: boolean };
    };
    const perms = json.permissions ?? {};
    if (perms.decrypt) {
      findings.push({
        id: "mcp-decrypt-enabled",
        severity: "high",
        title: "MCP decrypt permission is enabled",
        file: ".pgpjs/mcp.config.json",
        hint: "Decrypt returns plaintext to the agent and is an exfiltration channel. Keep it off unless required."
      });
    }
    if (perms.sign) {
      findings.push({
        id: "mcp-sign-enabled",
        severity: "high",
        title: "MCP sign permission is enabled",
        file: ".pgpjs/mcp.config.json",
        hint: "Signing as an agent can produce authentic-looking artifacts. Enable only with a passphrase source and allowlist."
      });
    }
    if (perms.exportPrivateKeys) {
      findings.push({
        id: "mcp-export-private",
        severity: "critical",
        title: "MCP exportPrivateKeys is set (this capability is never implemented)",
        file: ".pgpjs/mcp.config.json",
        hint: "Private-key export over MCP is unconditionally denied. Remove the flag."
      });
    }
  } catch {
    findings.push({
      id: "mcp-config-invalid",
      severity: "medium",
      title: "MCP config is not valid JSON",
      file: ".pgpjs/mcp.config.json",
      hint: "Run `pgpjs mcp config` to regenerate a valid file."
    });
  }
}

function scanEnv(root: string, findings: Finding[]): void {
  for (const name of [".env", ".env.local", ".env.production", ".env.development"]) {
    const file = join(root, name);
    if (!existsSync(file)) continue;
    const text = readFileSync(file, "utf8");
    if (text.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----") || /pgpjs_mcp_/.test(text)) {
      findings.push({
        id: "secret-in-env",
        severity: "critical",
        title: "Private key or MCP token found in an environment file",
        file: name,
        hint: "Move secrets to a 0600 file referenced by PGPJS_PASSPHRASE_FILE. Never put private keys in .env."
      });
    }
  }
}

function scanPermissions(root: string, findings: Finding[]): void {
  if (platform() === "win32") return;
  const keysDir = join(root, ".pgpjs", "keys");
  if (!existsSync(keysDir)) return;
  let files: string[] = [];
  try {
    files = readdirSync(keysDir);
  } catch {
    return;
  }
  for (const f of files) {
    if (!f.includes(".sec.")) continue;
    const full = join(keysDir, f);
    try {
      const mode = statSync(full).mode & 0o777;
      if (mode & 0o077) {
        findings.push({
          id: "insecure-key-permissions",
          severity: "high",
          title: "Private key file is readable by group or others",
          file: relative(root, full),
          hint: "chmod 600 this file. `pgpjs security scan --fix` can correct permissions."
        });
      }
    } catch {
      /* ignore */
    }
  }
}

function applySafeFixes(root: string, findings: Finding[]): void {
  const gitignore = join(root, ".gitignore");
  const needsGitignore = findings.some((f) => f.id === "pgpjs-not-gitignored" || f.id === "missing-gitignore");
  if (needsGitignore) {
    const existing = existsSync(gitignore) ? readFileSync(gitignore, "utf8") : "";
    if (!existing.includes(".pgpjs/")) {
      if (existing.length === 0) {
        writeFileSync(gitignore, ".pgpjs/\n", "utf8");
      } else {
        const nl = existing.endsWith("\n") ? "" : "\n";
        appendFileSync(gitignore, `${nl}# PGPJS keystore\n.pgpjs/\n!.pgpjs/keys/*.pub.asc\n`);
      }
    }
  }

  if (platform() === "win32") return;
  for (const f of findings) {
    if (f.id !== "insecure-key-permissions") continue;
    try {
      chmodSync(join(root, f.file), 0o600);
    } catch {
      /* ignore */
    }
  }
}

export { SEVERITY_RANK };
