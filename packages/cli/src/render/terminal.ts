import chalk from "chalk";
import type { Command, Help } from "commander";

const ACCENT = "#3B82F6";
const WIDTH = 64;
const ESC = String.fromCharCode(27);
const ANSI = new RegExp(`${ESC}\\[[0-9;]*m`, "g");

export function wantsColor(): boolean {
  if (process.env["NO_COLOR"]) return false;
  if (process.env["TERM"] === "dumb") return false;
  if (process.env["FORCE_COLOR"] === "0") return false;
  if (process.env["FORCE_COLOR"]) return true;
  return Boolean(process.stdout.isTTY);
}

export function stripAnsi(s: string): string {
  return s.replace(ANSI, "");
}

function padEndVis(s: string, n: number): string {
  const w = stripAnsi(s).length;
  if (w >= n) return s;
  return `${s}${" ".repeat(n - w)}`;
}

function paint(enabled: boolean) {
  const hex = enabled ? chalk.hex(ACCENT) : (s: string) => s;
  const dim = enabled ? chalk.dim : (s: string) => s;
  const bold = enabled ? chalk.bold : (s: string) => s;
  const white = enabled ? chalk.whiteBright : (s: string) => s;
  const green = enabled ? chalk.green : (s: string) => s;
  const yellow = enabled ? chalk.yellow : (s: string) => s;
  const red = enabled ? chalk.red : (s: string) => s;
  return { hex, dim, bold, white, green, yellow, red };
}

function spread(left: string, right: string, width = WIDTH): string {
  const gap = Math.max(1, width - stripAnsi(left).length - stripAnsi(right).length);
  return `${left}${" ".repeat(gap)}${right}`;
}

export function formatChromeHeader(color: boolean): string {
  const c = paint(color);
  return `${spread(c.dim("pgpjs"), c.hex("PGPJS CLI"))}\n${c.dim("─".repeat(WIDTH))}`;
}

export function formatChromeFooter(color: boolean): string {
  const c = paint(color);
  return `${c.dim("─".repeat(WIDTH))}\n${spread(c.dim("PGP / OpenPGP"), c.hex("READY • LOCAL CRYPTO"))}`;
}

export function formatScreen(color: boolean, body: string[]): string {
  return [formatChromeHeader(color), "", ...body, "", formatChromeFooter(color)].join("\n");
}

export function printScreen(color: boolean, body: string[]): void {
  process.stdout.write(`${formatScreen(color, body)}\n`);
}

export function heading(color: boolean, text: string): string {
  const c = paint(color);
  return `  ${c.bold(c.white(text))}`;
}

export function muted(color: boolean, text: string): string {
  return `  ${paint(color).dim(text)}`;
}

export function statusLine(
  color: boolean,
  kind: "ok" | "warn" | "fail" | "dot",
  text: string
): string {
  const c = paint(color);
  const mark =
    kind === "ok" ? c.green("✓") : kind === "warn" ? c.yellow("⚠") : kind === "fail" ? c.red("✗") : c.hex("•");
  return `  ${mark} ${text}`;
}

export function kvLine(color: boolean, label: string, value: string, width = 14): string {
  return `  ${paint(color).dim(padEndVis(label, width))}${value}`;
}

export function promptLine(color: boolean, cmd: string): string {
  const c = paint(color);
  return `    ${c.hex("$")} ${c.hex(cmd)}`;
}

export function boxLines(color: boolean, lines: string[], tone: "blue" | "yellow" = "blue"): string[] {
  const c = paint(color);
  const paintBox = tone === "yellow" ? c.yellow : c.hex;
  const inner = Math.max(20, ...lines.map((l) => stripAnsi(l).length + 2));
  const width = Math.min(WIDTH - 4, inner);
  const out = [`  ${paintBox(`┌${"─".repeat(width)}┐`)}`];
  for (const line of lines) {
    out.push(`  ${paintBox("│")}${padEndVis(` ${line}`, width)}${paintBox("│")}`);
  }
  out.push(`  ${paintBox(`└${"─".repeat(width)}┘`)}`);
  return out;
}

const COMMANDS: Array<[string, string]> = [
  ["init", "Initialize PGPJS in a project"],
  ["install", "Install PGPJS integrations"],
  ["key", "Manage OpenPGP keys"],
  ["encrypt", "Encrypt data"],
  ["decrypt", "Decrypt data"],
  ["sign", "Sign data"],
  ["verify", "Verify signatures"],
  ["doctor", "Diagnose project configuration"],
  ["security", "Security checks"],
  ["mcp", "Run and configure MCP"],
  ["config", "Show effective configuration"]
];

const OPTIONS: Array<[string, string]> = [
  ["--json", "Machine-readable output"],
  ["--quiet", "Minimal output"],
  ["--verbose", "Verbose output"],
  ["--no-color", "Disable colour"],
  ["--no-input", "Never prompt"],
  ["--help", "Show this screen"],
  ["--version", "Show version"]
];

const ROOT_EXAMPLES = [
  "pgpjs key generate",
  "pgpjs encrypt message.txt",
  "pgpjs decrypt message.pgp",
  "pgpjs sign message.txt",
  "pgpjs verify message.asc"
];

const EXAMPLES_BY_COMMAND: Record<string, string[]> = {
  pgpjs: ROOT_EXAMPLES,
  "pgpjs init": ["pgpjs init"],
  "pgpjs install": ["pgpjs install next", "pgpjs install node"],
  "pgpjs install next": ["pgpjs install next"],
  "pgpjs install node": ["pgpjs install node"],
  "pgpjs key": ["pgpjs key generate", "pgpjs key list", "pgpjs key show <id>"],
  "pgpjs key generate": [
    "pgpjs key generate --name Alice --email alice@example.com --passphrase-file ./pass"
  ],
  "pgpjs key list": ["pgpjs key list"],
  "pgpjs key show": ["pgpjs key show alice@example.com"],
  "pgpjs key export": ["pgpjs key export alice@example.com --output alice.asc"],
  "pgpjs key import": ["pgpjs key import alice.asc"],
  "pgpjs key delete": ["pgpjs key delete alice@example.com --yes"],
  "pgpjs key reindex": ["pgpjs key reindex"],
  "pgpjs encrypt": ["pgpjs encrypt message.txt --recipient alice@example.com --armor"],
  "pgpjs decrypt": ["pgpjs decrypt message.asc --output message.txt"],
  "pgpjs sign": ["pgpjs sign message.txt --detached"],
  "pgpjs verify": ["pgpjs verify message.txt --signature message.txt.asc"],
  "pgpjs doctor": ["pgpjs doctor"],
  "pgpjs security": ["pgpjs security scan"],
  "pgpjs security scan": ["pgpjs security scan", "pgpjs security scan --fix"],
  "pgpjs mcp": ["pgpjs mcp start", "pgpjs mcp token create --name local"],
  "pgpjs mcp start": ["pgpjs mcp start", "pgpjs mcp start --http --port 8787"],
  "pgpjs mcp token": ["pgpjs mcp token create --name local"],
  "pgpjs mcp token create": ["pgpjs mcp token create --name local --scope encrypt --scope verify"],
  "pgpjs mcp token list": ["pgpjs mcp token list"],
  "pgpjs mcp token revoke": ["pgpjs mcp token revoke <id>"],
  "pgpjs mcp token rotate": ["pgpjs mcp token rotate <id>"],
  "pgpjs mcp config": ["pgpjs mcp config"],
  "pgpjs mcp audit": ["pgpjs mcp audit"],
  "pgpjs config": ["pgpjs config show"],
  "pgpjs config show": ["pgpjs config show"]
};

function commandPath(cmd: Command): string {
  const parts: string[] = [];
  for (let current: Command | null | undefined = cmd; current; current = current.parent) {
    parts.unshift(current.name());
  }
  return parts.join(" ");
}

function examplesFor(path: string): string[] {
  return EXAMPLES_BY_COMMAND[path] ?? [];
}

function versionBadge(color: boolean, version: string): string[] {
  const c = paint(color);
  const inner = 14;
  const label = padEndVis(` CLI ${version} `, inner);
  return [
    `  ${c.hex(`┌${"─".repeat(inner)}┐`)}`,
    `  ${c.hex("│")}${c.white(label)}${c.hex("│")}`,
    `  ${c.hex(`└${"─".repeat(inner)}┘`)}`
  ];
}

function zipColumns(left: string[], right: string[], gap = 3): string[] {
  const rows = Math.max(left.length, right.length);
  const leftW = Math.max(0, ...left.map((l) => stripAnsi(l).length));
  const out: string[] = [];
  for (let i = 0; i < rows; i++) {
    const L = left[i] ?? "";
    const R = right[i] ?? "";
    out.push(`${padEndVis(L, leftW)}${" ".repeat(gap)}${R}`);
  }
  return out;
}

export function formatRootHelp(color = wantsColor(), version = "1.0.0"): string {
  const c = paint(color);
  const icon = [
    "      ╭───╮",
    "     ╱     ╲━━━━┓",
    "     ╲     ╱    ┃",
    "      ╰───╯     ┃",
    "       ▪ ▪"
  ].map((row) => c.hex(row));

  const title = [
    c.bold(c.white("PGPJS CLI")),
    c.dim("OpenPGP encryption toolkit"),
    c.dim("JavaScript  •  secure keys  •  encrypt  •  decrypt  •  sign  •  verify"),
    "",
    ...versionBadge(color, version).map((row) => row.replace(/^ {2}/, ""))
  ];

  const body: string[] = [
    ...zipColumns(icon, title),
    "",
    c.dim("─".repeat(WIDTH)),
    "",
    `  ${c.dim(">")} ${c.white("pgpjs --help")}`,
    "",
    muted(color, "OpenPGP.js command-line interface"),
    "",
    ...ROOT_EXAMPLES.map((ex) => promptLine(color, ex)),
    "",
    heading(color, "Usage:"),
    `  ${c.hex("pgpjs")} <command> [options]`,
    "",
    heading(color, "Commands:"),
    ...COMMANDS.map(([name, desc]) => `  ${c.hex(padEndVis(name, 14))}${c.dim(desc)}`),
    "",
    heading(color, "Options:"),
    ...OPTIONS.map(([name, desc]) => `  ${c.hex(padEndVis(name, 14))}${c.dim(desc)}`)
  ];

  return formatScreen(color, body);
}

export function printRootHelp(color = wantsColor(), version = "1.0.0"): void {
  process.stdout.write(`${formatRootHelp(color, version)}\n`);
}

export function formatVersion(color = wantsColor(), version = "1.0.0"): string {
  return formatScreen(color, [
    heading(color, "PGPJS CLI"),
    muted(color, "OpenPGP encryption toolkit"),
    "",
    ...versionBadge(color, version)
  ]);
}

export function printVersion(color = wantsColor(), version = "1.0.0"): void {
  process.stdout.write(`${formatVersion(color, version)}\n`);
}

export function formatCommandHelp(cmd: Command, helper: Help, color = wantsColor()): string {
  const c = paint(color);
  const path = commandPath(cmd);
  const usage = helper.commandUsage(cmd);
  const description = helper.commandDescription(cmd);
  const args = helper.visibleArguments(cmd);
  const options = helper.visibleOptions(cmd);
  const commands = helper.visibleCommands(cmd);
  const examples = examplesFor(path);

  const body: string[] = [
    heading(color, path),
    muted(color, description || "OpenPGP encryption toolkit"),
    "",
    heading(color, "Usage:"),
    `  ${c.hex(usage)}`
  ];

  if (args.length > 0) {
    body.push("", heading(color, "Arguments:"));
    const w = Math.max(12, ...args.map((a) => helper.argumentTerm(a).length));
    for (const a of args) {
      body.push(`  ${c.hex(padEndVis(helper.argumentTerm(a), w + 2))}${c.dim(helper.argumentDescription(a))}`);
    }
  }

  if (commands.length > 0) {
    body.push("", heading(color, "Commands:"));
    const w = Math.max(12, ...commands.map((sub) => helper.subcommandTerm(sub).length));
    for (const sub of commands) {
      if (sub.name() === "help") continue;
      body.push(
        `  ${c.hex(padEndVis(helper.subcommandTerm(sub), w + 2))}${c.dim(helper.subcommandDescription(sub))}`
      );
    }
  }

  if (options.length > 0) {
    body.push("", heading(color, "Options:"));
    const w = Math.max(14, ...options.map((o) => helper.optionTerm(o).length));
    for (const o of options) {
      body.push(`  ${c.hex(padEndVis(helper.optionTerm(o), w + 2))}${c.dim(helper.optionDescription(o))}`);
    }
  }

  if (examples.length > 0) {
    body.push("", heading(color, "Examples:"));
    for (const ex of examples) {
      body.push(promptLine(color, ex));
    }
  }

  return formatScreen(color, body);
}

export function formatJsonHelp(version = "1.0.0"): string {
  return JSON.stringify({
    ok: true,
    version: 1,
    command: "help",
    data: {
      name: "pgpjs",
      product: "PGPJS CLI",
      tagline: "OpenPGP encryption toolkit",
      cliVersion: version,
      commands: COMMANDS.map(([name, description]) => ({ name, description })),
      examples: ROOT_EXAMPLES
    }
  });
}

export function formatJsonCommandHelp(cmd: Command, helper: Help, version = "1.0.0"): string {
  const path = commandPath(cmd);
  return JSON.stringify({
    ok: true,
    version: 1,
    command: "help",
    data: {
      name: path,
      product: "PGPJS CLI",
      cliVersion: version,
      description: helper.commandDescription(cmd),
      usage: helper.commandUsage(cmd),
      commands: helper
        .visibleCommands(cmd)
        .filter((sub) => sub.name() !== "help")
        .map((sub) => ({
          name: helper.subcommandTerm(sub),
          description: helper.subcommandDescription(sub)
        })),
      options: helper.visibleOptions(cmd).map((o) => ({
        flags: helper.optionTerm(o),
        description: helper.optionDescription(o)
      })),
      arguments: helper.visibleArguments(cmd).map((a) => ({
        name: helper.argumentTerm(a),
        description: helper.argumentDescription(a)
      })),
      examples: examplesFor(path)
    }
  });
}

export function formatJsonVersion(version = "1.0.0"): string {
  return JSON.stringify({
    ok: true,
    version: 1,
    command: "version",
    data: { name: "pgpjs", product: "PGPJS CLI", cliVersion: version }
  });
}
