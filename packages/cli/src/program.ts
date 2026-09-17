import { Command, Option } from "commander";
import { createContext, type GlobalFlags } from "./context.js";
import { emitError, type OutputMode } from "./render/output.js";
import {
  formatCommandHelp,
  formatJsonCommandHelp,
  formatJsonHelp,
  formatJsonVersion,
  printRootHelp,
  printVersion,
  wantsColor
} from "./render/terminal.js";
import { EXIT_CODES, PgpjsError } from "@pgpjs/core";
import { runInit } from "./commands/init.js";
import { runInstall } from "./commands/install.js";
import {
  runKeyDelete,
  runKeyExport,
  runKeyGenerate,
  runKeyImport,
  runKeyList,
  runKeyReindex,
  runKeyShow
} from "./commands/key.js";
import { runEncrypt } from "./commands/encrypt.js";
import { runDecrypt } from "./commands/decrypt.js";
import { runSign } from "./commands/sign.js";
import { runVerify } from "./commands/verify.js";
import { runDoctor } from "./commands/doctor.js";
import { runSecurityScan } from "./commands/security.js";
import {
  runMcpAudit,
  runMcpConfig,
  runMcpStart,
  runMcpStatus,
  runMcpTokenCreate,
  runMcpTokenList,
  runMcpTokenRevoke,
  runMcpTokenRotate
} from "./commands/mcp.js";
import { runConfigShow } from "./commands/config.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function pkgVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string };
    return pkg.version;
  } catch {
    return "1.0.0";
  }
}

function globalFrom(cmd: Command): GlobalFlags {
  const opts = cmd.optsWithGlobals() as GlobalFlags & { input?: boolean; color?: boolean };
  const flags: GlobalFlags = {
    json: Boolean(opts.json),
    quiet: Boolean(opts.quiet),
    verbose: Boolean(opts.verbose),
    noColor: opts.color === false || Boolean(opts.noColor),
    noInput: opts.input === false || Boolean(opts.noInput)
  };
  if (typeof opts.config === "string") flags.config = opts.config;
  if (typeof opts.home === "string") flags.home = opts.home;
  if (opts.configFormat === "any" || opts.configFormat === "json") flags.configFormat = opts.configFormat;
  return flags;
}

function hiddenGlobals(): Option[] {
  return [
    new Option("--json", "Machine-readable JSON on stdout").hideHelp(),
    new Option("--quiet", "Minimal output").hideHelp(),
    new Option("--verbose", "Verbose output").hideHelp(),
    new Option("--no-color", "Disable colour").hideHelp(),
    new Option("--no-input", "Never prompt").hideHelp(),
    new Option("--config <path>", "Path to a config file").hideHelp(),
    new Option("--home <path>", "Override PGPJS_HOME").hideHelp(),
    new Option("--config-format <fmt>", "Refuse non-JSON configs").choices(["any", "json"]).hideHelp()
  ];
}

function inheritGlobals(cmd: Command): void {
  for (const sub of cmd.commands) {
    for (const opt of hiddenGlobals()) {
      sub.addOption(opt);
    }
    inheritGlobals(sub);
  }
}

function modeFor(cmd: Command, command: string): OutputMode {
  const g = globalFrom(cmd);
  const json = Boolean(g.json);
  const color =
    !g.noColor && !json && Boolean(process.stdout.isTTY) && !process.env["NO_COLOR"] && process.env["TERM"] !== "dumb";
  return {
    json,
    quiet: Boolean(g.quiet),
    verbose: Boolean(g.verbose),
    color,
    command
  };
}

async function withCtx(
  cmd: Command,
  command: string,
  fn: (ctx: Awaited<ReturnType<typeof createContext>>, mode: OutputMode) => Promise<number | void>
): Promise<void> {
  const mode = modeFor(cmd, command);
  try {
    const ctx = await createContext(globalFrom(cmd));
    const code = await fn(ctx, mode);
    process.exitCode = code ?? EXIT_CODES.OK;
  } catch (err) {
    process.exitCode = emitError(mode, err);
  }
}

export function buildProgram(): Command {
  const program = new Command();
  program
    .name("pgpjs")
    .description("OpenPGP encryption toolkit")
    .version(pkgVersion(), "-V, --version", "Show version")
    .option("--json", "Machine-readable JSON on stdout")
    .option("--quiet", "Minimal output")
    .option("--verbose", "Verbose output")
    .option("--no-color", "Disable colour")
    .option("--no-input", "Never prompt")
    .option("--config <path>", "Path to a config file")
    .option("--home <path>", "Override PGPJS_HOME")
    .addOption(new Option("--config-format <fmt>", "Refuse non-JSON configs").choices(["any", "json"]))
    .enablePositionalOptions()
    .showHelpAfterError(false)
    .helpOption("-h, --help", "Show this screen")
    .helpCommand(false)
    .configureHelp({
      formatHelp(cmd, helper) {
        const json = process.argv.includes("--json");
        const color = wantsColor() && !process.argv.includes("--no-color") && !json;
        if (json) {
          return cmd.parent ? formatJsonCommandHelp(cmd, helper, pkgVersion()) : formatJsonHelp(pkgVersion());
        }
        if (!cmd.parent) {
          return "";
        }
        return formatCommandHelp(cmd, helper, color);
      }
    })
    .configureOutput({
      writeOut: (str) => {
        if (str.trim().length === 0) return;
        process.stdout.write(str.endsWith("\n") ? str : `${str}\n`);
      },
      writeErr: (str) => process.stderr.write(str)
    });

  program.action((opts: GlobalFlags) => {
    if (opts.json) {
      process.stdout.write(`${formatJsonHelp(pkgVersion())}\n`);
      return;
    }
    printRootHelp(wantsColor() && !opts.noColor, pkgVersion());
  });

  program
    .command("init")
    .description("Initialize PGPJS in a project")
    .option("--dry-run", "Show the plan without writing")
    .option("--yes", "Do not confirm")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "init", (ctx, mode) => runInit(ctx, opts, mode));
    });

  const install = program.command("install").description("Install PGPJS integrations");
  install
    .command("next")
    .description("Install Next.js App Router / Route Handler integration")
    .option("--force", "Run even if Next.js is not detected")
    .option("--skip-install", "Scaffold files without installing packages")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "install.next", (ctx, mode) => runInstall(ctx, "next", opts, mode));
    });
  install
    .command("node")
    .description("Install Node.js network / server helpers")
    .option("--skip-install", "Scaffold files without installing packages")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "install.node", (ctx, mode) => runInstall(ctx, "node", opts, mode));
    });
  install
    .command("react")
    .description("Install React / Vite client helpers (no private keys)")
    .option("--force", "Run even if React is not detected")
    .option("--skip-install", "Scaffold files without installing packages")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "install.react", (ctx, mode) => runInstall(ctx, "react", opts, mode));
    });

  const key = program.command("key").description("Manage OpenPGP keys");
  key
    .command("generate")
    .description("Generate an OpenPGP keypair")
    .option("--name <name>", "User name")
    .option("--email <email>", "User email")
    .option("--algorithm <algo>", "ed25519 | rsa3072 | rsa4096")
    .option("--expires <duration>", "30d, 1y, 2y, or never (default 2y)")
    .option("--passphrase-file <path>", "Read passphrase from file")
    .option("--passphrase-fd <n>", "Read passphrase from file descriptor")
    .option("--no-passphrase", "Generate an unprotected key (dangerous)")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "key.generate", (ctx, mode) => runKeyGenerate(ctx, opts, mode));
    });
  key
    .command("list")
    .description("List keys in the keystore")
    .action(async (_opts, cmd) => {
      await withCtx(cmd, "key.list", (ctx, mode) => runKeyList(ctx, mode));
    });
  key
    .command("show")
    .argument("<id>", "Fingerprint, long key ID, or email")
    .description("Show key details")
    .action(async (id, _opts, cmd) => {
      await withCtx(cmd, "key.show", (ctx, mode) => runKeyShow(ctx, id, mode));
    });
  key
    .command("export")
    .argument("<id>", "Fingerprint, long key ID, or email")
    .description("Export a public (or private) key")
    .option("--private", "Export the private key (disabled by default)")
    .option("--output <path>", "Write to a file")
    .option("--stdout", "Write to stdout")
    .option("--yes", "Confirm private export in non-interactive mode")
    .action(async (id, opts, cmd) => {
      await withCtx(cmd, "key.export", (ctx, mode) => runKeyExport(ctx, id, opts, mode));
    });
  key
    .command("import")
    .argument("<file>", "Armored or binary key file")
    .description("Import a key into the keystore")
    .action(async (file, _opts, cmd) => {
      await withCtx(cmd, "key.import", (ctx, mode) => runKeyImport(ctx, file, mode));
    });
  key
    .command("delete")
    .argument("<id>", "Fingerprint, long key ID, or email")
    .option("--yes", "Do not confirm")
    .description("Delete a key from the keystore")
    .action(async (id, opts, cmd) => {
      await withCtx(cmd, "key.delete", (ctx, mode) => runKeyDelete(ctx, id, opts, mode));
    });
  key
    .command("reindex")
    .description("Rebuild the keystore index from .asc files")
    .action(async (_opts, cmd) => {
      await withCtx(cmd, "key.reindex", (ctx, mode) => runKeyReindex(ctx, mode));
    });

  const passphraseOpts = (c: Command) =>
    c
      .option("--passphrase-file <path>", "Read passphrase from file")
      .option("--passphrase-fd <n>", "Read passphrase from file descriptor");

  passphraseOpts(
    program
      .command("encrypt")
      .argument("[file]", "Input file, or - for stdin")
      .description("Encrypt data")
      .option("--recipient <id>", "Recipient email or fingerprint (repeatable)", collect, [])
      .option("--sign", "Also sign with --key / defaultKey")
      .option("--key <id>", "Signing key")
      .option("--armor", "Armored output")
      .option("--binary", "Binary output")
      .option("--output <path>", "Output path")
      .option("--force", "Overwrite existing output")
      .option("--allow-expired", "Allow encrypting to an expired key")
  ).action(async (file, opts, cmd) => {
    await withCtx(cmd, "encrypt", (ctx, mode) => runEncrypt(ctx, file, opts, mode));
  });

  passphraseOpts(
    program
      .command("decrypt")
      .argument("[file]", "Input file, or - for stdin")
      .description("Decrypt data")
      .option("--key <id>", "Private key to use")
      .option("--output <path>", "Output path")
      .option("--force", "Overwrite existing output")
      .option("--allow-unauthenticated", "Allow messages without MDC/AEAD (dangerous)")
      .option("--emit-plaintext", "Include plaintext in --json output")
  ).action(async (file, opts, cmd) => {
    await withCtx(cmd, "decrypt", (ctx, mode) => runDecrypt(ctx, file, opts, mode));
  });

  passphraseOpts(
    program
      .command("sign")
      .argument("[file]", "Input file, or - for stdin")
      .description("Sign data (default: detached)")
      .option("--key <id>", "Signing key")
      .option("--detached", "Detached signature (default for files)")
      .option("--inline", "Inline signature")
      .option("--cleartext", "Clearsigned text")
      .option("--armor", "Armored output")
      .option("--binary", "Binary output")
      .option("--output <path>", "Output path")
      .option("--force", "Overwrite existing output")
  ).action(async (file, opts, cmd) => {
    await withCtx(cmd, "sign", (ctx, mode) => runSign(ctx, file, opts, mode));
  });

  program
    .command("verify")
    .argument("<file>", "Signed file")
    .description("Verify a signature")
    .option("--signature <file>", "Detached signature")
    .option("--signer <id>", "Expected signer fingerprint")
    .action(async (file, opts, cmd) => {
      await withCtx(cmd, "verify", (ctx, mode) => runVerify(ctx, file, opts, mode));
    });

  program
    .command("doctor")
    .description("Diagnose project configuration")
    .action(async (_opts, cmd) => {
      await withCtx(cmd, "doctor", (ctx, mode) => runDoctor(ctx, mode));
    });

  const security = program.command("security").description("Run security checks");
  security
    .command("scan")
    .description("Scan for exposed keys, tokens, and insecure configuration")
    .option("--fix", "Apply safe fixes (gitignore, permissions)")
    .option("--fail-on <severity>", "critical|high|medium|low", "high")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "security.scan", (ctx, mode) => runSecurityScan(ctx, opts, mode));
    });
  security.action(async (opts, cmd) => {
    await withCtx(cmd, "security.scan", (ctx, mode) => runSecurityScan(ctx, opts, mode));
  });

  const mcp = program.command("mcp").description("Run and configure MCP");
  mcp
    .command("start")
    .description("Start the MCP server (stdio by default)")
    .option("--http", "Streamable HTTP transport")
    .option("--port <n>", "HTTP port", "8787")
    .option("--host <host>", "Bind address", "127.0.0.1")
    .option("--allow-remote", "Allow non-loopback bind")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "mcp.start", (ctx) => runMcpStart(ctx, opts));
    });
  mcp
    .command("status")
    .description("Show MCP server, token, and network status")
    .action(async (_opts, cmd) => {
      await withCtx(cmd, "mcp.status", (ctx, mode) => runMcpStatus(ctx, mode));
    });
  mcp.action(async (_opts, cmd) => {
    await withCtx(cmd, "mcp.start", (ctx) => runMcpStart(ctx, {}));
  });

  mcp
    .command("config")
    .description("Print MCP client configuration")
    .option("--format <fmt>", "json|yaml", "json")
    .option("--http", "Emit URL + header variant")
    .option("--port <n>", "HTTP port for --http")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "mcp.config", (ctx, mode) => runMcpConfig(ctx, opts, mode));
    });
  mcp.command("audit").description("Read the MCP audit log").action(async (_opts, cmd) => {
    await withCtx(cmd, "mcp.audit", (ctx, mode) => runMcpAudit(ctx, mode));
  });

  const token = program.command("token").description("Manage MCP authentication tokens");
  token
    .command("create")
    .description("Create an MCP token (shown once)")
    .requiredOption("--name <name>", "Token name")
    .option("--scope <scope>", "Repeatable scope", collect, [])
    .option("--expires <duration>", "30d, 12h, 1y (default 90d)")
    .action(async (opts, cmd) => {
      await withCtx(cmd, "token.create", (ctx, mode) => runMcpTokenCreate(ctx, opts, mode));
    });
  token
    .command("list")
    .description("List MCP tokens (hashes only)")
    .action(async (_opts, cmd) => {
      await withCtx(cmd, "token.list", (ctx, mode) => runMcpTokenList(ctx, mode));
    });
  token
    .command("revoke")
    .argument("<id>", "Token id")
    .description("Revoke an MCP token")
    .action(async (id, _opts, cmd) => {
      await withCtx(cmd, "token.revoke", (ctx, mode) => runMcpTokenRevoke(ctx, id, mode));
    });
  token
    .command("rotate")
    .argument("<id>", "Token id")
    .description("Rotate an MCP token")
    .action(async (id, _opts, cmd) => {
      await withCtx(cmd, "token.rotate", (ctx, mode) => runMcpTokenRotate(ctx, id, mode));
    });

  const cfg = program.command("config").description("Manage configuration");
  cfg.command("show").description("Print effective config with origins").action(async (_opts, cmd) => {
    await withCtx(cmd, "config.show", (ctx, mode) => runConfigShow(ctx, mode));
  });
  cfg.action(async (_opts, cmd) => {
    await withCtx(cmd, "config.show", (ctx, mode) => runConfigShow(ctx, mode));
  });

  inheritGlobals(program);

  program.exitOverride((err) => {
    if (err.code === "commander.helpDisplayed" || err.code === "commander.version") {
      throw err;
    }
    if (err.code === "commander.help") {
      throw err;
    }
    throw new PgpjsError("USAGE_ERROR", err.message);
  });

  return program;
}

function collect(value: string, prev: string[]): string[] {
  return prev.concat([value]);
}

function flagsOnly(rest: string[]): boolean {
  return rest.every((a) => a.startsWith("-"));
}

function wantsRootHelp(rest: string[]): boolean {
  if (rest.length === 0) return true;
  if (rest[0] === "--help" || rest[0] === "-h") return true;
  if (rest[0] === "help") {
    return rest.slice(1).every((a) => a.startsWith("-"));
  }
  return flagsOnly(rest) && (rest.includes("--help") || rest.includes("-h"));
}

function wantsVersion(rest: string[]): boolean {
  return flagsOnly(rest) && (rest.includes("--version") || rest.includes("-V"));
}

export async function run(argv = process.argv): Promise<void> {
  const rest = argv.slice(2);
  const json = rest.includes("--json");
  const color = wantsColor() && !rest.includes("--no-color") && !json;

  if (wantsRootHelp(rest)) {
    if (json) {
      process.stdout.write(`${formatJsonHelp(pkgVersion())}\n`);
    } else {
      printRootHelp(color, pkgVersion());
    }
    process.exitCode = 0;
    return;
  }

  if (wantsVersion(rest)) {
    if (json) {
      process.stdout.write(`${formatJsonVersion(pkgVersion())}\n`);
    } else {
      printVersion(color, pkgVersion());
    }
    process.exitCode = 0;
    return;
  }

  const program = buildProgram();
  try {
    await program.parseAsync(argv);
  } catch (err) {
    if (err && typeof err === "object" && "code" in err) {
      const code = String((err as { code: string }).code);
      if (code === "commander.helpDisplayed" || code === "commander.version" || code === "commander.help") {
        process.exitCode = 0;
        return;
      }
      if (code.startsWith("commander.")) {
        process.exitCode = EXIT_CODES.USAGE_ERROR;
        return;
      }
    }
    process.exitCode = emitError(
      { json, quiet: false, verbose: rest.includes("--verbose"), color: false, command: "pgpjs" },
      err
    );
  }
}
