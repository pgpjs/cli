import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createJiti } from "jiti";
import type { PgpjsConfig } from "./schema.js";
import { pgpjsConfigSchema } from "./schema.js";
import { defaultHome } from "./home.js";

export type ConfigOrigin = "default" | "global" | "project" | "env" | "flag";

export interface ResolvedValue<T> {
  value: T;
  origin: ConfigOrigin;
}

export interface ResolvedConfig {
  config: PgpjsConfig;
  origins: Record<string, ConfigOrigin>;
  files: {
    global?: string;
    project?: string;
  };
  home: string;
  projectRoot: string;
  keystoreRoot: string;
}

const PROJECT_FILES = [
  "pgpjs.config.ts",
  "pgpjs.config.mts",
  "pgpjs.config.js",
  "pgpjs.config.mjs",
  "pgpjs.config.json"
];

export interface ResolveOptions {
  cwd?: string | undefined;
  home?: string | undefined;
  configPath?: string | undefined;
  configFormat?: "any" | "json" | undefined;
  flags?: Partial<PgpjsConfig> | undefined;
}

export async function resolveConfig(options: ResolveOptions = {}): Promise<ResolvedConfig> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const home = options.home ?? defaultHome();
  const origins: Record<string, ConfigOrigin> = {};
  markDefaults(origins);

  let merged: Record<string, unknown> = { ...pgpjsConfigSchema.parse({}) };

  const globalPath = join(home, "config.json");
  const files: ResolvedConfig["files"] = {};

  if (existsSync(globalPath)) {
    const globalCfg = readJsonFile(globalPath);
    merged = deepMerge(merged, globalCfg);
    markOrigin(origins, globalCfg, "global");
    files.global = globalPath;
  }

  const projectFile = options.configPath
    ? resolve(options.configPath)
    : process.env["PGPJS_CONFIG"]
      ? resolve(process.env["PGPJS_CONFIG"])
      : findProjectConfig(cwd);

  const projectRoot = projectFile ? dirname(projectFile) : findGitRoot(cwd) ?? cwd;

  if (projectFile) {
    if (options.configFormat === "json" && !projectFile.endsWith(".json")) {
      throw Object.assign(new Error("Non-declarative config refused (--config-format=json)."), {
        code: "CONFIG_INVALID"
      });
    }
    const loaded = await loadConfigFile(projectFile);
    merged = deepMerge(merged, loaded);
    markOrigin(origins, loaded, "project");
    files.project = projectFile;
  }

  const envOverlay = envOverrides();
  merged = deepMerge(merged, envOverlay);
  markOrigin(origins, envOverlay, "env");

  if (options.flags) {
    const cleaned = stripUndefined(options.flags as Record<string, unknown>);
    merged = deepMerge(merged, cleaned);
    markOrigin(origins, cleaned, "flag");
  }

  const parsed = pgpjsConfigSchema.safeParse(merged);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw Object.assign(new Error(issue?.message ?? "Invalid configuration."), {
      code: "CONFIG_INVALID",
      details: parsed.error.flatten()
    });
  }

  const keystoreRoot = parsed.data.keyDirectory.startsWith("/")
    ? parsed.data.keyDirectory
    : join(projectRoot, ".pgpjs");

  return {
    config: parsed.data,
    origins,
    files,
    home,
    projectRoot,
    keystoreRoot
  };
}

function markDefaults(origins: Record<string, ConfigOrigin>): void {
  origins["keyDirectory"] = "default";
  origins["defaultArmor"] = "default";
  origins["maxFileSize"] = "default";
  origins["security.allowPrivateKeyExport"] = "default";
  origins["security.requireEncryptedPrivateKeys"] = "default";
  origins["security.warnOnUnprotectedKeystore"] = "default";
}

function markOrigin(origins: Record<string, ConfigOrigin>, obj: Record<string, unknown>, origin: ConfigOrigin, prefix = ""): void {
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      markOrigin(origins, v as Record<string, unknown>, origin, path);
    } else {
      origins[path] = origin;
    }
  }
}

function envOverrides(): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (process.env["PGPJS_KEY_DIRECTORY"]) {
    out["keyDirectory"] = process.env["PGPJS_KEY_DIRECTORY"];
  }
  if (process.env["PGPJS_DEFAULT_ARMOR"] === "0" || process.env["PGPJS_DEFAULT_ARMOR"] === "false") {
    out["defaultArmor"] = false;
  }
  if (process.env["PGPJS_DEFAULT_ARMOR"] === "1" || process.env["PGPJS_DEFAULT_ARMOR"] === "true") {
    out["defaultArmor"] = true;
  }
  if (process.env["PGPJS_DEFAULT_KEY"]) {
    out["defaultKey"] = process.env["PGPJS_DEFAULT_KEY"];
  }
  if (process.env["PGPJS_MAX_FILE_SIZE"]) {
    out["maxFileSize"] = process.env["PGPJS_MAX_FILE_SIZE"];
  }
  return out;
}

function findProjectConfig(start: string): string | undefined {
  const root = findGitRoot(start) ?? start;
  let dir = start;
  while (true) {
    for (const name of PROJECT_FILES) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
    const pkg = join(dir, "package.json");
    if (existsSync(pkg)) {
      try {
        const json = JSON.parse(readFileSync(pkg, "utf8")) as { pgpjs?: unknown };
        if (json.pgpjs) return pkg;
      } catch {
        /* ignore */
      }
    }
    if (dir === root) break;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

function findGitRoot(start: string): string | undefined {
  let dir = start;
  while (true) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

async function loadConfigFile(file: string): Promise<Record<string, unknown>> {
  if (file.endsWith("package.json")) {
    const json = JSON.parse(readFileSync(file, "utf8")) as { pgpjs?: Record<string, unknown> };
    return json.pgpjs ?? {};
  }
  if (file.endsWith(".json")) {
    return readJsonFile(file);
  }
  const jiti = createJiti(import.meta.url, { moduleCache: false });
  const loaded = await jiti.import(file);
  const mod = loaded as { default?: unknown; config?: unknown };
  const value = (mod.default ?? mod.config ?? loaded) as unknown;
  if (typeof value !== "object" || value === null) {
    throw Object.assign(new Error("Config file did not export an object."), { code: "CONFIG_INVALID" });
  }
  return value as Record<string, unknown>;
}

function readJsonFile(file: string): Record<string, unknown> {
  try {
    return JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
  } catch (err) {
    throw Object.assign(new Error(`Failed to parse JSON config at ${file}.`), {
      code: "CONFIG_INVALID",
      cause: err
    });
  }
}

function deepMerge(a: Record<string, unknown>, b: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...a };
  for (const [k, v] of Object.entries(b)) {
    if (v && typeof v === "object" && !Array.isArray(v) && typeof out[k] === "object" && out[k] !== null && !Array.isArray(out[k])) {
      out[k] = deepMerge(out[k] as Record<string, unknown>, v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function stripUndefined(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined) continue;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      out[k] = stripUndefined(v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export { findGitRoot };
