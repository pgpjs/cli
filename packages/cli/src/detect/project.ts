import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type Framework =
  | "next-app"
  | "next-pages"
  | "nuxt"
  | "remix"
  | "vite"
  | "react"
  | "express"
  | "hono"
  | "astro"
  | "node";

export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

export interface ProjectInfo {
  cwd: string;
  isTypeScript: boolean;
  framework: Framework;
  hasSrcDir: boolean;
  packageManager: PackageManager;
  hasPackageJson: boolean;
  nextVersion?: string | undefined;
}

export function detectProject(cwd: string): ProjectInfo {
  const pkgPath = join(cwd, "package.json");
  let pkg: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    packageManager?: string;
  } = {};
  const hasPackageJson = existsSync(pkgPath);
  if (hasPackageJson) {
    try {
      pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as typeof pkg;
    } catch {
      pkg = {};
    }
  }
  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  const isTypeScript = existsSync(join(cwd, "tsconfig.json"));
  const hasSrcDir = existsSync(join(cwd, "src"));

  let framework: Framework = "node";
  if (deps["next"]) {
    const appDir = hasSrcDir ? join(cwd, "src/app") : join(cwd, "app");
    framework = existsSync(appDir) ? "next-app" : "next-pages";
  } else if (deps["nuxt"]) {
    framework = "nuxt";
  } else if (deps["@remix-run/node"] || deps["@remix-run/react"]) {
    framework = "remix";
  } else if (deps["astro"]) {
    framework = "astro";
  } else if (deps["hono"]) {
    framework = "hono";
  } else if (deps["express"]) {
    framework = "express";
  } else if (deps["vite"]) {
    framework = "vite";
  } else if (deps["react"]) {
    framework = "react";
  }

  return {
    cwd,
    isTypeScript,
    framework,
    hasSrcDir,
    packageManager: detectPackageManager(cwd, pkg.packageManager),
    hasPackageJson,
    nextVersion: deps["next"]
  };
}

export function detectPackageManager(cwd: string, field?: string): PackageManager {
  if (existsSync(join(cwd, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(cwd, "yarn.lock"))) return "yarn";
  if (existsSync(join(cwd, "bun.lockb")) || existsSync(join(cwd, "bun.lock"))) return "bun";
  if (existsSync(join(cwd, "package-lock.json"))) return "npm";
  if (field?.startsWith("pnpm")) return "pnpm";
  if (field?.startsWith("yarn")) return "yarn";
  if (field?.startsWith("bun")) return "bun";
  const ua = process.env["npm_config_user_agent"] ?? "";
  if (ua.includes("pnpm")) return "pnpm";
  if (ua.includes("yarn")) return "yarn";
  if (ua.includes("bun")) return "bun";
  return "npm";
}

export function installArgs(pm: PackageManager, packages: string[]): { cmd: string; args: string[] } {
  switch (pm) {
    case "pnpm":
      return { cmd: "pnpm", args: ["add", ...packages] };
    case "yarn":
      return { cmd: "yarn", args: ["add", ...packages] };
    case "bun":
      return { cmd: "bun", args: ["add", ...packages] };
    default:
      return { cmd: "npm", args: ["install", ...packages] };
  }
}
