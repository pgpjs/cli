import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/config-export.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  target: "node20",
  external: [
    "@pgpjs/config",
    "@pgpjs/core",
    "@pgpjs/mcp",
    "@pgpjs/security",
    "@inquirer/prompts",
    "chalk",
    "commander",
    "jiti",
    "openpgp",
    "ora",
    "zod"
  ]
});
