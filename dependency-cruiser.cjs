/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    {
      name: "core-must-not-import-cli",
      comment: "@pgpjs/core must not import CLI presentation libraries or the CLI package.",
      severity: "error",
      from: { path: "^packages/core/src" },
      to: {
        path: "(packages/cli|chalk|commander|ora|@inquirer)"
      }
    },
    {
      name: "core-must-not-import-mcp",
      severity: "error",
      from: { path: "^packages/core/src" },
      to: { path: "^packages/mcp" }
    },
    {
      name: "config-must-not-import-core",
      severity: "error",
      from: { path: "^packages/config/src" },
      to: { path: "^packages/core" }
    },
    {
      name: "security-must-not-import-cli-or-mcp",
      severity: "error",
      from: { path: "^packages/security/src" },
      to: { path: "^packages/(cli|mcp)" }
    }
  ],
  options: {
    doNotFollow: { path: "node_modules" },
    tsPreCompilationDeps: true,
    combinedDependencies: true
  }
};
