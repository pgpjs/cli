import { readFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { mcpConfigSchema, type McpConfig } from "@pgpjs/config";
import { atomicWriteFile } from "@pgpjs/core";
import { DEFAULT_PERMISSIONS, type PermissionSet } from "@pgpjs/security";

export const DEFAULT_MCP_CONFIG: McpConfig = mcpConfigSchema.parse({
  version: 1,
  permissions: DEFAULT_PERMISSIONS,
  allowedKeys: [],
  requireConfirmation: ["decrypt", "sign"],
  audit: { enabled: true, path: ".pgpjs/audit.log" }
});

export async function loadMcpConfig(path: string): Promise<McpConfig> {
  try {
    const raw = await readFile(path, "utf8");
    return mcpConfigSchema.parse(JSON.parse(raw));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return DEFAULT_MCP_CONFIG;
    }
    throw err;
  }
}

export async function writeMcpConfig(path: string, config: McpConfig): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await atomicWriteFile(path, `${JSON.stringify(config, null, 2)}\n`, 0o600);
}

export function permissionsFromConfig(config: McpConfig): PermissionSet {
  return {
    readKeys: config.permissions.readKeys,
    encrypt: config.permissions.encrypt,
    verify: config.permissions.verify,
    exportPublicKey: config.permissions.exportPublicKey,
    securityScan: config.permissions.securityScan,
    decrypt: config.permissions.decrypt,
    sign: config.permissions.sign,
    generateKeys: config.permissions.generateKeys,
    exportPrivateKeys: false
  };
}
