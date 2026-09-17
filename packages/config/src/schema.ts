import { z } from "zod";

function containsForbiddenSecret(value: unknown, keyPath = ""): boolean {
  if (typeof value === "string") {
    if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(value)) return true;
    if (/pgpjs_mcp_/.test(value)) return true;
    if (/(passphrase|password|^token$|privateKey|private_key)/i.test(keyPath) && value.length > 0) {
      return true;
    }
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (containsForbiddenSecret(v, keyPath ? `${keyPath}.${k}` : k)) return true;
    }
  }
  return false;
}

export const mcpPermissionsSchema = z.object({
  readKeys: z.boolean().default(true),
  encrypt: z.boolean().default(true),
  verify: z.boolean().default(true),
  exportPublicKey: z.boolean().default(true),
  securityScan: z.boolean().default(true),
  decrypt: z.boolean().default(false),
  sign: z.boolean().default(false),
  generateKeys: z.boolean().default(false),
  exportPrivateKeys: z.boolean().default(false)
});

export const mcpConfigSchema = z.object({
  version: z.literal(1).default(1),
  permissions: mcpPermissionsSchema.default({}),
  allowedKeys: z.array(z.string()).default([]),
  requireConfirmation: z.array(z.string()).default(["decrypt", "sign"]),
  audit: z
    .object({
      enabled: z.boolean().default(true),
      path: z.string().default(".pgpjs/audit.log")
    })
    .default({})
});

export const securityConfigSchema = z.object({
  allowPrivateKeyExport: z.boolean().default(false),
  requireEncryptedPrivateKeys: z.boolean().default(true),
  warnOnUnprotectedKeystore: z.boolean().default(true)
});

export const pgpjsConfigSchema = z
  .object({
    keyDirectory: z.string().default(".pgpjs/keys"),
    defaultArmor: z.boolean().default(true),
    defaultKey: z.string().optional(),
    maxFileSize: z.string().default("512mb"),
    security: securityConfigSchema.default({}),
    mcp: mcpConfigSchema.optional()
  })
  .superRefine((val, ctx) => {
    if (containsForbiddenSecret(val)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Configuration must not contain passphrases, tokens, or private keys."
      });
    }
  });

export type PgpjsConfig = z.infer<typeof pgpjsConfigSchema>;
export type McpConfig = z.infer<typeof mcpConfigSchema>;
export type McpPermissions = z.infer<typeof mcpPermissionsSchema>;
export type SecurityConfig = z.infer<typeof securityConfigSchema>;

export function defineConfig(config: z.input<typeof pgpjsConfigSchema>): z.input<typeof pgpjsConfigSchema> {
  return config;
}

export const DEFAULT_CONFIG: PgpjsConfig = pgpjsConfigSchema.parse({});
