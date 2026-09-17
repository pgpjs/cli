import { z } from "zod";
import {
  encryptData,
  generateKey,
  PgpjsError,
  Keystore,
  signData,
  decryptData,
  verifyData,
  verifyStatusToError
} from "@pgpjs/core";
import {
  capabilityAllowed,
  denyReason,
  effectivePermissions,
  scanProject,
  type Capability,
  type PermissionSet,
  type ScopeName
} from "@pgpjs/security";
import type { McpConfig } from "@pgpjs/config";
import { appendAudit } from "./audit.js";
import { permissionsFromConfig } from "./config.js";
import { RateLimiter } from "./rate-limit.js";
import type { TokenRecord } from "./tokens.js";

export const toolSchemas = {
  pgpjs_key_list: z.object({}),
  pgpjs_key_info: z.object({
    id: z.string().min(1)
  }),
  pgpjs_encrypt: z.object({
    message: z.string(),
    recipient: z.string().min(1),
    armor: z.boolean().optional()
  }),
  pgpjs_verify: z.object({
    message: z.string(),
    signature: z.string().optional(),
    signer: z.string().optional()
  }),
  pgpjs_sign: z.object({
    message: z.string(),
    key: z.string().optional(),
    mode: z.enum(["detached", "inline", "cleartext"]).optional()
  }),
  pgpjs_decrypt: z.object({
    message: z.string(),
    key: z.string().optional()
  }),
  pgpjs_key_generate: z.object({
    name: z.string().min(1),
    email: z.string().email(),
    algorithm: z.enum(["ed25519", "rsa3072", "rsa4096"]).optional(),
    expires: z.string().optional()
  }),
  pgpjs_export_public_key: z.object({
    id: z.string().min(1)
  }),
  pgpjs_security_scan: z.object({
    failOn: z.enum(["critical", "high", "medium", "low"]).optional()
  })
} as const;

export const TOOL_CAPABILITY: Record<keyof typeof toolSchemas, Capability> = {
  pgpjs_key_list: "READ_KEYS",
  pgpjs_key_info: "READ_KEYS",
  pgpjs_encrypt: "ENCRYPT",
  pgpjs_verify: "VERIFY",
  pgpjs_sign: "SIGN",
  pgpjs_decrypt: "DECRYPT",
  pgpjs_key_generate: "GENERATE_KEYS",
  pgpjs_export_public_key: "EXPORT_PUBLIC_KEY",
  pgpjs_security_scan: "SECURITY_SCAN"
};

export const TOOL_RISK: Record<keyof typeof toolSchemas, string> = {
  pgpjs_key_list: "Returns public key metadata only.",
  pgpjs_key_info: "Returns public key metadata for one identity.",
  pgpjs_encrypt: "Returns ciphertext and the resolved recipient fingerprint.",
  pgpjs_verify: "Returns valid/untrusted/invalid; never returns key material.",
  pgpjs_sign: "Produces an authentic signature. Off by default.",
  pgpjs_decrypt: "Returns plaintext to the agent — an exfiltration channel. Off by default.",
  pgpjs_key_generate: "Mutates the keystore. Off by default.",
  pgpjs_export_public_key: "Returns an armored public key.",
  pgpjs_security_scan: "Returns redacted findings for the working directory."
};

export interface ToolContext {
  cwd: string;
  keystore: Keystore;
  mcpConfig: McpConfig;
  token: TokenRecord | null;
  passphrase?: string | undefined;
  auditPath: string;
  limiter: RateLimiter;
}

function envelopeOk(command: string, data: unknown): { ok: true; version: 1; command: string; data: unknown } {
  return { ok: true, version: 1, command, data };
}

function envelopeErr(command: string, err: PgpjsError): {
  ok: false;
  version: 1;
  command: string;
  error: ReturnType<PgpjsError["toJSON"]>;
} {
  return { ok: false, version: 1, command, error: err.toJSON() };
}

function effective(ctx: ToolContext): PermissionSet {
  const scopes: ScopeName[] | "all" = ctx.token ? ctx.token.scopes : "all";
  return effectivePermissions(permissionsFromConfig(ctx.mcpConfig), scopes);
}

function assertCap(ctx: ToolContext, cap: Capability): void {
  if (cap === "EXPORT_PRIVATE_KEY") {
    throw new PgpjsError("PERMISSION_DENIED", "Private-key export is not available over MCP.", {
      details: { capability: cap, side: "hard-limit" }
    });
  }
  const configPerms = permissionsFromConfig(ctx.mcpConfig);
  const scopes: ScopeName[] | "all" = ctx.token ? ctx.token.scopes : "all";
  const reason = denyReason(cap, configPerms, scopes);
  if (reason) {
    throw new PgpjsError("PERMISSION_DENIED", `Capability ${cap} is denied by ${reason.side}.`, {
      details: { capability: cap, side: reason.side }
    });
  }
  if (!capabilityAllowed(effective(ctx), cap)) {
    throw new PgpjsError("PERMISSION_DENIED", `Capability ${cap} is not granted.`, {
      details: { capability: cap }
    });
  }
}

function assertAllowedKey(ctx: ToolContext, fingerprint: string): void {
  const allow = ctx.mcpConfig.allowedKeys;
  if (!allow || allow.length === 0) return;
  const ok = allow.some((k) => k.replace(/\s/g, "").toUpperCase() === fingerprint.replace(/\s/g, "").toUpperCase());
  if (!ok) {
    throw new PgpjsError("PERMISSION_DENIED", "Recipient is not in the MCP allowedKeys allowlist.", {
      details: { fingerprint }
    });
  }
}

export async function executeTool(
  name: keyof typeof toolSchemas,
  rawArgs: unknown,
  ctx: ToolContext
): Promise<{ ok: boolean; version: 1; command: string; data?: unknown; error?: unknown }> {
  const command = name;
  try {
    if (ctx.token && !ctx.limiter.check(ctx.token.id, name === "pgpjs_key_generate" ? "keygen" : "op")) {
      throw new PgpjsError("PERMISSION_DENIED", "Rate limit exceeded for this MCP token.");
    }
    const parsed = toolSchemas[name].parse(rawArgs);
    assertCap(ctx, TOOL_CAPABILITY[name]);

    let fingerprints: string[] = [];
    let bytes = 0;
    let data: unknown;

    switch (name) {
      case "pgpjs_key_list": {
        const keys = await ctx.keystore.list();
        data = {
          keys: keys.map((k) => ({
            id: k.fingerprint,
            fingerprint: k.fingerprint,
            email: k.emails[0],
            algorithm: k.algorithm,
            expiresAt: k.expiresAt
          }))
        };
        fingerprints = keys.map((k) => k.fingerprint);
        break;
      }
      case "pgpjs_key_info": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_key_info>;
        const { meta } = await ctx.keystore.readPublic(args.id);
        data = { key: meta };
        fingerprints = [meta.fingerprint];
        break;
      }
      case "pgpjs_encrypt": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_encrypt>;
        const { key, meta } = await ctx.keystore.readPublic(args.recipient);
        assertAllowedKey(ctx, meta.fingerprint);
        const armor = args.armor ?? true;
        const result = await encryptData({
          text: args.message,
          encryptionKeys: [key],
          armor
        });
        data = {
          encrypted: result.output,
          recipients: result.result.recipientFingerprints
        };
        fingerprints = result.result.recipientFingerprints;
        bytes = result.result.bytes;
        break;
      }
      case "pgpjs_verify": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_verify>;
        const keys = await ctx.keystore.list();
        const verificationKeys = [];
        for (const k of keys) {
          const { key } = await ctx.keystore.readPublic(k.fingerprint);
          verificationKeys.push(key);
        }
        const verifyInput: Parameters<typeof verifyData>[0] = { verificationKeys };
        if (args.signature) {
          verifyInput.text = args.message;
          verifyInput.detachedSignature = args.signature;
        } else {
          verifyInput.armoredMessage = args.message;
        }
        if (args.signer) {
          verifyInput.expectedSignerFingerprint = args.signer;
        }
        const result = await verifyData(verifyInput);
        if (result.status === "invalid" || result.status === "missing") {
          verifyStatusToError(result.status);
        }
        data = result;
        fingerprints = result.signerFingerprint ? [result.signerFingerprint] : [];
        break;
      }
      case "pgpjs_sign": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_sign>;
        const identity = args.key;
        if (!identity) {
          throw new PgpjsError("KEY_NOT_FOUND", "Signing key id is required.", {
            hint: "Pass key as a fingerprint."
          });
        }
        const { key, meta } = await ctx.keystore.readPrivate(identity, ctx.passphrase);
        const signed = await signData({
          text: args.message,
          signingKey: key,
          mode: args.mode ?? "detached",
          armor: true
        });
        data = { signature: signed.output, fingerprint: signed.fingerprint };
        fingerprints = [meta.fingerprint];
        bytes = typeof signed.output === "string" ? signed.output.length : signed.output.byteLength;
        break;
      }
      case "pgpjs_decrypt": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_decrypt>;
        const keys = await ctx.keystore.list();
        const privateKeys = [];
        for (const k of keys.filter((x) => x.hasPrivate)) {
          if (args.key && k.fingerprint !== args.key && !k.emails.includes(args.key)) continue;
          try {
            const { key } = await ctx.keystore.readPrivate(k.fingerprint, ctx.passphrase);
            privateKeys.push(key);
          } catch {
            continue;
          }
        }
        const decrypted = await decryptData({
          armored: args.message,
          decryptionKeys: privateKeys
        });
        data = {
          plaintext: decrypted.text ?? Buffer.from(decrypted.data).toString("base64"),
          encoding: decrypted.text ? "utf8" : "base64",
          wasSigned: decrypted.meta.wasSigned
        };
        bytes = decrypted.data.byteLength;
        break;
      }
      case "pgpjs_key_generate": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_key_generate>;
        const generated = await generateKey({
          name: args.name,
          email: args.email,
          algorithm: args.algorithm ?? "ed25519"
        });
        await ctx.keystore.saveGenerated({
          fingerprint: generated.fingerprint,
          publicKeyArmored: generated.publicKeyArmored,
          privateKeyArmored: generated.privateKeyArmored,
          revocationCertificate: generated.revocationCertificate
        });
        data = {
          fingerprint: generated.fingerprint,
          algorithm: generated.algorithm,
          expiresAt: generated.expiresAt
        };
        fingerprints = [generated.fingerprint];
        break;
      }
      case "pgpjs_export_public_key": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_export_public_key>;
        const armored = await ctx.keystore.exportPublic(args.id);
        const { meta } = await ctx.keystore.readPublic(args.id);
        data = { publicKey: armored, fingerprint: meta.fingerprint };
        fingerprints = [meta.fingerprint];
        break;
      }
      case "pgpjs_security_scan": {
        const args = parsed as z.infer<typeof toolSchemas.pgpjs_security_scan>;
        const result = scanProject({ cwd: ctx.cwd, failOn: args.failOn ?? "high" });
        data = { findings: result.findings, failed: result.failed };
        break;
      }
    }

    await appendAudit(ctx.auditPath, {
      timestamp: new Date().toISOString(),
      tokenId: ctx.token?.id ?? null,
      tool: name,
      decision: "allow",
      reason: "ok",
      fingerprints,
      bytes
    });
    return envelopeOk(command, data);
  } catch (err) {
    const mapped =
      err instanceof PgpjsError
        ? err
        : new PgpjsError("GENERIC_ERROR", err instanceof Error ? err.message : "Tool failed.");
    await appendAudit(ctx.auditPath, {
      timestamp: new Date().toISOString(),
      tokenId: ctx.token?.id ?? null,
      tool: name,
      decision: "deny",
      reason: mapped.code,
      fingerprints: [],
      bytes: 0
    });
    return envelopeErr(command, mapped);
  }
}

/** There is intentionally no private-key export tool. */
export const PRIVATE_KEY_EXPORT_IMPLEMENTED = false;
