export type Capability =
  | "READ_KEYS"
  | "ENCRYPT"
  | "VERIFY"
  | "DECRYPT"
  | "SIGN"
  | "GENERATE_KEYS"
  | "EXPORT_PUBLIC_KEY"
  | "SECURITY_SCAN"
  | "EXPORT_PRIVATE_KEY";

export const CAPABILITY_TO_CONFIG: Record<Capability, string> = {
  READ_KEYS: "readKeys",
  ENCRYPT: "encrypt",
  VERIFY: "verify",
  DECRYPT: "decrypt",
  SIGN: "sign",
  GENERATE_KEYS: "generateKeys",
  EXPORT_PUBLIC_KEY: "exportPublicKey",
  SECURITY_SCAN: "securityScan",
  EXPORT_PRIVATE_KEY: "exportPrivateKeys"
};

export interface PermissionSet {
  readKeys: boolean;
  encrypt: boolean;
  verify: boolean;
  exportPublicKey: boolean;
  securityScan: boolean;
  decrypt: boolean;
  sign: boolean;
  generateKeys: boolean;
  exportPrivateKeys: boolean;
}

export const DEFAULT_PERMISSIONS: PermissionSet = {
  readKeys: true,
  encrypt: true,
  verify: true,
  exportPublicKey: true,
  securityScan: true,
  decrypt: false,
  sign: false,
  generateKeys: false,
  exportPrivateKeys: false
};

export type ScopeName =
  | "readKeys"
  | "encrypt"
  | "verify"
  | "decrypt"
  | "sign"
  | "generateKeys"
  | "exportPublicKey"
  | "securityScan";

export const ALL_SCOPES: ScopeName[] = [
  "readKeys",
  "encrypt",
  "verify",
  "decrypt",
  "sign",
  "generateKeys",
  "exportPublicKey",
  "securityScan"
];

/**
 * effective = config.permissions ∩ token.scopes
 * Intersection, never union. EXPORT_PRIVATE_KEY is always denied.
 */
export function effectivePermissions(
  config: PermissionSet,
  tokenScopes: ScopeName[] | "all"
): PermissionSet {
  const scopeSet = tokenScopes === "all" ? new Set(ALL_SCOPES) : new Set(tokenScopes);
  const pick = (key: ScopeName, configAllows: boolean): boolean =>
    configAllows && scopeSet.has(key);

  return {
    readKeys: pick("readKeys", config.readKeys),
    encrypt: pick("encrypt", config.encrypt),
    verify: pick("verify", config.verify),
    exportPublicKey: pick("exportPublicKey", config.exportPublicKey),
    securityScan: pick("securityScan", config.securityScan),
    decrypt: pick("decrypt", config.decrypt),
    sign: pick("sign", config.sign),
    generateKeys: pick("generateKeys", config.generateKeys),
    exportPrivateKeys: false
  };
}

export function capabilityAllowed(effective: PermissionSet, cap: Capability): boolean {
  if (cap === "EXPORT_PRIVATE_KEY") return false;
  const key = CAPABILITY_TO_CONFIG[cap] as keyof PermissionSet;
  return Boolean(effective[key]);
}

export function denyReason(
  cap: Capability,
  config: PermissionSet,
  tokenScopes: ScopeName[] | "all"
): { side: "config" | "token" | "hard-limit"; capability: Capability } | undefined {
  if (cap === "EXPORT_PRIVATE_KEY") {
    return { side: "hard-limit", capability: cap };
  }
  const key = CAPABILITY_TO_CONFIG[cap] as keyof PermissionSet;
  if (!config[key]) {
    return { side: "config", capability: cap };
  }
  if (tokenScopes !== "all" && !tokenScopes.includes(key as ScopeName)) {
    return { side: "token", capability: cap };
  }
  return undefined;
}
