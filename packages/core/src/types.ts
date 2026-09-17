export type KeyAlgorithm =
  | "ed25519"
  | "x25519"
  | "rsa3072"
  | "rsa4096"
  | "rsa2048"
  | "ecdsa-p256"
  | "ecdsa-p384"
  | "ecdh-p256"
  | "ecdh-p384"
  | "unknown";

export type GenerateAlgorithm = "ed25519" | "rsa3072" | "rsa4096";

export interface UserIdParts {
  name: string;
  email: string;
  comment?: string;
}

export interface KeyMetadata {
  id: string;
  fingerprint: string;
  keyId: string;
  userIds: string[];
  email: string | undefined;
  algorithm: string;
  createdAt: string;
  expiresAt: string | null;
  revoked: boolean;
  expired: boolean;
  isPrivate: boolean;
  encrypted: boolean;
  capabilities: string[];
  subkeys: SubkeyMetadata[];
}

export interface SubkeyMetadata {
  keyId: string;
  algorithm: string;
  expiresAt: string | null;
  capabilities: string[];
}

export interface StoredKeyRecord {
  fingerprint: string;
  keyId: string;
  userIds: string[];
  emails: string[];
  algorithm: string;
  createdAt: string;
  expiresAt: string | null;
  revoked: boolean;
  hasPrivate: boolean;
  hasPublic: boolean;
}

export interface KeystoreIndex {
  version: 1;
  keys: StoredKeyRecord[];
}

export type SignMode = "detached" | "inline" | "cleartext";

export type VerifyStatus = "valid" | "untrusted" | "invalid" | "missing";

export interface SignatureInfo {
  keyId: string | undefined;
  fingerprint: string | undefined;
  createdAt: string | undefined;
  valid: boolean;
}

export interface EncryptResult {
  armored: boolean;
  bytes: number;
  recipientFingerprints: string[];
  signedBy: string | undefined;
}

export interface DecryptResultMeta {
  signatures: SignatureInfo[];
  wasSigned: boolean;
  filename: string | undefined;
  integrityProtected: boolean;
}

export const DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024;
export const DEFAULT_KEY_EXPIRY_SECONDS = 2 * 365 * 24 * 60 * 60;
export const JSON_SCHEMA_VERSION = 1;
