export {
  PgpjsError,
  isPgpjsError,
  ERROR_CODES,
  EXIT_CODES,
  assertNodeVersion,
  exitCodeFor
} from "./errors.js";
export type { ErrorCode, ExitCode, PgpjsErrorOptions } from "./errors.js";

export type {
  GenerateAlgorithm,
  KeyAlgorithm,
  KeyMetadata,
  StoredKeyRecord,
  SignMode,
  VerifyStatus,
  EncryptResult,
  DecryptResultMeta,
  SignatureInfo,
  UserIdParts
} from "./types.js";
export { DEFAULT_MAX_FILE_SIZE, DEFAULT_KEY_EXPIRY_SECONDS, JSON_SCHEMA_VERSION } from "./types.js";

export {
  formatFingerprint,
  normalizeFingerprint,
  classifyIdentity,
  rejectShortKeyId,
  fingerprintsEqual
} from "./fingerprint.js";

export { parseDuration, durationToDate } from "./duration.js";
export { parseByteSize, getSecureRandomBytes, sha256Hex, sha256Bytes, timingSafeEqualHex, toBase64Url, zeroFill } from "./bytes.js";
export {
  assertGenerateAlgorithm,
  describeGenerateAlgorithm,
  ALLOWED_GENERATE,
  algorithmFromOpenPgp
} from "./algorithms.js";

export { generateKey } from "./crypto/generate.js";
export type { GenerateKeyInput, GenerateKeyOutput } from "./crypto/generate.js";
export { encryptData } from "./crypto/encrypt.js";
export { decryptData, sanitizeEmbeddedFilename } from "./crypto/decrypt.js";
export { signData } from "./crypto/sign.js";
export { verifyData, verifyStatusToError } from "./crypto/verify.js";
export {
  readArmoredKey,
  readBinaryKey,
  readKeyAuto,
  decryptPrivateKey,
  toKeyMetadata,
  matchKeyIdentity,
  assertUsableEncryptionKey
} from "./crypto/keys.js";
export { encryptToPublicKey, parseArmoredPublicKey, verifySignature } from "./crypto/client-safe.js";

export { Keystore, keystorePaths, fileExists, withKeystoreLock, atomicWriteFile, ensureDir, applySecureMode } from "./keystore/index.js";
