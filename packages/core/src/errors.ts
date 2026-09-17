/**
 * Closed error-code union. These codes are public API; changing one is a breaking change.
 */
export const ERROR_CODES = [
  "CONFIG_NOT_FOUND",
  "CONFIG_INVALID",
  "KEY_NOT_FOUND",
  "KEY_AMBIGUOUS",
  "KEY_MALFORMED",
  "KEY_EXPIRED",
  "KEY_REVOKED",
  "KEY_EXISTS",
  "PASSPHRASE_REQUIRED",
  "PASSPHRASE_INCORRECT",
  "RECIPIENT_UNRESOLVED",
  "DECRYPT_FAILED",
  "SIGNATURE_INVALID",
  "SIGNATURE_UNTRUSTED",
  "SIGNATURE_MISSING",
  "INPUT_NOT_FOUND",
  "OUTPUT_EXISTS",
  "OUTPUT_UNSAFE_PATH",
  "PERMISSION_DENIED",
  "SCOPE_DENIED",
  "TOKEN_INVALID",
  "TOKEN_EXPIRED",
  "TOKEN_REVOKED",
  "NON_INTERACTIVE",
  "NODE_VERSION_UNSUPPORTED",
  "KEYSTORE_LOCKED",
  "KEYSTORE_CORRUPT",
  "UNSUPPORTED_ALGORITHM",
  "FILE_TOO_LARGE",
  "USAGE_ERROR",
  "IO_ERROR",
  "CRYPTO_ERROR",
  "GENERIC_ERROR",
  "SECURITY_FINDINGS",
  "WEAK_ALGORITHM"
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export const EXIT_CODES = {
  OK: 0,
  GENERIC_ERROR: 1,
  USAGE_ERROR: 2,
  CONFIG_ERROR: 3,
  KEY_ERROR: 4,
  CRYPTO_ERROR: 5,
  VERIFY_FAILED: 6,
  VERIFY_UNTRUSTED: 7,
  PERMISSION_DENIED: 8,
  IO_ERROR: 9,
  ENVIRONMENT_ERROR: 10,
  INTERACTION_REQUIRED: 11,
  SECURITY_FINDINGS: 12
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

const CODE_TO_EXIT: Record<ErrorCode, ExitCode> = {
  CONFIG_NOT_FOUND: EXIT_CODES.CONFIG_ERROR,
  CONFIG_INVALID: EXIT_CODES.CONFIG_ERROR,
  KEY_NOT_FOUND: EXIT_CODES.KEY_ERROR,
  KEY_AMBIGUOUS: EXIT_CODES.KEY_ERROR,
  KEY_MALFORMED: EXIT_CODES.KEY_ERROR,
  KEY_EXPIRED: EXIT_CODES.KEY_ERROR,
  KEY_REVOKED: EXIT_CODES.KEY_ERROR,
  KEY_EXISTS: EXIT_CODES.KEY_ERROR,
  PASSPHRASE_REQUIRED: EXIT_CODES.KEY_ERROR,
  PASSPHRASE_INCORRECT: EXIT_CODES.KEY_ERROR,
  RECIPIENT_UNRESOLVED: EXIT_CODES.KEY_ERROR,
  DECRYPT_FAILED: EXIT_CODES.CRYPTO_ERROR,
  SIGNATURE_INVALID: EXIT_CODES.VERIFY_FAILED,
  SIGNATURE_UNTRUSTED: EXIT_CODES.VERIFY_UNTRUSTED,
  SIGNATURE_MISSING: EXIT_CODES.VERIFY_FAILED,
  INPUT_NOT_FOUND: EXIT_CODES.IO_ERROR,
  OUTPUT_EXISTS: EXIT_CODES.IO_ERROR,
  OUTPUT_UNSAFE_PATH: EXIT_CODES.IO_ERROR,
  PERMISSION_DENIED: EXIT_CODES.PERMISSION_DENIED,
  SCOPE_DENIED: EXIT_CODES.PERMISSION_DENIED,
  TOKEN_INVALID: EXIT_CODES.PERMISSION_DENIED,
  TOKEN_EXPIRED: EXIT_CODES.PERMISSION_DENIED,
  TOKEN_REVOKED: EXIT_CODES.PERMISSION_DENIED,
  NON_INTERACTIVE: EXIT_CODES.INTERACTION_REQUIRED,
  NODE_VERSION_UNSUPPORTED: EXIT_CODES.ENVIRONMENT_ERROR,
  KEYSTORE_LOCKED: EXIT_CODES.KEY_ERROR,
  KEYSTORE_CORRUPT: EXIT_CODES.KEY_ERROR,
  UNSUPPORTED_ALGORITHM: EXIT_CODES.CRYPTO_ERROR,
  FILE_TOO_LARGE: EXIT_CODES.IO_ERROR,
  USAGE_ERROR: EXIT_CODES.USAGE_ERROR,
  IO_ERROR: EXIT_CODES.IO_ERROR,
  CRYPTO_ERROR: EXIT_CODES.CRYPTO_ERROR,
  GENERIC_ERROR: EXIT_CODES.GENERIC_ERROR,
  SECURITY_FINDINGS: EXIT_CODES.SECURITY_FINDINGS,
  WEAK_ALGORITHM: EXIT_CODES.CRYPTO_ERROR
};

export interface PgpjsErrorOptions {
  details?: Record<string, unknown>;
  hint?: string;
  cause?: unknown;
}

export class PgpjsError extends Error {
  readonly code: ErrorCode;
  readonly details: Record<string, unknown>;
  readonly hint: string | undefined;
  readonly exitCode: ExitCode;

  constructor(code: ErrorCode, message: string, options: PgpjsErrorOptions = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "PgpjsError";
    this.code = code;
    this.details = options.details ?? {};
    this.hint = options.hint;
    this.exitCode = CODE_TO_EXIT[code];
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON(): {
    code: ErrorCode;
    message: string;
    details: Record<string, unknown>;
    hint?: string;
  } {
    const json: {
      code: ErrorCode;
      message: string;
      details: Record<string, unknown>;
      hint?: string;
    } = {
      code: this.code,
      message: this.message,
      details: this.details
    };
    if (this.hint !== undefined) {
      json.hint = this.hint;
    }
    return json;
  }
}

export function isPgpjsError(value: unknown): value is PgpjsError {
  return value instanceof PgpjsError;
}

export function exitCodeFor(code: ErrorCode): ExitCode {
  return CODE_TO_EXIT[code];
}

export function assertNodeVersion(min = "20.10.0"): void {
  const [majS, minS] = process.versions.node.split(".");
  const major = Number(majS);
  const minor = Number(minS);
  const [reqMajS, reqMinS] = min.split(".");
  const reqMaj = Number(reqMajS);
  const reqMin = Number(reqMinS);
  if (major < reqMaj || (major === reqMaj && minor < reqMin)) {
    throw new PgpjsError(
      "NODE_VERSION_UNSUPPORTED",
      `PGPJS CLI requires Node.js >= ${min}. Detected ${process.version}.`,
      { details: { node: process.version, required: min } }
    );
  }
}
