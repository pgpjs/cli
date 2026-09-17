import { PgpjsError } from "./errors.js";
import type { GenerateAlgorithm } from "./types.js";

const WEAK_HASH = new Set(["sha1", "md5", "ripemd160"]);
const WEAK_SYMMETRIC = new Set(["tripledes", "cast5", "idea", "blowfish"]);
const WEAK_ALGO = new Set(["dsa", "elgamal", "rsa_encrypt", "rsa_encrypt_sign"]);

export const ALLOWED_GENERATE: readonly GenerateAlgorithm[] = ["ed25519", "rsa3072", "rsa4096"];

export function assertGenerateAlgorithm(value: string): GenerateAlgorithm {
  if ((ALLOWED_GENERATE as readonly string[]).includes(value)) {
    return value as GenerateAlgorithm;
  }
  throw new PgpjsError(
    "UNSUPPORTED_ALGORITHM",
    `Algorithm '${value}' is not allowed for key generation. Use ed25519 (default), rsa3072, or rsa4096.`,
    { details: { algorithm: value, allowed: [...ALLOWED_GENERATE] } }
  );
}

export function isWeakHash(name: string): boolean {
  return WEAK_HASH.has(name.toLowerCase());
}

export function isWeakSymmetric(name: string): boolean {
  return WEAK_SYMMETRIC.has(name.toLowerCase());
}

export function isWeakPublicAlgo(name: string): boolean {
  const n = name.toLowerCase().replace(/[\s-]/g, "");
  if (n === "rsa" || n.startsWith("rsa")) {
    return false;
  }
  return WEAK_ALGO.has(n);
}

export function describeGenerateAlgorithm(algo: GenerateAlgorithm): string {
  switch (algo) {
    case "ed25519":
      return "ed25519 (sign) / x25519 (encrypt)";
    case "rsa3072":
      return "rsa3072 (interop)";
    case "rsa4096":
      return "rsa4096 (interop)";
  }
}

export function rsaBitsFromAlgorithm(algo: GenerateAlgorithm): number | undefined {
  if (algo === "rsa3072") return 3072;
  if (algo === "rsa4096") return 4096;
  return undefined;
}

export function algorithmFromOpenPgp(info: { algorithm: string; bits?: number }): string {
  const algo = info.algorithm.toLowerCase();
  if (algo.includes("ed25519")) return "ed25519";
  if (algo.includes("x25519") || algo.includes("curve25519")) return "x25519";
  if (algo.includes("p256") || algo.includes("nist p256")) {
    return algo.includes("ecdh") ? "ecdh-p256" : "ecdsa-p256";
  }
  if (algo.includes("p384")) {
    return algo.includes("ecdh") ? "ecdh-p384" : "ecdsa-p384";
  }
  if (algo === "rsaencryptsign" || algo === "rsa" || algo.startsWith("rsa")) {
    const bits = info.bits;
    if (bits !== undefined && bits >= 4096) return "rsa4096";
    if (bits !== undefined && bits >= 3072) return "rsa3072";
    if (bits !== undefined && bits > 0) return `rsa${bits}`;
    return "rsa";
  }
  return info.algorithm;
}

export function isWeakRsaBits(bits: number | undefined): boolean {
  return bits !== undefined && bits > 0 && bits < 3072;
}
