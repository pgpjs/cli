import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export function getSecureRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function sha256Bytes(data: string | Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

export function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

export function toBase64Url(buf: Uint8Array | Buffer): string {
  return Buffer.from(buf).toString("base64url");
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function parseByteSize(input: string): number {
  const match = /^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i.exec(input.trim());
  if (!match || match[1] === undefined) {
    throw new Error(`Invalid size: ${input}`);
  }
  const n = Number(match[1]);
  const unit = (match[2] ?? "b").toLowerCase();
  const mul =
    unit === "gb" ? 1024 ** 3 : unit === "mb" ? 1024 ** 2 : unit === "kb" ? 1024 : 1;
  return Math.floor(n * mul);
}

export async function zeroFill(buf: Buffer | Uint8Array): Promise<void> {
  buf.fill(0);
}
