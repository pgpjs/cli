import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { redact } from "@pgpjs/security";

export interface AuditEvent {
  timestamp: string;
  tokenId: string | null;
  tool: string;
  decision: "allow" | "deny";
  reason: string;
  fingerprints: string[];
  bytes: number;
}

export async function appendAudit(path: string, event: AuditEvent): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const line = redact(JSON.stringify(event));
  await appendFile(path, `${line}\n`, { mode: 0o600 });
}

export async function readAudit(path: string): Promise<AuditEvent[]> {
  try {
    const { readFile } = await import("node:fs/promises");
    const raw = await readFile(path, "utf8");
    return raw
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as AuditEvent);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}
