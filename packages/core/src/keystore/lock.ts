import lockfile from "proper-lockfile";
import { PgpjsError } from "../errors.js";
import { ensureDir } from "./fs-safe.js";
import { dirname } from "node:path";

export async function withKeystoreLock<T>(lockPath: string, fn: () => Promise<T>): Promise<T> {
  await ensureDir(dirname(lockPath));
  let release: (() => Promise<void>) | undefined;
  try {
    release = await lockfile.lock(dirname(lockPath), {
      lockfilePath: lockPath,
      retries: {
        retries: 0
      },
      stale: 15_000
    });
  } catch (err) {
    throw new PgpjsError(
      "KEYSTORE_LOCKED",
      "The keystore is locked by another process. Retry after that operation finishes.",
      { cause: err }
    );
  }
  try {
    return await fn();
  } finally {
    if (release) {
      await release();
    }
  }
}
