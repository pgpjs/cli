import { chmod, lstat, mkdir, rename, rm, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}

export async function atomicWriteFile(
  file: string,
  data: string | Uint8Array,
  mode: number
): Promise<void> {
  const tmp = `${file}.tmp.${process.pid}.${Date.now()}`;
  await writeFile(tmp, data, { mode });
  await rename(tmp, file);
  await applySecureMode(file, mode);
}

export async function applySecureMode(file: string, mode: number): Promise<void> {
  if (platform() === "win32") {
    await applyWindowsAcl(file);
    return;
  }
  try {
    await chmod(file, mode);
  } catch {
    /* ignore on filesystems that don't support chmod */
  }
}

export async function applyWindowsAcl(file: string): Promise<boolean> {
  if (platform() !== "win32") return true;
  const user = process.env["USERNAME"] ?? process.env["USER"] ?? "";
  if (!user) return false;
  try {
    await execFileAsync("icacls", [file, "/inheritance:r"]);
    await execFileAsync("icacls", [file, "/grant:r", `${user}:(R,W)`]);
    return true;
  } catch {
    return false;
  }
}

export async function isModeAtMost(file: string, maxMode: number): Promise<boolean> {
  if (platform() === "win32") {
    return true;
  }
  try {
    const st = await lstat(file);
    return (st.mode & 0o777) <= maxMode;
  } catch {
    return false;
  }
}

export async function removeFile(file: string): Promise<void> {
  await rm(file, { force: true });
}
