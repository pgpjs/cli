import { homedir, platform } from "node:os";
import { join } from "node:path";

export function defaultHome(): string {
  if (process.env["PGPJS_HOME"]) {
    return process.env["PGPJS_HOME"];
  }
  const home = homedir();
  const plat = platform();
  if (plat === "darwin") {
    return join(home, "Library", "Application Support", "pgpjs");
  }
  if (plat === "win32") {
    const appdata = process.env["APPDATA"] ?? join(home, "AppData", "Roaming");
    return join(appdata, "pgpjs");
  }
  const xdg = process.env["XDG_CONFIG_HOME"] ?? join(home, ".config");
  return join(xdg, "pgpjs");
}

export function defaultProjectKeystore(cwd: string): string {
  return join(cwd, ".pgpjs");
}
