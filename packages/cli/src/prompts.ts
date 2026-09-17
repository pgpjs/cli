import { password, confirm, input, select } from "@inquirer/prompts";
import { PgpjsError } from "@pgpjs/core";

export async function promptMasked(message: string): Promise<string> {
  return password({ message, mask: "*" });
}

export async function promptConfirm(message: string): Promise<boolean> {
  return confirm({ message, default: false });
}

export async function promptText(message: string, def?: string): Promise<string> {
  return def === undefined ? input({ message }) : input({ message, default: def });
}

export async function promptSelect<T extends string>(
  message: string,
  choices: Array<{ value: T; name: string }>
): Promise<T> {
  return select({ message, choices });
}

export function missingFlag(flag: string): never {
  throw new PgpjsError("NON_INTERACTIVE", `Missing required input. Provide ${flag}.`);
}
