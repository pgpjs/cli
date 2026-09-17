import "server-only";
import * as openpgp from "openpgp";

if (typeof window !== "undefined") {
  throw new Error("server.ts is server-only");
}

export async function encryptMessage(message: string, publicKeyArmored: string): Promise<string> {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted as string;
}
