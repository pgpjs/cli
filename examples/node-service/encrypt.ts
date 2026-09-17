import * as openpgp from "openpgp";

export async function encryptMessage(message: string, publicKeyArmored: string): Promise<string> {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted as string;
}
