"use client";

import * as openpgp from "openpgp";

export async function encryptToPublicKey(message: string, publicKeyArmored: string): Promise<string> {
  const key = await openpgp.readKey({ armoredKey: publicKeyArmored });
  if (key.isPrivate()) {
    throw new Error("Security violation: a private key must never be used in the client bundle.");
  }
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: key,
    format: "armored"
  });
  return encrypted as string;
}
