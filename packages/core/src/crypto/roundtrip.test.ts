import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import * as fc from "fast-check";
import { decryptData } from "./decrypt.js";
import { encryptData } from "./encrypt.js";
import { generateKey } from "./generate.js";
import { decryptPrivateKey, readArmoredKey } from "./keys.js";
import { signData } from "./sign.js";
import { verifyData } from "./verify.js";
import { Keystore } from "../keystore/store.js";
import { PgpjsError } from "../errors.js";

const PASS = "correct-horse-battery-staple-test-only";

describe("crypto round-trip", () => {
  it("encrypts and decrypts a string", async () => {
    const generated = await generateKey({
      name: "Alice",
      email: "alice@example.com",
      passphrase: PASS,
      algorithm: "ed25519"
    });
    const pub = await readArmoredKey(generated.publicKeyArmored);
    const sec = await decryptPrivateKey(await readArmoredKey(generated.privateKeyArmored), PASS);
    const { output } = await encryptData({
      text: "hello pgpjs",
      encryptionKeys: [pub],
      armor: true
    });
    const decrypted = await decryptData({
      armored: output as string,
      decryptionKeys: [sec]
    });
    expect(decrypted.text).toBe("hello pgpjs");
  });

  it("signs and verifies detached", async () => {
    const generated = await generateKey({
      name: "Bob",
      email: "bob@example.com",
      passphrase: PASS
    });
    const sec = await decryptPrivateKey(await readArmoredKey(generated.privateKeyArmored), PASS);
    const pub = await readArmoredKey(generated.publicKeyArmored);
    const signed = await signData({
      text: "release-artifact",
      signingKey: sec,
      mode: "detached",
      armor: true
    });
    const result = await verifyData({
      text: "release-artifact",
      detachedSignature: signed.output as string,
      verificationKeys: [pub]
    });
    expect(result.status).toBe("valid");
    expect(result.signerFingerprint).toBe(generated.fingerprint);
  });

  it("property: encrypt/decrypt arbitrary utf8 including empty", async () => {
    const generated = await generateKey({
      name: "Prop",
      email: "prop@example.com",
      passphrase: PASS
    });
    const pub = await readArmoredKey(generated.publicKeyArmored);
    const sec = await decryptPrivateKey(await readArmoredKey(generated.privateKeyArmored), PASS);

    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 2048 }), async (bytes) => {
        const { output } = await encryptData({
          binary: bytes,
          encryptionKeys: [pub],
          armor: true
        });
        const decrypted = await decryptData({
          armored: output as string,
          decryptionKeys: [sec]
        });
        expect(Buffer.from(decrypted.data).equals(Buffer.from(bytes))).toBe(true);
      }),
      { numRuns: 10 }
    );
  });

  it("rejects malformed keys", async () => {
    await expect(readArmoredKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\njunk\n-----END PGP PUBLIC KEY BLOCK-----")).rejects.toBeInstanceOf(
      PgpjsError
    );
  });

  it("keystore resolve is unique and rejects short ids", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-ks-"));
    try {
      const store = new Keystore(dir);
      const a = await generateKey({ name: "A", email: "shared@example.com", passphrase: PASS });
      await store.saveGenerated({
        fingerprint: a.fingerprint,
        publicKeyArmored: a.publicKeyArmored,
        privateKeyArmored: a.privateKeyArmored,
        revocationCertificate: a.revocationCertificate
      });
      await expect(store.resolve("DEADBEEF")).rejects.toMatchObject({ code: "KEY_MALFORMED" });
      const listed = await store.list();
      expect(listed).toHaveLength(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("KEY_AMBIGUOUS when two keys share an email", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pgpjs-amb-"));
    try {
      const store = new Keystore(dir);
      const a = await generateKey({ name: "A", email: "shared@example.com", passphrase: PASS });
      const b = await generateKey({ name: "B", email: "shared@example.com", passphrase: PASS });
      await store.saveGenerated({
        fingerprint: a.fingerprint,
        publicKeyArmored: a.publicKeyArmored,
        privateKeyArmored: a.privateKeyArmored,
        revocationCertificate: a.revocationCertificate
      });
      await store.saveGenerated({
        fingerprint: b.fingerprint,
        publicKeyArmored: b.publicKeyArmored,
        privateKeyArmored: b.privateKeyArmored,
        revocationCertificate: b.revocationCertificate
      });
      await expect(store.resolve("shared@example.com")).rejects.toMatchObject({ code: "KEY_AMBIGUOUS" });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("wrong passphrase fails closed", async () => {
    const generated = await generateKey({
      name: "C",
      email: "c@example.com",
      passphrase: PASS
    });
    const key = await readArmoredKey(generated.privateKeyArmored);
    await expect(decryptPrivateKey(key, "nope")).rejects.toMatchObject({ code: "PASSPHRASE_INCORRECT" });
  });
});
