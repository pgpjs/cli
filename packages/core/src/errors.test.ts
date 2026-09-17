import { describe, expect, it } from "vitest";
import { EXIT_CODES, PgpjsError } from "./errors.js";
import { assertGenerateAlgorithm } from "./algorithms.js";

describe("errors", () => {
  it("maps KEY_NOT_FOUND to exit 4", () => {
    const err = new PgpjsError("KEY_NOT_FOUND", "missing");
    expect(err.exitCode).toBe(EXIT_CODES.KEY_ERROR);
  });

  it("maps SIGNATURE_UNTRUSTED to exit 7", () => {
    expect(new PgpjsError("SIGNATURE_UNTRUSTED", "u").exitCode).toBe(EXIT_CODES.VERIFY_UNTRUSTED);
  });

  it("rejects weak generate algorithms", () => {
    expect(() => assertGenerateAlgorithm("rsa1024")).toThrow(/not allowed/);
  });
});
