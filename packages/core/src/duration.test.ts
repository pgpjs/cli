import { describe, expect, it } from "vitest";
import { parseDuration } from "./duration.js";
import { parseByteSize } from "./bytes.js";

describe("parseDuration", () => {
  it("parses 30d, 12h, 1y", () => {
    expect(parseDuration("30d")).toBe(30 * 24 * 3600);
    expect(parseDuration("12h")).toBe(12 * 3600);
    expect(parseDuration("1y")).toBe(365 * 24 * 3600);
  });

  it("parses never as null", () => {
    expect(parseDuration("never")).toBeNull();
  });
});

describe("parseByteSize", () => {
  it("parses mb", () => {
    expect(parseByteSize("512mb")).toBe(512 * 1024 * 1024);
  });
});
