import { afterEach } from "vitest";

/**
 * Global output-leak harness. Any test that captures CLI/MCP streams into
 * `globalThis.__PGPJS_CAPTURED_OUTPUT__` is checked for fixture secrets.
 *
 * Unit tests that intentionally feed secrets into redact()/scan() must not
 * push those raw inputs into the capture buffer.
 */
const FORBIDDEN = [
  "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "pgpjs_mcp_",
  "correct-horse-battery-staple-test-only"
];

declare global {
  // eslint-disable-next-line no-var
  var __PGPJS_CAPTURED_OUTPUT__: string[];
}

globalThis.__PGPJS_CAPTURED_OUTPUT__ = [];

afterEach((ctx) => {
  const captured = globalThis.__PGPJS_CAPTURED_OUTPUT__.join("\n");
  globalThis.__PGPJS_CAPTURED_OUTPUT__ = [];
  for (const needle of FORBIDDEN) {
    if (captured.includes(needle)) {
      throw new Error(
        `Output leak detected in test "${ctx.task.name}": captured streams contain "${needle}".`
      );
    }
  }
});
