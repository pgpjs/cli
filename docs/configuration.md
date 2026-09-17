# Configuration

Resolution order (last wins):

1. Built-in defaults
2. Global `$PGPJS_HOME/config.json`
   - Linux: `~/.config/pgpjs/` (XDG)
   - macOS: `~/Library/Application Support/pgpjs`
   - Windows: `%APPDATA%\pgpjs`
3. Project: `pgpjs.config.ts` / `.mts` / `.js` / `.mjs` / `.json` / `package.json#pgpjs`, walking up to the git root
4. `PGPJS_*` environment variables
5. Command-line flags

`pgpjs config show --json` prints the effective object and the origin of each value.

```ts
import { defineConfig } from "pgpjs-cli/config";

export default defineConfig({
  keyDirectory: ".pgpjs/keys",
  defaultArmor: true,
  defaultKey: "0xA1B2C3D4E5F60718",
  maxFileSize: "512mb",
  security: {
    allowPrivateKeyExport: false,
    requireEncryptedPrivateKeys: true,
    warnOnUnprotectedKeystore: true
  }
});
```

A TypeScript config is executable code (loaded with jiti). In CI, `--config-format=json` refuses non-declarative files.

Config **must not** contain secrets. Zod rejects private-key blocks and `pgpjs_mcp_` tokens.
