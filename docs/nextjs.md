# Next.js integration

```bash
cd my-next-app
pgpjs init
pgpjs install next
pgpjs doctor
```

## Generated layout

```
src/lib/pgpjs/
  client.ts       "use client" — encrypt-to-public, verify
  server.ts       "server-only" — encrypt, decrypt
  keys.ts         loads keys from files / env (server only)
  encryption.ts   typed JSON helpers
app/api/pgpjs/echo/route.ts   example Route Handler
```

## Server Component / Route Handler

```ts
import { encryptMessage } from "@/lib/pgpjs/server";

const encrypted = await encryptMessage(message, publicKey);
```

## Client Component

```ts
"use client";
import { encryptToPublicKey } from "@/lib/pgpjs/client";

const ciphertext = await encryptToPublicKey(plaintext, serverPublicKeyArmored);
```

Never import `server.ts`, `keys.ts`, or `encryption.ts` from a file that has `"use client"`. `pgpjs doctor` walks that import graph and fails if it finds a violation.

## Environment

`.env.example` documents `PGPJS_SERVER_PUBLIC_KEY_FILE` and `PGPJS_SERVER_PRIVATE_KEY_FILE`. Do **not** prefix these with `NEXT_PUBLIC_`. Private keys inlined into the browser bundle are a critical finding for `pgpjs security scan`.

## App Router vs Pages Router

App Router is detected via `app/` or `src/app/`. Pages Router projects still get the `src/lib/pgpjs` helpers; the example Route Handler is only generated for App Router.
