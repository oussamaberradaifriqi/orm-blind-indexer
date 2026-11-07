# orm-blind-indexer

> A Prisma Client Extension that implements **Blind Indexing** for secure, searchable encrypted database fields.
>
> Author: **Oussama Berrada Ifriqi**

[![npm version](https://badge.fury.io/js/orm-blind-indexer.svg)](https://badge.fury.io/js/orm-blind-indexer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

---

## The Problem

Encrypting sensitive fields like emails breaks database lookups. If `alice@example.com` is stored as an AES-256-GCM ciphertext like `abc123...`, a `WHERE email = 'alice@example.com'` query simply fails — the database can only compare ciphertexts, and AES-GCM uses a random IV so the same plaintext produces a different ciphertext every time.

## The Solution: Blind Indexing

Blind Indexing stores a **deterministic HMAC-SHA256 hash** of the plaintext in a separate `_bidx` column alongside the encrypted value.

```
┌──────────────────────────────────────────────────┬──────────────────────────┐
│ email (AES-256-GCM ciphertext, random IV)        │ email_bidx (HMAC-SHA256) │
├──────────────────────────────────────────────────┼──────────────────────────┤
│ dGVzdA==:abc123==:xyz789==                       │ k7a8b...== (base64)      │
└──────────────────────────────────────────────────┴──────────────────────────┘
```

- **On write**: The extension encrypts the value with AES-256-GCM and injects the HMAC hash automatically.
- **On read**: The extension intercepts the `WHERE` clause, hashes the search term, and queries `email_bidx` instead.
- **On result**: The extension decrypts the ciphertext back to plaintext and strips `_bidx` fields before returning.

The developer's code is completely transparent — they always work with plaintext.

---

## Security Properties

| Property                    | Implementation                                                |
|-----------------------------|---------------------------------------------------------------|
| **Confidentiality**         | AES-256-GCM (authenticated encryption, random 12-byte IV)    |
| **Integrity / Authenticity**| 16-byte GCM Auth Tag — decryption fails if tampered          |
| **Query Security**          | HMAC-SHA256 keyed hash — requires secret key to compute       |
| **No Double-Encryption**    | Idempotency check prevents encrypting already-encrypted data  |
| **Case-Insensitive Search** | Optional lowercasing before hashing (configurable per field)  |

> [!CAUTION]
> Blind indexes reveal **equality relationships**: an attacker with the database can tell if two records have the same email, but cannot determine the actual email without the index key. This is an inherent trade-off of searchable encryption. For highly sensitive use cases, see [CipherSweet](https://ciphersweet.paragonie.com/) for more advanced schemes.

---

## Installation

```bash
npm install orm-blind-indexer
# Peer dependencies (if not already installed):
npm install prisma @prisma/client
```

**Node.js 18+** is required (uses the native `crypto` module — zero external dependencies).

---

## Quick Start

### 1. Update Your Prisma Schema

Add a `_bidx` column for every field you want to encrypt and query:

```prisma
model User {
  id         String @id @default(cuid())
  name       String

  // The encrypted email (AES-256-GCM ciphertext)
  email      String @unique

  // The blind index (HMAC-SHA256 hash for queries)
  email_bidx String @unique

  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

Run `npx prisma migrate dev` to apply the schema changes.

### 2. Generate Secure Keys

```bash
# Generate the AES-256 encryption key (32 bytes → 44-char base64)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Generate the HMAC index key (separate from the encryption key!)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Add them to your `.env`:

```bash
ENCRYPTION_KEY="<your-32-byte-base64-encryption-key>"
INDEX_KEY="<your-32-byte-base64-index-key>"
```

> [!IMPORTANT]
> Keep these keys secret and **never commit them to version control**. Store them in a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) in production. Losing the encryption key means your data is permanently unrecoverable.

### 3. Apply the Extension

```typescript
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';

const prisma = new PrismaClient().$extends(
  withBlindIndexer({
    encryptionKey: process.env.ENCRYPTION_KEY!,
    indexKey: process.env.INDEX_KEY!,
    fields: {
      User: {
        email: {
          indexFieldName: 'email_bidx',
          caseSensitive: false, // "Test@Test.com" matches "test@test.com"
        },
      },
    },
  })
);

export default prisma;
```

### 4. Use It Transparently

The extension works invisibly — write your Prisma queries as normal:

```typescript
// CREATE: email is automatically encrypted, email_bidx is auto-injected
const user = await prisma.user.create({
  data: { name: 'Alice', email: 'alice@example.com' },
});
// user.email === 'alice@example.com' (decrypted in result)
// user.email_bidx === undefined       (stripped from result)

// FIND: WHERE email is auto-transformed to WHERE email_bidx = hash(...)
const found = await prisma.user.findUnique({
  where: { email: 'alice@example.com' },
});
// found.email === 'alice@example.com' (decrypted from DB)
```

---

## Configuration Reference

```typescript
interface BlindIndexConfig {
  /**
   * AES-256-GCM encryption key.
   * Must decode to exactly 32 bytes.
   * Accepts: 44-char base64 string OR 64-char hex string.
   */
  encryptionKey: string;

  /**
   * HMAC-SHA256 index key (salt).
   * Must be different from encryptionKey!
   * Minimum 16 bytes recommended; 32 bytes is best practice.
   */
  indexKey: string;

  /**
   * Map of model names to their encrypted field configurations.
   */
  fields: {
    [ModelName: string]: {
      [fieldName: string]: {
        /** Name of the blind index column in the database. */
        indexFieldName: string;
        /**
         * When false (default), input is lowercased before hashing.
         * Enables case-insensitive equality searches.
         */
        caseSensitive?: boolean;
      };
    };
  };
}
```

---

## Supported Query Patterns

### ✅ Supported (Exact-Match)

```typescript
// Direct equality
prisma.user.findUnique({ where: { email: 'alice@example.com' } });

// Explicit equals operator
prisma.user.findMany({ where: { email: { equals: 'alice@example.com' } } });

// IN operator (hashes each element)
prisma.user.findMany({ where: { email: { in: ['alice@example.com', 'bob@example.com'] } } });

// AND / OR / NOT combinators
prisma.user.findMany({
  where: {
    OR: [
      { email: 'alice@example.com' },
      { email: 'bob@example.com' },
    ],
  },
});

// Nested AND
prisma.user.findMany({
  where: {
    AND: [{ email: 'alice@example.com' }, { name: 'Alice' }],
  },
});
```

### ❌ Not Supported (Partial-Match)

```typescript
// These will throw a helpful error:
prisma.user.findMany({ where: { email: { contains: 'example.com' } } });
prisma.user.findMany({ where: { email: { startsWith: 'alice' } } });
prisma.user.findMany({ where: { email: { endsWith: '.com' } } });
```

Partial-match (LIKE) queries are fundamentally incompatible with deterministic hashing. For substring search on encrypted fields, you need to fetch and decrypt records in your application layer.

---

## Multiple Encrypted Fields

```typescript
// Schema:
model User {
  id           String @id @default(cuid())
  email        String @unique
  email_bidx   String @unique
  phoneNumber  String?
  phone_bidx   String? @unique
  ssn          String?
  ssn_bidx     String? @unique
}

// Extension config:
withBlindIndexer({
  encryptionKey: process.env.ENCRYPTION_KEY!,
  indexKey: process.env.INDEX_KEY!,
  fields: {
    User: {
      email: { indexFieldName: 'email_bidx', caseSensitive: false },
      phoneNumber: { indexFieldName: 'phone_bidx', caseSensitive: true },
      ssn: { indexFieldName: 'ssn_bidx', caseSensitive: true },
    },
  },
})
```

---

## Multiple Models

```typescript
withBlindIndexer({
  encryptionKey: process.env.ENCRYPTION_KEY!,
  indexKey: process.env.INDEX_KEY!,
  fields: {
    User: {
      email: { indexFieldName: 'email_bidx' },
    },
    Patient: {
      dateOfBirth: { indexFieldName: 'dob_bidx', caseSensitive: true },
      ssn: { indexFieldName: 'ssn_bidx', caseSensitive: true },
    },
  },
})
```

---

## Advanced: Using Crypto Primitives Directly

The package exports its cryptographic primitives for advanced use cases:

```typescript
import {
  encrypt,
  decrypt,
  generateBlindIndex,
  validateEncryptionKey,
} from 'orm-blind-indexer';

// Standalone encryption
const key = validateEncryptionKey(process.env.ENCRYPTION_KEY!);
const ciphertext = encrypt('sensitive data', key);
const plaintext = decrypt(ciphertext, key);

// Standalone blind index generation
import { validateIndexKey } from 'orm-blind-indexer';
const indexKey = validateIndexKey(process.env.INDEX_KEY!);
const hash = generateBlindIndex('alice@example.com', indexKey, false);
```

---

## Key Rotation

Rotating encryption keys requires a data migration:

1. Decrypt all existing records with the old key.
2. Re-encrypt with the new key.
3. Regenerate all blind indexes with the new index key.

> [!WARNING]
> Key rotation must be atomic. Run it in a transaction and deploy the new application binary (with new keys in env vars) simultaneously with the migration to avoid downtime.

---

## Framework Integration Guides

`orm-blind-indexer` is built as a universal dual CommonJS + ESM package with full TypeScript definitions, compatible with any modern JavaScript/TypeScript framework running Node.js 18+.

> [!NOTE]
> Database ORMs and cryptographic operations run exclusively in **server-side runtimes** (Node.js, Bun, serverless containers). Never import Prisma or encryption keys in client-side component code.

### 1. Next.js (App Router, Server Actions, Route Handlers)

In Next.js, hot module reloading (HMR) during local development can create multiple Prisma instances if not memoized on `globalThis`. Use the singleton pattern:

```typescript
// lib/prisma.ts
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';

const prismaClientSingleton = () => {
  return new PrismaClient().$extends(
    withBlindIndexer({
      encryptionKey: process.env.ENCRYPTION_KEY!,
      indexKey: process.env.INDEX_KEY!,
      fields: {
        User: {
          email: { indexFieldName: 'email_bidx', caseSensitive: false },
        },
      },
    })
  );
};

declare global {
  var prismaGlobal: undefined | ReturnType<typeof prismaClientSingleton>;
}

export const prisma = globalThis.prismaGlobal ?? prismaClientSingleton();

if (process.env.NODE_ENV !== 'production') globalThis.prismaGlobal = prisma;
```

Then in any Server Action or Route Handler:

```typescript
// app/actions/user.ts
'use server';

import { prisma } from '@/lib/prisma';

export async function getUserByEmail(email: string) {
  // Query operates transparently through the blind index
  return await prisma.user.findUnique({
    where: { email },
  });
}
```

---

### 2. NestJS (Angular-Style Architecture / Backend)

In NestJS, extend `PrismaClient` within a custom service and register it as an injectable provider:

```typescript
// src/prisma/prisma.service.ts
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';

function createExtendedClient() {
  const baseClient = new PrismaClient();
  return baseClient.$extends(
    withBlindIndexer({
      encryptionKey: process.env.ENCRYPTION_KEY!,
      indexKey: process.env.INDEX_KEY!,
      fields: {
        User: {
          email: { indexFieldName: 'email_bidx', caseSensitive: false },
        },
      },
    })
  );
}

export type ExtendedPrismaClient = ReturnType<typeof createExtendedClient>;

@Injectable()
export class PrismaService implements OnModuleInit, OnModuleDestroy {
  public readonly client: ExtendedPrismaClient;
  private readonly rawBaseClient: PrismaClient;

  constructor() {
    this.rawBaseClient = new PrismaClient();
    this.client = this.rawBaseClient.$extends(
      withBlindIndexer({
        encryptionKey: process.env.ENCRYPTION_KEY!,
        indexKey: process.env.INDEX_KEY!,
        fields: {
          User: {
            email: { indexFieldName: 'email_bidx', caseSensitive: false },
          },
        },
      })
    ) as ExtendedPrismaClient;
  }

  async onModuleInit() {
    await this.rawBaseClient.$connect();
  }

  async onModuleDestroy() {
    await this.rawBaseClient.$disconnect();
  }
}
```

Inject and use in NestJS services:

```typescript
// src/users/users.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findByEmail(email: string) {
    return this.prisma.client.user.findUnique({
      where: { email },
    });
  }
}
```

---

### 3. Svelte / SvelteKit

In SvelteKit, place your Prisma client in the `$lib/server` folder so Vite guarantees it is never bundled into client-side code:

```typescript
// src/lib/server/prisma.ts
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';
import { ENCRYPTION_KEY, INDEX_KEY } from '$env/static/private';

export const prisma = new PrismaClient().$extends(
  withBlindIndexer({
    encryptionKey: ENCRYPTION_KEY,
    indexKey: INDEX_KEY,
    fields: {
      User: {
        email: { indexFieldName: 'email_bidx', caseSensitive: false },
      },
    },
  })
);
```

Then in any `+page.server.ts` or `+server.ts`:

```typescript
// src/routes/users/+page.server.ts
import { prisma } from '$lib/server/prisma';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url }) => {
  const email = url.searchParams.get('email') ?? '';
  const user = await prisma.user.findUnique({
    where: { email },
  });
  return { user };
};
```

---

### 4. Angular (with AnalogJS SSR or NestJS/Express API)

In modern full-stack Angular setups (e.g., [AnalogJS](https://analogjs.org/)), use server routes in `src/server/routes/`:

```typescript
// src/server/routes/api/users.get.ts (AnalogJS / Nitro server)
import { defineEventHandler, getQuery } from 'h3';
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';

const prisma = new PrismaClient().$extends(
  withBlindIndexer({
    encryptionKey: process.env.ENCRYPTION_KEY!,
    indexKey: process.env.INDEX_KEY!,
    fields: {
      User: { email: { indexFieldName: 'email_bidx' } },
    },
  })
);

export default defineEventHandler(async (event) => {
  const { email } = getQuery(event);
  return await prisma.user.findUnique({
    where: { email: String(email) },
  });
});
```

---

### 5. Remix & Nuxt (Vue)

**Remix** (`app/db.server.ts`):
```typescript
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';

export const prisma = new PrismaClient().$extends(
  withBlindIndexer({
    encryptionKey: process.env.ENCRYPTION_KEY!,
    indexKey: process.env.INDEX_KEY!,
    fields: { User: { email: { indexFieldName: 'email_bidx' } } },
  })
);
```

**Nuxt 3** (`server/utils/prisma.ts`):
```typescript
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';

const config = useRuntimeConfig();

export const prisma = new PrismaClient().$extends(
  withBlindIndexer({
    encryptionKey: config.encryptionKey,
    indexKey: config.indexKey,
    fields: { User: { email: { indexFieldName: 'email_bidx' } } },
  })
);
```

---

### 6. Express & Fastify (Node.js CommonJS or ESM)

```typescript
import express from 'express';
import { PrismaClient } from '@prisma/client';
import { withBlindIndexer } from 'orm-blind-indexer';

const app = express();
const prisma = new PrismaClient().$extends(
  withBlindIndexer({
    encryptionKey: process.env.ENCRYPTION_KEY!,
    indexKey: process.env.INDEX_KEY!,
    fields: { User: { email: { indexFieldName: 'email_bidx' } } },
  })
);

app.get('/users', async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { email: String(req.query.email) },
  });
  res.json(user);
});
```

---

## Development

```bash
# Install dependencies
npm install

# Generate Prisma client for tests
npx prisma generate --schema=tests/setup/schema.prisma

# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Build the library
npm run build

# Type check
npm run lint
```

---

## How It Works — Architecture

```
Developer Code                 Extension                      Database
─────────────────────────────────────────────────────────────────────

prisma.user.create({      ──▶  encrypt(email)           ──▶  email = "iv:tag:ct"
  data: { email: "..." }       inject email_bidx              email_bidx = hmac(email)
})

prisma.user.findUnique({  ──▶  hash(where.email)         ──▶  WHERE email_bidx = hash
  where: { email: "..." }  ◀──  decrypt(result.email)         (returns encrypted row)
})                             strip _bidx fields
```

---

## License

MIT © Oussama Berrada Ifriqi

