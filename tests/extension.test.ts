/**
 * @file tests/extension.test.ts
 * @description End-to-end integration tests for the Prisma blind indexer extension.
 *
 * These tests use a real Prisma Client connected to a temporary SQLite database.
 * They verify the full lifecycle:
 * 1. Creating a user encrypts the email and injects the blind index.
 * 2. The raw SQLite data contains ciphertext (not plaintext) for `email`.
 * 3. Finding a user by email (via blind index) returns the decrypted plaintext.
 * 4. The returned object contains no `_bidx` fields.
 * 5. Complex WHERE clauses (AND/OR/NOT/in) are correctly transformed.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { randomBytes } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import fs from 'fs';

// We import from the source directly (not the built dist) since vitest
// handles TypeScript transpilation via ts-node / esbuild.
import { withBlindIndexer } from '../src/index.js';
import { generateBlindIndex } from '../src/crypto/hasher.js';
import { isEncryptedFormat } from '../src/crypto/encryptor.js';

// ============================================================================
// Test Environment Setup
// ============================================================================

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TEST_DB_PATH = path.join(__dirname, 'test.db');
const DATABASE_URL = `file:${TEST_DB_PATH}`;
const SCHEMA_PATH = path.join(__dirname, 'setup', 'schema.prisma');
const GENERATED_CLIENT_PATH = path.join(__dirname, 'generated', 'client');

// Fixed test keys (32 bytes each, base64-encoded)
const TEST_ENCRYPTION_KEY = randomBytes(32).toString('base64');
const TEST_INDEX_KEY = randomBytes(32).toString('base64');

// Lazy-loaded Prisma client type to avoid top-level import issues
let PrismaClientClass: typeof import('./generated/client/index.js').PrismaClient;
let prisma: ReturnType<typeof createExtendedClient>;

function createExtendedClient() {
  const base = new PrismaClientClass({
    datasources: { db: { url: DATABASE_URL } },
    log: [],
  });
  return base.$extends(
    withBlindIndexer({
      encryptionKey: TEST_ENCRYPTION_KEY,
      indexKey: TEST_INDEX_KEY,
      fields: {
        User: {
          email: {
            indexFieldName: 'email_bidx',
            caseSensitive: false,
          },
        },
      },
    })
  );
}

// Raw Prisma client (without extension) to inspect the actual stored values
let rawPrisma: InstanceType<typeof import('./generated/client/index.js').PrismaClient>;

beforeAll(async () => {
  // 1. Generate the Prisma client for the test schema
  try {
    execSync(
      `npx prisma generate --schema="${SCHEMA_PATH}"`,
      {
        env: { ...process.env, DATABASE_URL },
        stdio: 'pipe',
      }
    );
  } catch (e) {
    console.error('Prisma generate failed:', e);
    throw e;
  }

  // 2. Push the schema to the SQLite database (creates the file + tables)
  try {
    execSync(
      `npx prisma db push --schema="${SCHEMA_PATH}" --skip-generate`,
      {
        env: { ...process.env, DATABASE_URL },
        stdio: 'pipe',
      }
    );
  } catch (e) {
    console.error('Prisma db push failed:', e);
    throw e;
  }

  // 3. Dynamically import the generated client
  const clientModule = await import('./generated/client/index.js');
  PrismaClientClass = clientModule.PrismaClient;

  // 4. Create clients
  rawPrisma = new PrismaClientClass({
    datasources: { db: { url: DATABASE_URL } },
    log: [],
  });

  prisma = createExtendedClient();
});

afterAll(async () => {
  await rawPrisma.$disconnect();
  // @ts-expect-error — extended client disconnect
  await prisma.$disconnect();

  // Clean up the SQLite test database file
  if (fs.existsSync(TEST_DB_PATH)) {
    fs.unlinkSync(TEST_DB_PATH);
  }
});

beforeEach(async () => {
  // Clear all users before each test for a clean state
  await rawPrisma.user.deleteMany();
});

// ============================================================================
// Helper: Compute expected blind index for verification
// ============================================================================

function indexKeyBuffer(): Buffer {
  return Buffer.from(TEST_INDEX_KEY, 'base64');
}

// ============================================================================
// Integration Tests
// ============================================================================

describe('Prisma Blind Indexer Extension', () => {

  // --- WRITE OPERATIONS ---

  describe('create()', () => {
    it('should encrypt the email field in the database', async () => {
      await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      // Inspect raw stored values using the non-extended client
      const rawUser = await rawPrisma.user.findFirst({
        where: { name: 'Alice' },
      });

      expect(rawUser).not.toBeNull();
      expect(rawUser!.email).not.toBe('alice@example.com');
      expect(isEncryptedFormat(rawUser!.email)).toBe(true);
    });

    it('should store the correct HMAC-SHA256 blind index', async () => {
      await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      const rawUser = await rawPrisma.user.findFirst({ where: { name: 'Alice' } });
      const expectedHash = generateBlindIndex('alice@example.com', indexKeyBuffer(), false);

      expect(rawUser!.email_bidx).toBe(expectedHash);
    });

    it('should return the plaintext email in the create result', async () => {
      const user = await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      expect(user.email).toBe('alice@example.com');
    });

    it('should not expose email_bidx in the returned result', async () => {
      const user = await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      expect((user as Record<string, unknown>)['email_bidx']).toBeUndefined();
    });

    it('should normalize email case for the blind index (case-insensitive config)', async () => {
      await prisma.user.create({
        data: { name: 'Bob', email: 'Bob@Example.COM' },
      });

      const rawUser = await rawPrisma.user.findFirst({ where: { name: 'Bob' } });
      // Blind index should be for the lowercased version
      const expectedHash = generateBlindIndex('bob@example.com', indexKeyBuffer(), false);
      expect(rawUser!.email_bidx).toBe(expectedHash);
    });
  });

  // --- READ OPERATIONS ---

  describe('findUnique() by encrypted field', () => {
    it('should find a user by exact email match', async () => {
      await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      const found = await prisma.user.findUnique({
        where: { email: 'alice@example.com' },
      });

      expect(found).not.toBeNull();
      expect(found!.name).toBe('Alice');
      expect(found!.email).toBe('alice@example.com');
    });

    it('should find a user using different case (case-insensitive mode)', async () => {
      await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      const found = await prisma.user.findUnique({
        where: { email: 'ALICE@EXAMPLE.COM' },
      });

      expect(found).not.toBeNull();
      expect(found!.name).toBe('Alice');
    });

    it('should return null for a non-existent email', async () => {
      const found = await prisma.user.findUnique({
        where: { email: 'nobody@example.com' },
      });

      expect(found).toBeNull();
    });

    it('should not expose email_bidx in the found result', async () => {
      await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      const found = await prisma.user.findUnique({
        where: { email: 'alice@example.com' },
      });

      expect((found as Record<string, unknown>)?.['email_bidx']).toBeUndefined();
    });
  });

  describe('findMany() with complex WHERE clauses', () => {
    beforeEach(async () => {
      await prisma.user.create({ data: { name: 'Alice', email: 'alice@example.com' } });
      await prisma.user.create({ data: { name: 'Bob', email: 'bob@example.com' } });
      await prisma.user.create({ data: { name: 'Charlie', email: 'charlie@example.com' } });
    });

    it('should find multiple users with { email: { in: [...] } }', async () => {
      const users = await prisma.user.findMany({
        where: { email: { in: ['alice@example.com', 'bob@example.com'] } },
        orderBy: { name: 'asc' },
      });

      expect(users).toHaveLength(2);
      expect(users[0]!.name).toBe('Alice');
      expect(users[1]!.name).toBe('Bob');
      // All emails should be decrypted
      expect(users[0]!.email).toBe('alice@example.com');
      expect(users[1]!.email).toBe('bob@example.com');
    });

    it('should find users with an AND clause on encrypted field', async () => {
      const users = await prisma.user.findMany({
        where: {
          AND: [
            { email: 'alice@example.com' },
            { name: 'Alice' },
          ],
        },
      });

      expect(users).toHaveLength(1);
      expect(users[0]!.email).toBe('alice@example.com');
    });

    it('should find users with an OR clause on encrypted field', async () => {
      const users = await prisma.user.findMany({
        where: {
          OR: [
            { email: 'alice@example.com' },
            { email: 'charlie@example.com' },
          ],
        },
        orderBy: { name: 'asc' },
      });

      expect(users).toHaveLength(2);
      expect(users[0]!.name).toBe('Alice');
      expect(users[1]!.name).toBe('Charlie');
    });

    it('should find all users when querying without email filter', async () => {
      const users = await prisma.user.findMany();
      expect(users).toHaveLength(3);
      // All emails should be decrypted
      const emails = users.map((u) => u.email).sort();
      expect(emails).toEqual([
        'alice@example.com',
        'bob@example.com',
        'charlie@example.com',
      ]);
    });

    it('should not expose email_bidx in findMany results', async () => {
      const users = await prisma.user.findMany();
      users.forEach((user) => {
        expect((user as Record<string, unknown>)['email_bidx']).toBeUndefined();
      });
    });
  });

  // --- UPDATE OPERATIONS ---

  describe('update()', () => {
    it('should re-encrypt and update the blind index on email change', async () => {
      const user = await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      await prisma.user.update({
        where: { id: user.id },
        data: { email: 'alice-new@example.com' },
      });

      // Verify raw data
      const rawUser = await rawPrisma.user.findUnique({ where: { id: user.id } });
      expect(isEncryptedFormat(rawUser!.email)).toBe(true);

      const expectedHash = generateBlindIndex('alice-new@example.com', indexKeyBuffer(), false);
      expect(rawUser!.email_bidx).toBe(expectedHash);

      // Verify findUnique works with new email
      const found = await prisma.user.findUnique({ where: { email: 'alice-new@example.com' } });
      expect(found).not.toBeNull();
      expect(found!.email).toBe('alice-new@example.com');

      // Old email should no longer work
      const notFound = await prisma.user.findUnique({ where: { email: 'alice@example.com' } });
      expect(notFound).toBeNull();
    });

    it('should return decrypted email in update result', async () => {
      const user = await prisma.user.create({
        data: { name: 'Alice', email: 'alice@example.com' },
      });

      const updated = await prisma.user.update({
        where: { id: user.id },
        data: { email: 'updated@example.com' },
      });

      expect(updated.email).toBe('updated@example.com');
    });
  });

  // --- UPSERT OPERATIONS ---

  describe('upsert()', () => {
    it('should encrypt on create path of upsert', async () => {
      const user = await prisma.user.upsert({
        where: { email: 'upsert@example.com' },
        create: { name: 'Upsert User', email: 'upsert@example.com' },
        update: { name: 'Upsert Updated' },
      });

      expect(user.email).toBe('upsert@example.com');

      const rawUser = await rawPrisma.user.findFirst({ where: { name: 'Upsert User' } });
      expect(isEncryptedFormat(rawUser!.email)).toBe(true);
    });

    it('should encrypt on update path of upsert', async () => {
      // Create first
      await prisma.user.create({ data: { name: 'Old Name', email: 'upsert2@example.com' } });

      // Upsert should hit the update path
      const user = await prisma.user.upsert({
        where: { email: 'upsert2@example.com' },
        create: { name: 'Should Not Happen', email: 'upsert2@example.com' },
        update: { name: 'New Name', email: 'upsert2-new@example.com' },
      });

      expect(user.name).toBe('New Name');
      expect(user.email).toBe('upsert2-new@example.com');
    });
  });

  // --- MODELS WITHOUT CONFIG (passthrough) ---

  describe('Models without blind index config (passthrough)', () => {
    it('should not interfere with models not in the fields config', async () => {
      // Post model is not configured — should work normally
      const user = await rawPrisma.user.create({
        data: {
          name: 'PostAuthor',
          email: 'fake-encrypted:aGVsbG8=:aGVsbG8=',
          email_bidx: 'somehash',
        },
      });

      const post = await rawPrisma.post.create({
        data: { title: 'Test Post', content: 'Hello World', authorId: user.id },
      });

      const foundPost = await (prisma as unknown as typeof rawPrisma).post.findUnique({
        where: { id: post.id },
      });

      expect(foundPost).not.toBeNull();
      expect((foundPost as Record<string, unknown>)['title']).toBe('Test Post');
    });
  });

  // --- SECURITY VERIFICATION ---

  describe('Security Properties', () => {
    it('should produce different ciphertexts for two users with the same email', async () => {
      // Create user, delete, create again to get a fresh encryption
      await prisma.user.create({ data: { name: 'Alice', email: 'alice@example.com' } });
      const raw1 = await rawPrisma.user.findFirst({ where: { name: 'Alice' } });
      await rawPrisma.user.deleteMany();

      await prisma.user.create({ data: { name: 'Alice', email: 'alice@example.com' } });
      const raw2 = await rawPrisma.user.findFirst({ where: { name: 'Alice' } });

      // Different IVs → different ciphertexts (AES-GCM with random IV)
      expect(raw1!.email).not.toBe(raw2!.email);
    });

    it('should produce the same blind index for two users with the same email', async () => {
      // The blind index must be deterministic so both records are findable
      await prisma.user.create({ data: { name: 'Alice', email: 'alice@example.com' } });
      const raw1 = await rawPrisma.user.findFirst({ where: { name: 'Alice' } });
      await rawPrisma.user.deleteMany();

      await prisma.user.create({ data: { name: 'Alice', email: 'alice@example.com' } });
      const raw2 = await rawPrisma.user.findFirst({ where: { name: 'Alice' } });

      expect(raw1!.email_bidx).toBe(raw2!.email_bidx);
    });

    it('stored email ciphertext should not contain the plaintext anywhere', async () => {
      await prisma.user.create({ data: { name: 'Bob', email: 'secret@private.com' } });
      const rawUser = await rawPrisma.user.findFirst({ where: { name: 'Bob' } });

      expect(rawUser!.email).not.toContain('secret@private.com');
      expect(rawUser!.email).not.toContain('secret');
      expect(rawUser!.email).not.toContain('private');
    });
  });
});

