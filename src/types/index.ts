/**
 * @file types/index.ts
 * @description Core TypeScript interfaces and types for the orm-blind-indexer package.
 */

/**
 * Configuration for a single encrypted field within a model.
 *
 * @example
 * ```ts
 * // For the "email" field on the User model:
 * {
 *   indexFieldName: "email_bidx",
 *   caseSensitive: false
 * }
 * ```
 */
export interface FieldConfig {
  /**
   * The name of the database column that stores the HMAC-SHA256 blind index.
   * This column must exist in your Prisma schema (e.g., `email_bidx String @unique`).
   */
  indexFieldName: string;

  /**
   * When `false` (the default), the plaintext is lowercased before hashing.
   * This ensures case-insensitive lookups: searching for "Test@Test.com"
   * will match a record where "test@test.com" was stored.
   *
   * When `true`, the plaintext is hashed as-is, so the case must match exactly.
   *
   * @default false
   */
  caseSensitive?: boolean;

  /**
   * Optional byte length to truncate the HMAC-SHA256 digest to before encoding.
   * Useful for frequency-analysis defense (k-anonymity / CipherSweet spec).
   * Minimum: 8 bytes, Maximum: 32 bytes.
   * Defaults to 32 (full SHA-256 digest length).
   *
   * @default undefined (full 32 bytes)
   */
  truncateBytes?: number;
}

/**
 * Per-model field configuration map.
 * Maps field names (as they appear in the Prisma schema) to their FieldConfig.
 */
export type ModelFieldConfig = Record<string, FieldConfig>;

/**
 * Full field map across all models.
 * Maps Prisma model names (PascalCase, e.g., "User") to their field configurations.
 */
export type FieldsConfig = Record<string, ModelFieldConfig>;

/**
 * Root configuration object for the `withBlindIndexer` Prisma extension.
 *
 * @example
 * ```ts
 * const config: BlindIndexConfig = {
 *   encryptionKey: process.env.ENCRYPTION_KEY!, // 32-byte base64 or hex string
 *   indexKey: process.env.INDEX_KEY!,           // HMAC salt (any length, min 32 bytes recommended)
 *   fields: {
 *     User: {
 *       email: {
 *         indexFieldName: "email_bidx",
 *         caseSensitive: false,
 *       },
 *     },
 *   },
 * };
 * ```
 */
export interface BlindIndexConfig {
  /**
   * The AES-256-GCM encryption key.
   *
   * Must decode to exactly **32 bytes** (256 bits).
   * Accepted formats:
   * - Base64-encoded 32-byte key (44 characters with padding)
   * - Hex-encoded 32-byte key (64 hex characters)
   *
   * Generate with: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
   */
  encryptionKey: string;

  /**
   * The HMAC-SHA256 index key (salt).
   *
   * Used as the secret for the HMAC function. Should be a high-entropy
   * random value, **different** from the encryptionKey.
   * Recommended minimum: 32 bytes of entropy.
   *
   * Generate with: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
   */
  indexKey: string;

  /**
   * Map of model names to their encrypted fields configuration.
   */
  fields: FieldsConfig;
}

/**
 * Represents the parsed components of an AES-256-GCM ciphertext string.
 * The on-disk format is `base64(iv):base64(authTag):base64(ciphertext)`.
 */
export interface ParsedCiphertext {
  /** 12-byte Initialization Vector, stored as base64. */
  iv: Buffer;
  /** 16-byte GCM Authentication Tag, stored as base64. */
  authTag: Buffer;
  /** The actual encrypted bytes, stored as base64. */
  ciphertext: Buffer;
}

/**
 * Result of a successful encryption operation.
 */
export interface EncryptionResult {
  /**
   * The serialized ciphertext string in the format:
   * `base64(iv):base64(authTag):base64(ciphertext)`
   */
  encrypted: string;
}

