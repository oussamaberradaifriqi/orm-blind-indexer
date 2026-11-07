/**
 * @file crypto/hasher.ts
 * @description HMAC-SHA256 blind index generation.
 *
 * ## What is a Blind Index?
 *
 * A blind index solves the problem of querying encrypted data. Because AES-256-GCM
 * uses a random IV on every encryption, the same plaintext produces a different
 * ciphertext each time. This makes exact-match database queries impossible on
 * the encrypted column.
 *
 * A blind index is a **deterministic** hash of the plaintext that:
 * - Always produces the same output for the same input (queryable)
 * - Reveals no information about the plaintext without the key (private)
 * - Is stored in a separate `_bidx` column alongside the encrypted data
 *
 * ## Why HMAC-SHA256 (not plain SHA256)?
 *
 * Plain SHA256 is a one-way function, but it has no secret. An attacker who
 * gains read access to your database could mount a **dictionary attack**:
 * they hash every common email address and look for matches.
 *
 * HMAC-SHA256 incorporates a **secret key** (the `indexKey`). Without knowing
 * the key, an attacker cannot compute the hash, so the blind index leaks no
 * information about the plaintext even if the database is fully compromised.
 *
 * ## Case Sensitivity
 *
 * Email addresses and usernames are often compared case-insensitively.
 * When `caseSensitive: false` (the default), we lowercase the input before
 * hashing. This ensures that "Test@Test.com" and "test@test.com" produce the
 * same blind index, enabling case-insensitive equality searches.
 *
 * **Important**: The case normalization must be applied consistently on both
 * write (when storing) and read (when querying). The extension handles this.
 */

import { createHmac } from 'crypto';

/** HMAC digest algorithm — SHA-256 produces a 32-byte (256-bit) output. */
const HMAC_ALGORITHM = 'sha256' as const;

/**
 * Generates a deterministic HMAC-SHA256 blind index for a given plaintext.
 *
 * The output is a base64-encoded 32-byte HMAC digest. Base64 is used (rather
 * than hex) for compactness: 44 characters vs 64 characters for the same value.
 *
 * @param text - The plaintext value to hash (e.g., an email address).
 * @param indexKey - A secret Buffer used as the HMAC key. Must be kept private.
 * @param caseSensitive - When `false`, `text` is lowercased before hashing.
 *   Defaults to `false` for case-insensitive equality searches.
 * @param truncateBytes - Optional byte length (8 to 32) to truncate the HMAC
 *   digest before base64 encoding. Useful for frequency-analysis defense.
 * @returns A base64-encoded HMAC-SHA256 digest string.
 *
 * @example
 * ```ts
 * const indexKey = Buffer.from(process.env.INDEX_KEY!, 'base64');
 *
 * // Case-insensitive (default): both produce the same hash
 * generateBlindIndex('Test@Test.com', indexKey, false);
 * generateBlindIndex('test@test.com', indexKey, false);
 *
 * // Case-sensitive: these produce different hashes
 * generateBlindIndex('Test@Test.com', indexKey, true);
 * generateBlindIndex('test@test.com', indexKey, true);
 *
 * // Truncated blind index (e.g., 16 bytes for frequency defense)
 * generateBlindIndex('user@example.com', indexKey, false, 16);
 * ```
 */
export function generateBlindIndex(
  text: string,
  indexKey: Buffer,
  caseSensitive: boolean = false,
  truncateBytes?: number
): string {
  // Normalize to lowercase for case-insensitive lookups
  const normalized = caseSensitive ? text : text.toLowerCase();

  const digest = createHmac(HMAC_ALGORITHM, indexKey)
    .update(normalized, 'utf8')
    .digest();

  if (truncateBytes !== undefined) {
    if (truncateBytes < 8 || truncateBytes > 32) {
      throw new Error(
        `[orm-blind-indexer] "truncateBytes" must be between 8 and 32 bytes, got ${truncateBytes}.`
      );
    }
    return digest.subarray(0, truncateBytes).toString('base64');
  }

  return digest.toString('base64');
}

/**
 * Generates blind indexes for an array of plaintext values.
 * Useful for `{ in: [...] }` and `{ notIn: [...] }` Prisma query operators.
 *
 * @param values - An array of plaintext strings to hash.
 * @param indexKey - The secret HMAC key Buffer.
 * @param caseSensitive - When `false`, each value is lowercased before hashing.
 * @param truncateBytes - Optional byte length (8 to 32) to truncate each digest.
 * @returns An array of base64-encoded HMAC-SHA256 digests, in the same order as `values`.
 */
export function generateBlindIndexBatch(
  values: string[],
  indexKey: Buffer,
  caseSensitive: boolean = false,
  truncateBytes?: number
): string[] {
  return values.map((value) => generateBlindIndex(value, indexKey, caseSensitive, truncateBytes));
}

