/**
 * @file crypto/encryptor.ts
 * @description AES-256-GCM authenticated encryption and decryption.
 *
 * ## Why AES-256-GCM?
 *
 * AES-256-GCM (Galois/Counter Mode) is an authenticated encryption with
 * associated data (AEAD) cipher. It provides:
 *
 * 1. **Confidentiality**: The ciphertext reveals nothing about the plaintext.
 * 2. **Integrity & Authenticity**: The 16-byte authentication tag (Auth Tag)
 *    cryptographically proves the ciphertext has not been tampered with.
 *    Decryption fails with an error if the tag doesn't verify.
 * 3. **No padding oracle**: GCM is a stream-cipher mode — no PKCS#7 padding
 *    means no padding oracle attacks.
 *
 * ## On-disk format
 *
 * We serialize the IV, Auth Tag, and ciphertext as three colon-separated
 * base64 segments: `base64(iv):base64(authTag):base64(ciphertext)`
 *
 * This is a self-contained format: everything needed to decrypt the value
 * lives in the value itself. The key is stored separately (environment variable).
 *
 * ## IV Randomness
 *
 * A fresh 12-byte random IV is generated for **every** encryption call using
 * `crypto.randomBytes()`. This is critical: reusing an IV with the same key
 * in GCM mode completely breaks confidentiality (two-time pad attack).
 * With a 12-byte IV, the probability of a collision is negligible for
 * reasonable database sizes (birthday bound: ~2^48 operations for 2^-32 risk).
 *
 * ## Auth Tag Length
 *
 * We use the full 16-byte (128-bit) authentication tag, which is the
 * maximum and recommended length. Shorter tags reduce forgery resistance.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import type { ParsedCiphertext } from '../types/index.js';

/** AES-256-GCM algorithm identifier used by Node.js crypto. */
const ALGORITHM = 'aes-256-gcm' as const;

/** Length of the random Initialization Vector in bytes. NIST recommends 96 bits (12 bytes) for GCM. */
const IV_LENGTH_BYTES = 12;

/** Length of the GCM authentication tag in bytes. 128 bits (16 bytes) is the maximum and recommended. */
const AUTH_TAG_LENGTH_BYTES = 16;

/** Delimiter used to separate the IV, Auth Tag, and ciphertext in the serialized format. */
const DELIMITER = ':';

/**
 * Encrypts a UTF-8 plaintext string using AES-256-GCM.
 *
 * @param plaintext - The plaintext string to encrypt (e.g., an email address).
 * @param key - A 32-byte Buffer containing the AES-256 encryption key.
 * @returns A serialized ciphertext string: `base64(iv):base64(authTag):base64(ciphertext)`.
 * @throws {Error} If encryption fails (e.g., invalid key length).
 *
 * @example
 * ```ts
 * const encrypted = encrypt('user@example.com', encryptionKeyBuffer);
 * // => "ABC123...:XYZ789...:cipher..."
 * ```
 */
export function encrypt(plaintext: string, key: Buffer): string {
  // Generate a fresh random 12-byte IV for every encryption
  const iv = randomBytes(IV_LENGTH_BYTES);

  // Create the cipher. Node.js validates the key length here and throws
  // if it doesn't match the algorithm's requirement (32 bytes for AES-256).
  const cipher = createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });

  // Encrypt the plaintext. The update() call does the actual encryption;
  // final() flushes any remaining bytes (empty for a stream cipher like GCM).
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  // Retrieve the GCM authentication tag AFTER calling final()
  const authTag = cipher.getAuthTag();

  // Serialize: base64(iv) : base64(authTag) : base64(ciphertext)
  return [
    iv.toString('base64'),
    authTag.toString('base64'),
    encrypted.toString('base64'),
  ].join(DELIMITER);
}

/**
 * Parses a serialized AES-256-GCM ciphertext string into its components.
 *
 * @param cipherText - The serialized string in `base64(iv):base64(authTag):base64(ct)` format.
 * @returns A `ParsedCiphertext` object with Buffer components.
 * @throws {Error} If the string format is invalid or any component has an unexpected length.
 */
function parseCiphertext(cipherText: string): ParsedCiphertext {
  const parts = cipherText.split(DELIMITER);
  if (parts.length !== 3) {
    throw new Error(
      `[orm-blind-indexer] Invalid ciphertext format. ` +
      `Expected "base64(iv):base64(authTag):base64(ciphertext)" with exactly 2 colons, ` +
      `but got ${parts.length - 1} colons. ` +
      `The value may not be encrypted or may be corrupted.`
    );
  }

  const [ivB64, authTagB64, ciphertextB64] = parts as [string, string, string];

  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');
  const ciphertext = Buffer.from(ciphertextB64, 'base64');

  if (iv.byteLength !== IV_LENGTH_BYTES) {
    throw new Error(
      `[orm-blind-indexer] Invalid IV length in ciphertext. ` +
      `Expected ${IV_LENGTH_BYTES} bytes, got ${iv.byteLength} bytes.`
    );
  }

  if (authTag.byteLength !== AUTH_TAG_LENGTH_BYTES) {
    throw new Error(
      `[orm-blind-indexer] Invalid Auth Tag length in ciphertext. ` +
      `Expected ${AUTH_TAG_LENGTH_BYTES} bytes, got ${authTag.byteLength} bytes.`
    );
  }

  return { iv, authTag, ciphertext };
}

/**
 * Decrypts a serialized AES-256-GCM ciphertext string back to UTF-8 plaintext.
 *
 * The decryption process automatically verifies the GCM authentication tag.
 * If the ciphertext or key has been tampered with, decryption will throw an error
 * ("Unsupported state or unable to authenticate data") before any plaintext is returned.
 *
 * @param cipherText - The serialized ciphertext string from `encrypt()`.
 * @param key - The same 32-byte Buffer used during encryption.
 * @returns The original UTF-8 plaintext string.
 * @throws {Error} If the ciphertext format is invalid, the key is wrong,
 *   or the authentication tag verification fails (indicating tampering).
 *
 * @example
 * ```ts
 * const plaintext = decrypt(encryptedValue, encryptionKeyBuffer);
 * // => "user@example.com"
 * ```
 */
export function decrypt(cipherText: string, key: Buffer): string {
  const { iv, authTag, ciphertext } = parseCiphertext(cipherText);

  const decipher = createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });

  // Set the authentication tag BEFORE decrypting.
  // The decipher will verify this tag during final(), throwing if it doesn't match.
  decipher.setAuthTag(authTag);

  // Decrypt the ciphertext. final() triggers the auth tag verification.
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(), // Throws if auth tag verification fails
  ]);

  return decrypted.toString('utf8');
}

/**
 * Checks if a string appears to be in the encrypted format produced by `encrypt()`.
 * Used to avoid double-encrypting values that are already encrypted.
 *
 * This is a heuristic check based on format, not cryptographic verification.
 *
 * @param value - The string to check.
 * @returns `true` if the string matches the `base64:base64:base64` pattern.
 */
export function isEncryptedFormat(value: string): boolean {
  const parts = value.split(DELIMITER);
  if (parts.length !== 3) return false;

  // Check that each part is non-empty and looks like base64
  const base64Pattern = /^[A-Za-z0-9+/]+=*$/;
  return parts.every(
    (part): boolean => typeof part === 'string' && part.length > 0 && base64Pattern.test(part)
  );
}

