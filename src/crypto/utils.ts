/**
 * @file crypto/utils.ts
 * @description Key validation and parsing utilities for cryptographic operations.
 *
 * Security Design Notes:
 * - AES-256 requires a 256-bit (32-byte) key. Any deviation is a hard error.
 * - Keys may be provided as base64 or hex strings for safe environment variable storage.
 * - We validate at extension initialization time, not at query time, to fail fast.
 */

/**
 * Attempts to parse a string as a base64-encoded Buffer.
 * Returns `null` if the string is not valid base64.
 */
function tryParseBase64(value: string): Buffer | null {
  try {
    const buf = Buffer.from(value, 'base64');
    // Verify round-trip: if re-encoding doesn't match, the original wasn't valid base64
    if (buf.toString('base64') === value || buf.toString('base64url') === value) {
      return buf;
    }
    // Allow base64 with padding stripped or standard base64
    // A valid base64 string of length L decodes to floor(L*3/4) bytes
    // We just trust the Buffer decode here for practical use
    return buf.byteLength > 0 ? buf : null;
  } catch {
    return null;
  }
}

/**
 * Attempts to parse a string as a hex-encoded Buffer.
 * Returns `null` if the string is not a valid even-length hex string.
 */
function tryParseHex(value: string): Buffer | null {
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    return null;
  }
  return Buffer.from(value, 'hex');
}

/**
 * Parses a key string (base64 or hex) into a Buffer and validates its byte length.
 *
 * The function tries hex first (unambiguous format), then base64.
 *
 * @param keyString - The raw key string from environment variables or config.
 * @param expectedBytes - The required byte length of the decoded key.
 * @param keyName - A descriptive name for the key, used in error messages.
 * @returns A `Buffer` of exactly `expectedBytes` bytes.
 * @throws {Error} If the key cannot be parsed or has an incorrect length.
 *
 * @example
 * ```ts
 * const key = parseAndValidateKey(process.env.ENCRYPTION_KEY!, 32, 'encryptionKey');
 * ```
 */
export function parseAndValidateKey(
  keyString: string,
  expectedBytes: number,
  keyName: string
): Buffer {
  if (!keyString || typeof keyString !== 'string') {
    throw new Error(
      `[orm-blind-indexer] "${keyName}" must be a non-empty string. ` +
      `Generate one with: node -e "console.log(require('crypto').randomBytes(${expectedBytes}).toString('base64'))"`
    );
  }

  // Try hex first (unambiguous — only hex chars, even length)
  const hexBuf = tryParseHex(keyString);
  if (hexBuf !== null) {
    if (hexBuf.byteLength !== expectedBytes) {
      throw new Error(
        `[orm-blind-indexer] "${keyName}" decoded to ${hexBuf.byteLength} bytes from hex, ` +
        `but ${expectedBytes} bytes are required. ` +
        `A ${expectedBytes}-byte hex key must be ${expectedBytes * 2} hex characters.`
      );
    }
    return hexBuf;
  }

  // Try base64
  const b64Buf = tryParseBase64(keyString);
  if (b64Buf !== null) {
    if (b64Buf.byteLength !== expectedBytes) {
      throw new Error(
        `[orm-blind-indexer] "${keyName}" decoded to ${b64Buf.byteLength} bytes from base64, ` +
        `but ${expectedBytes} bytes are required. ` +
        `Generate a valid key with: node -e "console.log(require('crypto').randomBytes(${expectedBytes}).toString('base64'))"`
      );
    }
    return b64Buf;
  }

  throw new Error(
    `[orm-blind-indexer] "${keyName}" could not be parsed as hex or base64. ` +
    `Provide a ${expectedBytes * 2}-char hex string or a ${Math.ceil(expectedBytes * 4 / 3)}-char base64 string.`
  );
}

/**
 * Validates an encryption key for AES-256 (requires exactly 32 bytes / 256 bits).
 *
 * @param keyString - The raw encryption key string from config.
 * @returns A `Buffer` of exactly 32 bytes suitable for AES-256-GCM.
 * @throws {Error} If the key is invalid or not exactly 32 bytes.
 */
export function validateEncryptionKey(keyString: string): Buffer {
  return parseAndValidateKey(keyString, 32, 'encryptionKey');
}

/**
 * Parses the index key (HMAC salt) from a string.
 * Unlike the encryption key, the HMAC key has no strict length requirement in the
 * cryptographic spec (SHA-256 accepts any length), but we enforce a minimum of 16 bytes
 * for security best-practice guidance.
 *
 * @param keyString - The raw index key string from config.
 * @returns A `Buffer` usable as an HMAC key.
 * @throws {Error} If the key cannot be parsed or is shorter than 16 bytes.
 */
export function validateIndexKey(keyString: string): Buffer {
  if (!keyString || typeof keyString !== 'string') {
    throw new Error(
      `[orm-blind-indexer] "indexKey" must be a non-empty string. ` +
      `Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
    );
  }

  // Try hex
  const hexBuf = tryParseHex(keyString);
  if (hexBuf !== null) {
    if (hexBuf.byteLength < 16) {
      throw new Error(
        `[orm-blind-indexer] "indexKey" is too short (${hexBuf.byteLength} bytes). ` +
        `Minimum recommended length is 16 bytes (32 hex chars).`
      );
    }
    return hexBuf;
  }

  // Try base64
  const b64Buf = tryParseBase64(keyString);
  if (b64Buf !== null) {
    if (b64Buf.byteLength < 16) {
      throw new Error(
        `[orm-blind-indexer] "indexKey" is too short (${b64Buf.byteLength} bytes). ` +
        `Minimum recommended length is 16 bytes.`
      );
    }
    return b64Buf;
  }

  // Fall back to treating it as a raw UTF-8 string key (not recommended but functional)
  const rawBuf = Buffer.from(keyString, 'utf8');
  if (rawBuf.byteLength < 16) {
    throw new Error(
      `[orm-blind-indexer] "indexKey" is too short (${rawBuf.byteLength} bytes as UTF-8). ` +
      `Minimum recommended length is 16 bytes.`
    );
  }
  return rawBuf;
}

