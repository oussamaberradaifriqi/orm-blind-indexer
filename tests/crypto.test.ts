/**
 * @file tests/crypto.test.ts
 * @description Unit tests for the cryptographic core of orm-blind-indexer.
 *
 * These tests verify the correctness, consistency, and security properties
 * of the encryption and blind indexing functions in isolation.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { randomBytes } from 'crypto';
import { encrypt, decrypt, isEncryptedFormat } from '../src/crypto/encryptor.js';
import { generateBlindIndex, generateBlindIndexBatch } from '../src/crypto/hasher.js';
import { validateEncryptionKey, validateIndexKey } from '../src/crypto/utils.js';

// ============================================================================
// Test Fixtures
// ============================================================================

let encryptionKey: Buffer;
let indexKey: Buffer;

beforeAll(() => {
  encryptionKey = randomBytes(32);
  indexKey = randomBytes(32);
});

// ============================================================================
// AES-256-GCM Encryption Tests
// ============================================================================

describe('AES-256-GCM Encryption', () => {
  describe('encrypt()', () => {
    it('should produce a string in the base64:base64:base64 format', () => {
      const result = encrypt('hello@example.com', encryptionKey);
      const parts = result.split(':');
      expect(parts).toHaveLength(3);
      // All parts should be valid base64
      const base64Re = /^[A-Za-z0-9+/]+=*$/;
      parts.forEach((part) => expect(part).toMatch(base64Re));
    });

    it('should produce different ciphertexts for the same plaintext (IV randomness)', () => {
      const ct1 = encrypt('user@example.com', encryptionKey);
      const ct2 = encrypt('user@example.com', encryptionKey);
      // With a random IV, two encryptions of the same plaintext must differ
      expect(ct1).not.toBe(ct2);
    });

    it('should encrypt empty strings', () => {
      const result = encrypt('', encryptionKey);
      expect(result.split(':')).toHaveLength(3);
    });

    it('should encrypt unicode strings', () => {
      const plaintext = '用户@例子.中国';
      const ciphertext = encrypt(plaintext, encryptionKey);
      const decrypted = decrypt(ciphertext, encryptionKey);
      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt strings with special characters', () => {
      const plaintext = 'user+tag@example.co.uk!$#@';
      const ciphertext = encrypt(plaintext, encryptionKey);
      expect(decrypt(ciphertext, encryptionKey)).toBe(plaintext);
    });

    it('should throw if the encryption key is the wrong length', () => {
      const badKey = randomBytes(16); // AES-128, not AES-256
      expect(() => encrypt('test', badKey)).toThrow();
    });
  });

  describe('decrypt()', () => {
    it('should correctly decrypt what encrypt() produces', () => {
      const plaintext = 'secret@email.com';
      const ciphertext = encrypt(plaintext, encryptionKey);
      expect(decrypt(ciphertext, encryptionKey)).toBe(plaintext);
    });

    it('should be consistent: multiple decrypts of the same ciphertext return the same value', () => {
      const plaintext = 'consistent@test.com';
      const ciphertext = encrypt(plaintext, encryptionKey);
      expect(decrypt(ciphertext, encryptionKey)).toBe(plaintext);
      expect(decrypt(ciphertext, encryptionKey)).toBe(plaintext);
      expect(decrypt(ciphertext, encryptionKey)).toBe(plaintext);
    });

    it('should throw when the ciphertext has been tampered with (auth tag failure)', () => {
      const ciphertext = encrypt('original@example.com', encryptionKey);
      // Corrupt the ciphertext portion (3rd part)
      const parts = ciphertext.split(':');
      // Flip a byte in the ciphertext base64
      const tamperedCt = parts[2]!.split('').reverse().join('');
      const tampered = `${parts[0]}:${parts[1]}:${tamperedCt}`;
      expect(() => decrypt(tampered, encryptionKey)).toThrow();
    });

    it('should throw when decrypting with the wrong key', () => {
      const wrongKey = randomBytes(32);
      const ciphertext = encrypt('secret', encryptionKey);
      expect(() => decrypt(ciphertext, wrongKey)).toThrow();
    });

    it('should throw for a malformed ciphertext (wrong number of colons)', () => {
      expect(() => decrypt('notAValidCiphertext', encryptionKey)).toThrow(
        /Invalid ciphertext format/
      );
    });

    it('should throw for a ciphertext with wrong IV length', () => {
      // Manually construct invalid: short IV
      const badIv = Buffer.from('tooshort').toString('base64');
      const authTag = randomBytes(16).toString('base64');
      const ct = randomBytes(32).toString('base64');
      expect(() => decrypt(`${badIv}:${authTag}:${ct}`, encryptionKey)).toThrow(
        /Invalid IV length/
      );
    });

    it('should throw for a ciphertext with wrong auth tag length', () => {
      const iv = randomBytes(12).toString('base64');
      const badAuthTag = randomBytes(8).toString('base64'); // Should be 16
      const ct = randomBytes(32).toString('base64');
      expect(() => decrypt(`${iv}:${badAuthTag}:${ct}`, encryptionKey)).toThrow(
        /Invalid Auth Tag length/
      );
    });
  });

  describe('isEncryptedFormat()', () => {
    it('should return true for a valid encrypted string', () => {
      const enc = encrypt('test@example.com', encryptionKey);
      expect(isEncryptedFormat(enc)).toBe(true);
    });

    it('should return false for a plaintext email', () => {
      expect(isEncryptedFormat('test@example.com')).toBe(false);
    });

    it('should return false for a string with too few colons', () => {
      expect(isEncryptedFormat('aGVsbG8=:aGVsbG8=')).toBe(false);
    });

    it('should return false for an empty string', () => {
      expect(isEncryptedFormat('')).toBe(false);
    });
  });
});

// ============================================================================
// HMAC-SHA256 Blind Index Tests
// ============================================================================

describe('HMAC-SHA256 Blind Index', () => {
  describe('generateBlindIndex()', () => {
    it('should produce a base64 string', () => {
      const hash = generateBlindIndex('user@example.com', indexKey);
      expect(typeof hash).toBe('string');
      expect(hash).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    it('should produce a 44-character base64 string (32 bytes HMAC-SHA256)', () => {
      const hash = generateBlindIndex('user@example.com', indexKey);
      // SHA-256 output is 32 bytes → 44 base64 chars (with padding)
      expect(hash).toHaveLength(44);
    });

    it('should be deterministic: same input produces the same hash', () => {
      const h1 = generateBlindIndex('user@example.com', indexKey);
      const h2 = generateBlindIndex('user@example.com', indexKey);
      expect(h1).toBe(h2);
    });

    it('should be case-insensitive by default (caseSensitive=false)', () => {
      const h1 = generateBlindIndex('User@Example.COM', indexKey, false);
      const h2 = generateBlindIndex('user@example.com', indexKey, false);
      expect(h1).toBe(h2);
    });

    it('should be case-sensitive when caseSensitive=true', () => {
      const h1 = generateBlindIndex('User@Example.COM', indexKey, true);
      const h2 = generateBlindIndex('user@example.com', indexKey, true);
      expect(h1).not.toBe(h2);
    });

    it('should produce different hashes for different inputs', () => {
      const h1 = generateBlindIndex('a@example.com', indexKey);
      const h2 = generateBlindIndex('b@example.com', indexKey);
      expect(h1).not.toBe(h2);
    });

    it('should produce different hashes for different keys (HMAC is keyed)', () => {
      const otherKey = randomBytes(32);
      const h1 = generateBlindIndex('user@example.com', indexKey);
      const h2 = generateBlindIndex('user@example.com', otherKey);
      expect(h1).not.toBe(h2);
    });

    it('should hash empty strings without error', () => {
      const hash = generateBlindIndex('', indexKey);
      expect(hash).toHaveLength(44);
    });
  });

  describe('generateBlindIndexBatch()', () => {
    it('should return an array of hashes in the same order as input', () => {
      const emails = ['a@test.com', 'b@test.com', 'c@test.com'];
      const hashes = generateBlindIndexBatch(emails, indexKey);
      expect(hashes).toHaveLength(3);
      emails.forEach((email, i) => {
        expect(hashes[i]).toBe(generateBlindIndex(email, indexKey));
      });
    });

    it('should return an empty array for an empty input', () => {
      expect(generateBlindIndexBatch([], indexKey)).toEqual([]);
    });

    it('should respect caseSensitive option', () => {
      const mixed = ['Upper@Test.com', 'lower@test.com'];
      const insensitive = generateBlindIndexBatch(mixed, indexKey, false);
      const sensitive = generateBlindIndexBatch(mixed, indexKey, true);
      // Insensitive: both become lowercase before hashing
      expect(insensitive[0]).toBe(generateBlindIndex('upper@test.com', indexKey));
      // Sensitive: each hashed as-is
      expect(sensitive[0]).not.toBe(sensitive[1]);
    });
  });
});

// ============================================================================
// Key Validation Tests
// ============================================================================

describe('Key Validation', () => {
  describe('validateEncryptionKey()', () => {
    it('should accept a valid 32-byte base64 key', () => {
      const key = randomBytes(32).toString('base64');
      const buf = validateEncryptionKey(key);
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.byteLength).toBe(32);
    });

    it('should accept a valid 32-byte hex key', () => {
      const key = randomBytes(32).toString('hex');
      const buf = validateEncryptionKey(key);
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.byteLength).toBe(32);
    });

    it('should throw for a 16-byte (AES-128) base64 key', () => {
      const key = randomBytes(16).toString('base64');
      expect(() => validateEncryptionKey(key)).toThrow(/32 bytes/);
    });

    it('should throw for a 16-byte hex key', () => {
      const key = randomBytes(16).toString('hex');
      expect(() => validateEncryptionKey(key)).toThrow(/32 bytes/);
    });

    it('should throw for an empty string', () => {
      expect(() => validateEncryptionKey('')).toThrow();
    });

    it('should throw for a non-string value', () => {
      // @ts-expect-error — testing runtime guard
      expect(() => validateEncryptionKey(null)).toThrow();
    });
  });

  describe('validateIndexKey()', () => {
    it('should accept a valid base64 key with ≥16 bytes', () => {
      const key = randomBytes(32).toString('base64');
      const buf = validateIndexKey(key);
      expect(buf).toBeInstanceOf(Buffer);
      expect(buf.byteLength).toBeGreaterThanOrEqual(16);
    });

    it('should throw for a key shorter than 16 bytes', () => {
      const key = randomBytes(8).toString('base64');
      expect(() => validateIndexKey(key)).toThrow(/too short/);
    });

    it('should throw for an empty string', () => {
      expect(() => validateIndexKey('')).toThrow();
    });
  });
});

