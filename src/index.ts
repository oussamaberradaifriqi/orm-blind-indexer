/**
 * @file index.ts
 * @description Public API surface for the orm-blind-indexer package.
 *
 * Only symbols explicitly exported from this file are part of the public API.
 * Internal implementation details remain private.
 */

// --- Primary Extension Factory ---
export { withBlindIndexer } from './extension/prisma.js';

// --- Cryptographic Primitives (for advanced use cases) ---
export { encrypt, decrypt, isEncryptedFormat } from './crypto/encryptor.js';
export { generateBlindIndex, generateBlindIndexBatch } from './crypto/hasher.js';
export { validateEncryptionKey, validateIndexKey, parseAndValidateKey } from './crypto/utils.js';

// --- TypeScript Types ---
export type {
  BlindIndexConfig,
  FieldConfig,
  ModelFieldConfig,
  FieldsConfig,
  ParsedCiphertext,
  EncryptionResult,
} from './types/index.js';

