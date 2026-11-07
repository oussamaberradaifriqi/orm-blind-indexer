/**
 * @file extension/prisma.ts
 * @description The core Prisma Client Extension implementing the blind indexing middleware.
 *
 * ## How Prisma Client Extensions Work
 *
 * Prisma Client Extensions (introduced in Prisma 4.7) allow augmenting the Prisma
 * client with custom behavior. We use the `query` extension component, which
 * intercepts all database operations before and after they execute.
 *
 * The `query.$allModels.$allOperations` hook receives:
 * - `model`: The Prisma model name (e.g., "User")
 * - `operation`: The operation name (e.g., "findUnique", "create")
 * - `args`: The operation arguments (where clause, data, etc.) — MUTATED before passing to `next()`
 * - `query`: The `next` function to call to execute the actual query
 *
 * ## Lifecycle of a Write Operation (create/update/upsert)
 *
 * 1. Developer calls: `prisma.user.create({ data: { email: "user@example.com" } })`
 * 2. Extension intercepts `args.data`
 * 3. For each configured encrypted field found in `data`:
 *    a. Encrypt the plaintext with AES-256-GCM → `email` becomes the ciphertext
 *    b. Generate HMAC-SHA256 blind index → inject as `email_bidx`
 * 4. The modified `args` are passed to `next()` → Prisma writes both columns
 * 5. The result is post-processed: `email` is decrypted back, `email_bidx` is stripped
 *
 * ## Lifecycle of a Read Operation (findUnique/findMany/findFirst)
 *
 * 1. Developer calls: `prisma.user.findUnique({ where: { email: "user@example.com" } })`
 * 2. Extension intercepts `args.where`
 * 3. `transformWhereClause()` replaces `email` with `email_bidx: hash("user@example.com")`
 * 4. The modified `args` are passed to `next()` → Prisma queries the blind index column
 * 5. The result is post-processed: `email` is decrypted, `email_bidx` is stripped
 *
 * ## Write Operations Supported
 *
 * | Operation           | Data Location      | Supported |
 * |--------------------|--------------------|-----------|
 * | create             | args.data          | ✅        |
 * | update             | args.data          | ✅        |
 * | upsert             | args.create + args.update | ✅ |
 * | createMany         | args.data (array)  | ✅        |
 * | updateMany         | args.data          | ✅        |
 *
 * ## Read Operations Supported
 *
 * | Operation           | Where Location     | Supported |
 * |--------------------|-------------------|-----------|
 * | findUnique          | args.where        | ✅        |
 * | findUniqueOrThrow   | args.where        | ✅        |
 * | findFirst           | args.where        | ✅        |
 * | findFirstOrThrow    | args.where        | ✅        |
 * | findMany            | args.where        | ✅        |
 * | count               | args.where        | ✅        |
 * | aggregate           | args.where        | ✅        |
 * | delete              | args.where        | ✅        |
 * | deleteMany          | args.where        | ✅        |
 */

import { Prisma } from '@prisma/client/extension';
import { encrypt, decrypt, isEncryptedFormat } from '../crypto/encryptor.js';
import { generateBlindIndex } from '../crypto/hasher.js';
import { validateEncryptionKey, validateIndexKey } from '../crypto/utils.js';
import { transformWhereClause, stripBlindIndexFields } from './interceptors.js';
import type { BlindIndexConfig, ModelFieldConfig } from '../types/index.js';

/** Operations that write data and require encrypt + blind-index injection */
const WRITE_OPERATIONS = new Set([
  'create',
  'update',
  'upsert',
  'createMany',
  'updateMany',
]);

/** Operations that read data and require where-clause transformation */
const READ_OPERATIONS = new Set([
  'findUnique',
  'findUniqueOrThrow',
  'findFirst',
  'findFirstOrThrow',
  'findMany',
  'count',
  'aggregate',
  'groupBy',
  'delete',
  'deleteMany',
]);

/**
 * Processes a single data object (from create/update `data`), encrypting
 * configured plaintext fields and injecting their blind index counterparts.
 *
 * @param data - The raw data object from the Prisma args.
 * @param modelConfig - Field configuration for the current model.
 * @param encryptionKey - AES-256-GCM key Buffer.
 * @param indexKey - HMAC-SHA256 key Buffer.
 * @returns A new data object with encrypted values and blind index fields injected.
 */
function processWriteData(
  data: Record<string, unknown>,
  modelConfig: ModelFieldConfig,
  encryptionKey: Buffer,
  indexKey: Buffer
): Record<string, unknown> {
  const result = { ...data };

  for (const [fieldName, fieldConfig] of Object.entries(modelConfig)) {
    const value = result[fieldName];

    if (value === undefined || value === null) {
      // Field not present in this write, or explicitly null — skip
      continue;
    }

    if (typeof value !== 'string') {
      // Non-string values (e.g. Prisma `set` wrappers) — skip for safety
      continue;
    }

    // Guard against double-encryption if the value is already in encrypted format
    if (isEncryptedFormat(value)) {
      continue;
    }

    // 1. Encrypt the plaintext value
    result[fieldName] = encrypt(value, encryptionKey);

    // 2. Generate and inject the blind index
    result[fieldConfig.indexFieldName] = generateBlindIndex(
      value,
      indexKey,
      fieldConfig.caseSensitive ?? false
    );
  }

  return result;
}

/**
 * Post-processes a Prisma result, decrypting encrypted fields and removing
 * blind index fields from the output.
 *
 * @param result - The raw result from Prisma.
 * @param modelConfig - Field configuration for the current model.
 * @param encryptionKey - AES-256-GCM key Buffer for decryption.
 * @returns The cleaned result with decrypted plaintext and no `_bidx` fields.
 */
function processResult(
  result: unknown,
  modelConfig: ModelFieldConfig,
  encryptionKey: Buffer
): unknown {
  if (result === null || result === undefined) {
    return result;
  }

  if (Array.isArray(result)) {
    return result.map((item) => processResult(item, modelConfig, encryptionKey));
  }

  if (typeof result === 'object') {
    const obj = result as Record<string, unknown>;
    // Decrypt each configured field
    for (const [fieldName] of Object.entries(modelConfig)) {
      const value = obj[fieldName];
      if (typeof value === 'string' && isEncryptedFormat(value)) {
        try {
          obj[fieldName] = decrypt(value, encryptionKey);
        } catch {
          // If decryption fails, leave the value as-is (may not be encrypted)
        }
      }
    }
    // Strip blind index fields from the result
    return stripBlindIndexFields(obj, modelConfig);
  }

  return result;
}

/**
 * Creates a Prisma Client Extension that transparently implements blind indexing
 * for the configured fields.
 *
 * **Usage:**
 * ```ts
 * import { PrismaClient } from '@prisma/client';
 * import { withBlindIndexer } from 'orm-blind-indexer';
 *
 * const prisma = new PrismaClient().$extends(
 *   withBlindIndexer({
 *     encryptionKey: process.env.ENCRYPTION_KEY!,
 *     indexKey: process.env.INDEX_KEY!,
 *     fields: {
 *       User: {
 *         email: {
 *           indexFieldName: 'email_bidx',
 *           caseSensitive: false,
 *         },
 *       },
 *     },
 *   })
 * );
 * ```
 *
 * @param config - The blind indexer configuration object.
 * @returns A Prisma Client Extension object to pass to `.$extends()`.
 * @throws {Error} At initialization time if the keys are invalid.
 */
export function withBlindIndexer(config: BlindIndexConfig) {
  // Validate keys eagerly at initialization time for fast failure
  const encryptionKey = validateEncryptionKey(config.encryptionKey);
  const indexKey = validateIndexKey(config.indexKey);

  return Prisma.defineExtension({
    name: 'orm-blind-indexer',

    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }) {
          // Get the field config for the current model (if any)
          const modelConfig: ModelFieldConfig | undefined =
            model !== undefined ? config.fields[model] : undefined;

          // If no config for this model, pass through unchanged
          if (modelConfig === undefined || Object.keys(modelConfig).length === 0) {
            return query(args);
          }

          const typedArgs = args as Record<string, unknown>;

          // ----------------------------------------------------------------
          // WRITE OPERATIONS: encrypt data + inject blind indexes
          // ----------------------------------------------------------------
          if (WRITE_OPERATIONS.has(operation)) {
            if (operation === 'upsert') {
              // upsert has both `create` and `update` data objects
              if (typedArgs['create'] && typeof typedArgs['create'] === 'object') {
                typedArgs['create'] = processWriteData(
                  typedArgs['create'] as Record<string, unknown>,
                  modelConfig,
                  encryptionKey,
                  indexKey
                );
              }
              if (typedArgs['update'] && typeof typedArgs['update'] === 'object') {
                typedArgs['update'] = processWriteData(
                  typedArgs['update'] as Record<string, unknown>,
                  modelConfig,
                  encryptionKey,
                  indexKey
                );
              }
            } else if (operation === 'createMany') {
              // createMany has an array of data objects
              if (Array.isArray(typedArgs['data'])) {
                typedArgs['data'] = (typedArgs['data'] as Record<string, unknown>[]).map(
                  (item) => processWriteData(item, modelConfig, encryptionKey, indexKey)
                );
              }
            } else {
              // create, update, updateMany
              if (typedArgs['data'] && typeof typedArgs['data'] === 'object') {
                typedArgs['data'] = processWriteData(
                  typedArgs['data'] as Record<string, unknown>,
                  modelConfig,
                  encryptionKey,
                  indexKey
                );
              }
            }

            // Also transform where clause for update/delete operations
            if (typedArgs['where'] && typeof typedArgs['where'] === 'object') {
              typedArgs['where'] = transformWhereClause(
                typedArgs['where'] as Record<string, unknown>,
                modelConfig,
                indexKey
              );
            }
          }

          // ----------------------------------------------------------------
          // READ OPERATIONS: transform where clause
          // ----------------------------------------------------------------
          if (READ_OPERATIONS.has(operation)) {
            if (typedArgs['where'] && typeof typedArgs['where'] === 'object') {
              typedArgs['where'] = transformWhereClause(
                typedArgs['where'] as Record<string, unknown>,
                modelConfig,
                indexKey
              );
            }
          }

          // Execute the (possibly mutated) query
          const result = await query(args);

          // ----------------------------------------------------------------
          // POST-PROCESS: decrypt results + strip blind index fields
          // ----------------------------------------------------------------
          // Don't post-process count/aggregate (they return numbers, not records)
          if (operation === 'count' || operation === 'aggregate' || operation === 'groupBy') {
            return result;
          }

          return processResult(result, modelConfig, encryptionKey);
        },
      },
    },
  });
}

