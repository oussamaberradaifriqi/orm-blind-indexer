/**
 * @file extension/interceptors.ts
 * @description Recursive WHERE clause transformation for blind index substitution.
 *
 * ## The Problem
 *
 * Prisma's `where` clause is a deeply nested object that can contain:
 * - Direct equality: `{ email: "user@example.com" }`
 * - Operator objects: `{ email: { in: [...], equals: "..." } }`
 * - Logical combinators: `{ AND: [...], OR: [...], NOT: { ... } }`
 * - Nested relations: `{ posts: { some: { author: { email: "..." } } } }`
 *
 * We need to intercept any occurrence of an encrypted field name and replace it
 * with a blind index lookup, regardless of how deeply nested it is.
 *
 * ## Strategy
 *
 * We use a **recursive depth-first traversal** of the `where` object:
 *
 * 1. For each key in the current object, check if it's a logical combinator
 *    (`AND`, `OR`, `NOT`). If so, recurse into its children.
 * 2. If the key matches a configured encrypted field, transform the value:
 *    - Remove the original field key.
 *    - Add the `indexFieldName` key with the hashed value.
 * 3. Handle the `in` operator specially: hash each array element.
 *
 * ## Supported Prisma Filter Operators (on encrypted fields)
 *
 * | Prisma Operator | Supported | Notes                                   |
 * |----------------|-----------|------------------------------------------|
 * | `equals`       | ✅        | Direct value or `{ equals: value }`      |
 * | `in`           | ✅        | Hashes each element of the array         |
 * | (direct)       | ✅        | `{ email: "value" }` shorthand           |
 * | `contains`     | ❌        | LIKE queries incompatible with hashing   |
 * | `startsWith`   | ❌        | LIKE queries incompatible with hashing   |
 * | `endsWith`     | ❌        | LIKE queries incompatible with hashing   |
 * | `lt/gt/lte/gte`| ❌        | Range queries incompatible with hashing  |
 *
 * Attempting to use unsupported operators on encrypted fields will throw an error
 * guiding the developer to the correct approach.
 */

import { generateBlindIndex, generateBlindIndexBatch } from '../crypto/hasher.js';
import type { ModelFieldConfig } from '../types/index.js';

/** Prisma logical combinator keys that contain nested where clause arrays or objects. */
const LOGICAL_COMBINATORS = new Set(['AND', 'OR', 'NOT']);

/** Prisma filter operators that are incompatible with blind indexing. */
const UNSUPPORTED_OPERATORS = new Set([
  'contains',
  'startsWith',
  'endsWith',
  'lt',
  'lte',
  'gt',
  'gte',
  'search',
]);

/**
 * Transforms a Prisma `where` clause, replacing encrypted field lookups with
 * their corresponding blind index field lookups.
 *
 * This function is **pure** (it returns a new object, not mutating the original)
 * and **recursive** (it handles arbitrarily nested `AND`/`OR`/`NOT` clauses).
 *
 * @param where - The Prisma where clause object to transform.
 * @param modelConfig - The field configuration for the current model.
 * @param indexKey - The HMAC key Buffer for generating blind indexes.
 * @returns A new where clause object with encrypted fields replaced by blind index fields.
 * @throws {Error} If an unsupported operator is used on an encrypted field.
 */
export function transformWhereClause(
  where: Record<string, unknown>,
  modelConfig: ModelFieldConfig,
  indexKey: Buffer
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(where)) {
    // --- Handle logical combinators: AND, OR, NOT ---
    if (LOGICAL_COMBINATORS.has(key)) {
      if (Array.isArray(value)) {
        // AND: [...], OR: [...]
        result[key] = value.map((item) => {
          if (item !== null && typeof item === 'object' && !Array.isArray(item)) {
            return transformWhereClause(
              item as Record<string, unknown>,
              modelConfig,
              indexKey
            );
          }
          return item;
        });
      } else if (value !== null && typeof value === 'object') {
        // NOT: { ... }
        result[key] = transformWhereClause(
          value as Record<string, unknown>,
          modelConfig,
          indexKey
        );
      } else {
        result[key] = value;
      }
      continue;
    }

    // --- Handle encrypted fields ---
    const fieldConfig = modelConfig[key];
    if (fieldConfig !== undefined) {
      const { indexFieldName, caseSensitive = false, truncateBytes } = fieldConfig;

      // Value is a plain string: `{ email: "user@example.com" }` shorthand
      if (typeof value === 'string') {
        result[indexFieldName] = generateBlindIndex(value, indexKey, caseSensitive, truncateBytes);
        continue;
      }

      // Value is null: pass through (querying for null encrypted fields)
      if (value === null) {
        result[indexFieldName] = null;
        continue;
      }

      // Value is an operator object: `{ email: { in: [...], equals: "..." } }`
      if (typeof value === 'object' && !Array.isArray(value)) {
        const operatorObj = value as Record<string, unknown>;
        const transformedOperator: Record<string, unknown> = {};

        for (const [op, opValue] of Object.entries(operatorObj)) {
          // Check for unsupported operators
          if (UNSUPPORTED_OPERATORS.has(op)) {
            throw new Error(
              `[orm-blind-indexer] The "${op}" filter operator is not supported on encrypted ` +
              `field "${key}". Blind indexes only support exact-match lookups (equals, in, notIn). ` +
              `Partial string searches on encrypted fields require application-level decryption.`
            );
          }

          // Handle Prisma's mode: "insensitive" / "default"
          if (op === 'mode') {
            if (opValue === 'insensitive' && caseSensitive) {
              throw new Error(
                `[orm-blind-indexer] "mode: 'insensitive'" cannot be used on encrypted field "${key}" ` +
                `configured with "caseSensitive: true". Change the field configuration to "caseSensitive: false" ` +
                `for case-insensitive blind index lookups.`
              );
            }
            // If caseSensitive is false, case insensitivity is inherently handled
            // during HMAC generation. We omit `mode` from the transformed query.
            continue;
          }

          if (op === 'equals') {
            if (typeof opValue === 'string') {
              transformedOperator['equals'] = generateBlindIndex(opValue, indexKey, caseSensitive, truncateBytes);
            } else if (opValue === null) {
              transformedOperator['equals'] = null;
            } else {
              throw new Error(
                `[orm-blind-indexer] The "equals" operator on encrypted field "${key}" ` +
                `expects a string value, got ${typeof opValue}.`
              );
            }
          } else if (op === 'in') {
            if (Array.isArray(opValue)) {
              const strings = opValue.filter((v): v is string => typeof v === 'string');
              if (strings.length !== opValue.length) {
                throw new Error(
                  `[orm-blind-indexer] The "in" operator on encrypted field "${key}" ` +
                  `requires all values to be strings.`
                );
              }
              transformedOperator['in'] = generateBlindIndexBatch(strings, indexKey, caseSensitive, truncateBytes);
            } else {
              throw new Error(
                `[orm-blind-indexer] The "in" operator on encrypted field "${key}" ` +
                `expects an array, got ${typeof opValue}.`
              );
            }
          } else if (op === 'notIn') {
            if (Array.isArray(opValue)) {
              const strings = opValue.filter((v): v is string => typeof v === 'string');
              if (strings.length !== opValue.length) {
                throw new Error(
                  `[orm-blind-indexer] The "notIn" operator on encrypted field "${key}" ` +
                  `requires all values to be strings.`
                );
              }
              transformedOperator['notIn'] = generateBlindIndexBatch(strings, indexKey, caseSensitive, truncateBytes);
            } else {
              throw new Error(
                `[orm-blind-indexer] The "notIn" operator on encrypted field "${key}" ` +
                `expects an array, got ${typeof opValue}.`
              );
            }
          } else if (op === 'not') {
            // `NOT` as a filter operator (different from `NOT` combinator)
            if (typeof opValue === 'string') {
              transformedOperator['not'] = generateBlindIndex(opValue, indexKey, caseSensitive, truncateBytes);
            } else if (opValue === null) {
              transformedOperator['not'] = null;
            } else {
              transformedOperator['not'] = opValue;
            }
          } else {
            // Pass through unknown operators (future Prisma operators)
            transformedOperator[op] = opValue;
          }
        }

        result[indexFieldName] = transformedOperator;
        continue;
      }

      // Fallback: pass through as-is (handles edge cases)
      result[key] = value;
      continue;
    }

    // --- Non-encrypted field: pass through unchanged ---
    result[key] = value;
  }

  return result;
}

/**
 * Strips blind index fields (`_bidx` columns) from a query result object
 * so the caller only sees the logical schema (without implementation details).
 *
 * This function also handles arrays of results (for `findMany`) and
 * recursively cleans nested relation objects.
 *
 * @param result - The raw result from Prisma (single object or array).
 * @param modelConfig - The field configuration for the current model.
 * @returns The cleaned result with `_bidx` fields removed.
 */
export function stripBlindIndexFields(
  result: unknown,
  modelConfig: ModelFieldConfig
): unknown {
  if (result === null || result === undefined) {
    return result;
  }

  if (Array.isArray(result)) {
    return result.map((item) => stripBlindIndexFields(item, modelConfig));
  }

  if (typeof result === 'object') {
    const obj = result as Record<string, unknown>;
    const cleaned: Record<string, unknown> = {};

    // Collect all bidx field names to exclude
    const bidxFieldNames = new Set(
      Object.values(modelConfig).map((cfg) => cfg.indexFieldName)
    );

    for (const [key, value] of Object.entries(obj)) {
      if (!bidxFieldNames.has(key)) {
        // Recursively clean nested objects (for relations)
        if (value !== null && typeof value === 'object') {
          cleaned[key] = stripBlindIndexFields(value, modelConfig);
        } else {
          cleaned[key] = value;
        }
      }
      // Skip bidx fields — don't include them in output
    }

    return cleaned;
  }

  return result;
}

