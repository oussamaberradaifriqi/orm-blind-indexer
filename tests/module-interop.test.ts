/**
 * @file tests/module-interop.test.ts
 * @description Verifies CommonJS and ESM module interoperability for the built package.
 *
 * Ensures full compatibility with:
 * - Next.js (Webpack / Turbopack with App Router / Pages Router)
 * - NestJS (CommonJS with ts-node or Webpack)
 * - Svelte / SvelteKit (Vite ESM resolution)
 * - Angular SSR / AnalogJS / Node backend
 * - Nuxt / Remix / Fastify / Express
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { execSync } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

describe('Module Interoperability & Multi-Framework Support', () => {
  beforeAll(() => {
    const cjsPath = path.resolve(__dirname, '../dist/index.js');
    const esmPath = path.resolve(__dirname, '../dist/index.mjs');
    if (!fs.existsSync(cjsPath) || !fs.existsSync(esmPath)) {
      execSync('npm run build', {
        cwd: path.resolve(__dirname, '..'),
        stdio: 'inherit',
      });
    }
  });
  it('should be loadable via CommonJS require (NestJS, Express, Node CJS)', () => {
    const cjsPath = path.resolve(__dirname, '../dist/index.js');
    const cjsModule = require(cjsPath);

    expect(cjsModule).toBeDefined();
    expect(typeof cjsModule.withBlindIndexer).toBe('function');
    expect(typeof cjsModule.encrypt).toBe('function');
    expect(typeof cjsModule.decrypt).toBe('function');
    expect(typeof cjsModule.generateBlindIndex).toBe('function');
    expect(typeof cjsModule.validateEncryptionKey).toBe('function');
    expect(typeof cjsModule.validateIndexKey).toBe('function');
  });

  it('should be loadable via ESM dynamic import (Next.js, SvelteKit, Nuxt, Remix)', async () => {
    const esmPath = path.resolve(__dirname, '../dist/index.mjs');
    const esmModule = await import(/* @vite-ignore */ `file://${esmPath}`);

    expect(esmModule).toBeDefined();
    expect(typeof esmModule.withBlindIndexer).toBe('function');
    expect(typeof esmModule.encrypt).toBe('function');
    expect(typeof esmModule.decrypt).toBe('function');
    expect(typeof esmModule.generateBlindIndex).toBe('function');
    expect(typeof esmModule.validateEncryptionKey).toBe('function');
    expect(typeof esmModule.validateIndexKey).toBe('function');
  });

  it('should execute crypto primitives identically in both CJS and ESM builds', async () => {
    const cjs = require(path.resolve(__dirname, '../dist/index.js'));
    const esm = await import(/* @vite-ignore */ `file://${path.resolve(__dirname, '../dist/index.mjs')}`);

    const key = cjs.validateEncryptionKey('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    const indexKey = cjs.validateIndexKey('0123456789abcdef0123456789abcdef');

    // Encrypt with CJS, decrypt with ESM
    const ciphertext = cjs.encrypt('hello@oussama.dev', key);
    const decrypted = esm.decrypt(ciphertext, key);
    expect(decrypted).toBe('hello@oussama.dev');

    // Blind index generated from both builds must be byte-for-byte identical
    const cjsHash = cjs.generateBlindIndex('hello@oussama.dev', indexKey);
    const esmHash = esm.generateBlindIndex('hello@oussama.dev', indexKey);
    expect(cjsHash).toBe(esmHash);
  });
});

