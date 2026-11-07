import { defineConfig } from 'tsup';

export default defineConfig({
  /**
   * Entry point for the library build.
   * tsup will trace all imports from this file.
   */
  entry: ['src/index.ts'],

  /**
   * Output both CommonJS (for Node.js require()) and
   * ESM (for Node.js import and bundlers like Vite/Webpack).
   */
  format: ['cjs', 'esm'],

  /**
   * Enable CJS interop to seamlessly support:
   * const { withBlindIndexer } = require('orm-blind-indexer');
   * as well as:
   * const blindIndexer = require('orm-blind-indexer');
   */
  cjsInterop: true,

  /**
   * Generate TypeScript declaration files (.d.ts) and
   * declaration maps (.d.ts.map) for IDE type intelligence.
   */
  dts: true,

  /**
   * Generate source maps for debuggability.
   */
  sourcemap: true,

  /**
   * Clean the dist/ directory before each build to avoid stale artifacts.
   */
  clean: true,

  /**
   * Split chunks for tree-shaking in ESM output.
   */
  splitting: false,

  /**
   * Mark all Node.js built-in modules and peer dependencies as external
   * so they are not bundled into the output.
   */
  external: ['@prisma/client', 'prisma'],

  /**
   * Target Node.js 18+, which natively supports crypto.webcrypto
   * and the full 'crypto' module with GCM support.
   */
  target: 'node18',

  /**
   * Output file naming convention:
   * - dist/index.js  (CJS)
   * - dist/index.mjs (ESM)
   */
  outExtension({ format }) {
    return {
      js: format === 'esm' ? '.mjs' : '.js',
    };
  },
});

