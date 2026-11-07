import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    /**
     * Use the Node.js test environment (not jsdom).
     * Required because we use the `crypto` module and child_process.
     */
    environment: 'node',

    /**
     * Global test timeout: 30s to account for Prisma client generation
     * during the first test run (`beforeAll`).
     */
    testTimeout: 60000,
    hookTimeout: 60000,

    /**
     * Run test files in a single thread to avoid SQLite file contention.
     * Crypto unit tests are fast enough to not need parallelism.
     */
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: false,
      },
    },

    /**
     * Coverage configuration (used with `npm run test:coverage`).
     */
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/types/**'],
      thresholds: {
        lines: 70,
        functions: 75,
        branches: 70,
        statements: 70,
      },
    },

    /**
     * Report slow tests (>1s) in the output.
     */
    slowTestThreshold: 1000,
  },

  /**
   * Allow top-level await and ESM imports in test files.
   */
  esbuild: {
    target: 'node18',
  },
});

