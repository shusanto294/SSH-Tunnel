import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The SSH layer has no Worker imports by design, so it runs under plain
    // Node — which has the same WebCrypto primitives the Worker uses.
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
