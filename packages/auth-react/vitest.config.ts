import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'jsdom',
        globals: false,
        setupFiles: ['./test/setup.ts'],
        // jsdom's default origin; tests override window.location per case.
        environmentOptions: { jsdom: { url: 'http://localhost:3000/callback' } },
    },
});
