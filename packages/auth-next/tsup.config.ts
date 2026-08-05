import { defineConfig } from 'tsup';

export default defineConfig({
  // Both entries: package.json advertises a "./server" subpath export.
  entry: ['src/index.ts', 'src/server.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  minify: true,
  external: ['next'],
});
