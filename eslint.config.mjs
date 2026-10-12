import js from "@eslint/js";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import jsdoc from "eslint-plugin-jsdoc";
import globals from "globals";

export default [
  {
    ignores: ["**/dist/", "**/node_modules/", "**/coverage/", "**/.turbo/", "**/*.config.ts", "**/*.config.js", "**/*.config.mjs"],
  },

  js.configs.recommended,
  ...tsPlugin.configs["flat/recommended"],

  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2022,
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: { jsx: true },
        // The nearest tsconfig.json to each file - per package, and covering src/ only.
        project: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: { ...globals.browser, ...globals.node, ...globals.es2021 },
    },
    plugins: { jsdoc },
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrors: "none" },
      ],
      "no-empty": ["error", { allowEmptyCatch: true }],
      eqeqeq: ["error", "smart"],
      "no-restricted-syntax": [
        "warn",
        {
          selector: "CallExpression > MemberExpression[property.name='parseIdToken']",
          message:
            "parseIdToken() does not verify the token. Use verifyIdToken() to authorize, or decodeIdTokenUnsafe() for display-only claims.",
        },
        {
          selector: "CallExpression > MemberExpression[property.name='isTokenExpired']",
          message: "isTokenExpired() is deprecated. Use isTokenNearExpiry().",
        },
      ],
      "@typescript-eslint/no-deprecated": "warn",
      "jsdoc/require-jsdoc": [
        "warn",
        { publicOnly: true, require: { FunctionDeclaration: true, ClassDeclaration: true } },
      ],
      "jsdoc/require-param": "off",
      "jsdoc/require-returns": "off",
      "@typescript-eslint/naming-convention": [
        "error",
        {
          selector: ["function", "method"],
          filter: { regex: "(decode|parse|unverified)", match: true },
          custom: { regex: "Unsafe$", match: true },
          format: ["camelCase"],
        },
      ],
    },
  },
  {
    files: ["**/test/**/*.{ts,tsx}", "**/*.test.{ts,tsx}"],
    languageOptions: {
      parserOptions: { project: null },
    },
    rules: {
      "no-restricted-syntax": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-deprecated": "off",
    },
  },
];
