/**
 * Documentation for node-oidc-kit, published to https://docs.wilsoon.dev.
 *
 * The push token is read from the DOCS_SYNC_SECRET environment variable and is
 * deliberately not stored here - this file is committed, and that is a secret.
 */
export default {
  // Permanent. It is the project's URL on the site and cannot be changed later.
  project: 'node-oidc-kit',

  // Free to change at any time.
  title: 'Wilsoon Node OIDC Kit',

  // One sentence, shown under the title on the site's home page.
  description: 'A framework-agnostic OpenID Connect relying party for TypeScript, with verified sessions, PKCE and live revocation built in from the start.',

  endpoint: 'https://docs.wilsoon.dev',
  repository: 'https://github.com/Wilsoon7721/node-oidc-kit',

  // Where the chapters live, relative to this file.
  dir: '.',
};
