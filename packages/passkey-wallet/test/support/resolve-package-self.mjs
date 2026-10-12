/**
 * A module resolve hook for tests that import packages/passkey-wallet: the
 * wallet names this repository's package as a peer dependency
 * (`@le-space/orbitdb-identity-provider-webauthn-did/standalone`), which an
 * install of this repository does not link to itself. Registered by the test
 * that needs it (`register(new URL(...), import.meta.url)`); nothing is
 * written to node_modules.
 */
const PACKAGE = '@le-space/orbitdb-identity-provider-webauthn-did';
const ROOT = new URL('../../../../', import.meta.url);
const SUBPATHS = {
  [PACKAGE]: 'src/index.js',
  [`${PACKAGE}/standalone`]: 'src/standalone/index.js',
  [`${PACKAGE}/keystore`]: 'src/keystore/index.js',
};

export async function resolve(specifier, context, nextResolve) {
  const local = SUBPATHS[specifier];
  if (local) return { url: new URL(local, ROOT).href, shortCircuit: true };
  return nextResolve(specifier, context);
}
