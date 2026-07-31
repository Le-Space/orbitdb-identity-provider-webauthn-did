/**
 * The three demos, in one place.
 *
 * Their pages used to be 270-line copies of each other differing in about ten
 * strings, and the switcher nav was hand-maintained in each — so every demo
 * listed a different subset of its siblings. Both now derive from this list:
 * add a fourth entry and every nav picks it up.
 *
 * `id` is the directory name, which is also the path segment GitHub Pages
 * publishes it under.
 */
export const demos = [
  {
    id: 'webauthn-todo-demo',
    nav: 'WebAuthn DID',
    company: 'OrbitDB WebAuthn Demo',
    title: 'OrbitDB WebAuthn TODO Demo',
    description:
      'Local-first peer-to-peer todo example with a WebAuthn passkey identity — data stored in the browser via OrbitDB.',
    heading: 'OrbitDB WebAuthn Demo',
    highlight: 'WebAuthn passkey identity (biometrics, Ledger, YubiKey)',
    techLabel: 'WebAuthn',
    footerNote:
      'local-first peer-to-peer with WebAuthn identity — data in browser IndexedDB via OrbitDB',
  },
  {
    id: 'ed25519-encrypted-keystore-demo',
    nav: 'Encrypted keystore',
    // This demo used to carry the WebAuthn DID demo's title verbatim — same
    // <title>, same header, same heading — so the two were indistinguishable in
    // a browser tab, in search results and in the switcher.
    company: 'OrbitDB Encrypted Keystore Demo',
    title: 'OrbitDB Ed25519 Encrypted Keystore Demo',
    description:
      'Local-first peer-to-peer todo example with an Ed25519 OrbitDB keystore encrypted at rest and unlocked by WebAuthn (PRF, largeBlob or hmac-secret).',
    heading: 'OrbitDB Encrypted Keystore Demo',
    highlight: 'an Ed25519 keystore, encrypted at rest and unlocked by WebAuthn',
    techLabel: 'WebAuthn + keystore',
    footerNote:
      'local-first peer-to-peer with a WebAuthn-encrypted Ed25519 keystore — data in browser IndexedDB via OrbitDB',
  },
  {
    id: 'webauthn-varsig-demo',
    nav: 'Varsig',
    company: 'OrbitDB WebAuthn Varsig Demo',
    title: 'OrbitDB WebAuthn Varsig TODO Demo',
    description:
      'Local-first peer-to-peer todo example with WebAuthn varsig identity and no OrbitDB keystore — every entry is signed by the authenticator.',
    heading: 'OrbitDB WebAuthn Varsig Demo',
    highlight: 'WebAuthn varsig passkey support (no OrbitDB keystore)',
    techLabel: 'WebAuthn Varsig',
    footerNote:
      'local-first peer-to-peer with WebAuthn varsig support — data in browser IndexedDB via OrbitDB',
  },
];

/** The entry for a demo id, for use as `<DemoShell demo={demoById(...)}>`. */
export function demoById(id) {
  const found = demos.find((d) => d.id === id);
  if (!found) throw new Error(`unknown demo id: ${id}`);
  return found;
}
