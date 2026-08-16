/**
 * A software WebAuthn authenticator for Node-context tests.
 *
 * Models the parts that matter for identity stability:
 * - a real P-256 keypair, so signatures actually verify
 * - spec-shaped attestationObject (WebAuthn L2 §6.5.2)
 * - a signature counter that increments on every assertion
 * - randomised ECDSA signatures
 *
 * The last two are why a WebAuthn assertion can never be content-addressed
 * reproducibly — see issue #18.
 */
import cborModule from 'cbor-web';

const cbor = cborModule.default ?? cborModule;
const { encode } = cbor;

function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base64urlToBytes(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function bytesToBase64url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/**
 * Create a mock authenticator backed by a real P-256 keypair.
 * @param {Object} [options]
 * @param {string} [options.rpId] - Relying party id.
 * @param {boolean} [options.exposeGetPublicKey] - Whether attestation responses
 *   expose getPublicKey(). Set false to force attestation-object parsing.
 * @returns {Promise<Object>} Authenticator handle with a `navigator` shim.
 */
export async function createMockAuthenticator({
  rpId = 'localhost',
  exposeGetPublicKey = true,
  credentialIdLength = 32,
  // Real authenticators derive PRF from a per-credential secret, so the output
  // is stable for a given input and identical on any device holding the same
  // synced passkey. `prfSecret` models exactly that: pass the same value to two
  // authenticators to represent one passkey on two devices. Set supportsPrf
  // false to model an authenticator without the extension.
  supportsPrf = true,
  prfSecret = null,
} = {}) {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const jwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
  const x = base64urlToBytes(jwk.x);
  const y = base64urlToBytes(jwk.y);
  const spki = new Uint8Array(
    await crypto.subtle.exportKey('spki', keypair.publicKey)
  );

  // One resident credential per (rpId, user.id), keyed by the handle — the rule
  // that makes a name-derived handle destructive (#45). A registration whose
  // handle is already present replaces what was there; a new handle adds to it.
  const residentByHandle = new Map();
  let activeCredentialId = crypto.getRandomValues(
    new Uint8Array(credentialIdLength)
  );
  const rpIdHash = await sha256(new TextEncoder().encode(rpId));

  const state = {
    signCount: 0,
    assertions: 0,
    creations: 0,
    prfEvals: 0,
    /** Every `user` dictionary passed to create(), in order. */
    createdUsers: [],
  };

  // Per-credential secret the PRF output is derived from.
  const prfKey = prfSecret ?? crypto.getRandomValues(new Uint8Array(32));

  const evaluatePrf = async (input) => {
    state.prfEvals += 1;
    const material = concatBytes([
      prfKey,
      new TextEncoder().encode('prf'),
      new Uint8Array(input),
    ]);
    return sha256(material);
  };

  const coseKey = new Uint8Array(
    encode(
      new Map([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, Buffer.from(x)],
        [-3, Buffer.from(y)],
      ])
    )
  );

  const buildAuthData = ({
    includeAttestedCredential,
    credentialId = activeCredentialId,
  }) => {
    const flagByte = includeAttestedCredential
      ? 0x01 | 0x04 | 0x40 // UP | UV | AT
      : 0x01 | 0x04; // UP | UV
    const signCountBytes = new Uint8Array(4);
    new DataView(signCountBytes.buffer).setUint32(0, state.signCount);

    if (!includeAttestedCredential) {
      return concatBytes([
        rpIdHash,
        new Uint8Array([flagByte]),
        signCountBytes,
      ]);
    }

    const credIdLen = new Uint8Array(2);
    new DataView(credIdLen.buffer).setUint16(0, credentialId.length);

    return concatBytes([
      rpIdHash,
      new Uint8Array([flagByte]),
      signCountBytes,
      new Uint8Array(16).fill(0), // aaguid
      credIdLen,
      credentialId,
      coseKey,
    ]);
  };

  const buildClientDataJSON = (type, challenge) =>
    new TextEncoder().encode(
      JSON.stringify({
        type,
        challenge: bytesToBase64url(new Uint8Array(challenge)),
        origin: `https://${rpId}`,
        crossOrigin: false,
      })
    );

  const navigatorShim = {
    credentials: {
      async create(options) {
        state.creations += 1;
        state.signCount += 1;

        const user = options?.publicKey?.user ?? {};
        state.createdUsers.push(user);

        const handleKey = bytesToBase64url(new Uint8Array(user.id ?? []));
        const credentialId = crypto.getRandomValues(
          new Uint8Array(credentialIdLength)
        );
        // set(), not a guard: a repeat handle silently drops the credential
        // that was stored under it, exactly as an authenticator does.
        residentByHandle.set(handleKey, credentialId);
        activeCredentialId = credentialId;

        const challenge = options?.publicKey?.challenge ?? new Uint8Array(32);
        const authData = buildAuthData({
          includeAttestedCredential: true,
          credentialId,
        });
        const attestationObject = new Uint8Array(
          encode(
            new Map([
              ['fmt', 'none'],
              ['attStmt', new Map()],
              ['authData', Buffer.from(authData)],
            ])
          )
        );

        const response = {
          attestationObject: attestationObject.buffer.slice(
            attestationObject.byteOffset,
            attestationObject.byteOffset + attestationObject.byteLength
          ),
          clientDataJSON: buildClientDataJSON('webauthn.create', challenge)
            .buffer,
        };

        if (exposeGetPublicKey) {
          response.getPublicKey = () =>
            spki.buffer.slice(
              spki.byteOffset,
              spki.byteOffset + spki.byteLength
            );
        }

        return {
          id: bytesToBase64url(credentialId),
          rawId: credentialId.buffer.slice(
            credentialId.byteOffset,
            credentialId.byteOffset + credentialId.byteLength
          ),
          type: 'public-key',
          response,
          getClientExtensionResults: () => ({}),
        };
      },

      async get(options) {
        state.assertions += 1;
        state.signCount += 1; // a real authenticator always increments

        const challenge = options?.publicKey?.challenge ?? new Uint8Array(32);
        const authData = buildAuthData({ includeAttestedCredential: false });
        const clientDataJSON = buildClientDataJSON('webauthn.get', challenge);
        const clientDataHash = await sha256(clientDataJSON);

        // PRF: deterministic in the input, so the same passkey always yields
        // the same output. Absent entirely when the authenticator has no PRF.
        const prfEval = options?.publicKey?.extensions?.prf?.eval;
        const extensionResults = {};
        if (supportsPrf && prfEval?.first) {
          extensionResults.prf = {
            results: { first: (await evaluatePrf(prfEval.first)).buffer },
          };
        }

        // ECDSA signatures are randomised: identical input, different output
        const signature = new Uint8Array(
          await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            keypair.privateKey,
            concatBytes([authData, clientDataHash])
          )
        );

        return {
          id: bytesToBase64url(activeCredentialId),
          rawId: activeCredentialId.buffer.slice(
            activeCredentialId.byteOffset,
            activeCredentialId.byteOffset + activeCredentialId.byteLength
          ),
          type: 'public-key',
          response: {
            authenticatorData: authData.buffer.slice(
              authData.byteOffset,
              authData.byteOffset + authData.byteLength
            ),
            clientDataJSON: clientDataJSON.buffer,
            signature: signature.buffer,
            userHandle: null,
          },
          getClientExtensionResults: () => extensionResults,
        };
      },
    },
  };

  return {
    navigator: navigatorShim,
    publicKey: { algorithm: -7, x, y, keyType: 2, curve: 1 },
    /** The credential an assertion would use: the most recently created one. */
    get credentialId() {
      return activeCredentialId;
    },
    /** What the authenticator still holds, one entry per distinct handle. */
    residentCredentials: () =>
      [...residentByHandle.entries()].map(([handle, id]) => ({
        handle,
        credentialId: bytesToBase64url(id),
      })),
    state,
  };
}

/**
 * Install the mock on globalThis and return a restore function.
 * @param {Object} authenticator - Result of createMockAuthenticator().
 * @returns {Function} Restores the previous globals.
 */
export function installMockAuthenticator(authenticator) {
  const previousNavigator = globalThis.navigator;
  const previousWindow = globalThis.window;
  const previousLocalStorage = globalThis.localStorage;

  // Browser storage survives a page reload, so this shim has to outlive the
  // simulated reloads within one test rather than being recreated per load.
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear(),
    key: (i) => [...store.keys()][i] ?? null,
    get length() {
      return store.size;
    },
  };

  Object.defineProperty(globalThis, 'navigator', {
    value: authenticator.navigator,
    configurable: true,
    writable: true,
  });

  // isSupported() reads window.PublicKeyCredential, so the shim has to live
  // on window, not just globalThis.
  class MockPublicKeyCredential {
    static isUserVerifyingPlatformAuthenticatorAvailable() {
      return Promise.resolve(true);
    }
  }

  globalThis.PublicKeyCredential = MockPublicKeyCredential;
  globalThis.window = {
    ...(previousWindow ?? {}),
    location: { hostname: 'localhost', origin: 'https://localhost' },
    navigator: authenticator.navigator,
    PublicKeyCredential: MockPublicKeyCredential,
  };

  return () => {
    Object.defineProperty(globalThis, 'navigator', {
      value: previousNavigator,
      configurable: true,
      writable: true,
    });
    globalThis.window = previousWindow;
    globalThis.localStorage = previousLocalStorage;
    delete globalThis.PublicKeyCredential;
  };
}
