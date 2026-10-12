# @le-space/passkey-wallet

A passkey — the same one that can be your OrbitDB identity through
[`@le-space/orbitdb-identity-provider-webauthn-did`](https://github.com/Le-Space/orbitdb-identity-provider-webauthn-did#readme)
— as the admin key of a [Uniswap Calibur](https://github.com/Uniswap/calibur) v1.0.0
account: an EOA delegated to Calibur with EIP-7702, driven by ERC-4337 user
operations through EntryPoint v0.8. Plus session keys for Zama user
decryption.

```
npm install @le-space/passkey-wallet @le-space/orbitdb-identity-provider-webauthn-did viem
```

Both are peer dependencies: the provider from 0.8.0, which brought
`getP256CredentialDescriptor` and `signP256Challenge`, and `viem` 2.56.5 or
later. The source lives in `packages/passkey-wallet` of
[the provider's repository](https://github.com/Le-Space/orbitdb-identity-provider-webauthn-did).

## How it works

| Piece      | Value                                                                                                                                                                                |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Calibur    | `0x000000009B1D0aF20D8C6d0A44e162d11F9b8f00`, same code on Sepolia and mainnet: `CaliburEntry` from tag v1.0.0 apart from its immutables (the original fork test compared Sepolia's) |
| EntryPoint | v0.8, `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`, the one Calibur accepts by default                                                                                               |
| Passkey    | `Key(KeyType.WebAuthnP256 = 1, abi.encode(uint256 x, uint256 y))`                                                                                                                    |
| Key hash   | `keccak256(abi.encode(uint8 keyType, keccak256(publicKey)))` (KeyLib.hash)                                                                                                           |
| Signature  | `abi.encode(bytes32 keyHash, bytes abi.encode(WebAuthnAuth), bytes hookData)`, the WebAuthn challenge being the user operation hash                                                  |
| Call data  | `executeUserOp.selector ‖ abi.encode(BatchedCall(calls, revertOnFailure))`                                                                                                           |

1. **Setup.** A secp256k1 key is generated in memory. Its address is the
   account. It signs the EIP-7702 authorization to Calibur and authorises the
   account's first batch, which Calibur runs as calls from the account to
   itself — the only way to add a key: `register(passkey)`, then
   `update(keyHash, settings)` with the admin bit (`1 << 200`), then any extra
   calls you pass, such as Zama delegations.
2. **Use.** From then on the passkey signs user operations: one WebAuthn
   prompt per operation, over the EntryPoint v0.8 user operation hash. As an
   admin key it can also manage the account's keys.

### The setup key remains Calibur's root key forever

Calibur treats the account's own address as its root key. The root key cannot
be revoked, and the same private key can sign a new EIP-7702 authorization
that points the address anywhere. **Whoever ever obtains the setup key owns
the account, now and later.** This package generates it in memory, never
writes it anywhere, never returns it, and drops every reference on
`discard()` — but JavaScript cannot wipe memory, and a compromised page
during setup could read it. Discard it as soon as `isActive()` is true, and
fund the account only after that.

## Use

```js
import { getP256CredentialDescriptor } from '@le-space/orbitdb-identity-provider-webauthn-did/standalone';
import {
  createCaliburBundlerClient,
  createCaliburPasskeySetup,
  createZamaSessionKey,
  getDelegateForUserDecryptionCalls,
  toCaliburPasskeyAccount,
} from '@le-space/passkey-wallet';
import { createPublicClient, http } from 'viem';
import { sepolia } from 'viem/chains';

const descriptor = getP256CredentialDescriptor(credential); // null for non-P-256 passkeys
const client = createPublicClient({ chain: sepolia, transport: http(RPC_URL) });

// Your bundler and paymaster; the package has no endpoints or keys of its own.
const bundlerClient = createCaliburBundlerClient({
  client,
  bundler: { url: BUNDLER_URL, headers: { 'x-api-key': BUNDLER_KEY } },
  paymaster: { url: PAYMASTER_URL },
  paymasterContext: { sponsorshipPolicyId: POLICY_ID },
});

// A Zama read key, delegated in the setup batch.
const session = createZamaSessionKey();
const setup = createCaliburPasskeySetup({
  descriptor,
  calls: getDelegateForUserDecryptionCalls({
    chainId: sepolia.id,
    delegate: session.address,
    contractAddresses: [TOKEN],
    expirationDate: BigInt(Math.floor(Date.now() / 1000) + 7 * 86400),
  }),
});

// (a) A sponsored user operation that carries the 7702 authorization …
const hash = await setup.sendUserOperation(bundlerClient);
await bundlerClient.waitForUserOperationReceipt({ hash });
// … or (b) a type-4 transaction from a funded account:
// await setup.sendTransaction(walletClient);

if (await setup.isActive(client)) setup.discard();
// Store setup.address with the credential; the key is gone.

const account = await toCaliburPasskeyAccount({
  client,
  address: setup.address,
  descriptor,
});
await bundlerClient.sendUserOperation({
  account,
  calls: [{ to: RECIPIENT, value: 1n }],
});
```

For Zama's SDK, `session.account` is a viem LocalAccount: wrap it in a wallet
client (`createWalletClient({ account: session.account, … })`) for
`@zama-fhe/sdk/viem`'s `ViemSigner`. To keep it across reloads,
`await session.seal(key)` with a 256-bit AES-GCM `CryptoKey` or 32 raw bytes
you provide (derived from the passkey's PRF output, say), and
`openZamaSessionKey(sealed, key)` later.

To have the passkey account sign Zama's unified decryption permit itself
(`@fhevm/sdk` 0.14), give the SDK the account as the signer, not a wallet
client holding it: the SDK calls `signer.signTypedData({ account, … })` with
the account's address, and a viem wallet client given an address asks its RPC
node to sign. On a Sepolia fork on 2026-10-12, a permit built by
`@fhevm/sdk` 0.14.3's own `createKmsUserDecryptEip712V2` and signed that way
passed the SDK's ERC-1271 precheck (`verifyErc1271UserDecrypt`); whether
Zama's KMS takes it too waits for the unified route on Sepolia
([Le-Space/simple-todo#54](https://github.com/Le-Space/simple-todo/issues/54)).

## API

- `createCaliburPasskeySetup({ descriptor, calls?, keySettings?, implementation? })`
  — a new in-memory EOA with `address`, `key`, `keyHash`, `calls` and:
  `sendUserOperation(bundlerClient, parameters?)` (path a),
  `sendTransaction(walletClient, { executor?, deadline? })` (path b, through
  `execute(SignedBatchedCall, bytes)`), `signAuthorization`, `toSmartAccount`
  (path a's viem account), `isActive(client)`, `discard()`.
- `toCaliburPasskeyAccount({ client, address, descriptor, verificationGasLimit?, nonceKeyManager?, sign? })`
  — the viem smart account for EntryPoint v0.8. `signTypedData` and
  `signMessage` sign for ERC-1271 in the ERC-7739 form Calibur takes from a
  registered key (nested `TypedDataSign` / `PersonalSign`, in the account's
  domain as `eip712Domain()` reports it); an app checks them with
  `isValidSignature(hashTypedData(…) | hashMessage(…), signature)` as for any
  account. `sign` replaces the passkey prompt with another signer of the same
  key.
- `createCaliburBundlerClient({ client, bundler: { url, headers? }, paymaster?, paymasterContext? })`
  — viem bundler and paymaster clients from your endpoints.
- `getCaliburKeyState({ client, address, keyHash })` — delegation target,
  registration and settings of a key.
- `createZamaSessionKey()`, `openZamaSessionKey(sealed, key)` — a session key
  `{ address, account, seal(key) }`.
- `getDelegateForUserDecryptionCalls({ chainId | acl, delegate, contractAddresses, expirationDate, account? })`,
  `getRevokeDelegationForUserDecryptionCalls(…)` — one ACL call per contract,
  refusing what ACL v0.4.0 would revert on where that is knowable off-chain.
- Calibur's encodings: `toWebAuthnP256Key`, `getKeyHash`,
  `encodeKeySettings`, `encodeWebAuthnAuth`, `encodeUserOperationSignature`,
  `encodeExecuteUserOpCallData` (each with a `decode…`),
  `getRegisterKeyCalls`, `getRevokeKeyCall`, `getSignedBatchedCallTypedData`,
  `encodeExecuteSignedBatchedCall`, `encodeWrappedSignature`,
  `getCaliburStubSignature`; for ERC-7739, `getTypedDataSignDigests`,
  `encodeTypedDataSignSignature` (Calibur's ABI layout, not the ERC's packed
  one), `getPersonalSignNestedDigest`, `getAccountDomainSeparator`,
  `encodeTypedDataType`.
- `CALIBUR_ADDRESS`, `ENTRY_POINT_ADDRESS`, `KeyType`, `ROOT_KEY_HASH`,
  `ZAMA_ACL_ADDRESSES`, `ZAMA_WILDCARD_CONTRACT_ADDRESS`,
  `DEFAULT_VERIFICATION_GAS_LIMIT`, `caliburAbi` (Calibur's full ABI),
  `zamaAclAbi`.

Zama's Sepolia ACL, `0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D`, is taken
from `ZamaConfig._getSepoliaConfig()` in `@fhevm/solidity@0.11.1`
(`config/ZamaConfig.sol`); on a Sepolia fork it reported `ACL v0.4.0`.

## Gas

A stub signature cannot run the P-256 check — its challenge cannot match a
hash still being estimated, and webauthn-sol stops there — so estimates made
with it are short. Measured on a Sepolia fork, the `verificationGasLimit` a
user operation needs (±1k):

| Chain                                  | Real passkey signature    | Stub |
| -------------------------------------- | ------------------------- | ---- |
| with the P-256 precompile (Osaka)      | 81k                       | 72k  |
| without it (prague; Solidity fallback) | 370k (±1%, per signature) | 72k  |

`toCaliburPasskeyAccount` therefore sets `verificationGasLimit` to at least
800k (`DEFAULT_VERIFICATION_GAS_LIMIT`). EntryPoint v0.8 charges nothing for
unused verification gas, but the limit counts towards the prefund a paymaster
or deposit must cover; pass a lower `verificationGasLimit` on chains known to
have the precompile.

`isValidSignature` for a `signTypedData` signature (a Zama decryption permit
as @fhevm/sdk 0.14.3 builds it), as the least gas an `eth_call` needs, intrinsic gas included —
measured on a Sepolia fork on 2026-10-12 (`test/fork/erc7739.test.js`):

| Chain                                  | Least `eth_call` gas |
| -------------------------------------- | -------------------- |
| with the P-256 precompile (Osaka)      | 89.6k                |
| without it (prague; Solidity fallback) | 372k–383k            |

@fhevm/sdk 0.14.3 checks such a signature with an `eth_call` capped at 250k
(`ERC1271_GAS_LIMIT`, which its comments give as the relayer and KMS default
too), so a passkey permit passes there only where the precompile exists, as on
Sepolia.

## Tests

This code was restored from the only copy left of it, a packed tarball
([#77](https://github.com/Le-Space/orbitdb-identity-provider-webauthn-did/pull/77)).
Its tests were not in that tarball, and neither were the suites they made up:
the encodings checked against Calibur's own libraries, and setup, user
operations and Zama delegation on a Sepolia fork, which is where the gas figures
below and the ACL version above come from. Of those, only ERC-7739 signing is
checked against Calibur again (below); setup, user operations and Zama
delegation are not.

What runs in the repository's node suite (`pnpm run test:node` at the root):

- `tests/passkey-wallet-session-key.test.js`: a Zama session key sealed and
  opened, the format pinned by an envelope the vendored build sealed, and
  refusals of another sealing key, an altered ciphertext, an envelope naming
  another address and anything that is not an envelope.
- `tests/passkey-wallet-erc7739.test.js`: the ERC-7739 digests recomputed
  through viem's own EIP-712 code with the nesting struct written out, and the
  account having its key sign exactly that digest as the WebAuthn challenge.

Calibur itself checks the ERC-7739 signatures in `test/fork/erc7739.test.js`
(`pnpm run test:wallet-fork` at the root; needs Foundry's anvil and a Sepolia
RPC, `PASSKEY_WALLET_FORK_URL`, a public one by default, so CI does not run
it): on a fork, a fresh EOA is delegated to Calibur v1.0.0 with a P-256 key
registered, and `isValidSignature` takes a Zama permit built as @fhevm/sdk
0.14.3 builds it (`test/support/zama-permit.mjs`) and a personal message
signed through `signTypedData` and `signMessage`, refuses another hash,
an altered contents hash, another account holding the same key, and an
account without the key — and the gas above is measured there. The key is a
P-256 key in memory that answers like an authenticator
(`test/support/software-passkey.mjs`).

## Releasing

A tag `passkey-wallet-vX.Y.Z` on a commit whose `package.json` here says
`X.Y.Z` makes the repository's `release.yml` run the full test suite and
publish this directory to npm with provenance. Trusted publishing needs an
entry for this package on npmjs.com (repository
`Le-Space/orbitdb-identity-provider-webauthn-did`, workflow `release.yml`);
until it exists, the workflow falls back to its `NPM_TOKEN`, as 0.1.0 did.
