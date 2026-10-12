/**
 * @le-space/passkey-wallet: the ERC-7739 encodings, without a chain.
 *
 * Calibur v1.0.0 accepting these signatures is shown on a Sepolia fork
 * (packages/passkey-wallet/test/fork/erc7739.test.js, `npm run test:wallet-fork`). Here,
 * in CI, each hash is recomputed a second way — through viem's own EIP-712
 * code with the nesting struct written out — and the account is shown to
 * have its key sign exactly that hash as the WebAuthn challenge.
 */
import { test, expect } from '@playwright/test';
import { register } from 'node:module';
import {
  createPublicClient,
  custom,
  decodeAbiParameters,
  encodeFunctionResult,
  hashMessage,
  hashTypedData,
  hexToBytes,
  toPrefixedMessage,
} from 'viem';

register(
  '../packages/passkey-wallet/test/support/resolve-package-self.mjs',
  import.meta.url
);
const wallet = await import('../packages/passkey-wallet/src/index.js');
const { createSoftwarePasskey, verifiesWithPasskey } =
  await import('../packages/passkey-wallet/test/support/software-passkey.mjs');
const { zamaPermit } =
  await import('../packages/passkey-wallet/test/support/zama-permit.mjs');

const ACCOUNT = '0x00000000000000000000000000000000000ca11b';
const ACCOUNT_DOMAIN = Object.freeze({
  name: 'Calibur',
  version: '1.0.0',
  chainId: 11155111n,
  verifyingContract: ACCOUNT,
  salt: '0x000000000000000000000000000000009b1d0af20d8c6d0a44e162d11f9b8f00',
});

const PERMIT = zamaPermit(ACCOUNT);

/**
 * A client that answers what signing asks the chain: the account's code (an
 * EIP-7702 delegation to Calibur, which tells viem not to wrap the signature
 * for an undeployed account) and its `eip712Domain()`.
 */
function domainClient() {
  return createPublicClient({
    transport: custom({
      async request({ method, params }) {
        if (method === 'eth_chainId') return '0xaa36a7';
        if (method === 'eth_getCode')
          return `0xef0100${wallet.CALIBUR_ADDRESS.slice(2).toLowerCase()}`;
        if (method === 'eth_call' && params[0].to.toLowerCase() === ACCOUNT) {
          return encodeFunctionResult({
            abi: wallet.caliburAbi,
            functionName: 'eip712Domain',
            result: [
              '0x0f',
              ACCOUNT_DOMAIN.name,
              ACCOUNT_DOMAIN.version,
              ACCOUNT_DOMAIN.chainId,
              ACCOUNT_DOMAIN.verifyingContract,
              ACCOUNT_DOMAIN.salt,
              [],
            ],
          });
        }
        throw new Error(`unexpected ${method}`);
      },
    }),
  });
}

/**
 * What the software passkey signed: the challenge from clientDataJSON, and
 * whether the signature verifies against the key.
 */
async function readAssertion(/** @type {`0x${string}`} */ webAuthn, passkey) {
  const auth = wallet.decodeWebAuthnAuth(webAuthn);
  const { challenge } = JSON.parse(auth.clientDataJSON);
  const verifies = await verifiesWithPasskey(passkey.publicKey, {
    ...auth,
    authenticatorData: hexToBytes(auth.authenticatorData),
  });
  return {
    challenge: `0x${Buffer.from(challenge, 'base64url').toString('hex')}`,
    verifies,
  };
}

test('encodeTypedDataType puts the primary type first and the rest in name order', () => {
  // EIP-712's own example, with a type that sorts before the primary one.
  const types = {
    Mail: [
      { name: 'from', type: 'Person' },
      { name: 'to', type: 'Person[]' },
      { name: 'attachment', type: 'Attachment' },
    ],
    Person: [
      { name: 'name', type: 'string' },
      { name: 'wallet', type: 'address' },
    ],
    Attachment: [{ name: 'hash', type: 'bytes32' }],
  };
  expect(wallet.encodeTypedDataType({ types, primaryType: 'Mail' })).toBe(
    'Mail(Person from,Person[] to,Attachment attachment)Attachment(bytes32 hash)Person(string name,address wallet)'
  );
  expect(() =>
    wallet.encodeTypedDataType({ types, primaryType: 'Missing' })
  ).toThrow(TypeError);
});

test('the TypedDataSign digests match viem, with the nesting struct written out', () => {
  const digests = wallet.getTypedDataSignDigests({
    typedData: PERMIT,
    accountDomain: ACCOUNT_DOMAIN,
  });
  expect(digests.digest).toBe(hashTypedData(PERMIT));
  expect(digests.contentsDescription).toBe(
    'UserDecryptRequestVerification(address userAddress,bytes publicKey,address[] allowedContracts,uint256 startTimestamp,uint256 durationSeconds,bytes extraData)'
  );
  // For contents without struct members, ERC-7739's type string and EIP-712's
  // encodeType of TypedDataSign coincide, so viem computes the same hash.
  const nestedByViem = hashTypedData({
    domain: PERMIT.domain,
    types: {
      ...PERMIT.types,
      TypedDataSign: [
        { name: 'contents', type: 'UserDecryptRequestVerification' },
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
        { name: 'salt', type: 'bytes32' },
      ],
    },
    primaryType: 'TypedDataSign',
    message: { contents: PERMIT.message, ...ACCOUNT_DOMAIN },
  });
  expect(digests.nestedDigest).toBe(nestedByViem);
  // The account's chain, not the app's, goes into the nesting.
  const otherChain = wallet.getTypedDataSignDigests({
    typedData: PERMIT,
    accountDomain: { ...ACCOUNT_DOMAIN, chainId: 1n },
  });
  expect(otherChain.digest).toBe(digests.digest);
  expect(otherChain.nestedDigest).not.toBe(digests.nestedDigest);
});

test('the PersonalSign digest matches viem, as EIP-712 typed data in the account domain', () => {
  const message = 'escrow01 asks this account to sign in';
  expect(
    wallet.getPersonalSignNestedDigest({
      hash: hashMessage(message),
      accountDomain: ACCOUNT_DOMAIN,
    })
  ).toBe(
    hashTypedData({
      domain: ACCOUNT_DOMAIN,
      types: { PersonalSign: [{ name: 'prefixed', type: 'bytes' }] },
      primaryType: 'PersonalSign',
      message: { prefixed: toPrefixedMessage(message) },
    })
  );
});

test('ERC-7739 refuses what Calibur would refuse to rebuild', () => {
  const sign = (/** @type {any} */ typedData) =>
    wallet.getTypedDataSignDigests({
      typedData,
      accountDomain: ACCOUNT_DOMAIN,
    });
  expect(() => sign({ ...PERMIT, primaryType: 'EIP712Domain' })).toThrow(
    TypeError
  );
  expect(() => sign({ ...PERMIT, primaryType: 'Not Allowed' })).toThrow(
    RangeError
  );
  expect(() => sign({ ...PERMIT, primaryType: 'Absent' })).toThrow(TypeError);
  expect(() =>
    wallet.encodeTypedDataSignSignature({
      signature: '0x00',
      appDomainSeparator: `0x${'00'.repeat(32)}`,
      contentsHash: `0x${'00'.repeat(32)}`,
      contentsDescription: '',
    })
  ).toThrow(TypeError);
});

test('signTypedData has the key sign the nested digest, in Calibur’s ABI layout', async () => {
  const passkey = await createSoftwarePasskey();
  const account = await wallet.toCaliburPasskeyAccount({
    client: domainClient(),
    address: ACCOUNT,
    descriptor: passkey.descriptor,
    sign: passkey.sign,
  });
  const signature = await account.signTypedData(PERMIT);

  const {
    keyHash,
    signature: inner,
    hookData,
  } = wallet.decodeUserOperationSignature(signature);
  expect(keyHash).toBe(
    wallet.getKeyHash(wallet.toWebAuthnP256Key(passkey.descriptor))
  );
  expect(hookData).toBe('0x');
  const [webAuthn, appSeparator, contentsHash, contentsDescription] =
    decodeAbiParameters(
      [
        { type: 'bytes' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'string' },
      ],
      inner
    );
  const digests = wallet.getTypedDataSignDigests({
    typedData: PERMIT,
    accountDomain: ACCOUNT_DOMAIN,
  });
  expect(appSeparator).toBe(digests.appDomainSeparator);
  expect(contentsHash).toBe(digests.contentsHash);
  expect(contentsDescription).toBe(digests.contentsDescription);
  expect(await readAssertion(webAuthn, passkey)).toEqual({
    challenge: digests.nestedDigest,
    verifies: true,
  });
});

test('signMessage has the key sign the nested PersonalSign digest, bare inside the key wrapping', async () => {
  const passkey = await createSoftwarePasskey();
  const account = await wallet.toCaliburPasskeyAccount({
    client: domainClient(),
    address: ACCOUNT,
    descriptor: passkey.descriptor,
    sign: passkey.sign,
  });
  const message = 'escrow01 asks this account to sign in';
  const { signature: webAuthn } = wallet.decodeUserOperationSignature(
    await account.signMessage({ message })
  );
  expect(await readAssertion(webAuthn, passkey)).toEqual({
    challenge: wallet.getPersonalSignNestedDigest({
      hash: hashMessage(message),
      accountDomain: ACCOUNT_DOMAIN,
    }),
    verifies: true,
  });
});

test('a signer that is not a function is refused before an account is built', async () => {
  const passkey = await createSoftwarePasskey();
  await expect(
    wallet.toCaliburPasskeyAccount({
      client: domainClient(),
      address: ACCOUNT,
      descriptor: passkey.descriptor,
      sign: /** @type {any} */ ('passkey'),
    })
  ).rejects.toThrow(TypeError);
});
