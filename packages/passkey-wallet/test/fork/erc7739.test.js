/**
 * @le-space/passkey-wallet: ERC-7739 signatures, checked by Calibur v1.0.0
 * itself on a Sepolia fork.
 *
 * `signTypedData` and `signMessage` build what Calibur's `isValidSignature`
 * rebuilds on chain — the nested TypedDataSign or PersonalSign hash, in an
 * ABI layout of Calibur's own — so the only proof that counts is Calibur
 * accepting them. Each test sets up a fresh EOA on an anvil fork of Sepolia,
 * delegates it to the Calibur v1.0.0 singleton (EIP-7702) in the same
 * transaction that registers a WebAuthn P-256 key, and asks
 * `isValidSignature` with the plain hash an app would pass.
 *
 * The typed data is shaped like Zama's unified decryption permit
 * (`UserDecryptRequestVerification`, @fhevm/sdk 0.14), because that is what
 * escrow01's passkey account is meant to sign
 * (Le-Space/simple-todo#54, step 4). The call is made the way @fhevm/sdk
 * 0.14.3 makes it before forwarding a permit: an eth_call with
 * `gas: 250_000` (ERC1271_GAS_LIMIT, the relayer/KMS default too).
 *
 * Calibur refuses in two ways: it returns 0xffffffff, or it reverts — with
 * `KeyDoesNotExist()` (0xe57b6304) for a key the account never registered, or
 * with a decoding panic when a TypedDataSign signature over another hash
 * falls through to the PersonalSign path. @fhevm/sdk 0.14.3 counts a revert
 * as a definitive rejection too, so the tests below take either as refused.
 *
 * The passkey is a P-256 key in memory answering like an authenticator: no
 * WebAuthn in Node. Not run in CI — it needs anvil and a Sepolia RPC:
 *
 *   npm run test:wallet-fork
 *   PASSKEY_WALLET_FORK_URL=<sepolia rpc> npm run test:wallet-fork
 */
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { register } from 'node:module';
import { createServer } from 'node:net';
import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  hashMessage,
  hashTypedData,
  http,
} from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

register('../support/resolve-package-self.mjs', import.meta.url);
const wallet = await import('../../src/index.js');
const { createSoftwarePasskey, p256PrecompileInput } =
  await import('../support/software-passkey.mjs');

const FORK_URL = process.env.PASSKEY_WALLET_FORK_URL;
const SDK_GAS_LIMIT = 250_000n;
const MAGIC = '0x1626ba7e';

test.skip(
  !FORK_URL,
  'needs PASSKEY_WALLET_FORK_URL (a Sepolia RPC); `npm run test:wallet-fork` sets a public one'
);
test.describe.configure({ timeout: 180_000 });

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = /** @type {import('node:net').AddressInfo} */ (
        server.address()
      );
      server.close(() => resolve(port));
    });
  });
}

/** @param {{ hardfork?: string }} [options] */
async function startFork({ hardfork } = {}) {
  const port = await freePort();
  const args = ['--fork-url', FORK_URL, '--port', String(port), '--silent'];
  if (hardfork) args.push('--hardfork', hardfork);
  const anvil = spawn('anvil', args, { stdio: 'ignore' });
  const url = `http://127.0.0.1:${port}`;
  const chain = { ...sepolia, rpcUrls: { default: { http: [url] } } };
  const client = createPublicClient({ chain, transport: http(url) });
  for (let i = 0; i < 150; i += 1) {
    try {
      await client.getChainId();
      return { url, chain, client, stop: () => anvil.kill() };
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  anvil.kill();
  throw new Error('anvil did not come up');
}

/**
 * A fresh EOA delegated to Calibur v1.0.0, with the passkey's key registered
 * — both in one type-4 transaction from the EOA to itself.
 * @param {Awaited<ReturnType<typeof startFork>>} fork
 * @param {Awaited<ReturnType<typeof createSoftwarePasskey>>} [given] a new one unless given
 */
async function caliburAccountWithPasskey(fork, given) {
  const passkey = given ?? (await createSoftwarePasskey());
  const eoa = privateKeyToAccount(generatePrivateKey());
  await fork.client.request({
    method: /** @type {any} */ ('anvil_setBalance'),
    params: /** @type {any} */ ([eoa.address, '0x56BC75E2D63100000']),
  });
  const walletClient = createWalletClient({
    account: eoa,
    chain: fork.chain,
    transport: http(fork.url),
  });
  const key = wallet.toWebAuthnP256Key(passkey.descriptor);
  const authorization = await walletClient.signAuthorization({
    contractAddress: wallet.CALIBUR_ADDRESS,
    executor: 'self',
  });
  const hash = await walletClient.sendTransaction({
    authorizationList: [authorization],
    to: eoa.address,
    data: encodeFunctionData({
      abi: wallet.caliburAbi,
      functionName: 'register',
      args: [key],
    }),
    gas: 500_000n,
  });
  const receipt = await fork.client.waitForTransactionReceipt({ hash });
  expect(receipt.status).toBe('success');
  expect(
    await fork.client.readContract({
      address: eoa.address,
      abi: wallet.caliburAbi,
      functionName: 'isRegistered',
      args: [wallet.getKeyHash(key)],
    })
  ).toBe(true);
  const account = await wallet.toCaliburPasskeyAccount({
    client: fork.client,
    address: eoa.address,
    descriptor: passkey.descriptor,
    sign: passkey.sign,
  });
  return { address: eoa.address, account };
}

/** Shaped like Zama's unified decryption permit, @fhevm/sdk 0.14 (V2). @param {`0x${string}`} userAddress */
function zamaPermit(userAddress) {
  return /** @type {const} */ ({
    domain: {
      name: 'Decryption',
      version: '1',
      chainId: 10901,
      verifyingContract: '0x0f6024a97684f7d90ddb0fAAD79cB15F2C888D24',
    },
    types: {
      UserDecryptRequestVerification: [
        { name: 'userAddress', type: 'address' },
        { name: 'publicKey', type: 'bytes' },
        { name: 'allowedContracts', type: 'address[]' },
        { name: 'startTimestamp', type: 'uint256' },
        { name: 'durationSeconds', type: 'uint256' },
        { name: 'extraData', type: 'bytes' },
      ],
    },
    primaryType: 'UserDecryptRequestVerification',
    message: {
      userAddress,
      publicKey: `0x${'ab'.repeat(800)}`,
      allowedContracts: [
        '0x6Ee3Fa9d3aEdaAD189F5DeA9d859605c9D743429',
        '0x4E7B06D78965594eB5EF5414c357ca21E1554491',
      ],
      startTimestamp: 1_791_800_000n,
      durationSeconds: 86_400n,
      extraData: '0x00',
    },
  });
}

/**
 * isValidSignature as @fhevm/sdk 0.14.3 calls it: eth_call, gas capped.
 * @param {any} client @param {`0x${string}`} address @param {`0x${string}`} digest @param {`0x${string}`} signature @param {bigint} [gas]
 */
async function isValidSignature(
  client,
  address,
  digest,
  signature,
  gas = SDK_GAS_LIMIT
) {
  const { data } = await client.call({
    to: address,
    data: encodeFunctionData({
      abi: wallet.caliburAbi,
      functionName: 'isValidSignature',
      args: [digest, signature],
    }),
    gas,
  });
  return data?.slice(0, 10);
}

/**
 * `valid` for the magic value; otherwise `refused`, with what Calibur gave.
 * @param {any} client @param {`0x${string}`} address @param {`0x${string}`} digest @param {`0x${string}`} signature
 */
async function verdict(client, address, digest, signature) {
  try {
    const result = await isValidSignature(client, address, digest, signature);
    return result === MAGIC ? 'valid' : `refused: returned ${result}`;
  } catch (error) {
    const reason = /** @type {any} */ (error).shortMessage ?? String(error);
    return `refused: reverted (${reason.split('\n')[0]})`;
  }
}

/** The least gas an eth_call needs to return the magic value. */
async function leastGas(/** @type {any} */ client, address, digest, signature) {
  let low = 21_000n;
  let high = 2_000_000n;
  while (high - low > 500n) {
    const middle = (low + high) / 2n;
    let ok = false;
    try {
      ok =
        (await isValidSignature(client, address, digest, signature, middle)) ===
        MAGIC;
    } catch {
      ok = false;
    }
    if (ok) high = middle;
    else low = middle;
  }
  return high;
}

/** Whether the P-256 precompile (EIP-7951 / RIP-7212, 0x100) answers. */
async function hasP256Precompile(/** @type {any} */ client) {
  const { data } = await client.call({
    to: '0x0000000000000000000000000000000000000100',
    data: await p256PrecompileInput(),
  });
  return data === `0x${'0'.repeat(63)}1`;
}

test.describe('ERC-7739 on Calibur v1.0.0, Sepolia fork', () => {
  /** @type {Awaited<ReturnType<typeof startFork>>} */
  let fork;
  test.beforeAll(async () => {
    fork = await startFork();
  });
  test.afterAll(() => fork?.stop());

  test('a Zama-shaped permit signed with signTypedData passes isValidSignature within the SDK gas cap', async () => {
    const { address, account } = await caliburAccountWithPasskey(fork);
    const permit = zamaPermit(address);
    const signature = await account.signTypedData(permit);
    const digest = hashTypedData(permit);

    expect(
      await isValidSignature(fork.client, address, digest, signature)
    ).toBe(MAGIC);

    const precompile = await hasP256Precompile(fork.client);
    const gas = await leastGas(fork.client, address, digest, signature);
    console.log(
      `isValidSignature, TypedDataSign: least eth_call gas ${gas} (P-256 precompile ${precompile ? 'present' : 'absent'}; SDK cap ${SDK_GAS_LIMIT})`
    );
    expect(gas).toBeLessThanOrEqual(SDK_GAS_LIMIT);
  });

  test('Calibur refuses it for any other hash, and a signature altered in its contents', async () => {
    const { address, account } = await caliburAccountWithPasskey(fork);
    const permit = zamaPermit(address);
    const signature = await account.signTypedData(permit);
    const later = {
      ...permit,
      message: { ...permit.message, durationSeconds: 86_401n },
    };
    const otherHash = await verdict(
      fork.client,
      address,
      hashTypedData(later),
      signature
    );
    console.log(`another hash: ${otherHash}`);
    expect(otherHash).toMatch(/^refused/);

    // The same signature with another contents hash inside: Calibur rebuilds
    // the caller's hash from it, finds a mismatch, and refuses.
    const {
      keyHash,
      signature: inner,
      hookData,
    } = wallet.decodeUserOperationSignature(signature);
    const { decodeAbiParameters } = await import('viem');
    const [webAuthn, appSeparator, , contentsDescription] = decodeAbiParameters(
      [
        { type: 'bytes' },
        { type: 'bytes32' },
        { type: 'bytes32' },
        { type: 'string' },
      ],
      inner
    );
    const forged = wallet.encodeUserOperationSignature({
      keyHash,
      hookData,
      signature: wallet.encodeTypedDataSignSignature({
        signature: webAuthn,
        appDomainSeparator: appSeparator,
        contentsHash: `0x${'11'.repeat(32)}`,
        contentsDescription,
      }),
    });
    const altered = await verdict(
      fork.client,
      address,
      hashTypedData(permit),
      forged
    );
    console.log(`altered contents hash: ${altered}`);
    expect(altered).toMatch(/^refused/);
  });

  test('another account cannot reuse the signature: the nested hash names the account', async () => {
    // The same passkey registered in two accounts: only the account in the
    // nested hash's domain takes the signature.
    const passkey = await createSoftwarePasskey();
    const first = await caliburAccountWithPasskey(fork, passkey);
    const second = await caliburAccountWithPasskey(fork, passkey);
    expect(
      await verdict(
        fork.client,
        first.address,
        hashTypedData(zamaPermit(first.address)),
        await first.account.signTypedData(zamaPermit(first.address))
      )
    ).toBe('valid');
    const permit = zamaPermit(first.address);
    const signature = await first.account.signTypedData(permit);
    const elsewhere = await verdict(
      fork.client,
      second.address,
      hashTypedData(permit),
      signature
    );
    console.log(`another account, same passkey: ${elsewhere}`);
    expect(elsewhere).toMatch(/^refused/);
    // And a key the account never registered is refused before any hashing.
    const stranger = await caliburAccountWithPasskey(fork);
    const unregistered = await verdict(
      fork.client,
      stranger.address,
      hashTypedData(permit),
      signature
    );
    console.log(`an account without that key: ${unregistered}`);
    expect(unregistered).toMatch(/KeyDoesNotExist|0xe57b6304/);
  });

  test('a personal message signed with signMessage passes as nested PersonalSign', async () => {
    const { address, account } = await caliburAccountWithPasskey(fork);
    const message = 'escrow01 asks this account to sign in';
    const signature = await account.signMessage({ message });
    expect(
      await isValidSignature(
        fork.client,
        address,
        hashMessage(message),
        signature
      )
    ).toBe(MAGIC);
    const otherMessage = await verdict(
      fork.client,
      address,
      hashMessage(`${message}.`),
      signature
    );
    console.log(`another message: ${otherMessage}`);
    expect(otherMessage).toMatch(/^refused/);
  });

  test('the digests agree with the helpers an app or the KMS can recompute', async () => {
    const { address, account } = await caliburAccountWithPasskey(fork);
    const permit = zamaPermit(address);
    const [, name, version, chainId, verifyingContract, salt] =
      await fork.client.readContract({
        address,
        abi: wallet.caliburAbi,
        functionName: 'eip712Domain',
      });
    const digests = wallet.getTypedDataSignDigests({
      typedData: permit,
      accountDomain: { name, version, chainId, verifyingContract, salt },
    });
    expect(digests.digest).toBe(hashTypedData(permit));
    expect(digests.contentsDescription).toBe(
      'UserDecryptRequestVerification(address userAddress,bytes publicKey,address[] allowedContracts,uint256 startTimestamp,uint256 durationSeconds,bytes extraData)'
    );
    expect(
      await fork.client.readContract({
        address,
        abi: wallet.caliburAbi,
        functionName: 'domainSeparator',
      })
    ).toBe(
      wallet.getAccountDomainSeparator({
        name,
        version,
        chainId,
        verifyingContract,
        salt,
      })
    );
    const signature = await account.signTypedData(permit);
    expect(
      await isValidSignature(fork.client, address, digests.digest, signature)
    ).toBe(MAGIC);
  });
});

test.describe('without the P-256 precompile', () => {
  /** @type {Awaited<ReturnType<typeof startFork>>} */
  let fork;
  test.beforeAll(async () => {
    fork = await startFork({ hardfork: 'prague' });
  });
  test.afterAll(() => fork?.stop());

  test('the signature still verifies, and what it costs is written down', async () => {
    const { address, account } = await caliburAccountWithPasskey(fork);
    const permit = zamaPermit(address);
    const signature = await account.signTypedData(permit);
    const digest = hashTypedData(permit);
    const precompile = await hasP256Precompile(fork.client);
    const gas = await leastGas(fork.client, address, digest, signature);
    console.log(
      `isValidSignature, TypedDataSign, hardfork prague: least eth_call gas ${gas} (P-256 precompile ${precompile ? 'present' : 'absent'}; SDK cap ${SDK_GAS_LIMIT})`
    );
    expect(
      await isValidSignature(
        fork.client,
        address,
        digest,
        signature,
        2_000_000n
      )
    ).toBe(MAGIC);
  });
});
