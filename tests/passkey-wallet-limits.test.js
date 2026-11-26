/**
 * @le-space/passkey-wallet: what the passkey refuses to sign.
 *
 * The bundler and the RPC are the app's, and either may be hostile or merely
 * wrong. Three things they used to decide on the account's behalf, each now
 * checked before the passkey is prompted:
 *
 * - the ERC-7739 domain an ERC-1271 signature is bound to (chain, account,
 *   implementation), read from `eip712Domain()` over the RPC;
 * - the gas a user operation carries, which a bundler is paid for whether it
 *   was needed or not;
 * - the nonce key, which decides whether a retry replaces an operation or
 *   runs beside it.
 *
 * Every refusal is asserted twice: that it throws the named error, and that
 * the passkey was never asked — a refusal after the prompt would still have
 * produced the signature.
 */
import { test, expect } from '@playwright/test';
import { register } from 'node:module';
import {
  createPublicClient,
  custom,
  decodeFunctionData,
  encodeFunctionResult,
} from 'viem';
import { entryPoint08Abi } from 'viem/account-abstraction';
import { sepolia } from 'viem/chains';

register(
  '../packages/passkey-wallet/test/support/resolve-package-self.mjs',
  import.meta.url
);
const wallet = await import('../packages/passkey-wallet/src/index.js');
const { createSoftwarePasskey } =
  await import('../packages/passkey-wallet/test/support/software-passkey.mjs');

const ACCOUNT = '0x00000000000000000000000000000000000ca11b';
const OTHER_ACCOUNT = '0x000000000000000000000000000000000000b0b0';
const SEPOLIA = 11155111n;
const SALT = `0x${'00'.repeat(12)}${wallet.CALIBUR_ADDRESS.slice(2).toLowerCase()}`;

/**
 * A client whose `eip712Domain()` answer the test chooses, and which answers
 * EntryPoint.getNonce as the EntryPoint would — key << 64 | sequence 0 — while
 * recording the keys it was asked about.
 */
function rpc({ domain = {}, chain = sepolia } = {}) {
  const nonceKeys = [];
  const client = createPublicClient({
    chain,
    transport: custom({
      async request({ method, params }) {
        if (method === 'eth_chainId') return '0xaa36a7';
        if (method === 'eth_getCode')
          return `0xef0100${wallet.CALIBUR_ADDRESS.slice(2).toLowerCase()}`;
        if (method === 'eth_call') {
          const { to, data, input } = params[0];
          if (to.toLowerCase() === ACCOUNT) {
            return encodeFunctionResult({
              abi: wallet.caliburAbi,
              functionName: 'eip712Domain',
              result: [
                '0x0f',
                domain.name ?? 'Calibur',
                domain.version ?? wallet.CALIBUR_VERSION,
                domain.chainId ?? SEPOLIA,
                domain.verifyingContract ?? ACCOUNT,
                domain.salt ?? SALT,
                [],
              ],
            });
          }
          const { args } = decodeFunctionData({
            abi: entryPoint08Abi,
            data: data ?? input,
          });
          nonceKeys.push(args[1]);
          return encodeFunctionResult({
            abi: entryPoint08Abi,
            functionName: 'getNonce',
            result: args[1] << 64n,
          });
        }
        throw new Error(`unexpected ${method}`);
      },
    }),
  });
  return { client, nonceKeys };
}

/** The software passkey, counting how often it was asked to sign. */
async function countingPasskey() {
  const passkey = await createSoftwarePasskey();
  const prompts = { count: 0 };
  return {
    descriptor: passkey.descriptor,
    prompts,
    sign: async (challenge) => {
      prompts.count += 1;
      return passkey.sign(challenge);
    },
  };
}

/** 0.01 ETH: what the tests' apps allow one user operation to cost. */
const COST_LIMIT = 10_000_000_000_000_000n;

async function accountWith({ domain, chain, ...options } = {}) {
  const { client, nonceKeys } = rpc({ domain, chain });
  const passkey = await countingPasskey();
  const account = await wallet.toCaliburPasskeyAccount({
    client,
    address: ACCOUNT,
    descriptor: passkey.descriptor,
    sign: passkey.sign,
    maxUserOperationCost: COST_LIMIT,
    ...options,
  });
  return { account, prompts: passkey.prompts, nonceKeys };
}

/** A user operation within every default ceiling. */
function userOperation(overrides = {}) {
  return {
    sender: ACCOUNT,
    nonce: 0n,
    callData: '0x',
    callGasLimit: 100_000n,
    verificationGasLimit: 800_000n,
    preVerificationGas: 60_000n,
    maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    signature: '0x',
    ...overrides,
  };
}

test.describe('ERC-7739 domain (D1)', () => {
  test('signs for the account it is, on the chain it is', async () => {
    const { account, prompts } = await accountWith();
    await account.signMessage({ message: 'Sign in to example.app' });
    expect(prompts.count).toBe(1);
  });

  const mismatches = [
    ['another chain', { chainId: 1n }, 'chainId'],
    [
      'another account',
      { verifyingContract: OTHER_ACCOUNT },
      'verifyingContract',
    ],
    [
      'another implementation',
      { salt: `0x${'00'.repeat(12)}${'ab'.repeat(20)}` },
      'salt implementation',
    ],
    ['another version', { version: '2.0.0' }, 'version'],
    ['another name', { name: 'NotCalibur' }, 'name'],
  ];

  for (const [what, domain, field] of mismatches) {
    test(`refuses a domain that names ${what}, before the passkey is asked`, async () => {
      const { account, prompts } = await accountWith({ domain });
      const typedData = {
        domain: { name: 'App', version: '1', chainId: 11155111 },
        types: { Hello: [{ name: 'who', type: 'string' }] },
        primaryType: 'Hello',
        message: { who: 'anna' },
      };
      for (const attempt of [
        () => account.signMessage({ message: 'hello' }),
        () => account.signTypedData(typedData),
      ]) {
        const error = await attempt().catch((e) => e);
        expect(error).toBeInstanceOf(wallet.AccountDomainMismatchError);
        expect(error.field).toBe(field);
      }
      expect(prompts.count).toBe(0);
    });
  }

  test('pins the chain at construction: an explicit chainId wins over the client', async () => {
    // The client says Sepolia and so does the domain, but the app said chain 1:
    // the domain no longer matches what the app asked for, so nothing is signed.
    const { account, prompts } = await accountWith({ chainId: 1 });
    const error = await account
      .signMessage({ message: 'hello' })
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.AccountDomainMismatchError);
    expect(error.field).toBe('chainId');
    expect(prompts.count).toBe(0);
  });
});

test.describe('gas and cost limits (D2)', () => {
  test('signs a user operation within the default ceilings', async () => {
    const { account, prompts } = await accountWith();
    await account.signUserOperation(userOperation());
    expect(prompts.count).toBe(1);
  });

  test('refuses an inflated preVerificationGas, before the passkey is asked', async () => {
    // The audit's reproduction: a bundler answering fifty million.
    const { account, prompts } = await accountWith();
    const error = await account
      .signUserOperation(userOperation({ preVerificationGas: 50_000_000n }))
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
    expect(error.field).toBe('preVerificationGas');
    expect(prompts.count).toBe(0);
  });

  for (const field of [
    'callGasLimit',
    'verificationGasLimit',
    'paymasterVerificationGasLimit',
    'paymasterPostOpGasLimit',
  ]) {
    test(`refuses ${field} past its ceiling`, async () => {
      const { account, prompts } = await accountWith();
      const ceiling = wallet.DEFAULT_USER_OPERATION_GAS_CEILINGS[field];
      const error = await account
        .signUserOperation(userOperation({ [field]: ceiling + 1n }))
        .catch((e) => e);
      expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
      expect(error.field).toBe(field);
      expect(prompts.count).toBe(0);
    });
  }

  test('an app may raise a ceiling its chain needs', async () => {
    const { account, prompts } = await accountWith({
      gasCeilings: { preVerificationGas: 5_000_000n },
    });
    await account.signUserOperation(
      userOperation({ preVerificationGas: 3_000_000n })
    );
    expect(prompts.count).toBe(1);
  });

  test('refuses a priority fee above the fee cap', async () => {
    const { account, prompts } = await accountWith();
    const error = await account
      .signUserOperation(
        userOperation({ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n })
      )
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
    expect(error.field).toBe('maxPriorityFeePerGas');
    expect(prompts.count).toBe(0);
  });

  test('an account cannot be made without maxUserOperationCost', async () => {
    // The gas ceilings count gas; the fee per gas comes from the RPC or the
    // bundler. Without a limit in wei, they decide what an operation costs.
    for (const maxUserOperationCost of [undefined, 10, -1n]) {
      await expect(accountWith({ maxUserOperationCost })).rejects.toThrow(
        /needs maxUserOperationCost/
      );
    }
  });

  test('refuses a fee that would drain the account, before the passkey is asked', async () => {
    // The review's reproduction: maxFeePerGas = maxPriorityFeePerGas = 1e24 wei,
    // within every gas ceiling.
    const { account, prompts } = await accountWith();
    const error = await account
      .signUserOperation(
        userOperation({
          maxFeePerGas: 10n ** 24n,
          maxPriorityFeePerGas: 10n ** 24n,
        })
      )
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
    expect(error.field).toBe('maxUserOperationCost');
    expect(prompts.count).toBe(0);
  });

  test('enforces maxUserOperationCost when the app sets one', async () => {
    // 960k gas at 2 gwei is 1.92e15 wei; a cap of 1e15 refuses it.
    const { account, prompts } = await accountWith({
      maxUserOperationCost: 1_000_000_000_000_000n,
    });
    const error = await account
      .signUserOperation(userOperation())
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
    expect(error.field).toBe('maxUserOperationCost');
    expect(prompts.count).toBe(0);
  });

  test('the preVerificationGas ceiling depends on the chain', async () => {
    expect(wallet.getDefaultGasCeilings(11155111).preVerificationGas).toBe(
      250_000n
    );
    expect(wallet.getDefaultGasCeilings(8453).preVerificationGas).toBe(
      5_000_000n
    );
    expect(wallet.getDefaultGasCeilings(42161).preVerificationGas).toBe(
      5_000_000n
    );
    // A chain nobody measured keeps the general ceiling.
    expect(wallet.getDefaultGasCeilings(999).preVerificationGas).toBe(
      wallet.DEFAULT_USER_OPERATION_GAS_CEILINGS.preVerificationGas
    );

    // Sepolia: 300k is past what a passkey operation needs there.
    const onSepolia = await accountWith();
    const error = await onSepolia.account
      .signUserOperation(userOperation({ preVerificationGas: 300_000n }))
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
    expect(error.field).toBe('preVerificationGas');
    expect(onSepolia.prompts.count).toBe(0);

    // Base prices L1 data into preVerificationGas; 3M is within its ceiling.
    const onBase = await accountWith({ chainId: 8453 });
    await onBase.account.signUserOperation(
      userOperation({
        preVerificationGas: 3_000_000n,
        maxFeePerGas: 1_000_000n,
        maxPriorityFeePerGas: 1_000n,
      })
    );
    expect(onBase.prompts.count).toBe(1);
  });

  test('refuses a user operation for another chain', async () => {
    const { account, prompts } = await accountWith();
    const error = await account
      .signUserOperation({ ...userOperation(), chainId: 1 })
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
    expect(error.field).toBe('chainId');
    expect(prompts.count).toBe(0);
  });

  test('refuses a verificationGasLimit floor above its own ceiling', async () => {
    await expect(
      accountWith({ verificationGasLimit: 3_000_000n })
    ).rejects.toThrow(/exceeds the verificationGasLimit ceiling/);
  });
});

test.describe('nonce key (D3)', () => {
  test('every user operation takes nonce key 0 by default', async () => {
    // With viem's default each operation drew a fresh key from Date.now(), so a
    // signed but abandoned operation kept a lane of its own and could still be
    // submitted after a retry had gone through.
    const { account, nonceKeys } = await accountWith();
    await account.getNonce();
    await account.getNonce();
    expect(nonceKeys).toEqual([0n, 0n]);
  });

  test('refuses a user operation on another nonce key, before the passkey is asked', async () => {
    // The nonce comes from EntryPoint.getNonce over the RPC; an RPC answering
    // with a fresh key would give the operation a lane of its own again.
    const { account, prompts } = await accountWith();
    const error = await account
      .signUserOperation(userOperation({ nonce: (123456789n << 64n) | 3n }))
      .catch((e) => e);
    expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
    expect(error.field).toBe('nonce');
    expect(prompts.count).toBe(0);

    await account.signUserOperation(userOperation({ nonce: 5n }));
    expect(prompts.count).toBe(1);
  });

  test('an app that wants lanes can still have them', async () => {
    let next = 7;
    const { account, nonceKeys } = await accountWith({
      nonceKeyManager: {
        async consume() {
          return next++;
        },
        increment() {},
        async get() {
          return next;
        },
        reset() {},
      },
    });
    await account.getNonce();
    await account.getNonce();
    expect(nonceKeys).toEqual([7n, 8n]);
    // Its own lanes are its duty: operations on them are signed.
    await account.signUserOperation(userOperation({ nonce: 9n << 64n }));
  });
});

test.describe('the setup account (path a)', () => {
  async function setupAccount(options = {}) {
    const { client, nonceKeys } = rpc();
    const passkey = await countingPasskey();
    const setup = wallet.createCaliburPasskeySetup({
      descriptor: passkey.descriptor,
    });
    const account = await setup.toSmartAccount({
      client,
      maxUserOperationCost: COST_LIMIT,
      ...options,
    });
    return { setup, account, nonceKeys };
  }

  test('needs maxUserOperationCost, and refuses chain 0', async () => {
    await expect(
      setupAccount({ maxUserOperationCost: undefined })
    ).rejects.toThrow(/needs maxUserOperationCost/);
    // An EIP-7702 authorization for chain 0 is valid on every chain.
    await expect(setupAccount({ chainId: 0 })).rejects.toThrow(
      /chainId must be a positive integer/
    );
  });

  test('its user operation passes the same checks before the setup key signs', async () => {
    const { account } = await setupAccount();
    for (const [overrides, field] of [
      [{ preVerificationGas: 50_000_000n }, 'preVerificationGas'],
      [
        { maxFeePerGas: 10n ** 24n, maxPriorityFeePerGas: 10n ** 24n },
        'maxUserOperationCost',
      ],
      [{ nonce: 1795575950183n << 64n }, 'nonce'],
    ]) {
      const error = await account
        .signUserOperation(userOperation(overrides))
        .catch((e) => e);
      expect(error).toBeInstanceOf(wallet.UserOperationLimitError);
      expect(error.field).toBe(field);
    }
    const signature = await account.signUserOperation(userOperation());
    expect(signature).toMatch(/^0x[0-9a-f]+$/);
  });

  test('takes nonce key 0, as the passkey account does', async () => {
    const { account, nonceKeys } = await setupAccount();
    await account.getNonce();
    expect(nonceKeys).toEqual([0n]);
  });
});
