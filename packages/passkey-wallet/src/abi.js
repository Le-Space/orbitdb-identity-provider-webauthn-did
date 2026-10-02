/**
 * The ABI of Calibur v1.0.0 (Uniswap/calibur@35d8091, `CaliburEntry`), as
 * forge compiles it from that tag, plus the two errors its libraries raise in
 * assembly and the compiler therefore does not list: `InvalidSignatureLength()`
 * (WrappedSignatureLib, 0x4be6321b) and `SliceOutOfBounds()` (CalldataDecoder,
 * 0x3b99b53d). test/calibur checks it against a fresh compile.
 */
export const caliburAbi = /** @type {const} */ ([
  {
    type: 'fallback',
    stateMutability: 'payable',
  },
  {
    type: 'receive',
    stateMutability: 'payable',
  },
  {
    type: 'function',
    name: 'CUSTOM_STORAGE_ROOT',
    inputs: [],
    outputs: [
      {
        name: '',
        type: 'bytes32',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'ENTRY_POINT',
    inputs: [],
    outputs: [
      {
        name: '',
        type: 'address',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'approveNative',
    inputs: [
      {
        name: 'spender',
        type: 'address',
      },
      {
        name: 'amount',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'approveNativeTransient',
    inputs: [
      {
        name: 'spender',
        type: 'address',
      },
      {
        name: 'amount',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'domainBytes',
    inputs: [],
    outputs: [
      {
        name: '',
        type: 'bytes',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'domainSeparator',
    inputs: [],
    outputs: [
      {
        name: '',
        type: 'bytes32',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'eip712Domain',
    inputs: [],
    outputs: [
      {
        name: 'fields',
        type: 'bytes1',
      },
      {
        name: 'name',
        type: 'string',
      },
      {
        name: 'version',
        type: 'string',
      },
      {
        name: 'chainId',
        type: 'uint256',
      },
      {
        name: 'verifyingContract',
        type: 'address',
      },
      {
        name: 'salt',
        type: 'bytes32',
      },
      {
        name: 'extensions',
        type: 'uint256[]',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'execute',
    inputs: [
      {
        name: 'batchedCall',
        type: 'tuple',
        components: [
          {
            name: 'calls',
            type: 'tuple[]',
            components: [
              {
                name: 'to',
                type: 'address',
              },
              {
                name: 'value',
                type: 'uint256',
              },
              {
                name: 'data',
                type: 'bytes',
              },
            ],
          },
          {
            name: 'revertOnFailure',
            type: 'bool',
          },
        ],
      },
    ],
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    name: 'execute',
    inputs: [
      {
        name: 'signedBatchedCall',
        type: 'tuple',
        components: [
          {
            name: 'batchedCall',
            type: 'tuple',
            components: [
              {
                name: 'calls',
                type: 'tuple[]',
                components: [
                  {
                    name: 'to',
                    type: 'address',
                  },
                  {
                    name: 'value',
                    type: 'uint256',
                  },
                  {
                    name: 'data',
                    type: 'bytes',
                  },
                ],
              },
              {
                name: 'revertOnFailure',
                type: 'bool',
              },
            ],
          },
          {
            name: 'nonce',
            type: 'uint256',
          },
          {
            name: 'keyHash',
            type: 'bytes32',
          },
          {
            name: 'executor',
            type: 'address',
          },
          {
            name: 'deadline',
            type: 'uint256',
          },
        ],
      },
      {
        name: 'wrappedSignature',
        type: 'bytes',
      },
    ],
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    name: 'execute',
    inputs: [
      {
        name: 'mode',
        type: 'bytes32',
      },
      {
        name: 'executionData',
        type: 'bytes',
      },
    ],
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    name: 'executeUserOp',
    inputs: [
      {
        name: 'userOp',
        type: 'tuple',
        components: [
          {
            name: 'sender',
            type: 'address',
          },
          {
            name: 'nonce',
            type: 'uint256',
          },
          {
            name: 'initCode',
            type: 'bytes',
          },
          {
            name: 'callData',
            type: 'bytes',
          },
          {
            name: 'accountGasLimits',
            type: 'bytes32',
          },
          {
            name: 'preVerificationGas',
            type: 'uint256',
          },
          {
            name: 'gasFees',
            type: 'bytes32',
          },
          {
            name: 'paymasterAndData',
            type: 'bytes',
          },
          {
            name: 'signature',
            type: 'bytes',
          },
        ],
      },
      {
        name: '',
        type: 'bytes32',
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'getKey',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          {
            name: 'keyType',
            type: 'uint8',
          },
          {
            name: 'publicKey',
            type: 'bytes',
          },
        ],
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'getKeySettings',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'getSeq',
    inputs: [
      {
        name: 'key',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: 'seq',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'hashTypedData',
    inputs: [
      {
        name: 'hash',
        type: 'bytes32',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'bytes32',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'invalidateNonce',
    inputs: [
      {
        name: 'newNonce',
        type: 'uint256',
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'isRegistered',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'isValidSignature',
    inputs: [
      {
        name: 'digest',
        type: 'bytes32',
      },
      {
        name: 'wrappedSignature',
        type: 'bytes',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'bytes4',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'keyAt',
    inputs: [
      {
        name: 'i',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          {
            name: 'keyType',
            type: 'uint8',
          },
          {
            name: 'publicKey',
            type: 'bytes',
          },
        ],
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'keyCount',
    inputs: [],
    outputs: [
      {
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'keyHashes',
    inputs: [],
    outputs: [
      {
        name: '_spacer',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'multicall',
    inputs: [
      {
        name: 'data',
        type: 'bytes[]',
      },
    ],
    outputs: [
      {
        name: 'results',
        type: 'bytes[]',
      },
    ],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    name: 'namespaceAndVersion',
    inputs: [],
    outputs: [
      {
        name: '',
        type: 'string',
      },
    ],
    stateMutability: 'pure',
  },
  {
    type: 'function',
    name: 'nativeAllowance',
    inputs: [
      {
        name: 'spender',
        type: 'address',
      },
    ],
    outputs: [
      {
        name: 'allowance',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'nonceSequenceNumber',
    inputs: [
      {
        name: 'key',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: 'seq',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'register',
    inputs: [
      {
        name: 'key',
        type: 'tuple',
        components: [
          {
            name: 'keyType',
            type: 'uint8',
          },
          {
            name: 'publicKey',
            type: 'bytes',
          },
        ],
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'revoke',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'supportsExecutionMode',
    inputs: [
      {
        name: 'mode',
        type: 'bytes32',
      },
    ],
    outputs: [
      {
        name: 'result',
        type: 'bool',
      },
    ],
    stateMutability: 'pure',
  },
  {
    type: 'function',
    name: 'transferFromNative',
    inputs: [
      {
        name: 'from',
        type: 'address',
      },
      {
        name: 'recipient',
        type: 'address',
      },
      {
        name: 'amount',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'transferFromNativeTransient',
    inputs: [
      {
        name: 'from',
        type: 'address',
      },
      {
        name: 'recipient',
        type: 'address',
      },
      {
        name: 'amount',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'bool',
      },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'transientNativeAllowance',
    inputs: [
      {
        name: 'spender',
        type: 'address',
      },
    ],
    outputs: [
      {
        name: '',
        type: 'uint256',
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'update',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
      },
      {
        name: 'settings',
        type: 'uint256',
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'updateEntryPoint',
    inputs: [
      {
        name: 'entryPoint',
        type: 'address',
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'updateSalt',
    inputs: [
      {
        name: 'prefix',
        type: 'uint96',
      },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'validateUserOp',
    inputs: [
      {
        name: 'userOp',
        type: 'tuple',
        components: [
          {
            name: 'sender',
            type: 'address',
          },
          {
            name: 'nonce',
            type: 'uint256',
          },
          {
            name: 'initCode',
            type: 'bytes',
          },
          {
            name: 'callData',
            type: 'bytes',
          },
          {
            name: 'accountGasLimits',
            type: 'bytes32',
          },
          {
            name: 'preVerificationGas',
            type: 'uint256',
          },
          {
            name: 'gasFees',
            type: 'bytes32',
          },
          {
            name: 'paymasterAndData',
            type: 'bytes',
          },
          {
            name: 'signature',
            type: 'bytes',
          },
        ],
      },
      {
        name: 'userOpHash',
        type: 'bytes32',
      },
      {
        name: 'missingAccountFunds',
        type: 'uint256',
      },
    ],
    outputs: [
      {
        name: 'validationData',
        type: 'uint256',
      },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'event',
    name: 'ApproveNative',
    inputs: [
      {
        name: 'owner',
        type: 'address',
        indexed: true,
      },
      {
        name: 'spender',
        type: 'address',
        indexed: true,
      },
      {
        name: 'value',
        type: 'uint256',
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'ApproveNativeTransient',
    inputs: [
      {
        name: 'owner',
        type: 'address',
        indexed: true,
      },
      {
        name: 'spender',
        type: 'address',
        indexed: true,
      },
      {
        name: 'value',
        type: 'uint256',
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'EIP712DomainChanged',
    inputs: [],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'EntryPointUpdated',
    inputs: [
      {
        name: 'newEntryPoint',
        type: 'address',
        indexed: true,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'KeySettingsUpdated',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
        indexed: true,
      },
      {
        name: 'settings',
        type: 'uint256',
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'NativeAllowanceUpdated',
    inputs: [
      {
        name: 'spender',
        type: 'address',
        indexed: true,
      },
      {
        name: 'value',
        type: 'uint256',
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'NonceInvalidated',
    inputs: [
      {
        name: 'nonce',
        type: 'uint256',
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'Registered',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
        indexed: true,
      },
      {
        name: 'key',
        type: 'tuple',
        indexed: false,
        components: [
          {
            name: 'keyType',
            type: 'uint8',
          },
          {
            name: 'publicKey',
            type: 'bytes',
          },
        ],
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'Revoked',
    inputs: [
      {
        name: 'keyHash',
        type: 'bytes32',
        indexed: true,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'TransferFromNative',
    inputs: [
      {
        name: 'from',
        type: 'address',
        indexed: true,
      },
      {
        name: 'to',
        type: 'address',
        indexed: true,
      },
      {
        name: 'value',
        type: 'uint256',
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: 'event',
    name: 'TransferFromNativeTransient',
    inputs: [
      {
        name: 'from',
        type: 'address',
        indexed: true,
      },
      {
        name: 'to',
        type: 'address',
        indexed: true,
      },
      {
        name: 'value',
        type: 'uint256',
        indexed: false,
      },
    ],
    anonymous: false,
  },
  {
    type: 'error',
    name: 'AllowanceExceeded',
    inputs: [],
  },
  {
    type: 'error',
    name: 'CallFailed',
    inputs: [
      {
        name: 'reason',
        type: 'bytes',
      },
    ],
  },
  {
    type: 'error',
    name: 'CannotRegisterRootKey',
    inputs: [],
  },
  {
    type: 'error',
    name: 'CannotUpdateRootKey',
    inputs: [],
  },
  {
    type: 'error',
    name: 'ExcessiveInvalidation',
    inputs: [],
  },
  {
    type: 'error',
    name: 'FnSelectorNotRecognized',
    inputs: [],
  },
  {
    type: 'error',
    name: 'IncorrectSender',
    inputs: [],
  },
  {
    type: 'error',
    name: 'IndexOutOfBounds',
    inputs: [],
  },
  {
    type: 'error',
    name: 'InvalidHookResponse',
    inputs: [],
  },
  {
    type: 'error',
    name: 'InvalidNonce',
    inputs: [],
  },
  {
    type: 'error',
    name: 'InvalidSignature',
    inputs: [],
  },
  {
    type: 'error',
    name: 'KeyDoesNotExist',
    inputs: [],
  },
  {
    type: 'error',
    name: 'KeyExpired',
    inputs: [
      {
        name: 'expiration',
        type: 'uint40',
      },
    ],
  },
  {
    type: 'error',
    name: 'NotEntryPoint',
    inputs: [],
  },
  {
    type: 'error',
    name: 'OnlyAdminCanSelfCall',
    inputs: [],
  },
  {
    type: 'error',
    name: 'SignatureExpired',
    inputs: [],
  },
  {
    type: 'error',
    name: 'TransferNativeFailed',
    inputs: [],
  },
  {
    type: 'error',
    name: 'Unauthorized',
    inputs: [],
  },
  {
    type: 'error',
    name: 'UnsupportedExecutionMode',
    inputs: [],
  },
  {
    type: 'error',
    name: 'InvalidSignatureLength',
    inputs: [],
  },
  {
    type: 'error',
    name: 'SliceOutOfBounds',
    inputs: [],
  },
]);

/**
 * The part of Zama's ACL (v0.4.0, the version on Sepolia and mainnet as of
 * 2026-09-16) that user-decryption delegation touches: the two calls and two
 * reads `IACL` declares in `@fhevm/solidity@0.11.1` (lib/Impl.sol), with the
 * events and errors of ACL.sol and ACLEvents.sol at zama-ai/fhevm v0.13.0,
 * whose ACL reports that version.
 */
export const zamaAclAbi = /** @type {const} */ ([
  {
    name: 'delegateForUserDecryption',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      {
        type: 'address',
        name: 'delegate',
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
      {
        type: 'uint64',
        name: 'expirationDate',
      },
    ],
    outputs: [],
  },
  {
    name: 'revokeDelegationForUserDecryption',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      {
        type: 'address',
        name: 'delegate',
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
    ],
    outputs: [],
  },
  {
    name: 'getUserDecryptionDelegationExpirationDate',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      {
        type: 'address',
        name: 'delegator',
      },
      {
        type: 'address',
        name: 'delegate',
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
    ],
    outputs: [
      {
        type: 'uint64',
      },
    ],
  },
  {
    name: 'isHandleDelegatedForUserDecryption',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      {
        type: 'address',
        name: 'delegator',
      },
      {
        type: 'address',
        name: 'delegate',
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
      {
        type: 'bytes32',
        name: 'handle',
      },
    ],
    outputs: [
      {
        type: 'bool',
      },
    ],
  },
  {
    name: 'DelegatedForUserDecryption',
    type: 'event',
    inputs: [
      {
        type: 'address',
        name: 'delegator',
        indexed: true,
      },
      {
        type: 'address',
        name: 'delegate',
        indexed: true,
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
      {
        type: 'uint64',
        name: 'delegationCounter',
      },
      {
        type: 'uint64',
        name: 'oldExpirationDate',
      },
      {
        type: 'uint64',
        name: 'newExpirationDate',
      },
    ],
  },
  {
    name: 'RevokedDelegationForUserDecryption',
    type: 'event',
    inputs: [
      {
        type: 'address',
        name: 'delegator',
        indexed: true,
      },
      {
        type: 'address',
        name: 'delegate',
        indexed: true,
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
      {
        type: 'uint64',
        name: 'delegationCounter',
      },
      {
        type: 'uint64',
        name: 'oldExpirationDate',
      },
    ],
  },
  {
    name: 'AlreadyDelegatedOrRevokedInSameBlock',
    type: 'error',
    inputs: [
      {
        type: 'address',
        name: 'delegator',
      },
      {
        type: 'address',
        name: 'delegate',
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
      {
        type: 'uint256',
        name: 'blockNumber',
      },
    ],
  },
  {
    name: 'DelegateCannotBeContractAddress',
    type: 'error',
    inputs: [
      {
        type: 'address',
        name: 'contractAddress',
      },
    ],
  },
  {
    name: 'DelegateCannotBeWildcard',
    type: 'error',
    inputs: [
      {
        type: 'address',
        name: 'delegate',
      },
    ],
  },
  {
    name: 'ExpirationDateAlreadySetToSameValue',
    type: 'error',
    inputs: [
      {
        type: 'address',
        name: 'delegator',
      },
      {
        type: 'address',
        name: 'delegate',
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
      {
        type: 'uint256',
        name: 'expirationDate',
      },
    ],
  },
  {
    name: 'ExpirationDateInThePast',
    type: 'error',
    inputs: [],
  },
  {
    name: 'NotDelegatedYet',
    type: 'error',
    inputs: [
      {
        type: 'address',
        name: 'delegator',
      },
      {
        type: 'address',
        name: 'delegate',
      },
      {
        type: 'address',
        name: 'contractAddress',
      },
    ],
  },
  {
    name: 'SenderCannotBeContractAddress',
    type: 'error',
    inputs: [
      {
        type: 'address',
        name: 'contractAddress',
      },
    ],
  },
  {
    name: 'SenderCannotBeDelegate',
    type: 'error',
    inputs: [
      {
        type: 'address',
        name: 'delegate',
      },
    ],
  },
  {
    name: 'EnforcedPause',
    type: 'error',
    inputs: [],
  },
]);
