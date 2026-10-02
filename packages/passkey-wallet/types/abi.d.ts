/**
 * The ABI of Calibur v1.0.0 (Uniswap/calibur@35d8091, `CaliburEntry`), as
 * forge compiles it from that tag, plus the two errors its libraries raise in
 * assembly and the compiler therefore does not list: `InvalidSignatureLength()`
 * (WrappedSignatureLib, 0x4be6321b) and `SliceOutOfBounds()` (CalldataDecoder,
 * 0x3b99b53d). test/calibur checks it against a fresh compile.
 */
export const caliburAbi: readonly [
  {
    readonly type: 'fallback';
    readonly stateMutability: 'payable';
  },
  {
    readonly type: 'receive';
    readonly stateMutability: 'payable';
  },
  {
    readonly type: 'function';
    readonly name: 'CUSTOM_STORAGE_ROOT';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bytes32';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'ENTRY_POINT';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'address';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'approveNative';
    readonly inputs: readonly [
      {
        readonly name: 'spender';
        readonly type: 'address';
      },
      {
        readonly name: 'amount';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bool';
      },
    ];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'approveNativeTransient';
    readonly inputs: readonly [
      {
        readonly name: 'spender';
        readonly type: 'address';
      },
      {
        readonly name: 'amount';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bool';
      },
    ];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'domainBytes';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bytes';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'domainSeparator';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bytes32';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'eip712Domain';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: 'fields';
        readonly type: 'bytes1';
      },
      {
        readonly name: 'name';
        readonly type: 'string';
      },
      {
        readonly name: 'version';
        readonly type: 'string';
      },
      {
        readonly name: 'chainId';
        readonly type: 'uint256';
      },
      {
        readonly name: 'verifyingContract';
        readonly type: 'address';
      },
      {
        readonly name: 'salt';
        readonly type: 'bytes32';
      },
      {
        readonly name: 'extensions';
        readonly type: 'uint256[]';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'execute';
    readonly inputs: readonly [
      {
        readonly name: 'batchedCall';
        readonly type: 'tuple';
        readonly components: readonly [
          {
            readonly name: 'calls';
            readonly type: 'tuple[]';
            readonly components: readonly [
              {
                readonly name: 'to';
                readonly type: 'address';
              },
              {
                readonly name: 'value';
                readonly type: 'uint256';
              },
              {
                readonly name: 'data';
                readonly type: 'bytes';
              },
            ];
          },
          {
            readonly name: 'revertOnFailure';
            readonly type: 'bool';
          },
        ];
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'payable';
  },
  {
    readonly type: 'function';
    readonly name: 'execute';
    readonly inputs: readonly [
      {
        readonly name: 'signedBatchedCall';
        readonly type: 'tuple';
        readonly components: readonly [
          {
            readonly name: 'batchedCall';
            readonly type: 'tuple';
            readonly components: readonly [
              {
                readonly name: 'calls';
                readonly type: 'tuple[]';
                readonly components: readonly [
                  {
                    readonly name: 'to';
                    readonly type: 'address';
                  },
                  {
                    readonly name: 'value';
                    readonly type: 'uint256';
                  },
                  {
                    readonly name: 'data';
                    readonly type: 'bytes';
                  },
                ];
              },
              {
                readonly name: 'revertOnFailure';
                readonly type: 'bool';
              },
            ];
          },
          {
            readonly name: 'nonce';
            readonly type: 'uint256';
          },
          {
            readonly name: 'keyHash';
            readonly type: 'bytes32';
          },
          {
            readonly name: 'executor';
            readonly type: 'address';
          },
          {
            readonly name: 'deadline';
            readonly type: 'uint256';
          },
        ];
      },
      {
        readonly name: 'wrappedSignature';
        readonly type: 'bytes';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'payable';
  },
  {
    readonly type: 'function';
    readonly name: 'execute';
    readonly inputs: readonly [
      {
        readonly name: 'mode';
        readonly type: 'bytes32';
      },
      {
        readonly name: 'executionData';
        readonly type: 'bytes';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'payable';
  },
  {
    readonly type: 'function';
    readonly name: 'executeUserOp';
    readonly inputs: readonly [
      {
        readonly name: 'userOp';
        readonly type: 'tuple';
        readonly components: readonly [
          {
            readonly name: 'sender';
            readonly type: 'address';
          },
          {
            readonly name: 'nonce';
            readonly type: 'uint256';
          },
          {
            readonly name: 'initCode';
            readonly type: 'bytes';
          },
          {
            readonly name: 'callData';
            readonly type: 'bytes';
          },
          {
            readonly name: 'accountGasLimits';
            readonly type: 'bytes32';
          },
          {
            readonly name: 'preVerificationGas';
            readonly type: 'uint256';
          },
          {
            readonly name: 'gasFees';
            readonly type: 'bytes32';
          },
          {
            readonly name: 'paymasterAndData';
            readonly type: 'bytes';
          },
          {
            readonly name: 'signature';
            readonly type: 'bytes';
          },
        ];
      },
      {
        readonly name: '';
        readonly type: 'bytes32';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'getKey';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'tuple';
        readonly components: readonly [
          {
            readonly name: 'keyType';
            readonly type: 'uint8';
          },
          {
            readonly name: 'publicKey';
            readonly type: 'bytes';
          },
        ];
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'getKeySettings';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'getSeq';
    readonly inputs: readonly [
      {
        readonly name: 'key';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: 'seq';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'hashTypedData';
    readonly inputs: readonly [
      {
        readonly name: 'hash';
        readonly type: 'bytes32';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bytes32';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'invalidateNonce';
    readonly inputs: readonly [
      {
        readonly name: 'newNonce';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'isRegistered';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bool';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'isValidSignature';
    readonly inputs: readonly [
      {
        readonly name: 'digest';
        readonly type: 'bytes32';
      },
      {
        readonly name: 'wrappedSignature';
        readonly type: 'bytes';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bytes4';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'keyAt';
    readonly inputs: readonly [
      {
        readonly name: 'i';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'tuple';
        readonly components: readonly [
          {
            readonly name: 'keyType';
            readonly type: 'uint8';
          },
          {
            readonly name: 'publicKey';
            readonly type: 'bytes';
          },
        ];
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'keyCount';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'keyHashes';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: '_spacer';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'multicall';
    readonly inputs: readonly [
      {
        readonly name: 'data';
        readonly type: 'bytes[]';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: 'results';
        readonly type: 'bytes[]';
      },
    ];
    readonly stateMutability: 'payable';
  },
  {
    readonly type: 'function';
    readonly name: 'namespaceAndVersion';
    readonly inputs: readonly [];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'string';
      },
    ];
    readonly stateMutability: 'pure';
  },
  {
    readonly type: 'function';
    readonly name: 'nativeAllowance';
    readonly inputs: readonly [
      {
        readonly name: 'spender';
        readonly type: 'address';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: 'allowance';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'nonceSequenceNumber';
    readonly inputs: readonly [
      {
        readonly name: 'key';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: 'seq';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'register';
    readonly inputs: readonly [
      {
        readonly name: 'key';
        readonly type: 'tuple';
        readonly components: readonly [
          {
            readonly name: 'keyType';
            readonly type: 'uint8';
          },
          {
            readonly name: 'publicKey';
            readonly type: 'bytes';
          },
        ];
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'revoke';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'supportsExecutionMode';
    readonly inputs: readonly [
      {
        readonly name: 'mode';
        readonly type: 'bytes32';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: 'result';
        readonly type: 'bool';
      },
    ];
    readonly stateMutability: 'pure';
  },
  {
    readonly type: 'function';
    readonly name: 'transferFromNative';
    readonly inputs: readonly [
      {
        readonly name: 'from';
        readonly type: 'address';
      },
      {
        readonly name: 'recipient';
        readonly type: 'address';
      },
      {
        readonly name: 'amount';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bool';
      },
    ];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'transferFromNativeTransient';
    readonly inputs: readonly [
      {
        readonly name: 'from';
        readonly type: 'address';
      },
      {
        readonly name: 'recipient';
        readonly type: 'address';
      },
      {
        readonly name: 'amount';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'bool';
      },
    ];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'transientNativeAllowance';
    readonly inputs: readonly [
      {
        readonly name: 'spender';
        readonly type: 'address';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: '';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'view';
  },
  {
    readonly type: 'function';
    readonly name: 'update';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
      },
      {
        readonly name: 'settings';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'updateEntryPoint';
    readonly inputs: readonly [
      {
        readonly name: 'entryPoint';
        readonly type: 'address';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'updateSalt';
    readonly inputs: readonly [
      {
        readonly name: 'prefix';
        readonly type: 'uint96';
      },
    ];
    readonly outputs: readonly [];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'function';
    readonly name: 'validateUserOp';
    readonly inputs: readonly [
      {
        readonly name: 'userOp';
        readonly type: 'tuple';
        readonly components: readonly [
          {
            readonly name: 'sender';
            readonly type: 'address';
          },
          {
            readonly name: 'nonce';
            readonly type: 'uint256';
          },
          {
            readonly name: 'initCode';
            readonly type: 'bytes';
          },
          {
            readonly name: 'callData';
            readonly type: 'bytes';
          },
          {
            readonly name: 'accountGasLimits';
            readonly type: 'bytes32';
          },
          {
            readonly name: 'preVerificationGas';
            readonly type: 'uint256';
          },
          {
            readonly name: 'gasFees';
            readonly type: 'bytes32';
          },
          {
            readonly name: 'paymasterAndData';
            readonly type: 'bytes';
          },
          {
            readonly name: 'signature';
            readonly type: 'bytes';
          },
        ];
      },
      {
        readonly name: 'userOpHash';
        readonly type: 'bytes32';
      },
      {
        readonly name: 'missingAccountFunds';
        readonly type: 'uint256';
      },
    ];
    readonly outputs: readonly [
      {
        readonly name: 'validationData';
        readonly type: 'uint256';
      },
    ];
    readonly stateMutability: 'nonpayable';
  },
  {
    readonly type: 'event';
    readonly name: 'ApproveNative';
    readonly inputs: readonly [
      {
        readonly name: 'owner';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'spender';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'value';
        readonly type: 'uint256';
        readonly indexed: false;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'ApproveNativeTransient';
    readonly inputs: readonly [
      {
        readonly name: 'owner';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'spender';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'value';
        readonly type: 'uint256';
        readonly indexed: false;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'EIP712DomainChanged';
    readonly inputs: readonly [];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'EntryPointUpdated';
    readonly inputs: readonly [
      {
        readonly name: 'newEntryPoint';
        readonly type: 'address';
        readonly indexed: true;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'KeySettingsUpdated';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
        readonly indexed: true;
      },
      {
        readonly name: 'settings';
        readonly type: 'uint256';
        readonly indexed: false;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'NativeAllowanceUpdated';
    readonly inputs: readonly [
      {
        readonly name: 'spender';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'value';
        readonly type: 'uint256';
        readonly indexed: false;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'NonceInvalidated';
    readonly inputs: readonly [
      {
        readonly name: 'nonce';
        readonly type: 'uint256';
        readonly indexed: false;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'Registered';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
        readonly indexed: true;
      },
      {
        readonly name: 'key';
        readonly type: 'tuple';
        readonly indexed: false;
        readonly components: readonly [
          {
            readonly name: 'keyType';
            readonly type: 'uint8';
          },
          {
            readonly name: 'publicKey';
            readonly type: 'bytes';
          },
        ];
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'Revoked';
    readonly inputs: readonly [
      {
        readonly name: 'keyHash';
        readonly type: 'bytes32';
        readonly indexed: true;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'TransferFromNative';
    readonly inputs: readonly [
      {
        readonly name: 'from';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'to';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'value';
        readonly type: 'uint256';
        readonly indexed: false;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'event';
    readonly name: 'TransferFromNativeTransient';
    readonly inputs: readonly [
      {
        readonly name: 'from';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'to';
        readonly type: 'address';
        readonly indexed: true;
      },
      {
        readonly name: 'value';
        readonly type: 'uint256';
        readonly indexed: false;
      },
    ];
    readonly anonymous: false;
  },
  {
    readonly type: 'error';
    readonly name: 'AllowanceExceeded';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'CallFailed';
    readonly inputs: readonly [
      {
        readonly name: 'reason';
        readonly type: 'bytes';
      },
    ];
  },
  {
    readonly type: 'error';
    readonly name: 'CannotRegisterRootKey';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'CannotUpdateRootKey';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'ExcessiveInvalidation';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'FnSelectorNotRecognized';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'IncorrectSender';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'IndexOutOfBounds';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'InvalidHookResponse';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'InvalidNonce';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'InvalidSignature';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'KeyDoesNotExist';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'KeyExpired';
    readonly inputs: readonly [
      {
        readonly name: 'expiration';
        readonly type: 'uint40';
      },
    ];
  },
  {
    readonly type: 'error';
    readonly name: 'NotEntryPoint';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'OnlyAdminCanSelfCall';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'SignatureExpired';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'TransferNativeFailed';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'Unauthorized';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'UnsupportedExecutionMode';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'InvalidSignatureLength';
    readonly inputs: readonly [];
  },
  {
    readonly type: 'error';
    readonly name: 'SliceOutOfBounds';
    readonly inputs: readonly [];
  },
];
/**
 * The part of Zama's ACL (v0.4.0, the version on Sepolia and mainnet as of
 * 2026-09-16) that user-decryption delegation touches: the two calls and two
 * reads `IACL` declares in `@fhevm/solidity@0.11.1` (lib/Impl.sol), with the
 * events and errors of ACL.sol and ACLEvents.sol at zama-ai/fhevm v0.13.0,
 * whose ACL reports that version.
 */
export const zamaAclAbi: readonly [
  {
    readonly name: 'delegateForUserDecryption';
    readonly type: 'function';
    readonly stateMutability: 'nonpayable';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
      {
        readonly type: 'uint64';
        readonly name: 'expirationDate';
      },
    ];
    readonly outputs: readonly [];
  },
  {
    readonly name: 'revokeDelegationForUserDecryption';
    readonly type: 'function';
    readonly stateMutability: 'nonpayable';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
    ];
    readonly outputs: readonly [];
  },
  {
    readonly name: 'getUserDecryptionDelegationExpirationDate';
    readonly type: 'function';
    readonly stateMutability: 'view';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegator';
      },
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
    ];
    readonly outputs: readonly [
      {
        readonly type: 'uint64';
      },
    ];
  },
  {
    readonly name: 'isHandleDelegatedForUserDecryption';
    readonly type: 'function';
    readonly stateMutability: 'view';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegator';
      },
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
      {
        readonly type: 'bytes32';
        readonly name: 'handle';
      },
    ];
    readonly outputs: readonly [
      {
        readonly type: 'bool';
      },
    ];
  },
  {
    readonly name: 'DelegatedForUserDecryption';
    readonly type: 'event';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegator';
        readonly indexed: true;
      },
      {
        readonly type: 'address';
        readonly name: 'delegate';
        readonly indexed: true;
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
      {
        readonly type: 'uint64';
        readonly name: 'delegationCounter';
      },
      {
        readonly type: 'uint64';
        readonly name: 'oldExpirationDate';
      },
      {
        readonly type: 'uint64';
        readonly name: 'newExpirationDate';
      },
    ];
  },
  {
    readonly name: 'RevokedDelegationForUserDecryption';
    readonly type: 'event';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegator';
        readonly indexed: true;
      },
      {
        readonly type: 'address';
        readonly name: 'delegate';
        readonly indexed: true;
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
      {
        readonly type: 'uint64';
        readonly name: 'delegationCounter';
      },
      {
        readonly type: 'uint64';
        readonly name: 'oldExpirationDate';
      },
    ];
  },
  {
    readonly name: 'AlreadyDelegatedOrRevokedInSameBlock';
    readonly type: 'error';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegator';
      },
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
      {
        readonly type: 'uint256';
        readonly name: 'blockNumber';
      },
    ];
  },
  {
    readonly name: 'DelegateCannotBeContractAddress';
    readonly type: 'error';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
    ];
  },
  {
    readonly name: 'DelegateCannotBeWildcard';
    readonly type: 'error';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
    ];
  },
  {
    readonly name: 'ExpirationDateAlreadySetToSameValue';
    readonly type: 'error';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegator';
      },
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
      {
        readonly type: 'uint256';
        readonly name: 'expirationDate';
      },
    ];
  },
  {
    readonly name: 'ExpirationDateInThePast';
    readonly type: 'error';
    readonly inputs: readonly [];
  },
  {
    readonly name: 'NotDelegatedYet';
    readonly type: 'error';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegator';
      },
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
    ];
  },
  {
    readonly name: 'SenderCannotBeContractAddress';
    readonly type: 'error';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'contractAddress';
      },
    ];
  },
  {
    readonly name: 'SenderCannotBeDelegate';
    readonly type: 'error';
    readonly inputs: readonly [
      {
        readonly type: 'address';
        readonly name: 'delegate';
      },
    ];
  },
  {
    readonly name: 'EnforcedPause';
    readonly type: 'error';
    readonly inputs: readonly [];
  },
];
