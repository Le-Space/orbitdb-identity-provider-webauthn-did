/** Sepolia's current KMS context id, 32 bytes. */
const CONTEXT_ID = `07${'00'.repeat(30)}01`;
/** Epoch 1, 32 bytes. */
const EPOCH_ID = `${'00'.repeat(31)}01`;

/**
 * Zama's unified decryption permit, built the way @fhevm/sdk 0.14.3 builds it
 * (`createKmsUserDecryptEip712V2`): `EIP712Domain` listed among the types,
 * the uint256 values as decimal strings, the start rounded down to the
 * minute, and extraData v2 — a version byte, the KMS context id, the epoch
 * id. The domain names the host chain, not Zama's gateway chain
 * (`createKmsEip712Domain`: for this primary type "chainId is the host
 * chain"), and the gateway's Decryption contract, as the SDK's Sepolia entry
 * gives it. The context id is Sepolia's
 * (`ProtocolConfig.getCurrentKmsContextId()`); epoch 1 stands in, because
 * Sepolia's KMSVerifier v0.3.0 reports none yet.
 *
 * Checked on 2026-10-12: a permit the SDK built itself, signed by the passkey
 * account on a Sepolia fork, passed the SDK's own ERC-1271 precheck
 * (`verifyErc1271UserDecrypt`) — Le-Space/simple-todo#54, step 5.
 * @param {`0x${string}`} userAddress
 */
export function zamaPermit(userAddress) {
  return /** @type {const} */ ({
    domain: {
      name: 'Decryption',
      version: '1',
      chainId: 11155111n,
      verifyingContract: '0x5D8BD78e2ea6bbE41f26dFe9fdaEAa349e077478',
    },
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
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
      startTimestamp: '1791799980',
      durationSeconds: '86400',
      extraData: `0x02${CONTEXT_ID}${EPOCH_ID}`,
    },
  });
}
