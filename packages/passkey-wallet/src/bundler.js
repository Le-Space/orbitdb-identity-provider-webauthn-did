/**
 * Bundler and paymaster clients from the app's own endpoints. This package has
 * no endpoints and no credentials: URLs, headers (an API key, say) and the
 * paymaster context all come from the caller.
 */
import { http } from 'viem';
import {
  createBundlerClient,
  createPaymasterClient,
} from 'viem/account-abstraction';

/**
 * @typedef {{ url: string, headers?: Record<string, string> | undefined }} Endpoint
 */

/**
 * @param {unknown} endpoint
 * @param {string} name
 * @returns {Endpoint}
 */
function readEndpoint(endpoint, name) {
  const { url, headers } = /** @type {Endpoint} */ (endpoint ?? {});
  if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
    throw new TypeError(`${name}.url must be an http(s) URL`);
  }
  if (
    headers !== undefined &&
    (typeof headers !== 'object' ||
      Object.values(headers).some((value) => typeof value !== 'string'))
  ) {
    throw new TypeError(`${name}.headers must map names to strings`);
  }
  return { url, headers };
}

/** @param {Endpoint} endpoint */
function transportFor({ url, headers }) {
  return http(url, headers ? { fetchOptions: { headers } } : {});
}

/**
 * A viem bundler client for EntryPoint v0.8 user operations, optionally with a
 * paymaster that sponsors them.
 *
 * @param {{
 *   client: import('./account.js').AccountClient,
 *   bundler: Endpoint,
 *   paymaster?: Endpoint | undefined,
 *   paymasterContext?: unknown,
 * }} parameters
 *   `client` reads chain state; `bundler` and `paymaster` are the app's
 *   endpoints (they may be the same); `paymasterContext` goes to
 *   `pm_getPaymasterStubData` / `pm_getPaymasterData` as the paymaster
 *   service defines it (a sponsorship policy id, say).
 */
export function createCaliburBundlerClient({
  client,
  bundler,
  paymaster,
  paymasterContext,
}) {
  if (!client) {
    throw new TypeError('createCaliburBundlerClient needs a viem client');
  }
  const bundlerEndpoint = readEndpoint(bundler, 'bundler');
  const paymasterClient =
    paymaster === undefined
      ? undefined
      : createPaymasterClient({
          transport: transportFor(readEndpoint(paymaster, 'paymaster')),
        });
  return createBundlerClient({
    client,
    chain: client.chain,
    transport: transportFor(bundlerEndpoint),
    ...(paymasterClient
      ? { paymaster: paymasterClient, paymasterContext }
      : {}),
  });
}
