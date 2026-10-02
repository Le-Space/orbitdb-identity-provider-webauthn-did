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
export function createCaliburBundlerClient({ client, bundler, paymaster, paymasterContext, }: {
    client: import("./account.js").AccountClient;
    bundler: Endpoint;
    paymaster?: Endpoint | undefined;
    paymasterContext?: unknown;
}): import("viem/account-abstraction").BundlerClient<import("viem").HttpTransport<undefined, false>, import("viem").Chain<import("viem").ChainFormatters | undefined, Record<string, unknown> | undefined> | undefined, undefined, import("./account.js").AccountClient, undefined>;
export type Endpoint = {
    url: string;
    headers?: Record<string, string> | undefined;
};
