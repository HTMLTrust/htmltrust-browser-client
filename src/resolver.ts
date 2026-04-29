/**
 * Resolver chain helpers.
 *
 * Re-exports the three pluggable resolvers from @htmltrust/canonicalization
 * and provides a small convenience builder for the typical "did:web first,
 * then direct URL, then trust directories" chain.
 */

import {
  didWebResolver,
  directUrlResolver,
  trustDirectoryResolver,
  resolveKey,
} from "@htmltrust/canonicalization";
import type { KeyResolver } from "@htmltrust/canonicalization";

export {
  didWebResolver,
  directUrlResolver,
  trustDirectoryResolver,
  resolveKey,
};

export interface DefaultResolverChainOptions {
  /** Trust directory base URLs (e.g. "https://eff.org/directory"). */
  directories?: string[];
  /** Optional fetch override (for tests, custom transports, etc.). */
  fetch?: typeof fetch;
}

/**
 * Build the canonical resolver chain used by most HTMLTrust clients:
 *   1. did:web (decentralized, primary identity scheme)
 *   2. direct URL (keyid IS the resolution endpoint)
 *   3. trust directories (federated convenience registries)
 *
 * Each resolver returns null when it doesn't apply, so resolveKey() walks
 * the chain in order until one matches.
 */
export function defaultResolverChain(
  opts: DefaultResolverChainOptions = {},
): KeyResolver[] {
  const { directories = [], fetch: fetchImpl } = opts;
  const chain: KeyResolver[] = [
    didWebResolver({ fetch: fetchImpl }),
    directUrlResolver({ fetch: fetchImpl }),
  ];
  if (directories.length > 0) {
    chain.push(trustDirectoryResolver({ baseUrls: directories, fetch: fetchImpl }));
  }
  return chain;
}
