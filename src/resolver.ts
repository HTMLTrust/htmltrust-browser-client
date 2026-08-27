/**
 * Resolver chain helpers.
 *
 * Re-exports the three pluggable resolvers from @htmltrust/canonicalization
 * and provides a small convenience builder for the typical "did:web first,
 * then direct URL, then trust directories" chain.
 */

import {
  didWebResolver as canonicalDidWebResolver,
  directUrlResolver as canonicalDirectUrlResolver,
  trustDirectoryResolver as canonicalTrustDirectoryResolver,
  resolveKey,
} from "@htmltrust/canonicalization";
import type { KeyResolver } from "@htmltrust/canonicalization";
import { isLoopbackHost, isPrivateHost, makeVerificationFetch } from "./spec.js";

export {
  resolveKey,
};

export interface DefaultResolverChainOptions {
  /** Trust directory base URLs (e.g. "https://eff.org/directory"). */
  directories?: string[];
  /** Optional fetch override (for tests, custom transports, etc.). */
  fetch?: typeof fetch;
  /** Allows http://127.0.0.1 fixture URLs in tests. Do not enable in production. */
  allowInsecureHttpForTesting?: boolean;
}

export type ResolverOptions = Omit<DefaultResolverChainOptions, "directories">;

export interface TrustDirectoryResolverOptions extends ResolverOptions {
  baseUrls: string[];
}

export function didWebResolver(opts: ResolverOptions = {}): KeyResolver {
  return canonicalDidWebResolver({
    fetch: makeVerificationFetch(opts),
  });
}

export function directUrlResolver(opts: ResolverOptions = {}): KeyResolver {
  return canonicalDirectUrlResolver({
    fetch: makeVerificationFetch(opts),
  });
}

export function trustDirectoryResolver(opts: TrustDirectoryResolverOptions): KeyResolver {
  for (const base of opts.baseUrls) {
    const url = new URL(base);
    const testingLoopback =
      opts.allowInsecureHttpForTesting === true && isLoopbackHost(url.hostname);
    if (url.protocol !== "https:" && !testingLoopback) {
      throw new Error("network-policy-blocked");
    }
    if (isPrivateHost(url.hostname) && !testingLoopback) {
      throw new Error("network-policy-blocked");
    }
  }
  return canonicalTrustDirectoryResolver({
    baseUrls: opts.baseUrls,
    fetch: makeVerificationFetch(opts),
  });
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
  const { directories = [], fetch: fetchImpl, allowInsecureHttpForTesting } = opts;
  const chain: KeyResolver[] = [
    didWebResolver({ fetch: fetchImpl, allowInsecureHttpForTesting }),
    directUrlResolver({ fetch: fetchImpl, allowInsecureHttpForTesting }),
  ];
  if (directories.length > 0) {
    chain.push(trustDirectoryResolver({ baseUrls: directories, fetch: fetchImpl, allowInsecureHttpForTesting }));
  }
  return chain;
}
