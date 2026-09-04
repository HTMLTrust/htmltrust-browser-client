/**
 * Key identifier binding (spec draft §8.1/§8.2), interim implementation.
 *
 * Closes the cross-host alias residual left after the keyid-alias fix: a
 * key document served under an alias hostname (www vs apex, a CDN
 * hostname distinct from the origin server, an IP literal presenting a
 * matching certificate, a trailing-dot FQDN) detaches the resolved key
 * from its own revocation list, because the list is discovered from the
 * origin of whatever `keyid` string a signer -- honest or hostile --
 * chose to address it by, not from any origin the key document itself
 * asserts. Two things can go wrong from there, both `valid: true`: the
 * alias also happens to serve a revocation list, which fails the
 * signer-origin check and reports `revocation-unknown` (silently missed
 * by a caller reading only `.valid`); or the alias 404s the well-known
 * path, reporting a clean `not-revoked`. Either way the `publicKeyHash`
 * match never runs, because the list itself is never consulted under the
 * alias's origin.
 *
 * The fix: a key document MUST name its own canonical identifier, and
 * resolution MUST fail on any other spelling. An alias then never
 * resolves AS the key's own identity in the first place, so the
 * revocation list is never reached under a false one. The honest key
 * document -- which a key thief does not control without separately
 * compromising the origin that serves it -- is what fixes the one true
 * spelling; changing it is origin compromise, a distinct, out-of-scope
 * threat.
 *
 * This closes the alias residual WITHIN one identity's own resolution
 * methods (a did:web identifier, or a URL identifier). It does not and
 * cannot make two genuinely different origins (an apex domain and a CDN
 * hostname the operator has not linked) into the same identity: a server
 * answering under several hostnames is several origins, and nothing
 * short of the operator publishing one canonical identifier collapses
 * that back to one.
 *
 * @htmltrust/canonicalization's pinned resolvers do not expose the raw
 * fetched key document to a caller, so this module re-fetches it itself,
 * under the same fetch policy every other verifier-initiated fetch in
 * this package uses, purely to check this binding -- one extra cacheable
 * GET to an origin key resolution already contacted, not a new network
 * destination. This is an interim implementation; it belongs in the
 * shared resolver once
 * https://github.com/HTMLTrust/htmltrust-canonicalization/issues/20
 * lands (extended to cover this cross-host case, not just the original
 * missing-`kid`-check gap).
 */

import { makeVerificationFetch } from "./spec.js";
import type { VerificationFetchOptions } from "./spec.js";

export type IdentifierBindingResult =
  | { ok: true }
  | { ok: false; reason: "key-resolution-failed" | "malformed-key-document" };

export interface IdentifierBindingOptions extends VerificationFetchOptions {
  /** Clock override, primarily for tests. */
  now?: () => number;
  /** Positive-result cache lifetime in ms. Default 1h, matching this package's existing key-document caching recommendation. */
  maxAgeMs?: number;
  /** Negative-result (failure) cache lifetime in ms. Default 5min: a failure must not be pinned as long as a success, the same reasoning as the revocation module's own short "unknown" backoff. */
  negativeMaxAgeMs?: number;
  /** Shared cache across calls. Defaults to a module-level cache; pass your own for isolation (mainly tests). */
  cache?: IdentifierBindingCache;
}

interface CachedBinding {
  result: IdentifierBindingResult;
  expiresAt: number;
}

export type IdentifierBindingCache = Map<string, CachedBinding>;

export function createIdentifierBindingCache(): IdentifierBindingCache {
  return new Map();
}

const defaultCache: IdentifierBindingCache = new Map();

export const DEFAULT_BINDING_CACHE_MS = 60 * 60 * 1000;
export const DEFAULT_NEGATIVE_BINDING_CACHE_MS = 5 * 60 * 1000;

/**
 * did:web path-segment encoding, copied exactly from
 * @htmltrust/canonicalization's own (unexported) `encodeDidWebPathPart`
 * so the two modules construct the identical DID document URL for the
 * same identifier. `encodeURIComponent` alone double-encodes a segment
 * that already contains a valid percent-encoded byte (`%62` -> `%2562`);
 * this rejects a malformed percent-encoding outright, then collapses the
 * `%25XX` sequences `encodeURIComponent` produces for an already-valid
 * `%XX` back down to `%XX`, leaving genuinely literal `%` characters
 * escaped and pre-escaped bytes untouched.
 */
function encodeDidWebPathPart(part: string): string {
  if (!part || /%(?![0-9a-f]{2})/iu.test(part)) throw new Error("did:web invalid path");
  return encodeURIComponent(part).replace(/%25([0-9a-f]{2})/giu, "%$1");
}

/**
 * Construct the did:web DID document URL and the "DID portion" of a
 * keyid -- the DID itself, with any DID URL path/query/fragment suffix
 * removed -- mirroring @htmltrust/canonicalization's own
 * didWebDocumentURL construction so the two agree on what a given
 * did:web keyid resolves to.
 */
function didWebDocumentUrl(keyid: string): { url: string; didPortion: string } | null {
  const rest = keyid.slice("did:web:".length).split(/[/?#]/u, 1)[0];
  const [host, ...pathParts] = rest.split(":");
  if (!host) return null;
  const authorityHost = host.replace(/%3a/gi, ":");
  if (authorityHost.includes("%")) return null;
  let authority: URL;
  try {
    authority = new URL(`https://${authorityHost}`);
  } catch {
    return null;
  }
  if (
    authorityHost.includes("@") ||
    authority.username ||
    authority.password ||
    authority.pathname !== "/" ||
    authority.search ||
    authority.hash
  ) {
    return null;
  }
  let url: string;
  try {
    url =
      pathParts.length === 0
        ? `https://${authority.host}/.well-known/did.json`
        : `https://${authority.host}/${pathParts.map(encodeDidWebPathPart).join("/")}/did.json`;
  } catch {
    return null;
  }
  return { url, didPortion: `did:web:${rest}` };
}

async function checkBindingUncached(
  keyid: string,
  options: IdentifierBindingOptions,
): Promise<IdentifierBindingResult> {
  const fetchImpl = makeVerificationFetch(options);

  if (keyid.startsWith("did:web:")) {
    const constructed = didWebDocumentUrl(keyid);
    if (!constructed) return { ok: false, reason: "key-resolution-failed" };
    let doc: unknown;
    try {
      const res = await fetchImpl(constructed.url);
      if (!res.ok) return { ok: false, reason: "key-resolution-failed" };
      doc = JSON.parse(await res.text());
    } catch {
      return { ok: false, reason: "key-resolution-failed" };
    }
    const id = doc && typeof doc === "object" ? (doc as Record<string, unknown>).id : undefined;
    if (id !== constructed.didPortion) return { ok: false, reason: "key-resolution-failed" };
    return { ok: true };
  }

  if (/^https?:\/\//i.test(keyid)) {
    let doc: unknown;
    try {
      const res = await fetchImpl(keyid);
      if (!res.ok) return { ok: false, reason: "malformed-key-document" };
      doc = JSON.parse(await res.text());
    } catch {
      return { ok: false, reason: "malformed-key-document" };
    }
    const kid = doc && typeof doc === "object" ? (doc as Record<string, unknown>).kid : undefined;
    if (kid !== keyid) return { ok: false, reason: "malformed-key-document" };
    return { ok: true };
  }

  // verify.ts's attribute validation rejects any keyid that is neither an
  // absolute HTTPS URL nor a did: URI before resolution is attempted, so
  // this path is unreachable through normal verification; kept as a safe
  // default for direct callers of this module.
  return { ok: false, reason: "key-resolution-failed" };
}

/**
 * Check that the resolved key document (or DID document) names `keyid`
 * itself as its own canonical identifier: `kid` for a URL-form keyid,
 * `id` for a did:web keyid. Re-fetches the document under the same
 * fetch policy as every other verifier-initiated fetch in this package.
 */
export async function checkKeyIdentifierBinding(
  keyid: string,
  options: IdentifierBindingOptions,
): Promise<IdentifierBindingResult> {
  const now = (options.now ?? Date.now)();
  const maxAge = options.maxAgeMs ?? DEFAULT_BINDING_CACHE_MS;
  const negativeMaxAge = options.negativeMaxAgeMs ?? DEFAULT_NEGATIVE_BINDING_CACHE_MS;
  const cache = options.cache ?? defaultCache;

  const cached = cache.get(keyid);
  if (cached && now < cached.expiresAt) return cached.result;

  const result = await checkBindingUncached(keyid, options);
  // A failure (fetch error, missing kid/id, mismatch) is cached for much
  // less time than a success: it must not be pinned as long as a positive
  // result, the same reasoning as the revocation module's own short
  // "unknown" backoff -- a transient fetch failure here must not make an
  // otherwise-valid key look permanently unbound.
  const ttl = result.ok ? maxAge : negativeMaxAge;
  cache.set(keyid, { result, expiresAt: now + ttl });
  return result;
}
