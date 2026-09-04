/**
 * Publisher-served revocation list (spec draft §9.5-9.9).
 *
 * A second, independent revocation channel alongside the key document's own
 * `revoked` field (§8.2, handled by @htmltrust/canonicalization's
 * `isKeyRevoked`). This one lives at a fixed path under the *identity's own
 * origin*, not under wherever the key document itself happens to be hosted:
 *
 *   https://<origin>/.well-known/htmltrust-revocations.json
 *
 * That gives an identity a way to revoke or supersede one of its keys even
 * when that key's own document is hosted elsewhere, unreachable, or
 * compromised alongside the key material itself.
 *
 * Two states, and the distinction is the whole point:
 *   - "revoked": compromise. Absolute and retroactive. Every signature ever
 *     made by the key fails, regardless of its claimed `signed-at`, because
 *     a stolen key can backdate that value and there is no trusted clock to
 *     check it against.
 *   - "superseded": orderly rotation. Existing signatures stay valid; the
 *     key must not sign anything new. This is a Layer 2 policy signal only
 *     and never fails Layer 1 verification.
 *
 * Fetch outcomes collapse to three statuses:
 *   - HTTP 404                                   -> "not-revoked"
 *   - HTTP 200, valid signed document             -> apply its entries
 *   - anything else (network error, bad signature,
 *     malformed JSON, signed by an already-revoked
 *     key, ...)                                   -> "revocation-unknown"
 *
 * "revocation-unknown" must never be reported as a clean pass, but it also
 * must never hard-fail Layer 1 by itself: a transient outage of a static
 * file must not make a publisher's other content look forged. This mirrors
 * how `directory-unavailable` is already handled elsewhere in this package.
 */

import { canonicalizeJson, isKeyRevoked, resolveKey, verifySignature } from "@htmltrust/canonicalization";
import type { KeyResolver } from "@htmltrust/canonicalization";
import { isCanonicalBase64, makeVerificationFetch } from "./spec.js";
import type { VerificationFetchOptions } from "./spec.js";

export type RevocationStatus = "not-revoked" | "revoked" | "revocation-unknown";

/** Default maximum acceptable cache staleness for a fetched revocation list (spec §9.9). */
export const DEFAULT_MAX_STALENESS_MS = 24 * 60 * 60 * 1000;

export interface RevocationEntry {
  keyid: string;
  status: "revoked" | "superseded";
  revokedAt?: string;
  supersededBy?: string;
  [key: string]: unknown;
}

export interface RevocationDocument {
  signer: string;
  algorithm: string;
  timestamp: string;
  revocations: RevocationEntry[];
  signature: string;
  [key: string]: unknown;
}

export interface RevocationCheckResult {
  status: RevocationStatus;
  /** Only meaningful when status === "revoked"; the list's own `revokedAt`, if it supplied one. */
  revokedAt?: string;
  /**
   * Metadata, independent of `status`: true when the list marks this key
   * "superseded". Never affects `status` itself (spec §9.7): a superseded
   * key's existing signatures remain valid.
   */
  superseded: boolean;
  supersededBy?: string;
}

const NOT_REVOKED: RevocationCheckResult = Object.freeze({ status: "not-revoked", superseded: false });
const UNKNOWN: RevocationCheckResult = Object.freeze({ status: "revocation-unknown", superseded: false });

type CachedList =
  | { outcome: "not-found"; fetchedAt: number }
  | { outcome: "unknown"; fetchedAt: number }
  | { outcome: "ok"; fetchedAt: number; entries: Map<string, RevocationEntry> };

/** Shared across calls so repeated checks against the same origin actually get cached (spec §9.9). */
export type RevocationCache = Map<string, CachedList>;

export function createRevocationCache(): RevocationCache {
  return new Map();
}

export interface RevocationCheckOptions extends VerificationFetchOptions {
  /** Resolver chain used to resolve the revocation list's own `signer` key. */
  keyResolvers: KeyResolver[];
  /**
   * Base URLs of trust directories the caller is configured to use. A keyid
   * whose origin matches one of these is treated as directory-resolved
   * (spec §8.3): that resolution method defines no identity origin
   * independent of the directory, so revocation-list consultation does not
   * apply and this function reports "revocation-unknown" rather than
   * silently trusting or distrusting the directory's own key document.
   */
  directoryBaseUrls?: string[];
  /** Clock override, primarily for tests. */
  now?: () => number;
  /** Maximum acceptable cache staleness in ms, regardless of Cache-Control. Default 24h. */
  maxStalenessMs?: number;
  /** Shared cache across calls; pass the same Map/createRevocationCache() result to get real caching. */
  cache?: RevocationCache;
}

/**
 * Derive the origin a `keyid`'s revocation list is served from (spec §9.5).
 * Returns null when no independent identity origin applies: an unrecognized
 * keyid scheme, or one that resolves through a configured trust directory.
 */
export function revocationListOrigin(keyid: string, directoryBaseUrls: string[] = []): string | null {
  if (keyid.startsWith("did:web:")) {
    return didWebOrigin(keyid);
  }
  if (/^https?:\/\//i.test(keyid)) {
    let url: URL;
    try {
      url = new URL(keyid);
    } catch {
      return null;
    }
    if (isDirectoryOrigin(url.origin, directoryBaseUrls)) return null;
    return url.origin;
  }
  return null;
}

function isDirectoryOrigin(origin: string, directoryBaseUrls: string[]): boolean {
  return directoryBaseUrls.some((base) => {
    try {
      return new URL(base).origin === origin;
    } catch {
      return false;
    }
  });
}

/**
 * did:web -> https origin, ignoring any DID path component: the revocation
 * list always lives at the origin root (RFC 8615 well-known convention),
 * never under a DID-encoded path. Host/port decoding mirrors
 * @htmltrust/canonicalization's own did:web resolver so the two agree on
 * what a given did:web identifier's origin is.
 */
function didWebOrigin(keyid: string): string | null {
  const rest = keyid.slice("did:web:".length).split(/[/?#]/u, 1)[0];
  const [host] = rest.split(":");
  if (!host) return null;
  const authorityHost = host.replace(/%3a/gi, ":");
  if (authorityHost.includes("%")) return null;
  let url: URL;
  try {
    url = new URL(`https://${authorityHost}`);
  } catch {
    return null;
  }
  if (
    authorityHost.includes("@") ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    return null;
  }
  return url.origin;
}

function isRevocationEntry(value: unknown): value is RevocationEntry {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.keyid !== "string" || v.keyid === "") return false;
  if (v.status !== "revoked" && v.status !== "superseded") return false;
  if (v.revokedAt !== undefined && typeof v.revokedAt !== "string") return false;
  if (v.supersededBy !== undefined && typeof v.supersededBy !== "string") return false;
  return true;
}

function isRevocationDocument(value: unknown): value is RevocationDocument {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.signer !== "string" || v.signer === "") return false;
  if (typeof v.algorithm !== "string" || v.algorithm === "") return false;
  if (typeof v.timestamp !== "string" || v.timestamp === "") return false;
  if (typeof v.signature !== "string" || !isCanonicalBase64(v.signature)) return false;
  if (!Array.isArray(v.revocations)) return false;
  return true;
}

function omitSignature(doc: RevocationDocument): Record<string, unknown> {
  const { signature: _signature, ...unsigned } = doc;
  return unsigned;
}

/**
 * Fetch, parse, and verify the revocation list at `url`. Never throws;
 * network, parse, and signature failures all collapse to the "unknown"
 * outcome so a caller never needs its own try/catch around this.
 */
async function fetchList(url: string, options: RevocationCheckOptions): Promise<CachedList> {
  const now = (options.now ?? Date.now)();
  const fetchImpl = makeVerificationFetch(options);
  let res: Response;
  try {
    res = await fetchImpl(url);
  } catch {
    return { outcome: "unknown", fetchedAt: now };
  }
  if (res.status === 404) {
    return { outcome: "not-found", fetchedAt: now };
  }
  if (!res.ok) {
    return { outcome: "unknown", fetchedAt: now };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await res.text());
  } catch {
    return { outcome: "unknown", fetchedAt: now };
  }
  if (!isRevocationDocument(parsed)) {
    return { outcome: "unknown", fetchedAt: now };
  }

  let resolved = null;
  try {
    resolved = await resolveKey(parsed.signer, options.keyResolvers);
  } catch {
    return { outcome: "unknown", fetchedAt: now };
  }
  // Spec §9.6: the signer must not itself be revoked. This checks the
  // signer's own key document (§8.2); it deliberately does not recurse into
  // that signer's own revocation list, which could loop indefinitely if a
  // key ever appeared in its own revocation chain.
  if (!resolved || isKeyRevoked(resolved)) {
    return { outcome: "unknown", fetchedAt: now };
  }

  let payload: string;
  try {
    payload = canonicalizeJson(omitSignature(parsed));
  } catch {
    return { outcome: "unknown", fetchedAt: now };
  }

  let sigOk = false;
  try {
    sigOk = await verifySignature(payload, parsed.signature, resolved.publicKeyPem, parsed.algorithm);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return { outcome: "unknown", fetchedAt: now };
  }

  const entries = new Map<string, RevocationEntry>();
  for (const entry of parsed.revocations) {
    if (isRevocationEntry(entry)) entries.set(entry.keyid, entry);
  }
  return { outcome: "ok", fetchedAt: now, entries };
}

/**
 * Check a `keyid`'s revocation status against its publisher-served
 * revocation list (spec §9.5-9.9). Off the critical path by design: callers
 * decide whether and when to consult this, independent of the key
 * document's own `revoked` field.
 */
export async function checkKeyRevocation(
  keyid: string,
  options: RevocationCheckOptions,
): Promise<RevocationCheckResult> {
  const origin = revocationListOrigin(keyid, options.directoryBaseUrls ?? []);
  if (origin === null) return UNKNOWN;

  const url = `${origin}/.well-known/htmltrust-revocations.json`;
  const now = (options.now ?? Date.now)();
  const maxStaleness = options.maxStalenessMs ?? DEFAULT_MAX_STALENESS_MS;
  const cache = options.cache;

  let cached = cache?.get(url);
  if (!cached || now - cached.fetchedAt >= maxStaleness) {
    cached = await fetchList(url, options);
    cache?.set(url, cached);
  }

  if (cached.outcome === "not-found") return NOT_REVOKED;
  if (cached.outcome === "unknown") return UNKNOWN;

  const entry = cached.entries.get(keyid);
  if (!entry) return NOT_REVOKED;
  if (entry.status === "revoked") {
    return { status: "revoked", superseded: false, revokedAt: entry.revokedAt };
  }
  return { status: "not-revoked", superseded: true, supersededBy: entry.supersededBy };
}
