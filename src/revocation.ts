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
 * compromised alongside the key material itself. `<origin>` is derived from
 * the keyid the same way for every resolution method that has one at all
 * (did:web domain, or any HTTPS key URL's own origin, directory-hosted keys
 * included -- a directory-hosted key's document already lives at that
 * origin and already controls that key's `revoked` field, so a list there
 * carries no additional authority). A keyid with no derivable HTTPS origin
 * (a non-did:web DID method) has no revocation list to consult at all;
 * `checkKeyRevocation` returns `undefined` for that case rather than
 * `revocation-unknown`, since nothing was attempted.
 *
 * This module alone closes keyid-string aliasing WITHIN one origin (a
 * dot-segment path variant, host case, default-port omission, ...), by
 * matching `revoked` on the resolved key's own SPKI hash rather than on
 * `keyid` text. It does NOT by itself close a CROSS-HOST alias, where a key
 * document is reachable under a second hostname the verifier was never told
 * is the same identity (www vs apex, a CDN hostname, an IP literal with a
 * matching certificate): that closure requires the key document to name its
 * own canonical identifier, which `../identifier-binding.js` checks
 * separately. See `verify.ts` for how the two combine.
 *
 * Two states, and the distinction is the whole point:
 *   - "revoked": compromise. Absolute and retroactive, with no time
 *     condition anywhere: every signature ever made by the key fails,
 *     regardless of its claimed `signed-at`, full stop. Matched ONLY by
 *     `publicKeyHash` (the SHA-256 of the resolved key's SPKI DER) against
 *     the key material a verifier already resolved, never by `keyid` text:
 *     `keyid` is opaque and signer-chosen, and the same key can be resolved
 *     under more than one spelling, so a text-based match is bypassable by
 *     construction. `publicKeyHash` is REQUIRED on a `revoked` entry; one
 *     missing it is malformed (spec §9.6) and invalidates the whole
 *     document, rather than falling back to a weaker text match.
 *   - "superseded": the same orderly-rotation state Section 9.1 already
 *     defines from a key document's own `expires`/`supersededBy` fields,
 *     now assertable through this second, independent channel too.
 *     Existing signatures stay valid; the key must not sign anything new.
 *     This is a Layer 2 policy signal only and never fails Layer 1
 *     verification. Matched by `publicKeyHash` when present, else by the
 *     canonical keyid form (`canonicalKeyidForm`) -- lower stakes than
 *     "revoked" since a missed alias here only means the supersession
 *     signal is not surfaced, not that a forged signature passes.
 *
 * If more than one entry matches the same key, by hash or by keyid, and
 * any of them says "revoked", the key is revoked: a "superseded" entry for
 * the same key never suppresses a "revoked" one, regardless of array order.
 *
 * Fetch outcomes collapse to three wire statuses:
 *   - HTTP 404                                   -> "not-revoked"
 *   - HTTP 200, valid signed document,
 *     signer's origin matches the list's own,
 *     signer not itself listed revoked/superseded,
 *     every entry well-formed                     -> apply its entries
 *   - anything else (network error, bad signature,
 *     malformed JSON (including a duplicate JSON
 *     member anywhere), a malformed entry anywhere
 *     in the document, signer hosted at a
 *     different origin than the list, signer
 *     already known revoked, signer listed
 *     revoked or superseded within this same
 *     list, ...)                                  -> "revocation-unknown"
 *
 * "revocation-unknown" must never be reported as a clean pass, but it also
 * must never hard-fail Layer 1 by itself: a transient outage of a static
 * file must not make a publisher's other content look forged. This mirrors
 * how `directory-unavailable` is already handled elsewhere in this package.
 * A fetch that was never attempted (no derivable origin) is a different,
 * fourth case: `undefined`, not "revocation-unknown".
 */

import { canonicalizeJson, canonicalizeJsonDocument, isKeyRevoked, resolveKey, verifySignature } from "@htmltrust/canonicalization";
import type { KeyResolver } from "@htmltrust/canonicalization";
import { bytesToUnpaddedBase64, isCanonicalBase64, makeVerificationFetch } from "./spec.js";
import type { VerificationFetchOptions } from "./spec.js";

export type RevocationStatus = "not-revoked" | "revoked" | "revocation-unknown";

/** Default maximum acceptable cache freshness for a fetched revocation list (spec §9.9); a ceiling on Cache-Control freshness, not a fixed TTL. */
export const DEFAULT_MAX_STALENESS_MS = 24 * 60 * 60 * 1000;

/** Default cache freshness for an HTTP 404 (no list published) when no shorter Cache-Control freshness applies -- shorter than DEFAULT_MAX_STALENESS_MS so a publisher's first list after a compromise is not unseen for up to a day. */
export const NOT_FOUND_DEFAULT_MS = 60 * 60 * 1000;

/** Negative-cache window for a "revocation-unknown" outcome: short, so a transient failure self-heals quickly rather than pinning "unknown" for up to DEFAULT_MAX_STALENESS_MS. */
export const UNKNOWN_RETRY_MS = 60 * 1000;

/**
 * `keyid` is opaque and signer-chosen (spec §8); the same key material can
 * be resolved under more than one `keyid` string (dot-segment path
 * variants, host case, default-port omission, ...). Matching a `revoked`
 * entry against `keyid` text is therefore bypassable by construction: sign
 * with an alias, and a check keyed to one spelling misses it. `publicKeyHash`
 * closes this by identifying the key itself, independent of how it was
 * addressed, and is REQUIRED on a `revoked` entry for exactly that reason.
 */
export interface RevocationEntry {
  keyid: string;
  status: "revoked" | "superseded";
  /** SHA-256 of the resolved key's SPKI DER, canonical unpadded Base64 (spec §9.6). REQUIRED when `status` is `revoked`; a `revoked` entry omitting it is malformed. OPTIONAL when `status` is `superseded`. */
  publicKeyHash?: string;
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
  | { outcome: "not-found"; expiresAt: number }
  | { outcome: "unknown"; expiresAt: number }
  | { outcome: "ok"; expiresAt: number; entries: RevocationEntry[] };

/** Shared across calls so repeated checks against the same origin actually get cached (spec §9.9). */
export type RevocationCache = Map<string, CachedList>;

export function createRevocationCache(): RevocationCache {
  return new Map();
}

/**
 * Used automatically when a caller does not supply `options.cache`, so the
 * staleness ceiling and the "unknown" backoff are exercised even without
 * explicit opt-in. Pass a fresh `createRevocationCache()` instead when
 * isolation from other callers in the same process matters (tests, mainly).
 */
const defaultCache: RevocationCache = new Map();

export interface RevocationCheckOptions extends VerificationFetchOptions {
  /** Resolver chain used to resolve the revocation list's own `signer` key. */
  keyResolvers: KeyResolver[];
  /** Clock override, primarily for tests. */
  now?: () => number;
  /** Maximum acceptable cache freshness in ms, regardless of Cache-Control. Default 24h; Cache-Control MAY shorten this but never lengthen it. */
  maxStalenessMs?: number;
  /** Shared cache across calls. Defaults to a module-level cache; pass your own (e.g. `createRevocationCache()`) for isolation. */
  cache?: RevocationCache;
}

/**
 * Derive the origin a `keyid`'s revocation list is served from (spec §9.5).
 * Every resolution method that has an HTTPS origin at all uses it here,
 * including a directory-hosted keyid (spec §8.3): the verifier has already
 * disclosed the key to that origin via `GET /keys/{id}`, and the directory
 * already controls that key's own `revoked` field, so a list at that
 * origin carries no authority the directory did not already have. Returns
 * null only when no HTTPS origin can be derived at all, which today means
 * a DID method other than did:web.
 */
export function revocationListOrigin(keyid: string): string | null {
  if (keyid.startsWith("did:web:")) {
    return didWebOrigin(keyid);
  }
  if (/^https?:\/\//i.test(keyid)) {
    try {
      return new URL(keyid).origin;
    } catch {
      return null;
    }
  }
  return null;
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
  if (v.publicKeyHash !== undefined && (typeof v.publicKeyHash !== "string" || !isCanonicalBase64(v.publicKeyHash))) {
    return false;
  }
  // Spec §9.6: publicKeyHash is REQUIRED for a revoked entry; missing it is
  // malformed, not a softer degrade to keyid-only matching. There is no
  // secondary text-based match for "revoked" in this revision.
  if (v.status === "revoked" && v.publicKeyHash === undefined) return false;
  if (v.revokedAt !== undefined && typeof v.revokedAt !== "string") return false;
  if (v.supersededBy !== undefined && typeof v.supersededBy !== "string") return false;
  return true;
}

/**
 * Canonical keyid comparison form (spec §8.5). Used only for the
 * `superseded` lookup -- the analogous match for `revoked` is
 * `publicKeyHash` alone, with no keyid-based fallback -- and never for the
 * signing/verification binding itself, which always uses the exact `keyid`
 * attribute value.
 */
export function canonicalKeyidForm(keyid: string): string {
  if (keyid.startsWith("did:web:")) {
    const afterPrefix = keyid.slice("did:web:".length);
    const stopIndex = afterPrefix.search(/[/?#]/u);
    const methodSpecific = stopIndex === -1 ? afterPrefix : afterPrefix.slice(0, stopIndex);
    const rest = stopIndex === -1 ? "" : afterPrefix.slice(stopIndex);
    const [host, ...pathParts] = methodSpecific.split(":");
    const normalizedHost = host.replace(/%3a/gi, "%3A").toLowerCase();
    return `did:web:${[normalizedHost, ...pathParts].join(":")}${rest}`;
  }
  if (/^https?:\/\//i.test(keyid)) {
    try {
      const url = new URL(keyid);
      // Neither a query nor a fragment carries identity for this
      // comparison. A signed section's own keyid can never carry either
      // (spec §5.1 forbids both outright), but an entry's keyid is
      // author-supplied JSON data, not a validated wire attribute, and MAY
      // carry one; strip both sides the same way so they still compare
      // equal.
      url.search = "";
      url.hash = "";
      return url.href;
    } catch {
      return keyid;
    }
  }
  return keyid;
}

/**
 * Spec §5.1: a URL-form `keyid` (resolved under §8.2/§8.3) MUST NOT carry a
 * query or fragment component; a `did:web` `keyid` (§8.1) is unaffected,
 * since a fragment there is the normal way to select one verification
 * method from a DID document. Closes the query/fragment alias forms
 * directly, rather than relying on canonicalization to erase them: a
 * `keyid` failing this MUST be rejected with `key-resolution-failed`
 * before resolution is attempted (Step 1 of the verification procedure).
 */
export function keyidHasForbiddenUrlSyntax(keyid: string): boolean {
  if (keyid.startsWith("did:web:")) return false;
  if (!/^https?:\/\//i.test(keyid)) return false;
  return keyid.includes("?") || keyid.includes("#");
}

/**
 * Spec §5.1/§8: a `keyid` MUST be either an absolute HTTPS (or, for
 * testing, HTTP) URL or a `did:` URI; nothing else is a supported
 * resolution method. Without this check, an opaque string like `"alice"`
 * is silently accepted by the pinned trust-directory resolver (which
 * URL-encodes and appends whatever string it is given, with no shape
 * validation of its own), and such a keyid has no derivable revocation-list
 * origin, so it evades revocation-list consultation entirely rather than
 * failing loudly. A `keyid` failing this MUST be rejected with
 * `key-resolution-failed` before resolution is attempted.
 */
export function keyidHasUnsupportedScheme(keyid: string): boolean {
  if (/^https?:\/\//i.test(keyid)) return false;
  if (keyid.startsWith("did:")) return false;
  return true;
}

/** Raw SPKI DER bytes from a PEM-encoded SubjectPublicKeyInfo. */
function derFromPem(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** SHA-256 of a resolved key's SPKI DER, canonical unpadded Base64 (spec §9.6 `publicKeyHash`). */
export async function spkiHash(publicKeyPem: string): Promise<string> {
  const subtle = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!subtle) {
    throw new Error("spkiHash: SubtleCrypto is unavailable; provide a runtime with WebCrypto");
  }
  const digest = await subtle.digest("SHA-256", derFromPem(publicKeyPem).slice());
  return bytesToUnpaddedBase64(new Uint8Array(digest));
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
 * Strictly parse a revocation-list response body: rejects a duplicate JSON
 * member anywhere in the document (top level or within an entry), which
 * plain `JSON.parse` silently accepts last-wins. Spec §9.8 requires this
 * (cross-referencing §11.2's JCS conformance rules, which already forbid
 * it for the sibling endorsement format). Reuses
 * @htmltrust/canonicalization's own strict JSON parser rather than writing
 * a second one: `canonicalizeJsonDocument` already rejects a duplicate
 * member, a lone UTF-16 surrogate, and other RFC 8259 violations before
 * producing its canonical output, so a successful call here is sufficient
 * proof the input has none of those problems, independent of the
 * canonical string itself.
 */
function parseRevocationDocumentStrict(body: string): unknown {
  const canonical = canonicalizeJsonDocument(body);
  return JSON.parse(canonical);
}

/**
 * Cache-Control (`max-age`/`s-maxage`), `Expires`, and `Age` freshness for a
 * 200 or 404 revocation-list response, capped at `maxStaleness`.
 * `no-store`/`no-cache` mean revalidate on the very next call (freshness
 * 0). An unparseable freshness value -- a malformed `max-age`/`s-maxage`
 * token (including a quoted one, which RFC 9111's grammar does not permit)
 * or an unparseable `Expires` value -- is treated as 0, not as though no
 * value were present at all: a value a verifier cannot make sense of is
 * untrusted, not a reason to fall back to the generous default. Only the
 * genuine absence of any freshness information falls back to
 * `defaultWhenAbsentMs`.
 */
function freshnessMsFor(res: Response, maxStaleness: number, defaultWhenAbsentMs: number, now: number): number {
  const header = res.headers.get?.("cache-control") ?? "";
  const directives = header.split(",").map((d) => d.trim());
  if (directives.some((d) => d.toLowerCase() === "no-store")) return 0;
  if (directives.some((d) => { const l = d.toLowerCase(); return l === "no-cache" || l.startsWith("no-cache="); })) {
    return 0;
  }

  const parseAgeDirective = (name: string): { present: boolean; seconds: number | null } => {
    for (const d of directives) {
      const eq = d.indexOf("=");
      if (eq === -1) continue;
      if (d.slice(0, eq).trim().toLowerCase() !== name) continue;
      const value = d.slice(eq + 1).trim();
      return { present: true, seconds: /^\d+$/.test(value) ? Number(value) : null };
    }
    return { present: false, seconds: null };
  };

  const sMaxAge = parseAgeDirective("s-maxage");
  const maxAge = parseAgeDirective("max-age");

  let declaredMs: number;
  if (sMaxAge.present) {
    declaredMs = sMaxAge.seconds === null ? 0 : sMaxAge.seconds * 1000;
  } else if (maxAge.present) {
    declaredMs = maxAge.seconds === null ? 0 : maxAge.seconds * 1000;
  } else {
    const expiresHeader = res.headers.get?.("expires");
    if (expiresHeader) {
      const expiresAt = Date.parse(expiresHeader);
      declaredMs = Number.isFinite(expiresAt) ? Math.max(0, expiresAt - now) : 0;
    } else {
      declaredMs = defaultWhenAbsentMs;
    }
  }

  const ageHeader = res.headers.get?.("age");
  const ageSeconds = ageHeader !== null && ageHeader !== undefined ? Number(ageHeader) : NaN;
  const ageMs = Number.isFinite(ageSeconds) && ageSeconds >= 0 ? ageSeconds * 1000 : 0;
  return Math.max(0, Math.min(declaredMs, maxStaleness) - ageMs);
}

/**
 * Fetch, parse, and verify the revocation list at `url`, which MUST be
 * hosted at `origin`. Never throws; network, parse, and signature failures
 * all collapse to the "unknown" outcome so a caller never needs its own
 * try/catch around this.
 */
async function fetchList(
  url: string,
  origin: string,
  now: number,
  maxStaleness: number,
  options: RevocationCheckOptions,
): Promise<CachedList> {
  const fetchImpl = makeVerificationFetch(options);
  let res: Response;
  try {
    res = await fetchImpl(url);
  } catch {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }
  if (res.status === 404) {
    // Capped below the 24h ceiling: a publisher's first list after a
    // compromise must not go unseen for up to a day just because an
    // earlier 404 was cached generously (spec §9.9/§13.4).
    return { outcome: "not-found", expiresAt: now + freshnessMsFor(res, maxStaleness, NOT_FOUND_DEFAULT_MS, now) };
  }
  if (!res.ok) {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }

  let parsed: unknown;
  try {
    parsed = parseRevocationDocumentStrict(await res.text());
  } catch {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }
  if (!isRevocationDocument(parsed)) {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }

  // Spec §9.8: the signer MUST be "the same identity" as the list, defined
  // as equality of the §9.5-derived origin. Computed BEFORE resolving the
  // signer at all, so a hostile signer URL pointing at a different origin
  // is never fetched.
  const signerOrigin = revocationListOrigin(parsed.signer);
  if (signerOrigin === null || signerOrigin !== origin) {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }

  let resolved = null;
  try {
    resolved = await resolveKey(parsed.signer, options.keyResolvers);
  } catch {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }
  // Spec §9.6/§9.1: the signer must be neither revoked nor superseded --
  // a superseded key MUST NOT sign new content, and this list is new
  // content. isKeyRevoked already covers "revoked" and the key-document-
  // derived flavor of "superseded" (superseded implies expired, which
  // isKeyRevoked already treats as revoked-for-verification purposes).
  if (!resolved || isKeyRevoked(resolved)) {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }

  // Every entry MUST be well-formed, or the whole document is rejected:
  // silently skipping a malformed entry is fail-open (a malformed
  // "revoked" entry would simply vanish instead of blocking the list).
  if (!parsed.revocations.every(isRevocationEntry)) {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }
  const entries = parsed.revocations;

  // Spec §9.6: a list whose signer is itself listed revoked or superseded,
  // within this same list, MUST be rejected rather than applied -- checked
  // by key material, matching how every other match in this module works.
  const signerHash = await spkiHash(resolved.publicKeyPem);
  const signerCanonical = canonicalKeyidForm(parsed.signer);
  const signerSelfListed = entries.some((entry) => {
    if (entry.status === "revoked") return entry.publicKeyHash === signerHash;
    return entry.publicKeyHash ? entry.publicKeyHash === signerHash : canonicalKeyidForm(entry.keyid) === signerCanonical;
  });
  if (signerSelfListed) {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }

  let payload: string;
  try {
    payload = canonicalizeJson(omitSignature(parsed));
  } catch {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }

  let sigOk = false;
  try {
    sigOk = await verifySignature(payload, parsed.signature, resolved.publicKeyPem, parsed.algorithm);
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    return { outcome: "unknown", expiresAt: now + UNKNOWN_RETRY_MS };
  }

  return { outcome: "ok", expiresAt: now + freshnessMsFor(res, maxStaleness, maxStaleness, now), entries };
}

/**
 * Minimal shape this module needs from a resolved key. `ResolvedKey` from
 * @htmltrust/canonicalization satisfies this.
 */
export interface RevocationCheckKey {
  publicKeyPem: string;
}

/**
 * Check a resolved key's revocation status against its publisher-served
 * revocation list (spec §9.5-9.9). Off the critical path by design: callers
 * decide whether and when to consult this, independent of the key
 * document's own `revoked` field.
 *
 * Takes the RESOLVED key, not just `keyid`, because the `revoked` match is
 * by key material (spec §9.7): `keyid` is opaque and signer-chosen, and a
 * match keyed only to its text is bypassable by resolving the same key
 * under a different, equally valid spelling of the same identifier.
 *
 * Returns `undefined`, not a "revocation-unknown" result, when `keyid` has
 * no derivable HTTPS origin at all (a DID method other than did:web): no
 * fetch was attempted, so there is nothing to report. This matches the
 * W3C IDL's null-for-not-implemented convention for
 * `SignedSectionCryptoOutcome/revocationStatus`.
 *
 * This function alone closes keyid aliasing WITHIN the origin `keyid`
 * itself names. It does not close a cross-host alias where a key document
 * is reachable under a second hostname the verifier was never told is the
 * same identity; see `../identifier-binding.js` and `verify.ts` for that.
 */
export async function checkKeyRevocation(
  keyid: string,
  resolvedKey: RevocationCheckKey,
  options: RevocationCheckOptions,
): Promise<RevocationCheckResult | undefined> {
  const origin = revocationListOrigin(keyid);
  if (origin === null) return undefined;

  const url = `${origin}/.well-known/htmltrust-revocations.json`;
  const now = (options.now ?? Date.now)();
  const maxStaleness = options.maxStalenessMs ?? DEFAULT_MAX_STALENESS_MS;
  const cache = options.cache ?? defaultCache;

  let cached = cache.get(url);
  if (!cached || now >= cached.expiresAt) {
    cached = await fetchList(url, origin, now, maxStaleness, options);
    cache.set(url, cached);
  }

  if (cached.outcome === "not-found") return NOT_REVOKED;
  if (cached.outcome === "unknown") return UNKNOWN;

  const resolvedHash = await spkiHash(resolvedKey.publicKeyPem);
  const canonicalChecked = canonicalKeyidForm(keyid);

  // "revoked": publicKeyHash against the resolved key's own SPKI hash,
  // full stop. No keyid-text fallback -- a revoked entry without
  // publicKeyHash is malformed (isRevocationEntry above) and the whole
  // document was already rejected before reaching this point. Checked
  // across every entry, so a "revoked" entry always wins over any
  // "superseded" entry for the same key, regardless of array order.
  for (const entry of cached.entries) {
    if (entry.status === "revoked" && entry.publicKeyHash === resolvedHash) {
      return { status: "revoked", superseded: false, revokedAt: entry.revokedAt };
    }
  }
  // "superseded" is Layer 2 metadata, not a security gate: match by
  // publicKeyHash when present, else by canonical keyid.
  for (const entry of cached.entries) {
    if (entry.status !== "superseded") continue;
    const matches = entry.publicKeyHash
      ? entry.publicKeyHash === resolvedHash
      : canonicalKeyidForm(entry.keyid) === canonicalChecked;
    if (matches) {
      return { status: "not-revoked", superseded: true, supersededBy: entry.supersededBy };
    }
  }
  return NOT_REVOKED;
}
